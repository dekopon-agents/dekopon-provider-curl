#!/usr/bin/env python3
"""Deterministic inventory and legal bundle for the isolated shipped Wasm graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections import deque
from dataclasses import dataclass

TARGET = "wasm32-unknown-unknown"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
LEGAL_BASENAME = re.compile(
    r"^(?:licen[cs]e|copying|copyright|notice|unlicense)(?:[-._].*)?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LegalDocument:
    """One exact legal file read from a checksum-verified .crate archive."""

    package: str
    version: str
    path: str
    digest: str
    content: bytes


def cargo_metadata(manifest: pathlib.Path, *, locked: bool, offline: bool = False) -> dict:
    """Run target-filtered Cargo metadata for one manifest."""
    command = [
        "cargo",
        "metadata",
        "--filter-platform",
        TARGET,
        "--format-version",
        "1",
        "--manifest-path",
        str(manifest),
    ]
    if locked:
        command.append("--locked")
    if offline:
        command.append("--offline")
    return json.loads(subprocess.check_output(command, text=True))


def without_dev_dependencies(manifest: str) -> str:
    """Remove every dev-dependency table while preserving all release declarations."""
    output: list[str] = []
    skip = False
    found = False
    for line in manifest.splitlines(keepends=True):
        match = re.match(r"^\s*\[([^]]+)]\s*(?:#.*)?$", line)
        if match:
            table = match.group(1).strip().strip('"').strip("'")
            skip = table == "dev-dependencies" or table.endswith(".dev-dependencies")
            found = found or skip
        if not skip:
            output.append(line)
    if not found:
        raise SystemExit("root manifest has no dev-dependency table to isolate")
    return "".join(output)


def prepare_release_graph(root: pathlib.Path, destination: pathlib.Path) -> dict:
    """Create and resolve a no-dev shadow package constrained to the committed lockfile."""
    root_manifest = root / "Cargo.toml"
    root_lock = root / "Cargo.lock"

    # Resolve the full committed lock once so every locked registry source/archive is available.
    full = cargo_metadata(root_manifest, locked=True)
    locked_packages = {
        (package["name"], package["version"], package.get("source"))
        for package in full["packages"]
    }

    if destination.exists() and any(destination.iterdir()):
        raise SystemExit(f"isolated graph destination is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "src").mkdir()
    (destination / "Cargo.toml").write_text(
        without_dev_dependencies(root_manifest.read_text(encoding="utf-8")),
        encoding="utf-8",
        newline="\n",
    )
    shutil.copyfile(root_lock, destination / "Cargo.lock")
    (destination / "src" / "lib.rs").write_text(
        "// Metadata-only source for the isolated normal/build graph.\n",
        encoding="utf-8",
        newline="\n",
    )

    shadow_manifest = destination / "Cargo.toml"
    # Cargo prunes the copied full lock to this package's no-dev closure without network access.
    cargo_metadata(shadow_manifest, locked=False, offline=True)
    isolated = cargo_metadata(shadow_manifest, locked=True, offline=True)
    for package in shipped_packages(isolated):
        identity = (package["name"], package["version"], package.get("source"))
        if identity not in locked_packages:
            raise SystemExit(
                "isolated graph selected a package outside the committed lock: "
                f"{package['name']} {package['version']}"
            )
    return isolated


def isolated_metadata(root: pathlib.Path) -> dict:
    """Resolve the shipped graph in a temporary package with no dev dependencies."""
    with tempfile.TemporaryDirectory(prefix="dekopon-curl-release-graph-") as temporary:
        return prepare_release_graph(root, pathlib.Path(temporary))


def shipped_packages(document: dict) -> list[dict]:
    """Return the root's target-specific normal/build transitive closure."""
    packages = {package["id"]: package for package in document["packages"]}
    nodes = {node["id"]: node for node in document["resolve"]["nodes"]}
    root_id = document["resolve"]["root"]
    seen = {root_id}
    queue = deque([root_id])
    while queue:
        node = nodes[queue.popleft()]
        for dependency in node["deps"]:
            if all(kind["kind"] == "dev" for kind in dependency["dep_kinds"]):
                continue
            package_id = dependency["pkg"]
            if package_id not in seen:
                seen.add(package_id)
                queue.append(package_id)
    return sorted(
        (packages[package_id] for package_id in seen if package_id != root_id),
        key=lambda package: (package["name"], package["version"], package["id"]),
    )


def lock_checksums(lockfile: pathlib.Path) -> dict[tuple[str, str, str], str]:
    """Read exact registry archive checksums from Cargo.lock without a TOML dependency."""
    checksums: dict[tuple[str, str, str], str] = {}
    text = lockfile.read_text(encoding="utf-8")
    for block in re.split(r"(?m)^\[\[package]]\s*$", text)[1:]:
        fields: dict[str, str] = {}
        for field in ("name", "version", "source", "checksum"):
            match = re.search(rf'(?m)^{field} = "([^"]+)"$', block)
            if match:
                fields[field] = match.group(1)
        if all(field in fields for field in ("name", "version", "source", "checksum")):
            key = (fields["name"], fields["version"], fields["source"])
            if key in checksums:
                raise SystemExit(f"duplicate lockfile package identity: {key}")
            checksums[key] = fields["checksum"]
    return checksums


def crate_archive(package: dict, expected_checksum: str) -> pathlib.Path:
    """Locate and checksum the Cargo-cached exact .crate archive for a package."""
    manifest = pathlib.Path(package["manifest_path"]).resolve()
    candidates: list[pathlib.Path] = []
    # Standard Cargo layout: registry/src/<index>/<crate>/Cargo.toml and registry/cache/<index>.
    if len(manifest.parents) >= 3 and manifest.parents[1].parent.name == "src":
        registry = manifest.parents[1].parent.parent
        candidates.append(
            registry
            / "cache"
            / manifest.parents[1].name
            / f"{package['name']}-{package['version']}.crate"
        )
    cargo_home = pathlib.Path(os.environ.get("CARGO_HOME", pathlib.Path.home() / ".cargo"))
    candidates.extend(
        sorted(
            (cargo_home / "registry" / "cache").glob(
                f"*/{package['name']}-{package['version']}.crate"
            )
        )
    )

    valid: list[pathlib.Path] = []
    for candidate in dict.fromkeys(candidates):
        if not candidate.is_file():
            continue
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if digest == expected_checksum:
            valid.append(candidate)
    if not valid:
        raise SystemExit(
            "exact checksum-verified crate archive is unavailable for "
            f"{package['name']} {package['version']} ({expected_checksum})"
        )
    return valid[0]


def archive_legal_documents(
    package: dict, checksums: dict[tuple[str, str, str], str]
) -> tuple[str, list[LegalDocument]]:
    """Read every legal/notice file from one exact checksum-verified archive."""
    key = (package["name"], package["version"], package.get("source"))
    checksum = checksums.get(key)
    if checksum is None:
        raise SystemExit(f"lockfile checksum missing for {package['name']} {package['version']}")
    archive = crate_archive(package, checksum)
    documents: list[LegalDocument] = []
    with tarfile.open(archive, mode="r:gz") as crate:
        members = sorted(crate.getmembers(), key=lambda member: member.name)
        for member in members:
            basename = pathlib.PurePosixPath(member.name).name
            if not member.isfile() or not LEGAL_BASENAME.fullmatch(basename):
                continue
            extracted = crate.extractfile(member)
            if extracted is None:
                raise SystemExit(f"cannot read legal archive member: {member.name}")
            content = extracted.read()
            try:
                content.decode("utf-8")
            except UnicodeDecodeError as error:
                raise SystemExit(f"legal archive member is not UTF-8: {member.name}") from error
            relative = "/".join(pathlib.PurePosixPath(member.name).parts[1:])
            documents.append(
                LegalDocument(
                    package=package["name"],
                    version=package["version"],
                    path=relative,
                    digest=hashlib.sha256(content).hexdigest(),
                    content=content,
                )
            )
    return checksum, documents


def inventory(packages: list[dict]) -> str:
    """Render the committed package inventory."""
    lines = [
        "# Generated by scripts/dependency_inventory.py; do not edit.",
        f"# Target: {TARGET}; isolated edge kinds: normal, build (no dev feature unification).",
    ]
    for package in packages:
        source = package.get("source") or "path"
        lines.append(f"{package['name']} {package['version']} {source}")
    return "\n".join(lines) + "\n"


def append_exact_document(output: bytearray, heading: str, content: bytes) -> None:
    """Append a labeled document while retaining its exact bytes as a contiguous subsequence."""
    output.extend(f"### {heading}\n\n```text\n".encode())
    output.extend(content)
    if not content.endswith(b"\n"):
        output.extend(b"\n")
    output.extend(b"```\n\n")


def notices(root: pathlib.Path, packages: list[dict]) -> bytes:
    """Render a self-contained, deterministic legal bundle from exact crate archives."""
    checksums = lock_checksums(root / "Cargo.lock")
    package_rows: list[tuple[dict, str, list[LegalDocument]]] = []
    unique: dict[str, LegalDocument] = {}
    supplied_by: dict[str, list[str]] = {}
    for package in packages:
        expression = package.get("license")
        if not expression:
            raise SystemExit(
                f"dependency {package['name']} {package['version']} has no SPDX license metadata"
            )
        checksum, documents = archive_legal_documents(package, checksums)
        package_rows.append((package, checksum, documents))
        for document in documents:
            previous = unique.get(document.digest)
            if previous is not None and previous.content != document.content:
                raise SystemExit(f"SHA-256 collision in legal documents: {document.digest}")
            unique.setdefault(document.digest, document)
            supplied_by.setdefault(document.digest, []).append(
                f"{document.package} {document.version}/{document.path}"
            )

    ordered_digests = sorted(unique)
    document_ids = {digest: f"A{index:03d}" for index, digest in enumerate(ordered_digests, 1)}

    # Every uncommon term in this exact closure must have its complete archive text represented.
    all_documents = list(unique.values())
    requirements = {
        "Unicode-3.0": lambda document: "unicode" in document.path.lower(),
        "Zlib": lambda document: document.package == "foldhash",
        "Unlicense": lambda document: "unlicense" in document.path.lower(),
        "LLVM-exception": lambda document: "llvm-exception" in document.path.lower(),
    }
    expressions = "\n".join(package["license"] for package in packages)
    for term, predicate in requirements.items():
        if term in expressions and not any(predicate(document) for document in all_documents):
            raise SystemExit(f"no exact archive legal text found for {term}")

    provider_files = [root / "LICENSE-APACHE", root / "LICENSE-MIT"]
    for provider_file in provider_files:
        if not provider_file.is_file():
            raise SystemExit(f"provider license file is missing: {provider_file.name}")

    output = bytearray(
        (
            "# Third-Party Notices and License Texts\n\n"
            "This is the self-contained legal bundle embedded in the provider component. The "
            f"package set is the locked, isolated `{TARGET}` normal/build graph; dev dependencies "
            "do not participate in feature resolution. Every `.crate` SHA-256 below is checked "
            "against `Cargo.lock`, and every legal, copyright, copying, exception, and NOTICE file "
            "present in those exact archives is reproduced below. Identical files are included once "
            "and referenced by document ID.\n\n"
            "The provider itself is licensed under MIT OR Apache-2.0. Its complete terms are P001 "
            "and P002 below. For archives that contain no legal file, those complete MIT/Apache-2.0 "
            "terms cover the declared alternatives; all special conjunctive/exception texts in this "
            "closure are also bundled from exact archives.\n\n"
            "## Package and archive inventory\n\n"
            "| Package | Version | SPDX expression | `.crate` SHA-256 | Exact archive legal documents |\n"
            "|---|---:|---|---|---|\n"
        ).encode()
    )
    for package, checksum, documents in package_rows:
        references = ", ".join(
            f"`{document.path}` ({document_ids[document.digest]})" for document in documents
        )
        if not references:
            references = "None in archive; see bundled P001/P002 terms"
        name = package["name"]
        version = package["version"]
        expression = package["license"]
        output.extend(
            f"| [`{name}`](https://crates.io/crates/{name}/{version}) | `{version}` | "
            f"`{expression}` | `{checksum}` | {references} |\n".encode()
        )

    output.extend(b"\n## Provider license terms\n\n")
    for index, provider_file in enumerate(provider_files, 1):
        content = provider_file.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        append_exact_document(
            output,
            f"P{index:03d} — `{provider_file.name}` (SHA-256 `{digest}`)",
            content,
        )

    output.extend(b"## Deduplicated exact archive legal texts\n\n")
    for digest in ordered_digests:
        document = unique[digest]
        sources = "; ".join(sorted(supplied_by[digest]))
        append_exact_document(
            output,
            f"{document_ids[digest]} — SHA-256 `{digest}`; supplied by {sources}",
            document.content,
        )

    output.extend(
        b"No crate in this shipped closure declares LGPL licensing. Source links identify the exact "
        b"crate versions, but this embedded bundle contains the applicable terms and notices and does "
        b"not rely on those links remaining available.\n"
    )
    return bytes(output)


def check_sources(packages: list[dict]) -> None:
    """Reject ambient/runtime and non-registry packages from the shipped graph."""
    failures = []
    forbidden = {
        "async-std",
        "curl",
        "curl-sys",
        "duct",
        "hyper",
        "js-sys",
        "libcurl",
        "reqwest",
        "smol",
        "subprocess",
        "tokio",
        "ureq",
        "wasm-bindgen",
        "wasm-bindgen-futures",
    }
    for package in packages:
        source = package.get("source")
        name = package["name"]
        lowered = name.lower()
        if source != CRATES_IO:
            failures.append(f"non-crates.io dependency: {name} {package['version']} ({source})")
        if lowered in forbidden or lowered.startswith(("wasi-", "wasip", "wasi_")):
            failures.append(f"forbidden ambient/runtime dependency: {name} {package['version']}")
    if failures:
        raise SystemExit("\n".join(failures))


def write_result(content: str | bytes, output: pathlib.Path | None) -> None:
    """Write generated bytes without platform newline conversion."""
    encoded = content.encode() if isinstance(content, str) else content
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(encoded)
    else:
        sys.stdout.buffer.write(encoded)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=["inventory", "notices", "check-sources", "prepare-release-graph"]
    )
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent

    if args.mode == "prepare-release-graph":
        if args.output is None:
            parser.error("prepare-release-graph requires --output DIRECTORY")
        document = prepare_release_graph(root, args.output.resolve())
        count = len(shipped_packages(document))
        print(f"prepared isolated {TARGET} normal/build graph with {count} shipped crates")
        return

    packages = shipped_packages(isolated_metadata(root))
    if args.mode == "check-sources":
        check_sources(packages)
        print(f"checked {len(packages)} shipped crates: crates.io-only, no ambient runtime")
        return
    rendered: str | bytes
    if args.mode == "inventory":
        rendered = inventory(packages)
    else:
        rendered = notices(root, packages)
    write_result(rendered, args.output)


if __name__ == "__main__":
    main()
