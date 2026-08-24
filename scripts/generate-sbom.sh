#!/usr/bin/env bash
# Generate a deterministic CycloneDX 1.5 SBOM for the isolated shipped Wasm graph.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
output=${1:?usage: generate-sbom.sh OUTPUT.json}
mkdir -p "$(dirname "$output")"
output_dir=$(cd "$(dirname "$output")" && pwd -P)
output="$output_dir/$(basename "$output")"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
graph="$temporary/release-graph"

[[ "$(cargo cyclonedx --version)" == "cargo-cyclonedx-cyclonedx 0.5.9" ]]
"$root/scripts/dependency_inventory.py" prepare-release-graph --output "$graph"
(
  cd "$graph"
  SOURCE_DATE_EPOCH=0 cargo cyclonedx \
    --format json \
    --spec-version 1.5 \
    --target wasm32-unknown-unknown \
    --override-filename curl-provider.raw
)
raw="$graph/curl-provider.raw.json"

python3 - "$root" "$graph" "$raw" "$root/security/wasm-dependencies.txt" "$output" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
graph = pathlib.Path(sys.argv[2]).resolve()
raw = pathlib.Path(sys.argv[3])
inventory = pathlib.Path(sys.argv[4])
output = pathlib.Path(sys.argv[5])
document = json.loads(raw.read_text())

if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
    raise SystemExit("unexpected CycloneDX document version")
if document["metadata"]["timestamp"] != "1970-01-01T00:00:00.000000000Z":
    raise SystemExit("SBOM timestamp is not SOURCE_DATE_EPOCH")
if document["metadata"]["tools"] != [
    {"vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.9"}
]:
    raise SystemExit("SBOM generator pin drifted")

expected = []
for line in inventory.read_text().splitlines():
    if not line or line.startswith("#"):
        continue
    name, version, source = line.split(" ", 2)
    if "crates.io-index" not in source:
        raise SystemExit(f"non-crates.io inventory entry: {line}")
    expected.append((name, version))
actual = sorted((item["name"], item["version"]) for item in document["components"])
if sorted(expected) != actual:
    raise SystemExit("SBOM components differ from the committed isolated dependency inventory")

# cargo-cyclonedx models the metadata-only local root as a file package. Normalize only local
# package paths; registry package identities and Cargo checksums remain untouched.
def normalize(value):
    if isinstance(value, str):
        return value.replace(str(graph), "/dekopon/source").replace(
            str(root), "/dekopon/source"
        )
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    return value

if len(actual) != 43:
    raise SystemExit(f"expected 43 isolated shipped components, found {len(actual)}")
document = normalize(document)
encoded = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
for local_path in (str(root), str(graph), str(graph.parent)):
    if local_path in encoded:
        raise SystemExit(f"SBOM retained a local build path: {local_path}")
output.write_text(encoded, encoding="utf-8", newline="\n")
PY

printf 'generated deterministic isolated-graph CycloneDX SBOM %s\n' "$output"
