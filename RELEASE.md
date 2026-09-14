# Release runbook

The tag workflow is intentionally the only publisher. Do not commit generated Wasm, use `cargo
publish`, push an OCI artifact by hand, or create a release manually.

1. On clean `main`, run all commands in the README's acceptance section and confirm `ci / validate`
   is green; it performs the two-archive reproducibility gate that used to run locally.
2. Confirm `git status --short` is empty, the package version in `Cargo.toml` is exactly the version
   you are about to tag, no release exists for that tag, and `ghcr.io/dekopon-agents/provider-curl`
   carries no version with that tag. Published versions are immutable; a reused tag is refused.
3. Create and push an **annotated** tag: `git tag -a v<version> -m 'v<version>' && git push origin
   v<version>`.
4. The workflow performs: MSRV/source/build gates -> provenance/SBOM attestations -> one newly owned
   draft with exact assets -> a verified GHCR `<version>` manifest -> prepublication
   re-verification -> explicit finalization -> anonymous verification. It never creates `latest` or
   `staging`.
5. Confirm release assets are exactly `curl-provider.wasm` and `curl-provider.wasm.sha256`. Confirm
   the public OCI manifest has one `application/wasm` layer, title `curl-provider.wasm`, and that
   the repository's tag list gained exactly the new version.

The workflow refuses lightweight/non-SemVer tags, a tag not resolving to the event SHA, a tag not on
`main`, a package-version mismatch, **any** existing draft/published release for the tag, an OCI tag
that already exists, wrong bytes, wrong WIT, missing commit-bound attestations, and extra
assets/layers. It captures release, asset, package, package-version, and OCI manifest IDs or digests
only after creation. Immediately before publication it re-peels the tag, downloads the draft assets
by captured immutable IDs, checks their bytes and checksum against the Actions artifact, checks WIT,
anonymously verifies attestations and digest-pinned OCI bytes, and then changes only the captured
release.

A failed or cancelled downstream job invokes rollback. Rollback deletes the exact captured release
ID even if this run already finalized it, deletes only the captured package version ID/manifest
digest, and verifies that version is gone. The package itself is only made private and deleted when
this run created it — the release that first publishes the package owns it, and a later release
rolling itself back must not take its predecessors offline. Rollback never discovers ownership
through a mutable tag, and cleanup errors fail loudly. Attestations are immutable and may remain as
non-release evidence for a failed digest.

GitHub release finalization explicitly sets `draft: false`, `prerelease: false`, and
`make_latest: "false"`.
