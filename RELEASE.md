# v0.1.0 release runbook

The tag workflow is intentionally the only publisher. Do not commit generated Wasm, use `cargo
publish`, push an OCI artifact by hand, or create a release manually.

1. On clean `main`, run all commands in the README's acceptance section, including the two-archive
   reproducibility gate.
2. Confirm `git status --short` is empty and the package version is exactly `0.1.0`.
3. Create and push an **annotated** tag: `git tag -a v0.1.0 -m 'v0.1.0' && git push origin v0.1.0`.
4. The workflow performs: build → provenance/SBOM attestations → exact draft assets → GHCR
   `0.1.0` → explicit finalization → anonymous verification. It never creates `latest` or
   `staging`.
5. Confirm release assets are exactly `curl-provider.wasm` and
   `curl-provider.wasm.sha256`. Confirm the public OCI manifest has one `application/wasm` layer,
   title `curl-provider.wasm`, and only tag `0.1.0`.

The workflow refuses lightweight/non-SemVer tags, a tag not resolving to the event SHA, a tag not on
`main`, a package-version mismatch, an existing published release/tag, wrong bytes, wrong WIT,
missing attestations, extra assets/layers/tags, and non-public GHCR. Newly created drafts and OCI
versions are removed on later failure where GitHub permits cleanup; attestations are immutable and
may remain as non-release evidence for a failed digest.

GitHub release finalization explicitly sets `draft: false`, `prerelease: false`, and
`make_latest: "false"`.
