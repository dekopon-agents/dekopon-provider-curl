# v0.1.0 release runbook

The tag workflow is intentionally the only publisher. Do not commit generated Wasm, use `cargo
publish`, push an OCI artifact by hand, or create a release manually.

1. On clean `main`, run all commands in the README's acceptance section, including the two-archive
   reproducibility gate.
2. Confirm `git status --short` is empty, the package version is exactly `0.1.0`, no release exists
   for `v0.1.0`, and the `ghcr.io/dekopon-agents/provider-curl` package is wholly absent.
3. Create and push an **annotated** tag: `git tag -a v0.1.0 -m 'v0.1.0' && git push origin v0.1.0`.
4. The workflow performs: MSRV/source/build gates → provenance/SBOM attestations → one newly owned
   draft with exact assets → a privately verified GHCR `0.1.0` manifest → prepublication
   re-verification → explicit finalization → anonymous verification. It never creates `latest` or
   `staging`.
5. Confirm release assets are exactly `curl-provider.wasm` and
   `curl-provider.wasm.sha256`. Confirm the public OCI manifest has one `application/wasm` layer,
   title `curl-provider.wasm`, and only tag `0.1.0`.

The workflow refuses lightweight/non-SemVer tags, a tag not resolving to the event SHA, a tag not on
`main`, a package-version mismatch, **any** existing draft/published release for the tag, **any**
existing GHCR package state, wrong bytes, wrong WIT, missing commit-bound attestations, and extra
assets/layers/tags. It captures release, asset, package, package-version, and OCI manifest IDs or
digests only after creation. Immediately before publication it re-peels the tag, downloads the draft
assets by captured immutable IDs, checks their bytes and checksum against the Actions artifact,
checks WIT, anonymously verifies attestations and digest-pinned OCI bytes, and then changes only the
captured release.

A failed or cancelled downstream job invokes rollback. Rollback first makes this run's package
private, deletes the exact captured release ID even if this run already finalized it, deletes only
the captured package version ID/manifest digest, and verifies that the initially absent package
state is restored. It never discovers ownership through a mutable tag, and cleanup errors fail
loudly. Attestations are immutable and may remain as non-release evidence for a failed digest.

GitHub release finalization explicitly sets `draft: false`, `prerelease: false`, and
`make_latest: "false"`.

## Pinned v0.1.0 recovery

Tagged run [`32770900739`](https://github.com/dekopon-agents/dekopon-provider-curl/actions/runs/32770900739)
built and reproducibly verified the final bytes and created their build-provenance attestation, then
failed before publication because `actions/attest-sbom` v2.4.0 incorrectly requires the optional
CycloneDX `serialNumber` field. Its successful rollback confirmed that no release or package was
left behind. The annotated tag was preserved unchanged.

`.github/workflows/recover-v0.1.0.yml` is the only authorized recovery. It is intentionally pinned to
the failed run, build job, workflow, tag object, source commit, two immutable Actions artifact IDs,
archive digests and sizes, component/checksum/SBOM digests, and exact confirmation phrase. The
helper refuses expired or substituted artifacts, re-verifies the tagged provenance, and never
builds provider bytes. The workflow attests the exact captured CycloneDX JSON through the pinned
underlying `actions/attest` action, then applies the same owned-draft, private-GHCR, prepublication,
finalization, anonymous-verification, and rollback controls. It cannot recover another version.
