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

The first recovery dispatch,
[`32775319816`](https://github.com/dekopon-agents/dekopon-provider-curl/actions/runs/32775319816),
stopped before attestation or publication because `gh attestation verify` refuses API lookup on a
fresh Actions runner without `GH_TOKEN`, even for a public repository. Its no-op rollback again
confirmed absence. The verifier now anonymously downloads the public Sigstore bundle with `curl`
and passes that local bundle to `gh` under a clean config directory with both token variables unset;
this makes the anonymous boundary executable rather than relying on ambient CLI login state.

Recovery run
[`32777291858`](https://github.com/dekopon-agents/dekopon-provider-curl/actions/runs/32777291858)
then created and exactly verified the CycloneDX attestation at recovery commit
`7d3c700e534e4bc6dd73f8cdf1bfc26c351fcedc`, but its raw REST draft request was denied before any
release existed. Runs
[`32779510352`](https://github.com/dekopon-agents/dekopon-provider-curl/actions/runs/32779510352)
and
[`32781476757`](https://github.com/dekopon-agents/dekopon-provider-curl/actions/runs/32781476757)
proved that neither adding `pull-requests: read` nor replacing generated notes with fixed notes made
that request form available. All no-op rollbacks confirmed package/release absence. Subsequent
recovery pins and reuses the one immutable SBOM attestation and uses the already proven organization
pattern, `gh release create --verify-tag`, with marker-owned fixed notes and no `target_commitish` or
generated-notes request. It does not create a duplicate attestation.

Run
[`32783422553`](https://github.com/dekopon-agents/dekopon-provider-curl/actions/runs/32783422553)
successfully created that marker-owned draft, but its immediate list request raced GitHub's draft
visibility and failed to capture the ID; the generic rollback therefore had no ID to delete. The
next control commit pins the exact residual draft ID `376021870`, marker, creating run/commit/job,
bot author, empty asset set, and successful no-package cleanup. It refuses every other release,
continues that existing transaction rather than creating/reusing an unowned draft, and fixes the
normal tag workflow with a bounded post-create visibility poll.
