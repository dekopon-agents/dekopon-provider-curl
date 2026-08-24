#!/usr/bin/env bash
# Download and verify only the immutable artifacts produced by tagged release run 32770900739.
# This one-off recovery helper never builds or substitutes provider bytes.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
destination=${1:?usage: recover-v0.1.0-artifacts.sh DESTINATION}

source_run_id=32770900739
source_build_job_id=97570764100
source_workflow_id=341521755
source_sha=b2228842c6dddc78b2eb4bfaa72c302b4bf284f2
tag=v0.1.0
tag_object=69f3dd845c9b9a4aa962328340e266aa4f2ba32d
component_artifact_id=9536872848
component_archive_sha=ec7d7bd00105285ae631b01b1c18e144c2fe4c8fb385345db233dc65f6ab618f
component_archive_size=77628
sbom_artifact_id=9536873521
sbom_archive_sha=b7d9857fc70f4a1de2b3822da8010f5dbc24f65cc9a7eb07e518c76f97762468
sbom_archive_size=6750
component_sha=c2167ce14a7aaaec55635091da233745c06e6757c5080a4a635c03ea0e82d9c0
checksum_sha=2331b33ebeb068068e5e2cc7c6eebb041dbf5e87d0b0663177926e034128c4f4
sbom_sha=e360e3313bfc0f92633eb2323ac217a780c1502f0c612b00c9d216437b83f97c
repo=dekopon-agents/dekopon-provider-curl

: "${GH_TOKEN:?GH_TOKEN is required to read the captured Actions artifacts}"
[[ "${GITHUB_REPOSITORY:-$repo}" == "$repo" ]]
for command in curl gh git jq shasum unzip; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "error: $command is required" >&2
    exit 1
  }
done

run=$(gh api "repos/$repo/actions/runs/$source_run_id")
jq -e \
  --arg sha "$source_sha" \
  --argjson id "$source_run_id" \
  --argjson workflow_id "$source_workflow_id" '
    .id == $id and
    .workflow_id == $workflow_id and
    .name == "Release v0.1.0" and
    .path == ".github/workflows/release.yml" and
    .event == "push" and
    .status == "completed" and
    .conclusion == "failure" and
    .head_branch == "v0.1.0" and
    .head_sha == $sha and
    .run_attempt == 1 and
    .repository.full_name == "dekopon-agents/dekopon-provider-curl"
  ' <<<"$run" >/dev/null

jobs=$(gh api "repos/$repo/actions/runs/$source_run_id/jobs?filter=all&per_page=100")
jq -e --argjson id "$source_build_job_id" '
  [.jobs[] | select(
    .id == $id and
    .name == "Build and verify immutable bytes" and
    .status == "completed" and
    .conclusion == "success"
  )] | length == 1
' <<<"$jobs" >/dev/null
jq -e '
  [.jobs[] | select(.name == "Attest provenance and SBOM")][0] as $job |
  $job.conclusion == "failure" and
  ([$job.steps[] | select(.name == "Attest build provenance") | .conclusion] == ["success"]) and
  ([$job.steps[] | select(.name == "Attest CycloneDX SBOM") | .conclusion] == ["failure"])
' <<<"$jobs" >/dev/null

artifacts=$(gh api "repos/$repo/actions/runs/$source_run_id/artifacts?per_page=100")
jq -e \
  --arg component_digest "sha256:$component_archive_sha" \
  --arg sbom_digest "sha256:$sbom_archive_sha" \
  --arg sha "$source_sha" \
  --argjson component_id "$component_artifact_id" \
  --argjson component_size "$component_archive_size" \
  --argjson run_id "$source_run_id" \
  --argjson sbom_id "$sbom_artifact_id" \
  --argjson sbom_size "$sbom_archive_size" '
    .total_count == 2 and
    ([.artifacts[] | {
      id,
      name,
      size_in_bytes,
      expired,
      digest,
      run_id: .workflow_run.id,
      head_branch: .workflow_run.head_branch,
      head_sha: .workflow_run.head_sha
    }] | sort_by(.id)) == ([
      {
        id: $component_id,
        name: "release-component",
        size_in_bytes: $component_size,
        expired: false,
        digest: $component_digest,
        run_id: $run_id,
        head_branch: "v0.1.0",
        head_sha: $sha
      },
      {
        id: $sbom_id,
        name: "release-sbom",
        size_in_bytes: $sbom_size,
        expired: false,
        digest: $sbom_digest,
        run_id: $run_id,
        head_branch: "v0.1.0",
        head_sha: $sha
      }
    ] | sort_by(.id))
  ' <<<"$artifacts" >/dev/null

git -C "$root" fetch --force origin "refs/tags/$tag:refs/tags/$tag"
[[ "$(git -C "$root" cat-file -t "refs/tags/$tag")" == tag ]]
[[ "$(git -C "$root" rev-parse "refs/tags/$tag")" == "$tag_object" ]]
[[ "$(git -C "$root" rev-parse "refs/tags/$tag^{}")" == "$source_sha" ]]
git -C "$root" merge-base --is-ancestor "$source_sha" HEAD

rm -rf "$destination"
mkdir -p "$destination/component" "$destination/sbom" "$destination/archives"
download() {
  local artifact_id=$1
  local archive_sha=$2
  local output=$3
  gh api "repos/$repo/actions/artifacts/$artifact_id/zip" >"$output"
  [[ "$(shasum -a 256 "$output" | awk '{print $1}')" == "$archive_sha" ]]
}
download "$component_artifact_id" "$component_archive_sha" \
  "$destination/archives/release-component.zip"
download "$sbom_artifact_id" "$sbom_archive_sha" \
  "$destination/archives/release-sbom.zip"
unzip -q "$destination/archives/release-component.zip" -d "$destination/component"
unzip -q "$destination/archives/release-sbom.zip" -d "$destination/sbom"

component_files=$(cd "$destination/component" && find . -type f -print | LC_ALL=C sort)
sbom_files=$(cd "$destination/sbom" && find . -type f -print | LC_ALL=C sort)
[[ "$component_files" == $'./curl-provider.wasm\n./curl-provider.wasm.sha256' ]]
[[ "$sbom_files" == './curl-provider.cdx.json' ]]
[[ "$(shasum -a 256 "$destination/component/curl-provider.wasm" | awk '{print $1}')" == \
   "$component_sha" ]]
[[ "$(shasum -a 256 "$destination/component/curl-provider.wasm.sha256" | awk '{print $1}')" == \
   "$checksum_sha" ]]
[[ "$(shasum -a 256 "$destination/sbom/curl-provider.cdx.json" | awk '{print $1}')" == \
   "$sbom_sha" ]]
[[ "$(cat "$destination/component/curl-provider.wasm.sha256")" == \
   "$component_sha  curl-provider.wasm" ]]
(cd "$destination/component" && shasum -a 256 -c curl-provider.wasm.sha256)
[[ "$(wc -c <"$destination/component/curl-provider.wasm" | tr -d '[:space:]')" == 270575 ]]
jq -e '
  .bomFormat == "CycloneDX" and
  .specVersion == "1.5" and
  .metadata.component.name == "dekopon-curl-provider" and
  (.components | length) == 43
' "$destination/sbom/curl-provider.cdx.json" >/dev/null

# The first attestation step of the tagged run succeeded. It is the immutable bridge from the tag
# commit to these bytes; recovery must never proceed from an unattested or locally rebuilt file.
"$root/scripts/verify-attestation-anonymously.sh" \
  "$destination/component/curl-provider.wasm" \
  "$repo" \
  "$component_sha" \
  'https://slsa.dev/provenance/v1' \
  "$repo/.github/workflows/release.yml" \
  "refs/tags/$tag" \
  "$source_sha"

printf 'verified immutable tagged artifacts: run=%s component=sha256:%s sbom=sha256:%s\n' \
  "$source_run_id" "$component_sha" "$sbom_sha"
