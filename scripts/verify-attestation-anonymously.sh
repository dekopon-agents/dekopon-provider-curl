#!/usr/bin/env bash
# Fetch one public GitHub attestation without credentials, then verify its local Sigstore bundle.
set -euo pipefail

artifact=${1:?usage: verify-attestation-anonymously.sh ARTIFACT REPO DIGEST PREDICATE SIGNER SOURCE_REF SOURCE_DIGEST}
repo=${2:?}
digest=${3:?}
predicate=${4:?}
signer=${5:?}
source_ref=${6:?}
source_digest=${7:?}
api=${GITHUB_API_URL:-https://api.github.com}

[[ -f "$artifact" ]]
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]
[[ "$digest" =~ ^[0-9a-f]{64}$ ]]
[[ "$source_digest" =~ ^[0-9a-f]{40}$ ]]
for command in curl gh jq mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "error: $command is required" >&2
    exit 1
  }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
response="$work/attestations.json"
status=
for _attempt in {1..12}; do
  status=$(curl --silent --show-error --location --get \
    --output "$response" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    --user-agent 'dekopon-provider-curl-anonymous-verifier/0.1.0' \
    --data-urlencode "predicate_type=$predicate" \
    "$api/repos/$repo/attestations/sha256:$digest")
  if [[ "$status" == 200 ]]; then
    break
  fi
  if [[ "$status" != 404 ]]; then
    echo "error: anonymous attestation fetch returned HTTP $status" >&2
    cat "$response" >&2
    exit 1
  fi
  sleep 5
done
[[ "$status" == 200 ]]
[[ "$(jq '.attestations | length' "$response")" == 1 ]]
jq -e '.attestations[0].bundle | type == "object"' "$response" >/dev/null
jq '.attestations[0].bundle' "$response" >"$work/bundle.json"

# A clean config directory plus unset token variables proves gh cannot use ambient authentication.
mkdir "$work/gh-config"
env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR="$work/gh-config" \
  gh attestation verify "$artifact" \
    --bundle "$work/bundle.json" \
    --repo "$repo" \
    --predicate-type "$predicate" \
    --signer-workflow "$signer" \
    --source-ref "$source_ref" \
    --source-digest "$source_digest" \
    --deny-self-hosted-runners >/dev/null

printf 'anonymously verified %s attestation for sha256:%s\n' "$predicate" "$digest"
