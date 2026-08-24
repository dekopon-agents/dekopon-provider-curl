#!/usr/bin/env bash
# Rebuild two independent clean git archives and compare every deterministic release input/output.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ -d "$root/.git" ]]
if ! git -C "$root" diff --quiet || ! git -C "$root" diff --cached --quiet; then
  echo "error: reproducibility must run from a clean committed tree" >&2
  exit 1
fi

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/a" "$temporary/b"
git -C "$root" archive --format=tar HEAD | tar -xf - -C "$temporary/a"
git -C "$root" archive --format=tar HEAD | tar -xf - -C "$temporary/b"

for tree in a b; do
  mkdir -p "$temporary/$tree/dist"
  CARGO_TARGET_DIR="$temporary/target-$tree" \
    "$temporary/$tree/build.sh" "$temporary/$tree/dist/curl-provider.wasm"
  "$temporary/$tree/scripts/generate-sbom.sh" \
    "$temporary/$tree/dist/curl-provider.cdx.json"
done

core=wasm32-unknown-unknown/release/dekopon_curl_provider.wasm
compare=(
  "a/dist/curl-provider.wasm b/dist/curl-provider.wasm"
  "a/dist/curl-provider.wasm.sha256 b/dist/curl-provider.wasm.sha256"
  "target-a/$core target-b/$core"
  "a/dist/curl-provider.cdx.json b/dist/curl-provider.cdx.json"
  "a/THIRD_PARTY_NOTICES.md b/THIRD_PARTY_NOTICES.md"
  "a/security/wasm-dependencies.txt b/security/wasm-dependencies.txt"
)
for pair in "${compare[@]}"; do
  read -r left right <<<"$pair"
  cmp "$temporary/$left" "$temporary/$right"
done

python3 - "$temporary" <<'PY'
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for side in ("a", "b"):
    notice = (root / side / "THIRD_PARTY_NOTICES.md").read_bytes()
    core = (root / f"target-{side}" / "wasm32-unknown-unknown/release/dekopon_curl_provider.wasm").read_bytes()
    component = (root / side / "dist/curl-provider.wasm").read_bytes()
    if notice not in core or notice not in component:
        raise SystemExit(f"{side}: embedded notices differ from committed notices")
PY

printf 'reproduced independently: core Wasm, component, checksum, SBOM, inventory, embedded notices\n'
