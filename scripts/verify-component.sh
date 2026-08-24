#!/usr/bin/env bash
# Static acceptance checks for the core module and decoded component interface.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
component=${1:-"$root/curl-provider.wasm"}
core=${2:-"$root/target/wasm32-unknown-unknown/release/dekopon_curl_provider.wasm"}
maximum_bytes=$((512 * 1024))

[[ -f "$component" && -f "$core" ]]
[[ "$(wasm-tools --version | awk '{print $2}')" == "1.236.1" ]]
wasm-tools validate "$component"

printf '%s  %s\n' \
  '02ba5a92067f53bc8f48e10bf221229c5b7f33f791a031741da5011c32ab37c9' \
  "$root/wit/deps/provider.wit" \
  'd0655d1ceba81fbd810f125cfc8fb2cbd8ad0696d91d34631b6b54f185dbc174' \
  "$root/wit/deps/http.wit" | shasum -a 256 -c -

component_bytes=$(wc -c <"$component" | tr -d '[:space:]')
((component_bytes <= maximum_bytes))
(
  cd "$(dirname "$component")"
  shasum -a 256 -c "$(basename "$component").sha256"
)

wit_json=$(mktemp)
wit_text=$(mktemp)
core_text=$(mktemp)
core_imports=$(mktemp)
trap 'rm -f "$wit_json" "$wit_text" "$core_text" "$core_imports"' EXIT
wasm-tools component wit --json "$component" >"$wit_json"
wasm-tools component wit "$component" >"$wit_text"
wasm-tools print "$core" >"$core_text"

python3 - "$wit_json" "$root/THIRD_PARTY_NOTICES.md" "$core" "$component" <<'PY'
import json
import pathlib
import sys

wit = json.loads(pathlib.Path(sys.argv[1]).read_text())
if len(wit["worlds"]) != 1:
    raise SystemExit("expected exactly one decoded component world")
world = wit["worlds"][0]
if set(world["exports"]) != {"describe", "invoke", "resolve-command"}:
    raise SystemExit(f"unexpected component exports: {sorted(world['exports'])}")
if len(world["imports"]) != 1 or len(wit["interfaces"]) != 1:
    raise SystemExit("expected exactly one component interface import")
interface = wit["interfaces"][0]
package = wit["packages"][interface["package"]]["name"]
if package != "dekopon:http@1.0.0" or interface["name"] != "client":
    raise SystemExit(f"unexpected component import: {package}/{interface['name']}")
if set(interface["functions"]) != {"send"}:
    raise SystemExit("HTTP import does not expose exactly send")
if {package["name"] for package in wit["packages"]} != {
    "dekopon:http@1.0.0",
    "root:component",
}:
    raise SystemExit("unexpected package in decoded component WIT")

notices = pathlib.Path(sys.argv[2]).read_bytes()
for artifact_name in sys.argv[3:]:
    artifact = pathlib.Path(artifact_name).read_bytes()
    if b"dekopon.third-party-notices" not in artifact or notices not in artifact:
        raise SystemExit(f"exact notices absent from {artifact_name}")
PY

grep -E '^  \(import ' "$core_text" >"$core_imports" || true
if [[ "$(wc -l <"$core_imports" | tr -d '[:space:]')" != 1 ]] ||
   ! grep -Fq 'import "dekopon:http/client@1.0.0" "send"' "$core_imports"; then
  echo 'unexpected core imports:' >&2
  cat "$core_imports" >&2
  exit 1
fi
if grep -Eqi 'wasi:|wasix|wasi_snapshot|wasm-bindgen|js-sys' "$wit_text" "$core_text"; then
  echo "error: ambient interface/runtime found in component" >&2
  exit 1
fi
if ! wasm-tools objdump "$component" | grep -q 'custom "dekopon.third-party-notices"'; then
  echo "error: notice custom section was not preserved by componentization" >&2
  exit 1
fi

printf 'verified component: %s bytes; 3 exports; exactly dekopon:http/client@1.0.0; no WASI\n' \
  "$component_bytes"
