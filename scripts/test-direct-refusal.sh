#!/usr/bin/env bash
# A host that does not link dekopon:http/client@1.0.0 must fail closed on this component.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
component=${1:-"$root/curl-provider.wasm"}
[[ -f "$component" ]]
[[ "$(wasmtime --version)" == "wasmtime 48.0.2" ]]

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

if wasmtime --invoke 'describe()' "$component" \
  >"$temporary/wasmtime.out" 2>"$temporary/wasmtime.err"; then
  echo "error: empty Wasmtime linker unexpectedly accepted the HTTP import" >&2
  exit 1
fi
grep -Fq "dekopon:http/client@1.0.0" "$temporary/wasmtime.err"
grep -Fq "imports instance" "$temporary/wasmtime.err"

printf 'verified direct refusal: an empty Wasmtime linker cannot instantiate the component\n'
