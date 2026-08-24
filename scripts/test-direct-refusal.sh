#!/usr/bin/env bash
# Privileged imports must make every immediate/direct host fail closed.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
component=${1:-"$root/curl-provider.wasm"}
[[ -f "$component" ]]
[[ "$(dekopon-run --version)" == "dekopon-run 0.11.1" ]]
[[ "$(wasmtime --version)" == "wasmtime 48.0.0" ]]

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

expect_dekopon_refusal() {
  local name=$1
  shift
  if "$@" >"$temporary/$name.out" 2>"$temporary/$name.err"; then
    echo "error: direct $name unexpectedly accepted the HTTP-importing component" >&2
    exit 1
  fi
  grep -Fq "could not instantiate provider component" "$temporary/$name.err"
}

expect_dekopon_refusal inspect \
  dekopon-run inspect --provider "$component"
expect_dekopon_refusal invoke \
  dekopon-run invoke --provider "$component" curl.get \
    --input '{"uri":"https://example.com"}'
expect_dekopon_refusal shell \
  dekopon-run shell --provider "$component" 'curlget https://example.com'

if wasmtime --invoke 'describe()' "$component" \
  >"$temporary/wasmtime.out" 2>"$temporary/wasmtime.err"; then
  echo "error: empty Wasmtime linker unexpectedly accepted the HTTP import" >&2
  exit 1
fi
grep -Fq "dekopon:http/client@1.0.0" "$temporary/wasmtime.err"
grep -Fq "imports instance" "$temporary/wasmtime.err"

printf 'verified direct refusal: inspect, invoke, shell, and empty Wasmtime linker\n'
