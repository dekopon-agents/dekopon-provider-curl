# dekopon-provider-curl

A production-bounded, unauthenticated HTTP GET provider for
[Dekopon](https://github.com/dekopon-agents/dekopon) 0.11.1.

| Manifest field | Value |
|---|---|
| Provider | `curl` |
| Capability | `curl.get` |
| Command word | `curlget` |
| Effect / risk / idempotency | `read-only` / `Medium` / `idempotent` |

`Medium` is deliberate: the caller controls the complete path/query, fetched content can be
sensitive or adversarial, and broken upstreams can make GET stateful.

## Broker-only execution

The component imports **exactly** `dekopon:http/client@1.0.0` and exports `describe`, `invoke`, and
`resolve-command`. It imports no WASI or other interface and contains no HTTP stack. Only a separate
Dekopon broker links the import and supplies authorization, canonical URL handling, DNS validation
and pinning, streaming limits, and transport.

Direct `dekopon-run inspect`, direct `invoke`, direct `shell`, and an empty Wasmtime linker must
refuse the component. That is expected—not an installation error. Configure the component in
`dekopon-brokerd`, an exact constraint set, and a separate Cedar grant. See
[`examples/broker.yaml`](examples/broker.yaml) and [`examples/policies.cedar`](examples/policies.cedar).

Supported v0.1.0 constraints are:

```yaml
constraintSets:
  curl.get:
    provider: curl
    effect: read-only
    risk: Medium
    idempotency: idempotent
    constraints:
      timeoutMs: 10000
      maxOutputBytes: 524288
      http:
        allowedHosts: [operator-selected-exact-authorities]
        allowedMethods: [GET]
        maxRequests: 1
        maxRequestBytes: 32768
        maxResponseBytes: 262144
        allowPlaintextLoopback: false
```

There must be no `credential` or `credentialByAgent`. These bounds sit below Dekopon 0.11.1 host
defaults (30 seconds, 64 MiB Wasm memory, 1 MiB input/output, 32 calls, 1 MiB request, 4 MiB
response, 128 headers, and 64 KiB header bytes).

### Contract limitations

1. **`curl` cannot be this provider's word.** The sandboxed shell reserves it as a builtin and the
   registry rejects a provider claiming it. `curlget` is separator-free and unreserved. `curl-get`
   is capability-shaped and also invalid. The reserved builtin remains available in broker mode:

   ```console
   dekopon-run prompt --broker --curl-capability curl.get ...
   ```

   Its broader parser can propose methods or bodies; this provider still rejects anything except a
   bodyless GET.
2. **Cedar cannot inspect URI path or query.** Granting `curl.get` for an authority grants every
   otherwise-permitted GET path/query on that authority. Use a dedicated authority when that is too
   broad.
3. **Duplicate raw JSON keys cannot be rejected after SDK decoding.** `serde_json::Value` retains
   the last value. Tests record this last-wins limitation; no documentation claims duplicate-key
   rejection.

## Invocation

```json
{
  "uri": "https://api.example.com/v1/items?limit=10",
  "method": "GET",
  "headers": [
    {"name": "accept", "value": "application/json"},
    {"name": "if-none-match", "value": "\"abc\""}
  ]
}
```

Only `uri` is required. The closed input contract rejects unknown fields. `method`, when present,
must be exactly uppercase `GET`. At most 32 headers are accepted; names are 1–64 bytes, values are
at most 4,096 UTF-8 bytes, and aggregate accounted bytes (`name + value + 4`) are at most 16,384.
Names are ASCII HTTP tokens normalized lowercase, values contain no ASCII controls or DEL, and the
only caller names are:

- `accept`
- `accept-language`
- `cache-control`
- `if-modified-since`
- `if-none-match`
- `range`

The provider appends `user-agent: dekopon-provider-curl/0.1.0`. It sends one `GET`, an empty body,
ordered caller headers (including duplicates), then that User-Agent. It never retries.

URIs are at most 4,096 UTF-8 bytes with no ASCII whitespace/control, backslash, or fragment. They
must have a nonempty, unambiguous authority, no userinfo (including empty `@` and percent-encoded
authority forms), and no zero port. HTTPS is accepted. HTTP is accepted only for a literal IPv4 or
bracketed IPv6 loopback with an explicit nonzero port, for constrained loopback tests; production's
`allowPlaintextLoopback: false` still denies it authoritatively. The original bounded URI is passed
to the broker—this guest intentionally does not duplicate its WHATWG parser or authorization logic.

Every HTTP status, including 3xx/4xx/5xx, is successful data. Redirects are not followed. Output is
byte-preserving padded RFC 4648 base64 with optional UTF-8 projections:

```json
{
  "status": 200,
  "headers": [
    {"name": "x-value", "valueBase64": "b25l", "valueText": "one"}
  ],
  "bodyBase64": "AAE=",
  "bodyText": "optional UTF-8 projection",
  "bodyBytes": 2,
  "bodyReturnedBytes": 2,
  "bodyTruncated": false
}
```

Response-header order and duplicates are preserved. The broker has already removed cookies,
authentication challenges, and hop-by-hop fields; these are not raw wire headers. The guest accepts
at most 128 response headers and 65,536 accounted header bytes. It returns at most 65,536 body
bytes, backing up when a cut splits an otherwise valid UTF-8 scalar but retaining a full binary
prefix for genuinely invalid UTF-8. `bodyBytes` is the complete host-returned size. `bodyText`
appears only for valid UTF-8 whose compact JSON string is at most 131,072 bytes.

The complete compact SDK success envelope is capped at 524,288 bytes. If optional text crosses the
ceiling, every optional body/header text projection is removed; mandatory base64 remains. A host
response overflow arrives as no partial response. All response content is untrusted and can
prompt-inject a model.

## Command word

`resolve-command` is a pure parser; Dekopon links imports into a disabled resolution context and
fails resolution if an import is touched. `argv` excludes `curlget`:

```text
curlget [-s|-S|<short bundle containing only s/S>]
        [--silent|--show-error]
        [-X GET|--request GET]
        [-H "Name: value"|--header "Name: value"]...
        URL
```

Quiet flags are documented no-ops because structured execution has no progress meter. Method values
are separate, case-insensitive `GET`, normalized uppercase, and may appear once. Headers are
separate values, split at the first colon, trimmed around name/value, and preserve later colons,
order, and duplicates. Exactly one URL, at most 70 argv entries, at most 24,576 aggregate UTF-8
bytes, and at most 32 headers are accepted. Attached values, `--flag=value`, and every unlisted
option produce exactly:

```text
usage: curlget [-sS] [-X GET] [-H "Name: value"]... URL
```

## Explicit non-goals

v0.1.0 is not general curl and intentionally provides none of the following:

- methods other than GET, HEAD, `-G`, request bodies, data, forms, or uploads;
- redirects, fail-on-status, retries, retry timing, or follow-up calls;
- authentication, generic credential injection, bearer/basic auth, cookies, or token fields;
- proxies or environment proxy inheritance;
- output files, file input, config files, filesystem access, subprocesses, or libcurl;
- compression negotiation, decompression, content decoding, or archive handling;
- TLS bypass, custom CA/client certificates, or plaintext non-loopback HTTP;
- caller-controlled Host, User-Agent, authorization, hop-by-hop, or arbitrary extension headers;
- progress output, curl exit-code emulation, formatting, or raw wire response headers;
- path/query-aware Cedar policy, a second URL library for authorization, redirects-as-navigation,
  or a claim that GET is side-effect-free;
- WASI, sockets, JS interop, clocks, randomness, environment access, or network-dependent tests;
- sanitizing, trusting, interpreting, or prompt-safety-classifying fetched content;
- rejecting duplicate raw JSON keys after the SDK has decoded them.

Generic credentialed GET is excluded because an arbitrary allowed path can reflect a broker-injected
credential in its response.

## Build and acceptance

Release bytes use Rust 1.97.0 and wasm-tools 1.236.1; MSRV is Rust 1.89.0. `build.sh` only targets
`wasm32-unknown-unknown`, normalizes crate metadata, remaps source/Cargo/sysroot paths, embeds the
exact deterministic notices in `dekopon.third-party-notices`, componentizes, validates, enforces
512 KiB, and writes a checksum. The inventory and SBOM resolve an isolated 43-crate normal/build
graph so native dev features cannot leak into shipped evidence. `wasm32-wasip2` is forbidden.

```console
rustup toolchain install 1.89.0 --profile minimal --component clippy --component rustfmt
rustup toolchain install 1.97.0 --profile minimal
rustup target add wasm32-unknown-unknown --toolchain 1.89.0
rustup target add wasm32-unknown-unknown --toolchain 1.97.0
cargo install wasm-tools --version 1.236.1 --locked
cargo install wasmtime-cli --version 48.0.0 --locked
cargo install cargo-deny --version 0.20.2 --locked
cargo install cargo-cyclonedx --version 0.5.9 --locked

cargo +1.89.0 fmt --all -- --check
cargo +1.89.0 clippy --locked --all-targets -- -D warnings
cargo +1.89.0 test --locked --lib
cargo +1.89.0 check --locked --target wasm32-unknown-unknown
cargo deny --locked check advisories licenses bans sources
./scripts/dependency_inventory.py check-sources
./scripts/dependency_inventory.py inventory --output /tmp/curl-dependencies.txt
./scripts/dependency_inventory.py notices --output /tmp/curl-notices.md
cmp security/wasm-dependencies.txt /tmp/curl-dependencies.txt
cmp THIRD_PARTY_NOTICES.md /tmp/curl-notices.md
shellcheck build.sh scripts/*.sh
actionlint .github/workflows/*.yml
zizmor --pedantic .github/workflows/*.yml
./build.sh
./scripts/verify-component.sh
cargo +1.97.0 test --locked --test broker_host
./scripts/test-direct-refusal.sh
./scripts/generate-sbom.sh dist/curl-provider.cdx.json
./scripts/check-reproducible.sh
```

Tests are native mocks or loopback-only broker fixtures. They never contact the public network.
Generated Wasm, checksums, SBOMs, `dist/`, and `target/` are ignored and must be removed after local
acceptance; do not use `cargo clean` as routine hygiene.

See [`security/RESOURCE_LIMITS.md`](security/RESOURCE_LIMITS.md) for measured fixed fuel/memory
gates and [`RELEASE.md`](RELEASE.md) for the tag-only release process.

## Distribution and license

The eventual `v0.1.0` tag publishes exactly two GitHub assets (`curl-provider.wasm` and its
`.sha256`), provenance and CycloneDX SBOM attestations, and one public one-layer OCI artifact at
`ghcr.io/dekopon-agents/provider-curl:0.1.0`. It does not publish to crates.io or create `latest`.
No repository, tag, release, or package is created by the implementation step itself.

The provider is MIT OR Apache-2.0, at your option. See `LICENSE-MIT`, `LICENSE-APACHE`, and the
embedded deterministic `THIRD_PARTY_NOTICES.md`. That self-contained bundle verifies exact
`Cargo.lock` archive checksums and includes deduplicated full license, exception, copyright, and
NOTICE texts rather than relying on external links. The shipped closure has no LGPL obligation.
