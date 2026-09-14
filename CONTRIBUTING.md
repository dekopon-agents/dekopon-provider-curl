# Contributing

Keep the provider closed and deterministic:

- normal dependencies must remain exact crates.io pins; no path or Git sources;
- build only `wasm32-unknown-unknown` (never `wasm32-wasip2`);
- add no transport, URL authorization library, WASI, JS, subprocess, runtime networking, or ambient
  host capability;
- never commit `.wasm`, checksums, `dist/`, or `target/`;
- keep every public failure fixed and secret-free, rendered command-word text included;
- run `cargo deny --all-features check bans licenses sources advisories` after a lock change; the
  shared CI's SBOM step is the dependency-license record, not a committed file.

Before opening a change, run the complete acceptance command block in `README.md`. Tests use native
mocks or loopback listeners only and must never depend on the public network.
