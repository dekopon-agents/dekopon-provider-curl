# Committed resource gates

The release component is tested with these independent broker-host ceilings:

| Resource | Fixed gate |
|---|---:|
| Wasm linear memory | 16,777,216 bytes |
| Fuel per fresh store | 64,000,000 units |
| Component artifact | 524,288 bytes |
| Provider success envelope | 524,288 bytes |

`tests/broker_host.rs::bounded_worst_case_runs_under_committed_memory_and_fuel_ceilings` sends a
190,000-byte body plus 90 duplicate, heavily JSON-escaped response headers. The returned prefix is
64 KiB and its optional text projection sits at the 131,072-byte compact-JSON boundary. This drives
the component through request handling, response copying, base64, optional projections, complete
envelope sizing, and host evidence under the fixed ceilings.

With the pinned v0.1.0 release component, Rust 1.97.0, wasm-tools 1.236.1, and Dekopon/Wasmtime
0.11.1/36.0.14, the measurement made on 2026-08-24 was:

- **43,196,521 fuel units** for the stressed invocation;
- **3,670,016 bytes** as the largest observed guest-memory request;
- zero denied memory-growth requests.

The committed 64 million fuel gate leaves deterministic headroom without falling back to the
broker host's 8 billion default. CI reruns the stressed invocation; a regression that crosses either
fixed gate fails before a tag can be released. Fuel is a Wasm execution budget, not a latency SLA;
the independent supported timeout remains 10 seconds.
