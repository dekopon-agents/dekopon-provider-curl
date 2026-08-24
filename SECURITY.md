# Security

Report vulnerabilities privately through GitHub Security Advisories once the public repository
exists. Do not put credentials, private URLs, response data, or exploit payloads in a public issue.

## Trust boundary

This component is broker-only. It imports `dekopon:http/client@1.0.0`; direct `dekopon-run inspect`,
`invoke`, and `shell` intentionally have no implementation for that import and refuse to load it.
The component has no WASI, sockets, filesystem, process, environment, clock, randomness, JS, or
other ambient import.

The guest's URI checks are defense in depth. Dekopon 0.11.1 remains authoritative for WHATWG URL
parsing, canonical exact-authority matching, DNS validation, destination pinning, timeout and byte
limits. Cedar sees capability metadata and caller identity, not URI path/query. Treat a grant for an
authority as permission for every GET path and query this provider can send there.

v0.1.0 is unauthenticated by design. A generic GET path can reflect an injected credential in its
response, so supported constraint sets contain neither `credential` nor `credentialByAgent`. The
provider also rejects caller-controlled authorization, cookies, tokens, and credential fields.

Responses are untrusted byte strings. They can contain secrets, malicious formats, or prompt
injection. Base64 is preservation, not validation or sanitization.
