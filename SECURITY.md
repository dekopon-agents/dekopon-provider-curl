# Security

Report vulnerabilities privately through GitHub Security Advisories once the public repository
exists. Do not put credentials, private URLs, response data, or exploit payloads in a public issue.

## Trust boundary

This component is broker-only. It imports `dekopon:http/client@1.0.0`; any host that does not link
that import — every direct, non-broker host — refuses to instantiate it. The component has no WASI,
sockets, filesystem, process, environment, clock, randomness, JS, or other ambient import.

The guest's URI checks are defense in depth. Dekopon 0.15.0 remains authoritative for WHATWG URL
parsing, canonical exact-authority matching, DNS validation, destination pinning, timeout and byte
limits. Cedar sees capability metadata and caller identity, not URI path/query. Treat a grant for an
authority as permission for every GET path and query this provider can send there.

## Secrets

`--oauth2-bearer <drn>` and `-u <username>:<drn>` carry a public DRN and nothing else. The DRN
travels on the proposal's `secretUse` rather than in the invocation input; the broker authorizes
that use through a `secret.use` Cedar statement **and** an owner-authored binding fixing sink,
username, host, method, path, query, and injection count, then writes the `Authorization` header
itself at the native HTTP boundary. No secret byte ever exists inside the component, and
`authorization` stays off the caller-header allowlist, so the guest cannot send that header under
any argv. A DRN with no matching binding is refused before any HTTP call, and a refusal naming a
credential flag is a fixed sentence that never echoes the value. An authenticated GET returns
exactly the content the credential unlocked, so bind a secret to the narrowest path that works.

Supported constraint sets still contain neither `credential` nor `credentialByAgent`: generic
credential injection over an arbitrary allowed path can reflect the credential in its response,
which is the failure a binding's exact path exists to prevent. The provider also rejects
caller-controlled authorization, cookies, tokens, and credential fields in its input.

Responses are untrusted byte strings. They can contain secrets, malicious formats, or prompt
injection. Base64 is preservation, not validation or sanitization.
