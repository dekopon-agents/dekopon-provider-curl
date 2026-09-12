//! Component and broker-host acceptance against loopback only.
//!
//! These tests require `./build.sh` first. No test resolves or contacts a public hostname.

use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use dekopon_broker::{
    AuditEvent, AuthenticatedContext, Broker, BrokerLimits, CapabilityRoute, ConstraintCatalog,
    ConstraintSet, CredentialStore, IdentityDirectory, InMemoryAuditLog, InvocationRequest,
    PolicyEngine, PolicyWorld,
};
use dekopon_broker_host::{
    BrokerHostError, BrokerHostLimits, BrokerProviderRegistry, CommandRunOutcome,
};
use dekopon_broker_protocol::TraceParent;
use dekopon_capability::{
    AuthorizedInvocation, EffectKind, ExecutionConstraints, HttpConstraints, InvocationOutcome,
    ProposedInvocation, broker::AuthorizationGate,
};
use dekopon_core::{
    Actor, AgentId, CapabilityId, InvocationId, PrincipalId, ProviderId, RiskLevel, TraceId,
};
use serde_json::{Value, json};

/// One W3C trace shared by every fixture, so audit records correlate the way a real run's do.
const TRACE_FIXTURE: TraceId = match TraceId::new([7; 16]) {
    Ok(trace) => trace,
    Err(_) => panic!("static trace fixture is valid"),
};

const RESOURCE_FUEL_CEILING: u64 = 64_000_000;
const RESOURCE_MEMORY_CEILING: usize = 16 * 1024 * 1024;

fn component() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("curl-provider.wasm")
}

fn capability() -> CapabilityId {
    "curl.get".parse().expect("valid capability fixture")
}

fn authorized(id: &str, input: Value, constraints: ExecutionConstraints) -> AuthorizedInvocation {
    let proposal = ProposedInvocation::new(
        id.parse::<InvocationId>()
            .expect("valid invocation fixture"),
        capability(),
        Actor::Agent {
            agent: "curl-test".parse::<AgentId>().expect("valid agent fixture"),
        },
        TRACE_FIXTURE,
        input,
    );
    AuthorizationGate::new()
        .authorize(
            proposal,
            "curl".parse::<ProviderId>().expect("valid provider"),
            format!("decision-{id}"),
            "broker-test"
                .parse::<PrincipalId>()
                .expect("valid principal"),
            "policy-test".to_owned(),
            constraints,
        )
        .expect("bounded fixture authorization")
}

fn profile(authority: &str) -> ExecutionConstraints {
    ExecutionConstraints {
        timeout_ms: 10_000,
        max_output_bytes: 524_288,
        http: Some(HttpConstraints {
            allowed_hosts: vec![authority.to_owned()],
            allowed_methods: vec!["GET".to_owned()],
            max_requests: 1,
            max_request_bytes: 32_768,
            max_response_bytes: 262_144,
            // Production remains false. Component tests opt in because HTTP is permitted only for
            // explicit loopback tests and no test owns a loopback TLS certificate.
            allow_plaintext_loopback: true,
        }),
        storage: None,
        secret_use: None,
    }
}

fn mock_http(response: Vec<u8>) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture request");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while request.windows(4).all(|window| window != b"\r\n\r\n") {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        sender.send(request).expect("record request");
        stream.write_all(&response).expect("write response");
        stream.flush().expect("flush response");
    });
    (format!("127.0.0.1:{}", address.port()), receiver, handle)
}

fn stalled_http() -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while request.windows(4).all(|window| window != b"\r\n\r\n") {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => request.extend_from_slice(&buffer[..read]),
            }
        }
        sender.send(request).expect("record stalled request");
        thread::sleep(Duration::from_millis(400));
    });
    (format!("127.0.0.1:{}", address.port()), receiver, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_loads_exact_manifest_and_resolution_is_import_free() {
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .expect("broker linker loads HTTP provider");
    assert_eq!(registry.command_words(), ["curlget"]);
    let manifest = registry.manifests().next().expect("one manifest");
    assert_eq!(manifest.id.as_str(), "curl");
    assert_eq!(manifest.capabilities.len(), 1);
    assert_eq!(manifest.capabilities[0].id.as_str(), "curl.get");
    assert_eq!(manifest.capabilities[0].effect, EffectKind::ReadOnly);
    assert_eq!(manifest.capabilities[0].risk, RiskLevel::Medium);

    let piped = registry
        .run_command(
            "curlget",
            &[
                "-sS".to_owned(),
                "-X".to_owned(),
                "get".to_owned(),
                "-H".to_owned(),
                "@-".to_owned(),
                "https://example.com/private".to_owned(),
            ],
            Some("Accept: application/json\n"),
        )
        .await
        .expect("disabled resolution context is untouched");
    match piped {
        CommandRunOutcome::Proposed { capability, input } => {
            assert_eq!(capability.as_str(), "curl.get");
            assert_eq!(input["method"], "GET");
            assert_eq!(input["uri"], "https://example.com/private");
            assert_eq!(
                input["headers"],
                json!([{"name": "Accept", "value": "application/json"}])
            );
        }
        other => panic!("unexpected outcome: {other:?}"),
    }

    // Help and usage errors are rendered by the guest before authorization, so neither reaches a
    // capability and neither can touch the HTTP import.
    match registry
        .run_command("curlget", &["--help".to_owned()], None)
        .await
        .expect("help renders")
    {
        CommandRunOutcome::Rendered {
            stdout,
            stderr,
            status,
        } => {
            assert!(stdout.starts_with("curlget: one bounded"));
            assert_eq!(stderr, "");
            assert_eq!(status, 0);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    match registry
        .run_command("curlget", &["--data".to_owned(), "x".to_owned()], None)
        .await
        .expect("a refused argv renders")
    {
        CommandRunOutcome::Rendered {
            stdout,
            stderr,
            status,
        } => {
            assert_eq!(stdout, "");
            assert!(stderr.starts_with("usage: curlget"));
            assert_eq!(status, 2);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn exact_loopback_grant_sends_one_bodyless_get_without_credentials() {
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .expect("broker loads component");
    let response = b"HTTP/1.1 418 Teapot\r\nX-Value: one\r\nX-Value: two\r\nSet-Cookie: secret=session\r\nWWW-Authenticate: secret\r\nContent-Length: 3\r\nConnection: close\r\n\r\n\x00\x01\xff".to_vec();
    let (authority, received, server) = mock_http(response);
    let output = registry
        .invoke(
            authorized(
                "host-success",
                json!({
                    "uri": format!("http://{authority}/private-path?query=secret"),
                    "headers": [
                        {"name": "Accept", "value": "application/octet-stream"},
                        {"name": "Accept", "value": "application/json"}
                    ]
                }),
                profile(&authority),
            ),
            None,
        )
        .await
        .expect("exact grant executes");

    assert_eq!(output.output["status"], 418);
    assert_eq!(output.output["bodyBase64"], "AAH/");
    assert_eq!(output.output["bodyBytes"], 3);
    let headers = output.output["headers"].as_array().expect("headers array");
    assert_eq!(
        headers
            .iter()
            .filter(|header| header["name"] == "x-value")
            .map(|header| header["valueText"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
    assert!(headers.iter().all(|header| {
        !matches!(
            header["name"].as_str(),
            Some("set-cookie" | "www-authenticate" | "connection")
        )
    }));
    assert_eq!(output.http_calls.len(), 1);
    assert_eq!(output.http_calls[0].method, "GET");
    assert_eq!(output.http_calls[0].authority, authority);
    assert_eq!(output.http_calls[0].status, Some(418));
    assert!(!output.http_calls[0].credential_injected);

    let wire = received.recv().expect("request recorded");
    assert!(wire.starts_with(b"GET /private-path?query=secret HTTP/1.1\r\n"));
    assert!(wire.ends_with(b"\r\n\r\n"), "GET has no body");
    let wire = String::from_utf8(wire).expect("request headers are text");
    assert_eq!(
        wire.lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("accept:"))
            .count(),
        2
    );
    assert!(wire.to_ascii_lowercase().contains(concat!(
        "user-agent: dekopon-provider-curl/",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(!wire.to_ascii_lowercase().contains("authorization:"));
    assert!(!wire.to_ascii_lowercase().contains("cookie:"));
    server.join().expect("fixture exits");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_wrong_host_method_port_and_plaintext_grants_are_terminal() {
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .expect("broker loads component");
    let uri = "http://127.0.0.1:9/never-connect";
    let mut cases = Vec::new();
    cases.push(("missing", ExecutionConstraints::default(), "denied"));
    cases.push(("wrong-port", profile("127.0.0.1:10"), "denied"));
    // Same port, different literal loopback host: enforcing only the port must not authorize.
    cases.push(("wrong-host-same-port", profile("127.0.0.2:9"), "denied"));
    let mut wrong_method = profile("127.0.0.1:9");
    wrong_method.http.as_mut().unwrap().allowed_methods = vec!["POST".to_owned()];
    cases.push(("wrong-method", wrong_method, "denied"));
    let mut plaintext_disabled = profile("127.0.0.1:9");
    plaintext_disabled
        .http
        .as_mut()
        .unwrap()
        .allow_plaintext_loopback = false;
    cases.push(("plaintext-disabled", plaintext_disabled, "denied"));
    let mut request_too_large = profile("127.0.0.1:9");
    request_too_large.http.as_mut().unwrap().max_request_bytes = 64;
    cases.push(("request-too-large", request_too_large, "byte-limit"));

    for (name, constraints, reason) in cases {
        let failure = registry
            .invoke(authorized(name, json!({"uri": uri}), constraints), None)
            .await
            .expect_err("host authorization is sticky and terminal");
        assert!(
            matches!(
                failure.error.as_ref(),
                BrokerHostError::HostCallRejected { reason: actual, .. } if *actual == reason
            ),
            "{name}: {failure}"
        );
        assert!(
            failure.http_calls.is_empty(),
            "{name}: denial must occur before any HTTP call"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn forbidden_caller_headers_and_credential_fields_fail_before_network() {
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .expect("broker loads component");
    for (index, input) in [
        json!({
            "uri": "http://127.0.0.1:9/",
            "headers": [{"name": "authorization", "value": "Bearer secret-sentinel"}]
        }),
        json!({"uri": "http://127.0.0.1:9/", "token": "secret-sentinel"}),
        json!({"uri": "http://127.0.0.1:9/", "credential": "secret-sentinel"}),
    ]
    .into_iter()
    .enumerate()
    {
        let failure = registry
            .invoke(
                authorized(
                    &format!("guest-closed-{index}"),
                    input,
                    profile("127.0.0.1:9"),
                ),
                None,
            )
            .await
            .expect_err("closed guest input is refused");
        assert!(
            matches!(
                failure.error.as_ref(),
                BrokerHostError::ProviderFailure { code, message, .. }
                    if (code == "invalid-header" || code == "invalid-input")
                        && !message.contains("secret-sentinel")
            ),
            "{failure}"
        );
        assert!(failure.http_calls.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_and_streamed_overflow_return_no_partial_provider_response() {
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .expect("broker loads component");
    let (authority, received, stalled) = stalled_http();
    let mut timeout_profile = profile(&authority);
    timeout_profile.timeout_ms = 75;
    let timeout = registry
        .invoke(
            authorized(
                "host-timeout",
                json!({"uri": format!("http://{authority}/slow")}),
                timeout_profile,
            ),
            None,
        )
        .await
        .expect_err("stalled response times out");
    assert!(
        matches!(
            timeout.error.as_ref(),
            BrokerHostError::ProviderFailure { code, .. } if code == "http-timeout"
        ) || matches!(timeout.error.as_ref(), BrokerHostError::Timeout { .. }),
        "{timeout}"
    );
    assert!(
        received
            .recv_timeout(Duration::from_secs(1))
            .expect("timed-out request dispatched")
            .starts_with(b"GET /slow")
    );
    stalled.join().expect("stalled fixture exits");

    let body = vec![b'x'; 8_192];
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend(body);
    let (authority, _received, server) = mock_http(response);
    let mut small = profile(&authority);
    small.http.as_mut().unwrap().max_response_bytes = 1_024;
    let overflow = registry
        .invoke(
            authorized(
                "host-overflow",
                json!({"uri": format!("http://{authority}/large")}),
                small,
            ),
            None,
        )
        .await
        .expect_err("streamed response bound is terminal");
    assert!(matches!(
        overflow.error.as_ref(),
        BrokerHostError::HostCallRejected {
            reason: "byte-limit",
            ..
        }
    ));
    assert!(overflow.http_calls.is_empty() || overflow.http_calls[0].status.is_none());
    server.join().expect("overflow fixture exits");
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_is_returned_without_contacting_location() {
    let location = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
    location
        .set_nonblocking(true)
        .expect("make redirect target observable");
    let location_address = location.local_addr().unwrap();
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{location_address}/must-not-run\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let (authority, received, server) = mock_http(response);
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .expect("broker loads component");
    let output = registry
        .invoke(
            authorized(
                "host-redirect",
                json!({"uri": format!("http://{authority}/redirect")}),
                profile(&authority),
            ),
            None,
        )
        .await
        .expect("302 is successful data");
    assert_eq!(output.output["status"], 302);
    assert_eq!(output.http_calls.len(), 1);
    assert!(received.recv().unwrap().starts_with(b"GET /redirect"));
    server.join().expect("origin fixture exits");
    assert!(matches!(location.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
}

#[tokio::test(flavor = "multi_thread")]
async fn bounded_worst_case_runs_under_committed_memory_and_fuel_ceilings() {
    let limits = BrokerHostLimits {
        max_memory_bytes: RESOURCE_MEMORY_CEILING,
        fuel: RESOURCE_FUEL_CEILING,
        ..BrokerHostLimits::default()
    };
    let registry = BrokerProviderRegistry::load([component()], limits)
        .await
        .expect("component describes under fixed resources");
    // Near the profile's complete-response ceiling, near the host's header count/byte ceilings,
    // and with optional text at its maximum compact-JSON encoding. A genuinely invalid byte after
    // the returned prefix makes the guest retain the raw 64 KiB cut; that prefix itself remains
    // valid UTF-8 and expensive to JSON-escape.
    let mut body = vec![b'\\'; 65_534];
    body.extend_from_slice(b"aa");
    body.resize(190_000, b'z');
    body[70_000] = 0xff;
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )
    .into_bytes();
    for _ in 0..90 {
        response.extend_from_slice(b"X: ");
        response.extend(std::iter::repeat_n(b'\\', 700));
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"\r\n");
    response.extend(body);
    let (authority, _received, server) = mock_http(response);
    let output = registry
        .invoke(
            authorized(
                "host-resources",
                json!({"uri": format!("http://{authority}/worst-case")}),
                profile(&authority),
            ),
            None,
        )
        .await
        .expect("bounded response fits fixed resources");
    assert_eq!(output.output["bodyBytes"], 190_000);
    assert_eq!(output.output["bodyReturnedBytes"], 65_536);
    server.join().expect("resource fixture exits");
}

fn principal(value: &str) -> PrincipalId {
    value.parse().expect("valid principal fixture")
}

fn context(value: &str) -> AuthenticatedContext {
    AuthenticatedContext::new(
        principal(value),
        Actor::Agent {
            agent: "curl-test".parse().expect("valid agent"),
        },
    )
    .expect("trusted context")
}

fn request(id: &str, input: Value) -> InvocationRequest {
    InvocationRequest {
        id: id.parse().expect("valid invocation ID"),
        capability: capability(),
        trace_parent: TraceParent::new(TRACE_FIXTURE.to_bytes(), [3; 8], 1)
            .expect("valid traceparent fixture"),
        secret_use: None,
        input,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cedar_denies_before_network_allows_exact_get_and_audits_metadata_only() {
    let response = b"HTTP/1.1 200 OK\r\nX-Audit: response-secret\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbody-secret".to_vec();
    let (authority, received, server) = mock_http(response);
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .expect("broker loads component");
    let world = PolicyWorld::new(
        [principal("allowed-caller"), principal("denied-caller")],
        [(capability(), "curl".parse().unwrap())],
    )
    .expect("policy world");
    let policy = r#"permit(
        principal == Dekopon::Principal::"allowed-caller",
        action == Dekopon::Action::"curl.get",
        resource == Dekopon::Provider::"curl"
    ) when { context has agent && context.agent == "curl-test" }
      unless { context has via };"#;
    let engine = PolicyEngine::new(policy, &world).expect("Cedar validates");
    let constraints = profile(&authority);
    let set = ConstraintSet {
        route: CapabilityRoute::Generic,
        provider: "curl".parse().unwrap(),
        effect: EffectKind::ReadOnly,
        risk: RiskLevel::Medium,
        credential: None,
        credential_by_agent: BTreeMap::new(),
        constraints,
    };
    assert!(set.credential.is_none());
    assert!(set.credential_by_agent.is_empty());
    let catalog = ConstraintCatalog::new([(capability(), set)]).expect("catalog");
    let audit = Arc::new(InMemoryAuditLog::new(16).expect("audit bound"));
    let broker = Broker::new(
        registry,
        principal("broker-test"),
        "policy-test".to_owned(),
        engine,
        catalog,
        CredentialStore::empty(),
        IdentityDirectory::empty(),
        Arc::clone(&audit),
        BrokerLimits::default(),
    )
    .expect("broker metadata and constraints agree");

    let denied = broker
        .invoke(
            &context("denied-caller"),
            None,
            None,
            request(
                "cedar-denied",
                json!({"uri": format!("http://{authority}/denied-secret")}),
            ),
        )
        .await
        .expect("denial is durably accounted");
    assert_eq!(denied.outcome, InvocationOutcome::Denied);
    assert_eq!(denied.error.as_deref(), Some("policy-denied"));
    assert!(denied.output.is_none());

    let allowed = broker
        .invoke(
            &context("allowed-caller"),
            None,
            None,
            request(
                "cedar-allowed",
                json!({
                    "uri": format!("http://{authority}/private-path?query-secret=yes"),
                    "headers": [{"name": "accept", "value": "header-secret"}]
                }),
            ),
        )
        .await
        .expect("allow is durably accounted");
    assert_eq!(allowed.outcome, InvocationOutcome::Succeeded);
    assert_eq!(allowed.output.as_ref().unwrap()["bodyText"], "body-secret");
    let wire = received
        .recv()
        .expect("exactly the allowed request arrives");
    assert!(wire.starts_with(b"GET /private-path?query-secret=yes"));
    server.join().expect("one-call server exits");

    let failed = broker
        .invoke(
            &context("allowed-caller"),
            None,
            None,
            request(
                "cedar-provider-failure",
                json!({
                    "uri": format!("http://{authority}/failure-secret"),
                    "headers": [{"name": "authorization", "value": "credential-secret"}]
                }),
            ),
        )
        .await
        .expect("ordinary component failure is accounted");
    assert_eq!(failed.outcome, InvocationOutcome::Failed);
    assert_eq!(failed.error.as_deref(), Some("provider-failure"));
    assert!(failed.output.is_none());

    let records = audit.records().await;
    assert_eq!(records.len(), 5);
    assert!(matches!(
        records[0],
        AuditEvent::Decision { allowed: false, .. }
    ));
    let serialized = serde_json::to_string(&records).expect("audit serializes");
    assert!(serialized.contains(&authority));
    assert!(serialized.contains("GET"));
    assert!(serialized.contains("200"));
    for secret in [
        "denied-secret",
        "private-path",
        "query-secret",
        "header-secret",
        "response-secret",
        "body-secret",
        "failure-secret",
        "credential-secret",
        "authorization",
    ] {
        assert!(!serialized.contains(secret), "audit leaked {secret}");
    }
}
