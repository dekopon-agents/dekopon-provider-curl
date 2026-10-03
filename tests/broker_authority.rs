//! Real-component broker policy and audit checks carried across the typed migration.
use dekopon_broker::{
    AuthenticatedContext, Broker, BrokerLimits, CapabilityRoute, ConstraintCatalog, ConstraintSet,
    CredentialStore, IdentityDirectory, InMemoryAuditLog, InvocationRequest, PolicyEngine,
    PolicyWorld,
};
use dekopon_broker_host::{BrokerHostLimits, BrokerProviderRegistry, asset::AssetInputs};
use dekopon_broker_protocol::{Streams, TraceParent};
use dekopon_capability::{EffectKind, ExecutionConstraints, HttpConstraints, InvocationOutcome};
use dekopon_core::{Actor, AgentId, CapabilityId, PrincipalId};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    os::fd::OwnedFd,
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("fresh component")
        .into()
}
fn capability() -> CapabilityId {
    "curl.get".parse().unwrap()
}
fn principal(value: &str) -> PrincipalId {
    value.parse().unwrap()
}
fn context(value: &str) -> AuthenticatedContext {
    AuthenticatedContext::attested(
        principal(value),
        Actor::Agent {
            agent: "curl-test".parse::<AgentId>().unwrap(),
        },
        principal("gateway"),
        "slack.t0123abc.u9xyz".parse().unwrap(),
    )
    .unwrap()
}
fn request(id: &str, input: Value) -> InvocationRequest {
    InvocationRequest {
        id: id.parse().unwrap(),
        capability: capability(),
        trace_parent: TraceParent::new([7; 16], [3; 8], 1).unwrap(),
        secret_use: None,
        input,
    }
}
fn profile(authority: &str) -> ExecutionConstraints {
    ExecutionConstraints {
        timeout_ms: 10_000,
        http: Some(HttpConstraints {
            allowed_hosts: vec![authority.to_owned()],
            allowed_methods: vec!["GET".to_owned()],
            max_requests: 1,
            max_request_bytes: 32_768,
            max_response_bytes: 262_144,
            allow_plaintext_loopback: true,
            propagate_trace: false,
        }),
        storage: None,
        asset: None,
        secret_use: None,
    }
}
fn mock_http(response: Vec<u8>) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while request.windows(4).all(|window| window != b"\r\n\r\n") {
            let count = stream.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
        }
        tx.send(request).unwrap();
        stream.write_all(&response).unwrap();
    });
    (format!("127.0.0.1:{}", address.port()), rx, server)
}
fn streams() -> (AssetInputs, UnixStream) {
    let (stdout, peer) = UnixStream::pair().unwrap();
    let assets = AssetInputs {
        streams: Some(Streams {
            stdin: None,
            stdout: OwnedFd::from(stdout),
        }),
        ..AssetInputs::default()
    };
    (assets, peer)
}
#[tokio::test(flavor = "multi_thread")]
async fn cedar_denies_before_http_and_exact_get_is_audited_without_payload() {
    let (authority, received, server) = mock_http(b"HTTP/1.1 200 OK\r\nX-Audit: response-secret\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbody-secret".to_vec());
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .unwrap();
    let world = PolicyWorld::new(
        [principal("allowed-caller"), principal("denied-caller")],
        [(capability(), "curl".parse().unwrap())],
    )
    .unwrap();
    let policy = r#"@id("caller-may-fetch") permit(
        principal == Dekopon::Principal::"allowed-caller",
        action == Dekopon::Action::"curl.get",
        resource == Dekopon::Provider::"curl"
    ) when { context.agent == "curl-test" && context.via == "gateway" };"#;
    let constraints = ConstraintSet {
        route: CapabilityRoute::Generic,
        provider: "curl".parse().unwrap(),
        effect: EffectKind::ReadOnly,
        risk: dekopon_core::RiskLevel::Medium,
        credential: None,
        constraints: profile(&authority),
    };
    let audit = Arc::new(InMemoryAuditLog::new(16).unwrap());
    let broker = Broker::new(
        registry,
        principal("broker-test"),
        "policy-test".to_owned(),
        PolicyEngine::new(policy, &world).unwrap(),
        ConstraintCatalog::new([(capability(), constraints)]).unwrap(),
        CredentialStore::empty(),
        IdentityDirectory::empty(),
        Arc::clone(&audit),
        BrokerLimits::default(),
    )
    .unwrap();
    let denied = broker
        .invoke(
            &context("denied-caller"),
            None,
            None,
            request(
                "cedar-denied",
                json!({"uri":format!("http://{authority}/denied-secret")}),
            ),
            AssetInputs::default(),
        )
        .await
        .unwrap();
    assert_eq!(denied.result.outcome, InvocationOutcome::Denied);
    assert_eq!(denied.result.error.as_deref(), Some("policy-denied"));
    let (assets, mut peer) = streams();
    let allowed = broker
        .invoke(
            &context("allowed-caller"),
            None,
            None,
            request(
                "cedar-allowed",
                json!({"uri":format!("http://{authority}/private-path?query-secret=yes"),
            "headers":[{"name":"accept","value":"header-secret"}]}),
            ),
            assets,
        )
        .await
        .unwrap();
    assert_eq!(allowed.result.outcome, InvocationOutcome::Succeeded);
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"body-secret");
    let wire = received.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(wire.starts_with(b"GET /private-path?query-secret=yes HTTP/1.1\r\n"));
    assert!(wire.ends_with(b"\r\n\r\n"), "GET has no body");
    server.join().unwrap();
    let serialized = serde_json::to_string(&audit.records()).unwrap();
    assert!(serialized.contains(&authority));
    assert!(serialized.contains("GET"));
    for secret in [
        "denied-secret",
        "private-path",
        "query-secret",
        "header-secret",
        "response-secret",
        "body-secret",
    ] {
        assert!(!serialized.contains(secret), "audit leaked {secret}");
    }
}
