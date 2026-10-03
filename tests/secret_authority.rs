//! A DRN proposes intent; policy AND an exact owner binding authorize injection.
use async_trait::async_trait;
use dekopon_broker::{
    AuthenticatedContext, Broker, BrokerLimits, CapabilityRoute, ConstraintCatalog, ConstraintSet,
    CredentialStore, IdentityDirectory, InMemoryAuditLog, InvocationRequest, PolicyEngine,
    PolicyWorld, SecretCatalog, SecretMaterial, SecretResolutionError, SecretResolver,
    SecretUseBinding,
};
use dekopon_broker_host::{
    BrokerHostLimits, BrokerProviderRegistry, CommandRunOutcome, asset::AssetInputs,
};
use dekopon_broker_protocol::{Streams, TraceParent};
use dekopon_capability::{
    EffectKind, ExecutionConstraints, HttpConstraints, HttpPathRule, InvocationOutcome,
};
use dekopon_core::{
    Actor, AgentId, CapabilityId, PrincipalId, SecretDrn, SecretSinkKind, SecretUseProposal,
};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::TcpListener,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

const SECRET: &str = "drn:com.xrl:secret:test:curl/token";
const SECRET_BYTES: &[u8] = b"drn-secret-never-visible";
const PATH: &str = "/api/v1/thing";
fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("fresh component")
        .into()
}
fn cap() -> CapabilityId {
    "curl.get".parse().unwrap()
}
fn principal(value: &str) -> PrincipalId {
    value.parse().unwrap()
}
fn context() -> AuthenticatedContext {
    AuthenticatedContext::attested(
        principal("allowed-caller"),
        Actor::Agent {
            agent: "curl-test".parse::<AgentId>().unwrap(),
        },
        principal("gateway"),
        "slack.t0123abc.u9xyz".parse().unwrap(),
    )
    .unwrap()
}
fn profile(host: &str) -> ExecutionConstraints {
    ExecutionConstraints {
        timeout_ms: 10_000,
        http: Some(HttpConstraints {
            allowed_hosts: vec![host.to_owned()],
            allowed_methods: vec!["GET".into()],
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
fn mock_http() -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
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
            let n = stream.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..n]);
        }
        tx.send(request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    (format!("127.0.0.1:{}", address.port()), rx, server)
}
fn mock_late_echo() -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
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
            let n = stream.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..n]);
        }
        tx.send(request).unwrap();
        let mut first = vec![b'a'; 64];
        first.extend_from_slice(&SECRET_BYTES[..8]);
        let mut second = SECRET_BYTES[8..].to_vec();
        second.extend_from_slice(b"tail");
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            first.len() + second.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&first).unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(75));
        let _ = stream.write_all(&second);
    });
    (format!("127.0.0.1:{}", address.port()), rx, server)
}
fn streams() -> (AssetInputs, UnixStream) {
    let (stdout, peer) = UnixStream::pair().unwrap();
    (
        AssetInputs {
            streams: Some(Streams {
                stdin: None,
                stdout: OwnedFd::from(stdout),
            }),
            ..Default::default()
        },
        peer,
    )
}
#[derive(Debug)]
struct StaticSecretResolver;
#[async_trait]
impl SecretResolver for StaticSecretResolver {
    async fn resolve(&self, _secret: &SecretDrn) -> Result<SecretMaterial, SecretResolutionError> {
        Ok(SecretMaterial::new(SECRET_BYTES.to_vec()))
    }
}
async fn broker(
    host: &str,
    binding: Option<(SecretSinkKind, Option<&str>)>,
    audit: Arc<InMemoryAuditLog>,
) -> Broker<InMemoryAuditLog> {
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .unwrap();
    let world = PolicyWorld::new(
        [principal("allowed-caller")],
        [(cap(), "curl".parse().unwrap())],
    )
    .unwrap()
    .with_secrets([SECRET.parse().unwrap()]);
    let policy = format!(
        r#"
        @id("caller-may-fetch") permit(principal == Dekopon::Principal::"allowed-caller",
            action == Dekopon::Action::"curl.get", resource == Dekopon::Provider::"curl")
            when {{ context.agent == "curl-test" && context.via == "gateway" }};
        @id("caller-may-use-token") permit(principal == Dekopon::Principal::"allowed-caller",
            action == Dekopon::Action::"secret.use", resource == Dekopon::Secret::"{SECRET}")
            when {{ context.capability == "curl.get" && context.provider == "curl" }};
    "#
    );
    let constraints = ConstraintSet {
        route: CapabilityRoute::Generic,
        provider: "curl".parse().unwrap(),
        effect: EffectKind::ReadOnly,
        risk: dekopon_core::RiskLevel::Medium,
        credential: None,
        constraints: profile(host),
    };
    let broker = Broker::new(
        registry,
        principal("broker-test"),
        "policy-test".into(),
        PolicyEngine::new(&policy, &world).unwrap(),
        ConstraintCatalog::new([(cap(), constraints)]).unwrap(),
        CredentialStore::empty(),
        IdentityDirectory::empty(),
        audit,
        BrokerLimits::default(),
    )
    .unwrap();
    if let Some((sink, username)) = binding {
        broker
            .with_secret_catalog(
                SecretCatalog::new(
                    vec![SecretUseBinding {
                        binding_id: "curl-token".to_owned(),
                        secret: SECRET.parse().unwrap(),
                        capability: cap(),
                        sink,
                        basic_username: username.map(str::to_owned),
                        allowed_hosts: vec![host.to_owned()],
                        allowed_methods: vec!["GET".to_owned()],
                        allowed_paths: vec![HttpPathRule::Exact {
                            path: PATH.to_owned(),
                        }],
                        allow_query: false,
                        max_injections: 1,
                    }],
                    Arc::new(StaticSecretResolver),
                )
                .unwrap(),
            )
            .unwrap()
    } else {
        broker
    }
}
fn request(id: &str, input: Value, secret_use: Option<SecretUseProposal>) -> InvocationRequest {
    InvocationRequest {
        id: id.parse().unwrap(),
        capability: cap(),
        trace_parent: TraceParent::new([7; 16], [3; 8], 1).unwrap(),
        input,
        secret_use,
    }
}
async fn proposal(
    broker: &Broker<InMemoryAuditLog>,
    args: &[&str],
) -> (Value, Option<SecretUseProposal>) {
    let result = broker
        .run_command(
            &context(),
            None,
            None,
            "curl",
            &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            false,
        )
        .await
        .unwrap();
    let CommandRunOutcome::Proposed {
        capability,
        input,
        secret_use,
    } = result
    else {
        panic!("proposal: {result:?}")
    };
    assert_eq!(capability.as_str(), "curl.get");
    assert!(!input.to_string().contains(SECRET));
    (input, secret_use)
}
#[tokio::test(flavor = "multi_thread")]
async fn bearer_and_basic_secrets_require_policy_and_binding_and_never_enter_guest_or_audit() {
    let audit = Arc::new(InMemoryAuditLog::new(32).unwrap());
    for (index, sink, username) in [
        ("bearer", SecretSinkKind::HttpBearer, None),
        ("basic", SecretSinkKind::HttpBasic, Some("user-a")),
    ] {
        let (host, received, server) = mock_http();
        let broker = broker(&host, Some((sink, username)), Arc::clone(&audit)).await;
        let uri = format!("http://{host}{PATH}");
        let basic = format!("user-a:{SECRET}");
        let words = if username.is_some() {
            vec!["-u", basic.as_str(), uri.as_str()]
        } else {
            vec!["--oauth2-bearer", SECRET, uri.as_str()]
        };
        let (input, secret_use) = proposal(&broker, &words).await;
        assert!(secret_use.is_some());
        let (assets, mut stdout) = streams();
        let result = broker
            .invoke(
                &context(),
                None,
                None,
                request(&format!("secret-{index}"), input, secret_use),
                assets,
            )
            .await
            .unwrap();
        assert_eq!(
            result.result.outcome,
            InvocationOutcome::Succeeded,
            "{index}: {:?}",
            result.result.error
        );
        let mut text = Vec::new();
        stdout.read_to_end(&mut text).unwrap();
        assert_eq!(text, b"ok");
        let wire =
            String::from_utf8(received.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
        assert!(wire.starts_with(&format!("GET {PATH} HTTP/1.1\r\n")));
        assert!(wire.to_ascii_lowercase().contains("authorization: "));
        assert!(
            wire.contains("drn-secret-never-visible")
                || wire.contains("dXNlci1hOmRybi1zZWNyZXQtbmV2ZXItdmlzaWJsZQ==")
        );
        server.join().unwrap();
    }
    let serialized = serde_json::to_string(&audit.records()).unwrap();
    assert!(
        serialized.contains(SECRET),
        "the public DRN remains attributable"
    );
    assert!(!serialized.contains("drn-secret-never-visible"));
    assert!(!serialized.contains("dXNlci1hOmRybi1zZWNyZXQtbmV2ZXItdmlzaWJsZQ=="));
}
#[tokio::test(flavor = "multi_thread")]
async fn a_secret_proposal_without_exact_sink_username_or_catalog_is_denied_before_http() {
    let host = "127.0.0.1:9";
    let uri = format!("http://{host}{PATH}");
    let audit = Arc::new(InMemoryAuditLog::new(24).unwrap());
    let basic = format!("user-a:{SECRET}");
    let unbound = broker(host, None, Arc::clone(&audit)).await;
    let (input, secret_use) = proposal(&unbound, &["-u", &basic, &uri]).await;
    for (name, binding) in [
        ("no-catalog", None),
        (
            "other-username",
            Some((SecretSinkKind::HttpBasic, Some("user-b"))),
        ),
        ("other-sink", Some((SecretSinkKind::HttpBearer, None))),
    ] {
        let broker = broker(host, binding, Arc::clone(&audit)).await;
        let result = broker
            .invoke(
                &context(),
                None,
                None,
                request(
                    &format!("secret-denied-{name}"),
                    input.clone(),
                    secret_use.clone(),
                ),
                AssetInputs::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.result.outcome, InvocationOutcome::Denied, "{name}");
        assert_eq!(
            result.result.error.as_deref(),
            Some("secret-denied"),
            "{name}"
        );
    }
    let records = serde_json::to_string(&audit.records()).unwrap();
    assert!(!records.contains("drn-secret-never-visible"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_late_echo_across_body_chunks_reaches_neither_stdout_nor_audit() {
    let (host, received, server) = mock_late_echo();
    let audit = Arc::new(InMemoryAuditLog::new(16).unwrap());
    let broker = broker(
        &host,
        Some((SecretSinkKind::HttpBearer, None)),
        Arc::clone(&audit),
    )
    .await;
    let uri = format!("http://{host}{PATH}");
    let (input, secret_use) = proposal(&broker, &["--oauth2-bearer", SECRET, &uri]).await;
    let (assets, mut stdout) = streams();
    let result = broker
        .invoke(
            &context(),
            None,
            None,
            request("secret-late-echo", input, secret_use),
            assets,
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    stdout.read_to_end(&mut bytes).unwrap();
    assert_eq!(
        result.result.outcome,
        InvocationOutcome::Failed,
        "{:?}",
        result.result.error
    );
    assert!(
        !bytes.is_empty(),
        "a scanned clean prefix should be delivered"
    );
    assert!(
        bytes.iter().all(|&b| b == b'a'),
        "no injected credential byte reaches stdout"
    );
    assert!(bytes.len() <= 64);
    assert!(
        received
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .starts_with(format!("GET {PATH}").as_bytes())
    );
    server.join().unwrap();
    let records = serde_json::to_string(&audit.records()).unwrap();
    assert!(!records.contains("drn-secret-never-visible"));
    assert!(!records.contains("dXNlci1hOmRybi1zZWNyZXQtbmV2ZXItdmlzaWJsZQ=="));
}
