//! Real checked component: exact HTTP host constraints, not just native scripted imports.
use dekopon_broker_host::{
    BrokerHostError, BrokerHostLimits, BrokerProviderRegistry, asset::AssetInputs,
};
use dekopon_broker_protocol::Streams;
use dekopon_capability::{
    AuthorizedInvocation, ExecutionConstraints, HttpConstraints, ProposedInvocation,
    broker::AuthorizationGate,
};
use dekopon_core::{Actor, AgentId, TraceId};
use serde_json::{Value, json};
use std::{
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::PathBuf,
    sync::mpsc,
    thread,
    time::Duration,
};

fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("fresh component")
        .into()
}
fn constraints(host: &str) -> ExecutionConstraints {
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
fn authorized(id: &str, input: Value, grant: ExecutionConstraints) -> AuthorizedInvocation {
    let proposal = ProposedInvocation::new(
        id.parse().unwrap(),
        "curl.get".parse().unwrap(),
        Actor::Agent {
            agent: "curl-test".parse::<AgentId>().unwrap(),
        },
        TraceId::new([7; 16]).unwrap(),
        input,
    );
    AuthorizationGate::new()
        .authorize(
            proposal,
            "curl".parse().unwrap(),
            format!("decision-{id}"),
            "broker-test".parse().unwrap(),
            "policy-test".into(),
            grant,
        )
        .unwrap()
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
#[tokio::test(flavor = "multi_thread")]
async fn host_refuses_missing_wrong_host_method_port_plaintext_and_request_limit() {
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .unwrap();
    let uri = "http://127.0.0.1:9/never-connect";
    let mut cases = vec![
        ("missing", ExecutionConstraints::default(), "denied"),
        ("wrong-port", constraints("127.0.0.1:10"), "denied"),
        ("wrong-host-same-port", constraints("127.0.0.2:9"), "denied"),
    ];
    let mut wrong_method = constraints("127.0.0.1:9");
    wrong_method.http.as_mut().unwrap().allowed_methods = vec!["POST".into()];
    cases.push(("wrong-method", wrong_method, "denied"));
    let mut plaintext = constraints("127.0.0.1:9");
    plaintext.http.as_mut().unwrap().allow_plaintext_loopback = false;
    cases.push(("plaintext-disabled", plaintext, "denied"));
    let mut too_large = constraints("127.0.0.1:9");
    too_large.http.as_mut().unwrap().max_request_bytes = 64;
    cases.push(("request-too-large", too_large, "byte-limit"));
    for (name, grant, reason) in cases {
        let failure = registry
            .invoke(
                authorized(name, json!({"uri":uri}), grant),
                None,
                AssetInputs::default(),
            )
            .await
            .expect_err("host authorization must refuse");
        assert!(
            matches!(failure.error.as_ref(), BrokerHostError::HostCallRejected { reason: actual, .. } if *actual == reason),
            "{name}: {failure}"
        );
        assert!(
            failure.http_calls.is_empty(),
            "{name}: denied before network"
        );
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn malformed_guest_input_is_a_status_without_any_http_effect() {
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .unwrap();
    for (index, input) in [
        json!({"uri":"http://127.0.0.1:9/", "headers":[{"name":"authorization","value":"secret-sentinel"}]}),
        json!({"uri":"http://127.0.0.1:9/", "token":"secret-sentinel"}),
        json!({"uri":"http://127.0.0.1:9/", "credential":"secret-sentinel"}),
    ].into_iter().enumerate() {
        let (assets, mut reader) = streams();
        let result = registry.invoke(authorized(&format!("guest-closed-{index}"), input, constraints("127.0.0.1:9")), None, assets).await;
        // Invalid inputs are guest status 1/2, never a host request.
        match result {
            Ok(output) => { assert!(output.http_calls.is_empty()); assert!(output.stderr.len() < 256); assert!(!output.stderr.contains("secret-sentinel")); }
            Err(failure) => { assert!(failure.http_calls.is_empty()); assert!(!failure.to_string().contains("secret-sentinel")); }
        }
        let mut bytes = Vec::new(); reader.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
    }
}

fn mock_http(
    response: Vec<u8>,
    delay: Duration,
) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0; 1024];
        while request.windows(4).all(|window| window != b"\r\n\r\n") {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
        }
        tx.send(request).unwrap();
        thread::sleep(delay);
        let _ = stream.write_all(&response);
    });
    (format!("127.0.0.1:{}", address.port()), rx, server)
}
#[tokio::test(flavor = "multi_thread")]
async fn response_timeout_and_overflow_are_terminal_without_partial_stdout() {
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .unwrap();
    let (host, request, server) = mock_http(Vec::new(), Duration::from_millis(400));
    let mut grant = constraints(&host);
    grant.timeout_ms = 75;
    let (assets, mut peer) = streams();
    let outcome = registry
        .invoke(
            authorized(
                "host-timeout",
                json!({"uri":format!("http://{host}/slow")}),
                grant,
            ),
            None,
            assets,
        )
        .await;
    match outcome {
        Ok(out) => {
            assert!(out.stderr.contains("timed out"), "{}", out.stderr);
        }
        Err(failure) => {
            assert!(
                matches!(
                    failure.error.as_ref(),
                    BrokerHostError::Timeout { .. } | BrokerHostError::HostCallRejected { .. }
                ),
                "{failure}"
            );
        }
    }
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty());
    assert!(
        request
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .starts_with(b"GET /slow")
    );
    server.join().unwrap();

    let body = vec![b'x'; 8192];
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend(body);
    let (host, _request, server) = mock_http(response, Duration::ZERO);
    let mut grant = constraints(&host);
    grant.http.as_mut().unwrap().max_response_bytes = 1024;
    let (assets, mut peer) = streams();
    let outcome = registry
        .invoke(
            authorized(
                "host-overflow",
                json!({"uri":format!("http://{host}/large")}),
                grant,
            ),
            None,
            assets,
        )
        .await;
    assert!(
        matches!(
            outcome.as_ref().err().map(|f| f.error.as_ref()),
            Some(BrokerHostError::HostCallRejected {
                reason: "byte-limit",
                ..
            })
        ),
        "{outcome:?}"
    );
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty());
    server.join().unwrap();
}
#[tokio::test(flavor = "multi_thread")]
async fn redirect_is_data_not_a_second_request() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let location = target.local_addr().unwrap();
    let response = format!("HTTP/1.1 302 Found\r\nLocation: http://{location}/must-not-run\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes();
    let (host, request, server) = mock_http(response, Duration::ZERO);
    let registry = BrokerProviderRegistry::load([component()], BrokerHostLimits::default())
        .await
        .unwrap();
    let (assets, mut peer) = streams();
    let output = registry
        .invoke(
            authorized(
                "host-redirect",
                json!({"uri":format!("http://{host}/redirect")}),
                constraints(&host),
            ),
            None,
            assets,
        )
        .await
        .unwrap();
    assert_eq!(output.http_calls.len(), 1);
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    assert!(
        bytes.is_empty(),
        "302 has an empty body, not a JSON envelope"
    );
    assert!(
        request
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .starts_with(b"GET /redirect")
    );
    server.join().unwrap();
    assert!(matches!(target.accept(), Err(e) if e.kind() == ErrorKind::WouldBlock));
}
#[tokio::test(flavor = "multi_thread")]
async fn checked_component_stays_within_old_committed_memory_and_fuel_ceiling() {
    let limits = BrokerHostLimits {
        max_memory_bytes: 16 * 1024 * 1024,
        fuel: 64_000_000,
        ..BrokerHostLimits::default()
    };
    let registry = BrokerProviderRegistry::load([component()], limits)
        .await
        .unwrap();
    let body = vec![b'x'; 190_000];
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend(body);
    let (host, request, server) = mock_http(response, Duration::ZERO);
    let (assets, mut peer) = streams();
    // A large provider stdout fills the socket unless the downstream consumes concurrently.
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let result = registry
        .invoke(
            authorized(
                "host-resources",
                json!({"uri":format!("http://{host}/large")}),
                constraints(&host),
            ),
            None,
            assets,
        )
        .await;
    let bytes = reader.join().unwrap();
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(bytes, vec![b'x'; 190_000]);
    assert!(
        request
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .starts_with(b"GET /large")
    );
    server.join().unwrap();
}
