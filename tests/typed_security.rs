//! Successors to pre-K response, transport, JSON and command-word security witnesses.
use dekopon_core::{CommandWordConflictKind, RESERVED_COMMAND_WORDS, command_word_conflicts};
use dekopon_curl_provider::Curl;
use dekopon_provider_sdk::provider;
use dekopon_provider_sdk::provider::{
    HttpError, HttpErrorCode, Port, Request, Response, StreamedRequest, StreamedResponse,
};
use dekopon_provider_sdk_testkit::{HttpScript, Native};
use serde_json::json;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct FailingHttp {
    code: HttpErrorCode,
    calls: Arc<AtomicUsize>,
}
impl Port for FailingHttp {
    fn now_unix_millis(&mut self) -> u64 {
        0
    }
    fn now_nanos(&mut self) -> u64 {
        0
    }
    fn fill_random(&mut self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
    fn settings(&mut self) -> Option<String> {
        None
    }
    fn send(&mut self, _: Request) -> Result<Response, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(HttpError {
            code: self.code,
            message: "SECRET-SENTINEL host URI / token / transport detail".into(),
        })
    }
    fn stream(&mut self, _: StreamedRequest<'_>) -> Result<StreamedResponse, HttpError> {
        panic!("no assets")
    }
}
#[test]
fn every_http_error_class_has_a_fixed_redacted_exit_and_no_retry() {
    let cases = [
        (HttpErrorCode::Denied, "broker HTTP request was denied"),
        (
            HttpErrorCode::HostCallLimit,
            "broker HTTP request was denied",
        ),
        (
            HttpErrorCode::RequestTooLarge,
            "broker HTTP request exceeded its limit",
        ),
        (
            HttpErrorCode::ResponseTooLarge,
            "broker HTTP response exceeded its limit",
        ),
        (HttpErrorCode::Timeout, "broker HTTP request timed out"),
        (
            HttpErrorCode::InvalidUri,
            "URI does not match the curl.get policy",
        ),
        (
            HttpErrorCode::InvalidHeader,
            "request headers do not match the curl.get policy",
        ),
        (HttpErrorCode::InvalidMethod, "broker HTTP request failed"),
        (HttpErrorCode::Dns, "broker HTTP request failed"),
        (HttpErrorCode::Connect, "broker HTTP request failed"),
        (HttpErrorCode::Tls, "broker HTTP request failed"),
        (HttpErrorCode::Protocol, "broker HTTP request failed"),
        (HttpErrorCode::Internal, "broker HTTP request failed"),
    ];
    for (code, message) in cases {
        let calls = Arc::new(AtomicUsize::new(0));
        let exit = provider::with_port(
            FailingHttp {
                code,
                calls: calls.clone(),
            },
            || {
                provider::invoke_native::<Curl>(
                    "curl.get",
                    &json!({"uri":"https://example.com/"}).to_string(),
                    provider::NativeStdio {
                        stdin: None,
                        stdout: Box::new(io::sink()),
                    },
                )
            },
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{code:?}");
        assert_eq!(exit.status, 1, "{code:?}");
        assert_eq!(exit.stderr.trim_end(), message, "{code:?}");
        assert!(!exit.stderr.contains("SECRET-SENTINEL"), "{code:?}");
    }
}
#[test]
fn duplicate_raw_input_keys_are_refused_by_current_typed_sdk() {
    let native = Native::<Curl>::new().http(HttpScript::new(
        "example.com",
        "GET",
        Response {
            status: 200,
            headers: vec![],
            body: vec![],
        },
    ));
    let result = native.call("curl.get", r#"{"uri":"https://ignored.invalid/","uri":"https://example.com/final","method":"POST","method":"GET"}"#);
    assert_eq!(result.status, 2, "{}", result.stderr);
    assert!(
        native.requests().is_empty(),
        "duplicate raw keys cannot reach HTTP"
    );
    assert!(result.stdout.is_empty());
}
#[test]
fn sdk_word_registry_grants_curl_but_refuses_reserved_and_contested_claims() {
    assert!(!RESERVED_COMMAND_WORDS.contains(&"curl"));
    assert!(command_word_conflicts(&[("curl".into(), vec!["curl".into()])]).is_empty());
    let reserved = command_word_conflicts(&[("curl".into(), vec!["cat".into()])]);
    assert_eq!(reserved.len(), 1);
    assert_eq!(reserved[0].kind, CommandWordConflictKind::Reserved);
    let contested = command_word_conflicts(&[
        ("curl".into(), vec!["curl".into()]),
        ("other".into(), vec!["curl".into()]),
    ]);
    assert_eq!(contested.len(), 1);
    assert_eq!(contested[0].kind, CommandWordConflictKind::Duplicate);
}
#[test]
fn fake_port_response_headers_are_not_a_guest_projection_or_validation_boundary() {
    // Typed send returns headers and a body to the guest. The real broker HTTP host validates wire
    // headers; native testkit scripts intentionally bypass that host and can contain bad names.
    for headers in [
        vec![dekopon_provider_sdk::provider::Header {
            name: "bad name".into(),
            value: b"secret".to_vec(),
        }],
        vec![dekopon_provider_sdk::provider::Header {
            name: "x".into(),
            value: vec![b'x'; 65_537],
        }],
    ] {
        let native = Native::<Curl>::new().http(HttpScript::new(
            "example.com",
            "GET",
            Response {
                status: 200,
                headers,
                body: b"body".to_vec(),
            },
        ));
        let result = native.call(
            "curl.get",
            &json!({"uri":"https://example.com/"}).to_string(),
        );
        assert_eq!(result.status, 0, "{}", result.stderr);
        assert_eq!(result.stdout, b"body");
    }
}
