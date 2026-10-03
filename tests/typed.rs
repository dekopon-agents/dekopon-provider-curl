//! Typed native and real-component conformance of curl's command and GET.
use dekopon_curl_provider::Curl;
use dekopon_provider_sdk::provider::{Header, Response};
use dekopon_provider_sdk::{CommandRunOutcome, EffectKind, RiskLevel, provider};
use dekopon_provider_sdk_testkit::{BrokerHostLimits, Harness, HttpScript, Native, conformance};
use serde_json::json;
use std::path::PathBuf;

fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("DEKOPON_PROVIDER_COMPONENT must point to freshly built component")
        .into()
}
fn command(words: &[&str], piped: bool) -> CommandRunOutcome {
    provider::command::<Curl>(
        &words.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        piped,
    )
}
fn proposal(words: &[&str], piped: bool) -> serde_json::Value {
    let CommandRunOutcome::Proposed {
        capability,
        input,
        secret_use,
    } = command(words, piped)
    else {
        panic!("proposal expected")
    };
    assert_eq!(capability.as_str(), "curl.get");
    assert!(secret_use.is_none());
    input
}
#[test]
fn typed_manifest_and_proposals_are_closed_and_preserve_authority() {
    let manifest = provider::manifest::<Curl>().unwrap();
    assert_eq!(manifest.id.as_str(), "curl");
    assert_eq!(manifest.command_words, ["curl"]);
    assert_eq!(manifest.capabilities.len(), 1);
    assert_eq!(manifest.capabilities[0].id.as_str(), "curl.get");
    assert_eq!(manifest.capabilities[0].effect, EffectKind::ReadOnly);
    assert_eq!(manifest.capabilities[0].risk, RiskLevel::Medium);
    assert_eq!(
        manifest.capabilities[0].input_schema["additionalProperties"],
        false
    );
    assert_eq!(
        manifest.capabilities[0].input_schema["properties"]["headers"]["items"]["additionalProperties"],
        false
    );
    let input = proposal(
        &["-H", "Accept: first", "-H", "@-", "https://example.com"],
        true,
    );
    assert_eq!(input["headers"], json!([{"name":"Accept","value":"first"}]));
    assert_eq!(input["stdin_headers"], true);
    assert_eq!(input["stdin_header_index"], 1);
    let CommandRunOutcome::Failed { error } = command(&["-H", "@-", "https://example.com"], false)
    else {
        panic!("missing pipe")
    };
    assert_eq!(error.code, "usage");
    for args in [
        vec!["-X", "POST", "https://example.com"],
        vec!["--data", "x", "https://example.com"],
        vec!["-H", "@file", "https://example.com"],
    ] {
        assert!(
            matches!(
                command(&args, false),
                CommandRunOutcome::Failed { .. } | CommandRunOutcome::Rendered { status: 2, .. }
            ),
            "{args:?}"
        );
    }
    let secret = "drn:com.xrl:secret:test:curl/token";
    let CommandRunOutcome::Proposed {
        input, secret_use, ..
    } = command(&["--oauth2-bearer", secret, "https://example.com"], false)
    else {
        panic!("secret proposal")
    };
    assert!(secret_use.is_some());
    assert!(!input.to_string().contains(secret));
    let basic = format!("user-a:{secret}");
    let CommandRunOutcome::Proposed {
        input, secret_use, ..
    } = command(&["-u", &basic, "https://example.com"], false)
    else {
        panic!("basic proposal")
    };
    assert_eq!(secret_use.unwrap().username(), Some("user-a"));
    assert!(!input.to_string().contains(secret));
}
#[test]
fn native_get_preserves_headers_and_bodyless_request() {
    let input = proposal(
        &["-H", "Accept: text/plain", "https://example.com/p"],
        false,
    );
    let native = Native::<Curl>::new().http(HttpScript::new(
        "example.com",
        "GET",
        Response {
            status: 200,
            headers: vec![Header::text("x-test", "one").unwrap()],
            body: b"body".to_vec(),
        },
    ));
    let output = native.call("curl.get", &input.to_string());
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(output.stdout, b"body");
    let requests = native.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert!(requests[0].body.is_empty());
    assert_eq!(requests[0].headers[0].name, "accept");
}
#[test]
fn native_pipe_headers_are_read_only_during_invoke() {
    let input = proposal(
        &["-H", "Accept: first", "-H", "@-", "https://example.com/p"],
        true,
    );
    let native = Native::<Curl>::new()
        .stdin(b"Accept-Language: en\nRange: bytes=0-9\n".to_vec())
        .http(HttpScript::new(
            "example.com",
            "GET",
            Response {
                status: 200,
                headers: vec![],
                body: vec![],
            },
        ));
    let result = native.call("curl.get", &input.to_string());
    assert_eq!(result.status, 0, "{}", result.stderr);
    assert_eq!(
        native.requests()[0]
            .headers
            .iter()
            .map(|h| h.name.as_str())
            .collect::<Vec<_>>(),
        ["accept", "accept-language", "range", "user-agent"]
    );
    let empty_native = Native::<Curl>::new().stdin(Vec::new());
    let empty = empty_native.call("curl.get", &input.to_string());
    assert_eq!(empty.status, 2);
    assert!(empty_native.requests().is_empty());
    let forbidden_native = Native::<Curl>::new();
    let forbidden = forbidden_native.call("curl.get", &json!({"uri":"https://example.com", "headers":[{"name":"authorization","value":"secret-sentinel"}]}).to_string());
    assert_ne!(forbidden.status, 0);
    assert!(!forbidden.stderr.contains("secret-sentinel"));
    assert!(forbidden_native.requests().is_empty());
}
#[test]
fn real_component_conforms_and_broker_grant_is_exact() -> Result<(), Box<dyn std::error::Error>> {
    conformance::<Curl>(component())?;
    let limits = BrokerHostLimits::default();
    assert_eq!(limits.max_memory_bytes, 64 * 1024 * 1024);
    let denied =
        Harness::<Curl>::get(component()).call("curl.get", json!({"uri":"https://example.com/"}));
    assert!(denied.is_err(), "no HTTP grant must not execute a request");
    let run = Harness::<Curl>::get(component()).http(HttpScript::new(
        "localhost",
        "GET",
        Response {
            status: 200,
            headers: vec![],
            body: b"ok".to_vec(),
        },
    ));
    let origin = run.origin().unwrap().to_owned();
    let wrong_grant = Harness::<Curl>::get(component()).http(HttpScript::new(
        "localhost",
        "GET",
        Response {
            status: 200,
            headers: vec![],
            body: vec![],
        },
    ));
    assert!(
        wrong_grant
            .call("curl.get", json!({"uri":"https://example.com/wrong-host"}))
            .is_err(),
        "the loopback pin cannot grant another host"
    );
    let bad_input = Harness::<Curl>::get(component()).call("curl.get", json!({
        "uri":"https://example.com/", "headers":[{"name":"authorization", "value":"credential-sentinel"}]
    }))?;
    assert_ne!(bad_input.status, 0);
    assert!(bad_input.stdout.is_empty());
    assert!(bad_input.http_calls.is_empty());
    assert!(!bad_input.stderr.contains("credential-sentinel"));
    let output = run.call("curl.get", json!({"uri":format!("{origin}/one")}))?;
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(output.http_calls.len(), 1);
    assert_eq!(output.http_calls[0].method, "GET");
    assert_eq!(output.http_calls[0].status, Some(200));
    assert_eq!(output.stdout, b"ok");
    Ok(())
}
