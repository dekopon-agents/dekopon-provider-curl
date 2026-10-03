//! Migrated pre-K guest security, request, resource, and failure assertions.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dekopon_curl_provider::Curl;
use dekopon_provider_sdk::provider::{Header, Response};
use dekopon_provider_sdk_testkit::{HttpScript, Native, NativeOutput};
use serde_json::{Value, json};

fn response(status: u16, body: Vec<u8>) -> Response {
    Response {
        status,
        body,
        headers: vec![],
    }
}
fn scripted(
    input: Value,
    response: Response,
) -> (NativeOutput, Vec<dekopon_provider_sdk::provider::Request>) {
    let native = Native::<Curl>::new().http(HttpScript::new("example.com", "GET", response));
    let result = native.call("curl.get", &input.to_string());
    (result, native.requests())
}
fn rejected(input: Value) -> String {
    let (result, calls) = scripted(input, response(200, vec![]));
    assert_ne!(result.status, 0);
    assert!(result.stdout.is_empty());
    assert!(calls.is_empty(), "no network before full validation");
    result.stderr
}
fn decoded(result: &NativeOutput) -> Value {
    assert_eq!(result.status, 0, "{}", result.stderr);
    serde_json::from_slice(&result.stdout).unwrap()
}
#[test]
fn closed_input_method_and_uri_validation_precede_all_network() {
    for value in [
        Value::Null,
        json!([]),
        json!("https://example.com"),
        json!({}),
        json!({"uri":null}),
        json!({"uri":"https://example.com","method":"get"}),
        json!({"uri":"https://example.com","method":"POST"}),
        json!({"uri":"https://example.com","body":"secret"}),
        json!({"uri":"https://example.com","credential":"secret"}),
        json!({"uri":"https://example.com","token":"secret"}),
        json!({"uri":"https://example.com","proxy":"https://proxy"}),
        json!({"uri":"https://example.com","redirects":true}),
        json!({"uri":"https://example.com","file":"/tmp/out"}),
        json!({"uri":"https://example.com","retries":1}),
        json!({"uri":"http://external.example.com/"}),
        json!({"uri":"https://user:pass@example.com/"}),
    ] {
        rejected(value);
    }
}
#[test]
fn forbidden_and_malformed_headers_never_reach_broker_http() {
    for name in [
        "authorization",
        "proxy-authorization",
        "cookie",
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "location",
        "x-custom",
        "accept text",
        "åccept",
        "",
    ] {
        let error = rejected(
            json!({"uri":"https://example.com/", "headers":[{"name":name,"value":"secret-sentinel"}]}),
        );
        assert!(!error.contains("secret-sentinel"));
    }
    for headers in [
        json!(null),
        json!({}),
        json!([null]),
        json!(["accept: x"]),
        json!([{}]),
        json!([{"name":"accept"}]),
        json!([{"value":"x"}]),
        json!([{"name":7,"value":"x"}]),
        json!([{"name":"accept","value":7}]),
        json!([{"name":"accept","value":"x","extra":true}]),
    ] {
        rejected(json!({"uri":"https://example.com/", "headers": headers}));
    }
    for byte in (0_u8..=31).chain([127]) {
        rejected(
            json!({"uri":"https://example.com/", "headers":[{"name":"accept","value":char::from(byte).to_string()}]}),
        );
    }
}
#[test]
fn header_allowlist_order_duplicates_and_limits_are_enforced() {
    let allowed = [
        "accept",
        "accept-language",
        "cache-control",
        "if-modified-since",
        "if-none-match",
        "range",
    ];
    let supplied = allowed
        .iter()
        .enumerate()
        .map(|(i, name)| json!({"name":name.to_ascii_uppercase(), "value":format!("value:{i}")}))
        .chain([json!({"name":"Accept", "value":"duplicate"})])
        .collect::<Vec<_>>();
    let (_, calls) = scripted(
        json!({"uri":"https://example.com/", "headers":supplied}),
        response(204, vec![]),
    );
    assert_eq!(calls.len(), 1);
    assert!(calls[0].body.is_empty());
    assert_eq!(calls[0].headers.len(), 8);
    for (header, expected) in calls[0].headers.iter().zip(allowed) {
        assert_eq!(header.name, expected);
    }
    assert_eq!(calls[0].headers[6].value, b"duplicate");
    assert_eq!(calls[0].headers[7].name, "user-agent");
    assert!(calls[0].headers.iter().all(|h| h.name != "authorization"));
    for value in ["v".repeat(4097), "x".repeat(16_385)] {
        rejected(
            json!({"uri":"https://example.com/", "headers":[{"name":"accept","value":value}]}),
        );
    }
    let at_count = (0..32)
        .map(|_| json!({"name":"accept","value":""}))
        .collect::<Vec<_>>();
    assert_eq!(
        scripted(
            json!({"uri":"https://example.com/", "headers":at_count}),
            response(200, vec![])
        )
        .1
        .len(),
        1
    );
    let over = (0..33)
        .map(|_| json!({"name":"accept","value":""}))
        .collect::<Vec<_>>();
    rejected(json!({"uri":"https://example.com/", "headers":over}));
    let at_bytes =
        [4096, 4096, 4096, 4056].map(|n| json!({"name":"accept", "value":"v".repeat(n)}));
    assert_eq!(
        scripted(
            json!({"uri":"https://example.com/", "headers":at_bytes}),
            response(200, vec![])
        )
        .1
        .len(),
        1
    );
    let over_bytes =
        [4096, 4096, 4096, 4057].map(|n| json!({"name":"accept", "value":"v".repeat(n)}));
    rejected(json!({"uri":"https://example.com/", "headers":over_bytes}));
}
#[test]
fn statuses_redirects_binary_and_duplicate_headers_are_data_not_retry() {
    for status in [100, 200, 204, 299, 301, 302, 399, 400, 404, 499, 500, 599] {
        let (result, calls) = scripted(
            json!({"uri":"https://example.com/private?token=sentinel"}),
            Response {
                status,
                headers: vec![
                    Header::text("location", "https://do-not-follow.invalid/").unwrap(),
                    Header {
                        name: "x-value".into(),
                        value: vec![0xff, 0],
                    },
                    Header::new("x-value", b"two".to_vec()).unwrap(),
                ],
                body: vec![0, 1, 0xff],
            },
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].uri, "https://example.com/private?token=sentinel");
        assert_eq!(calls[0].method, "GET");
        assert!(calls[0].body.is_empty());
        let json = decoded(&result);
        assert_eq!(json["status"], status);
        assert_eq!(json["bodyBase64"], "AAH/");
        assert_eq!(json["bodyBytes"], 3);
        assert_eq!(json["headers"][1]["valueBase64"], "/wA=");
        assert!(json["headers"][1].get("valueText").is_none());
        assert_eq!(json["headers"][2]["valueBase64"], "dHdv");
    }
}
#[test]
fn response_projection_stays_bounded_and_preserves_binary_prefix() {
    let body = vec![0xff; 262_144];
    let (result, _) = scripted(json!({"uri":"https://example.com/"}), response(200, body));
    let json = decoded(&result);
    assert_eq!(json["bodyBytes"], 262_144);
    assert_eq!(json["bodyReturnedBytes"], 65_536);
    assert_eq!(json["bodyTruncated"], true);
    assert_eq!(
        STANDARD
            .decode(json["bodyBase64"].as_str().unwrap())
            .unwrap(),
        vec![0xff; 65_536]
    );
    assert!(result.stdout.len() <= 524_289);
    let mut split_valid = vec![b'a'; 65_535];
    split_valid.extend_from_slice("éz".as_bytes());
    let (result, _) = scripted(
        json!({"uri":"https://example.com/"}),
        response(200, split_valid),
    );
    let output = decoded(&result);
    assert_eq!(
        output["bodyReturnedBytes"], 65_535,
        "do not split a valid UTF-8 scalar"
    );
    let headers = (0..129).map(|_| Header::text("x", "").unwrap()).collect();
    let (invalid, _) = scripted(
        json!({"uri":"https://example.com/"}),
        Response {
            status: 200,
            headers,
            body: vec![],
        },
    );
    assert_ne!(invalid.status, 0);
    assert!(invalid.stdout.is_empty());
}
#[test]
fn piped_headers_are_interleaved_and_failed_pipes_send_nothing() {
    let input = json!({"uri":"https://example.com/", "headers":[{"name":"accept","value":"first"},{"name":"range","value":"bytes=0-9"}], "stdin_headers":true, "stdin_header_index":1});
    let native = Native::<Curl>::new()
        .stdin(b"Accept-Language: en\n\nCache-Control: no-cache\n".to_vec())
        .http(HttpScript::new("example.com", "GET", response(200, vec![])));
    let output = native.call("curl.get", &input.to_string());
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(
        native.requests()[0]
            .headers
            .iter()
            .map(|h| h.name.as_str())
            .collect::<Vec<_>>(),
        [
            "accept",
            "accept-language",
            "cache-control",
            "range",
            "user-agent"
        ]
    );
    for bytes in [&b""[..], &b"missing-colon\n"[..], &b" : value\n"[..]] {
        let native = Native::<Curl>::new().stdin(bytes.to_vec());
        let failed = native.call("curl.get", &input.to_string());
        assert_eq!(failed.status, 2);
        assert!(native.requests().is_empty());
    }
}
