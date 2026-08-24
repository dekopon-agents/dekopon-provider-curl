use std::cell::Cell;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dekopon_core::{CommandWordConflictKind, command_word_conflicts};
use dekopon_provider_http::{Header, HttpError, HttpErrorCode, Request, Response};
use dekopon_provider_sdk::{CapabilityId, ComponentResponse, EffectKind, Idempotency, Provider};
use serde_json::{Value, json};

use super::{
    ALLOWED_HEADERS, CAPABILITY, Curl, HTTP_DENIED_MESSAGE, HTTP_FAILED_MESSAGE,
    HTTP_TIMEOUT_MESSAGE, INVALID_HEADER_MESSAGE, INVALID_INPUT_MESSAGE, INVALID_RESPONSE_MESSAGE,
    INVALID_URI_MESSAGE, MAX_BODY_TEXT_JSON_BYTES, MAX_HEADER_NAME_BYTES, MAX_HEADER_VALUE_BYTES,
    MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS, MAX_RESPONSE_HEADER_BYTES, MAX_RESPONSE_HEADERS,
    MAX_RETURNED_BODY_BYTES, MAX_SUCCESS_ENVELOPE_BYTES, REQUEST_TOO_LARGE_MESSAGE,
    RESPONSE_TOO_LARGE_MESSAGE, UNSUPPORTED_CAPABILITY_MESSAGE, USER_AGENT, bounded_body_prefix,
    input_schema, invoke_with, map_http_error, project_response_with_limit, success_envelope_len,
};

fn capability(value: &str) -> CapabilityId {
    value.parse().expect("valid capability fixture")
}

fn valid_input() -> Value {
    json!({"uri": "https://example.com/private?token=secret"})
}

fn empty_response(status: u16) -> Response {
    Response {
        status,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn invoke_ok(input: Value, response: Response) -> Value {
    invoke_with(&capability(CAPABILITY), input, move |_request| {
        Ok(response.clone())
    })
    .expect("invocation succeeds")
}

fn assert_failure(input: Value, expected_code: &str, expected_message: &str) {
    let calls = Cell::new(0);
    let failure = invoke_with(&capability(CAPABILITY), input, |_request| {
        calls.set(calls.get() + 1);
        Ok(empty_response(200))
    })
    .expect_err("input is refused");
    assert_eq!(failure.code(), expected_code);
    assert_eq!(failure.message(), expected_message);
    assert_eq!(calls.get(), 0, "validation must precede HTTP");
}

#[test]
fn manifest_is_the_exact_single_capability_contract() {
    let manifest = Curl::manifest();
    assert_eq!(manifest.id.as_str(), "curl");
    assert_eq!(
        manifest.description,
        "Performs one bounded broker-authorized bodyless HTTP GET."
    );
    assert_eq!(manifest.command_words, ["curlget"]);
    assert_eq!(manifest.capabilities.len(), 1);
    let declared = &manifest.capabilities[0];
    assert_eq!(declared.id.as_str(), "curl.get");
    assert_eq!(
        declared.description,
        "Fetches one HTTPS URL, or explicit loopback HTTP test URL, and returns a bounded byte-preserving response."
    );
    assert_eq!(declared.effect, EffectKind::ReadOnly);
    assert_eq!(declared.risk.to_string(), "Medium");
    assert_eq!(declared.idempotency, Idempotency::Idempotent);
    assert_eq!(declared.input_schema, input_schema());
    assert_eq!(
        serde_json::to_value(manifest).expect("manifest serializes")["apiVersion"],
        "dekopon.dev/provider/v1alpha1"
    );
}

#[test]
fn schema_is_closed_and_carries_every_model_facing_bound() {
    assert_eq!(
        input_schema(),
        json!({
            "type": "object",
            "properties": {
                "uri": {"type": "string", "format": "uri", "minLength": 1, "maxLength": 4096},
                "method": {"type": "string", "enum": ["GET"], "default": "GET"},
                "headers": {
                    "type": "array",
                    "maxItems": 32,
                    "default": [],
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "minLength": 1, "maxLength": 64},
                            "value": {"type": "string", "maxLength": 4096}
                        },
                        "required": ["name", "value"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["uri"],
            "additionalProperties": false
        })
    );
}

#[test]
fn unsupported_capability_is_stable_and_never_calls_http() {
    let calls = Cell::new(0);
    let failure = invoke_with(&capability("other.get"), valid_input(), |_request| {
        calls.set(calls.get() + 1);
        Ok(empty_response(200))
    })
    .expect_err("other capability is refused");
    assert_eq!(failure.code(), "unsupported-capability");
    assert_eq!(failure.message(), UNSUPPORTED_CAPABILITY_MESSAGE);
    assert_eq!(calls.get(), 0);
}

#[test]
fn input_shape_is_closed_and_method_is_exact_uppercase_get() {
    for input in [
        Value::Null,
        json!([]),
        json!("https://example.com"),
        json!({}),
        json!({"uri": null}),
        json!({"uri": 7}),
        json!({"uri": "https://example.com", "method": null}),
        json!({"uri": "https://example.com", "method": "get"}),
        json!({"uri": "https://example.com", "method": "POST"}),
        json!({"uri": "https://example.com", "body": "secret"}),
        json!({"uri": "https://example.com", "credential": "secret"}),
        json!({"uri": "https://example.com", "token": "secret"}),
        json!({"uri": "https://example.com", "proxy": "https://proxy"}),
        json!({"uri": "https://example.com", "redirects": true}),
        json!({"uri": "https://example.com", "file": "/tmp/out"}),
        json!({"uri": "https://example.com", "retries": 1}),
    ] {
        assert_failure(input, "invalid-input", INVALID_INPUT_MESSAGE);
    }
    assert!(
        invoke_with(
            &capability(CAPABILITY),
            json!({"uri": "https://example.com", "method": "GET"}),
            |_request| Ok(empty_response(200))
        )
        .is_ok()
    );
}

#[test]
fn every_header_shape_error_is_classified_without_transport() {
    for headers in [
        json!(null),
        json!({}),
        json!([null]),
        json!(["accept: x"]),
        json!([{}]),
        json!([{"name": "accept"}]),
        json!([{"value": "x"}]),
        json!([{"name": 7, "value": "x"}]),
        json!([{"name": "accept", "value": 7}]),
        json!([{"name": "accept", "value": "x", "extra": true}]),
    ] {
        assert_failure(
            json!({"uri": "https://example.com", "headers": headers}),
            "invalid-header",
            INVALID_HEADER_MESSAGE,
        );
    }
}

#[test]
fn header_allowlist_normalization_order_and_duplicates_are_exact() {
    let supplied = ALLOWED_HEADERS
        .iter()
        .enumerate()
        .map(|(index, name)| {
            json!({
                "name": name.to_ascii_uppercase(),
                "value": format!("value:{index}")
            })
        })
        .chain([json!({"name": "Accept", "value": "duplicate"})])
        .collect::<Vec<_>>();
    let mut observed = None;
    invoke_with(
        &capability(CAPABILITY),
        json!({"uri": "https://example.com", "headers": supplied}),
        |request| {
            observed = Some(request);
            Ok(empty_response(200))
        },
    )
    .expect("allowed headers pass");
    let request = observed.expect("one request observed");
    assert_eq!(request.headers.len(), ALLOWED_HEADERS.len() + 2);
    for (header, expected) in request.headers.iter().zip(ALLOWED_HEADERS) {
        assert_eq!(header.name, expected);
    }
    assert_eq!(request.headers[6].name, "accept");
    assert_eq!(request.headers[6].value, b"duplicate");
    assert_eq!(request.headers[7].name, "user-agent");
    assert_eq!(request.headers[7].value, USER_AGENT.as_bytes());
}

#[test]
fn forbidden_and_malformed_request_headers_are_closed() {
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
        assert_failure(
            json!({
                "uri": "https://example.com",
                "headers": [{"name": name, "value": "sentinel"}]
            }),
            "invalid-header",
            INVALID_HEADER_MESSAGE,
        );
    }

    for byte in (0_u8..=31).chain([127]) {
        let value = String::from(char::from(byte));
        assert_failure(
            json!({
                "uri": "https://example.com",
                "headers": [{"name": "accept", "value": value}]
            }),
            "invalid-header",
            INVALID_HEADER_MESSAGE,
        );
    }
}

#[test]
fn request_header_count_name_and_value_byte_boundaries_are_exact() {
    let at_count = (0..MAX_REQUEST_HEADERS)
        .map(|_| json!({"name": "accept", "value": ""}))
        .collect::<Vec<_>>();
    assert!(
        invoke_with(
            &capability(CAPABILITY),
            json!({"uri": "https://example.com", "headers": at_count}),
            |_request| Ok(empty_response(200))
        )
        .is_ok()
    );
    let over_count = (0..=MAX_REQUEST_HEADERS)
        .map(|_| json!({"name": "accept", "value": ""}))
        .collect::<Vec<_>>();
    assert_failure(
        json!({"uri": "https://example.com", "headers": over_count}),
        "invalid-header",
        INVALID_HEADER_MESSAGE,
    );

    // A 64-byte token reaches the name limit but is not allowlisted; the length itself remains
    // independently pinned through the private validator by using the 64-byte allowlist prefix is
    // impossible. Limit + 1 is nevertheless rejected before any allowlist ambiguity can matter.
    assert_eq!(MAX_HEADER_NAME_BYTES, 64);
    assert_failure(
        json!({
            "uri": "https://example.com",
            "headers": [{"name": "a".repeat(MAX_HEADER_NAME_BYTES + 1), "value": ""}]
        }),
        "invalid-header",
        INVALID_HEADER_MESSAGE,
    );

    let at_value = "v".repeat(MAX_HEADER_VALUE_BYTES);
    assert!(
        invoke_with(
            &capability(CAPABILITY),
            json!({
                "uri": "https://example.com",
                "headers": [{"name": "accept", "value": at_value}]
            }),
            |_request| Ok(empty_response(200))
        )
        .is_ok()
    );
    assert_failure(
        json!({
            "uri": "https://example.com",
            "headers": [{"name": "accept", "value": "v".repeat(MAX_HEADER_VALUE_BYTES + 1)}]
        }),
        "invalid-header",
        INVALID_HEADER_MESSAGE,
    );
}

#[test]
fn request_header_aggregate_boundary_and_limit_plus_one_are_exact() {
    // Four `accept` fields account 6 name bytes + 4 framing bytes each. The values fill exactly
    // the remaining aggregate budget while each remains within its independent 4096-byte limit.
    let values = [4_096, 4_096, 4_096, 4_056];
    assert_eq!(
        values.iter().sum::<usize>() + values.len() * 10,
        MAX_REQUEST_HEADER_BYTES
    );
    let at_limit = values
        .into_iter()
        .map(|bytes| json!({"name": "accept", "value": "v".repeat(bytes)}))
        .collect::<Vec<_>>();
    assert!(
        invoke_with(
            &capability(CAPABILITY),
            json!({"uri": "https://example.com", "headers": at_limit}),
            |_request| Ok(empty_response(200))
        )
        .is_ok()
    );

    let over = [4_096, 4_096, 4_096, 4_057]
        .into_iter()
        .map(|bytes| json!({"name": "accept", "value": "v".repeat(bytes)}))
        .collect::<Vec<_>>();
    assert_failure(
        json!({"uri": "https://example.com", "headers": over}),
        "invalid-header",
        INVALID_HEADER_MESSAGE,
    );
}

#[test]
fn invocation_sends_exactly_one_get_with_empty_body_and_owned_user_agent() {
    let calls = Cell::new(0);
    let output = invoke_with(&capability(CAPABILITY), valid_input(), |request| {
        calls.set(calls.get() + 1);
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.uri, "https://example.com/private?token=secret",
            "the bounded original URI is not rewritten"
        );
        assert!(request.body.is_empty());
        assert_eq!(request.headers.len(), 1);
        assert_eq!(request.headers[0].name, "user-agent");
        assert_eq!(request.headers[0].value, USER_AGENT.as_bytes());
        Ok(empty_response(204))
    })
    .expect("request succeeds");
    assert_eq!(calls.get(), 1);
    assert_eq!(output["status"], 204);
}

#[test]
fn every_http_status_is_success_and_redirects_do_not_trigger_a_retry() {
    for status in [100, 200, 204, 299, 301, 302, 399, 400, 404, 499, 500, 599] {
        let calls = Cell::new(0);
        let output = invoke_with(&capability(CAPABILITY), valid_input(), |_request| {
            calls.set(calls.get() + 1);
            Ok(Response {
                status,
                headers: vec![Header {
                    name: "location".to_owned(),
                    value: b"https://do-not-follow.invalid/secret".to_vec(),
                }],
                body: Vec::new(),
            })
        })
        .expect("status is returned as data");
        assert_eq!(calls.get(), 1, "status {status}");
        assert_eq!(output["status"], status, "status {status}");
    }
}

#[test]
fn response_preserves_header_order_duplicates_and_binary_values() {
    let output = invoke_ok(
        valid_input(),
        Response {
            status: 200,
            headers: vec![
                Header {
                    name: "x-value".to_owned(),
                    value: b"one".to_vec(),
                },
                Header {
                    name: "x-value".to_owned(),
                    value: vec![0xff, 0x00],
                },
                Header {
                    name: "X-Case".to_owned(),
                    value: b"three".to_vec(),
                },
            ],
            body: vec![0x00, 0x01],
        },
    );
    assert_eq!(
        output["headers"],
        json!([
            {"name": "x-value", "valueBase64": "b25l", "valueText": "one"},
            {"name": "x-value", "valueBase64": "/wA="},
            {"name": "X-Case", "valueBase64": "dGhyZWU=", "valueText": "three"}
        ])
    );
    assert_eq!(output["bodyBase64"], "AAE=");
    assert!(output.get("bodyText").is_some());
    assert_eq!(output["bodyBytes"], 2);
    assert_eq!(output["bodyReturnedBytes"], 2);
    assert_eq!(output["bodyTruncated"], false);
}

#[test]
fn response_header_count_and_aggregate_boundaries_are_exact() {
    let at_count = (0..MAX_RESPONSE_HEADERS)
        .map(|_| Header {
            name: "x".to_owned(),
            value: Vec::new(),
        })
        .collect();
    assert!(
        project_response_with_limit(
            Response {
                status: 200,
                headers: at_count,
                body: Vec::new(),
            },
            MAX_SUCCESS_ENVELOPE_BYTES,
        )
        .is_ok()
    );
    let over_count = (0..=MAX_RESPONSE_HEADERS)
        .map(|_| Header {
            name: "x".to_owned(),
            value: Vec::new(),
        })
        .collect();
    let error = project_response_with_limit(
        Response {
            status: 200,
            headers: over_count,
            body: Vec::new(),
        },
        MAX_SUCCESS_ENVELOPE_BYTES,
    )
    .expect_err("header count + 1 is rejected");
    assert_eq!(error.code(), "invalid-response");

    // 128 * (one-byte name + 507-byte value + four framing bytes) == 65,536.
    let at_bytes = (0..MAX_RESPONSE_HEADERS)
        .map(|_| Header {
            name: "x".to_owned(),
            value: vec![0xff; 507],
        })
        .collect::<Vec<_>>();
    assert_eq!(MAX_RESPONSE_HEADERS * 512, MAX_RESPONSE_HEADER_BYTES);
    assert!(
        project_response_with_limit(
            Response {
                status: 200,
                headers: at_bytes.clone(),
                body: Vec::new(),
            },
            MAX_SUCCESS_ENVELOPE_BYTES,
        )
        .is_ok()
    );
    let mut over_bytes = at_bytes;
    over_bytes[0].value.push(0xff);
    let error = project_response_with_limit(
        Response {
            status: 200,
            headers: over_bytes,
            body: Vec::new(),
        },
        MAX_SUCCESS_ENVELOPE_BYTES,
    )
    .expect_err("header bytes + 1 are rejected");
    assert_eq!(error.code(), "invalid-response");
    assert_eq!(error.message(), INVALID_RESPONSE_MESSAGE);
}

#[test]
fn malformed_host_response_header_is_a_fixed_invalid_response() {
    for name in ["", "bad name", "å"] {
        let failure = project_response_with_limit(
            Response {
                status: 200,
                headers: vec![Header {
                    name: name.to_owned(),
                    value: b"secret".to_vec(),
                }],
                body: Vec::new(),
            },
            MAX_SUCCESS_ENVELOPE_BYTES,
        )
        .expect_err("malformed host header is rejected");
        assert_eq!(failure.code(), "invalid-response");
        assert_eq!(failure.message(), INVALID_RESPONSE_MESSAGE);
    }
}

#[test]
fn body_prefix_boundary_binary_behavior_and_utf8_scalar_backup_are_exact() {
    let at_limit = vec![b'a'; MAX_RETURNED_BODY_BYTES];
    assert_eq!(
        bounded_body_prefix(&at_limit).len(),
        MAX_RETURNED_BODY_BYTES
    );

    let over_ascii = vec![b'a'; MAX_RETURNED_BODY_BYTES + 1];
    assert_eq!(
        bounded_body_prefix(&over_ascii).len(),
        MAX_RETURNED_BODY_BYTES
    );

    let mut split_valid = vec![b'a'; MAX_RETURNED_BODY_BYTES - 1];
    split_valid.extend_from_slice("éz".as_bytes());
    assert!(core::str::from_utf8(&split_valid).is_ok());
    assert_eq!(
        bounded_body_prefix(&split_valid).len(),
        MAX_RETURNED_BODY_BYTES - 1,
        "the raw cut lands after the first byte of é"
    );

    let mut genuinely_invalid = vec![b'a'; MAX_RETURNED_BODY_BYTES + 1];
    genuinely_invalid[MAX_RETURNED_BODY_BYTES - 1] = 0xff;
    assert_eq!(
        bounded_body_prefix(&genuinely_invalid).len(),
        MAX_RETURNED_BODY_BYTES,
        "invalid binary retains the full raw prefix"
    );
    let output = invoke_ok(
        valid_input(),
        Response {
            status: 200,
            headers: Vec::new(),
            body: genuinely_invalid,
        },
    );
    assert!(output.get("bodyText").is_none());
    assert_eq!(output["bodyReturnedBytes"], MAX_RETURNED_BODY_BYTES);
    assert_eq!(output["bodyTruncated"], true);
}

#[test]
fn body_text_compact_json_boundary_is_exact() {
    let at_count = (MAX_BODY_TEXT_JSON_BYTES - 2) / 6;
    assert_eq!(2 + at_count * 6, MAX_BODY_TEXT_JSON_BYTES);
    let at = vec![0_u8; at_count];
    let at_output = invoke_ok(
        valid_input(),
        Response {
            status: 200,
            headers: Vec::new(),
            body: at,
        },
    );
    assert!(at_output.get("bodyText").is_some());

    let over = vec![0_u8; at_count + 1];
    let over_output = invoke_ok(
        valid_input(),
        Response {
            status: 200,
            headers: Vec::new(),
            body: over,
        },
    );
    assert!(over_output.get("bodyText").is_none());
}

#[test]
fn complete_success_envelope_drops_all_optional_text_before_failing() {
    let headers = (0..MAX_RESPONSE_HEADERS)
        .map(|_| Header {
            name: "x".to_owned(),
            value: vec![0_u8; 507],
        })
        .collect();
    let output = project_response_with_limit(
        Response {
            status: 200,
            headers,
            body: vec![0_u8; (MAX_BODY_TEXT_JSON_BYTES - 2) / 6],
        },
        MAX_SUCCESS_ENVELOPE_BYTES,
    )
    .expect("mandatory binary output fits after optional text is removed");
    assert!(output.get("bodyText").is_none());
    assert!(
        output["headers"]
            .as_array()
            .expect("headers array")
            .iter()
            .all(|header| header.get("valueText").is_none())
    );
    assert!(success_envelope_len(&output).unwrap() <= MAX_SUCCESS_ENVELOPE_BYTES);

    let failure = project_response_with_limit(empty_response(200), 1)
        .expect_err("even mandatory fields cannot fit a one-byte envelope");
    assert_eq!(failure.code(), "invalid-response");
    assert_eq!(failure.message(), INVALID_RESPONSE_MESSAGE);
}

#[test]
fn worst_case_mandatory_binary_projection_stays_under_the_public_ceiling() {
    let output = project_response_with_limit(
        Response {
            status: 599,
            headers: (0..MAX_RESPONSE_HEADERS)
                .map(|_| Header {
                    name: "x".to_owned(),
                    value: vec![0xff; 507],
                })
                .collect(),
            body: vec![0xff; 262_144],
        },
        MAX_SUCCESS_ENVELOPE_BYTES,
    )
    .expect("guest truncation and base64 fit the envelope");
    let envelope = serde_json::to_vec(&ComponentResponse::Succeeded {
        output: output.clone(),
    })
    .expect("envelope serializes");
    assert!(envelope.len() <= MAX_SUCCESS_ENVELOPE_BYTES);
    assert_eq!(output["bodyBytes"], 262_144);
    assert_eq!(output["bodyReturnedBytes"], MAX_RETURNED_BODY_BYTES);
    assert_eq!(output["bodyTruncated"], true);
    assert_eq!(
        STANDARD
            .decode(output["bodyBase64"].as_str().expect("base64 text"))
            .expect("standard padded base64")
            .len(),
        MAX_RETURNED_BODY_BYTES
    );
}

#[test]
fn every_http_error_class_maps_without_copying_host_detail() {
    let cases = [
        (HttpErrorCode::Denied, "http-denied", HTTP_DENIED_MESSAGE),
        (
            HttpErrorCode::HostCallLimit,
            "http-denied",
            HTTP_DENIED_MESSAGE,
        ),
        (
            HttpErrorCode::RequestTooLarge,
            "request-too-large",
            REQUEST_TOO_LARGE_MESSAGE,
        ),
        (
            HttpErrorCode::ResponseTooLarge,
            "response-too-large",
            RESPONSE_TOO_LARGE_MESSAGE,
        ),
        (HttpErrorCode::Timeout, "http-timeout", HTTP_TIMEOUT_MESSAGE),
        (
            HttpErrorCode::InvalidUri,
            "invalid-uri",
            INVALID_URI_MESSAGE,
        ),
        (
            HttpErrorCode::InvalidHeader,
            "invalid-header",
            INVALID_HEADER_MESSAGE,
        ),
        (
            HttpErrorCode::InvalidMethod,
            "http-failed",
            HTTP_FAILED_MESSAGE,
        ),
        (HttpErrorCode::Dns, "http-failed", HTTP_FAILED_MESSAGE),
        (HttpErrorCode::Connect, "http-failed", HTTP_FAILED_MESSAGE),
        (HttpErrorCode::Tls, "http-failed", HTTP_FAILED_MESSAGE),
        (HttpErrorCode::Protocol, "http-failed", HTTP_FAILED_MESSAGE),
        (HttpErrorCode::Internal, "http-failed", HTTP_FAILED_MESSAGE),
    ];
    for (code, expected_code, expected_message) in cases {
        let mapped = map_http_error(HttpError {
            code,
            message: "SECRET-SENTINEL uri/header/body/dns/tls detail".to_owned(),
        });
        assert_eq!(mapped.code(), expected_code, "{code:?}");
        assert_eq!(mapped.message(), expected_message, "{code:?}");
        assert!(!mapped.to_string().contains("SECRET-SENTINEL"));
    }
}

#[test]
fn transport_failure_is_not_retried() {
    let calls = Cell::new(0);
    let failure = invoke_with(&capability(CAPABILITY), valid_input(), |_request| {
        calls.set(calls.get() + 1);
        Err(HttpError {
            code: HttpErrorCode::Connect,
            message: "secret destination".to_owned(),
        })
    })
    .expect_err("transport fails");
    assert_eq!(calls.get(), 1);
    assert_eq!(failure.code(), "http-failed");
    assert_eq!(failure.message(), HTTP_FAILED_MESSAGE);
}

#[test]
fn duplicate_raw_json_keys_record_the_sdk_last_value_wins_limitation() {
    let decoded: Value = serde_json::from_str(
        r#"{"uri":"https://ignored.invalid","uri":"https://example.com/final","method":"POST","method":"GET"}"#,
    )
    .expect("SDK JSON representation decodes");
    assert_eq!(decoded["uri"], "https://example.com/final");
    assert_eq!(decoded["method"], "GET");

    let mut observed = None;
    invoke_with(&capability(CAPABILITY), decoded, |request| {
        observed = Some(request);
        Ok(empty_response(200))
    })
    .expect("the final duplicate values satisfy the contract");
    assert_eq!(observed.expect("request").uri, "https://example.com/final");
}

#[test]
fn every_public_failure_is_fixed_and_secret_sentinel_free() {
    const SENTINEL: &str = "secret-sentinel-never-return";
    let inputs = [
        json!({SENTINEL: true}),
        json!({"uri": format!("not-a-uri-{SENTINEL}")}),
        json!({
            "uri": "https://example.com",
            "headers": [{"name": "authorization", "value": SENTINEL}]
        }),
    ];
    for input in inputs {
        let failure = invoke_with(&capability(CAPABILITY), input, |_request| {
            panic!("invalid input cannot call HTTP")
        })
        .expect_err("sentinel input is refused");
        assert!(!failure.code().contains(SENTINEL));
        assert!(!failure.message().contains(SENTINEL));
    }

    let transport = map_http_error(HttpError {
        code: HttpErrorCode::Internal,
        message: SENTINEL.to_owned(),
    });
    assert!(!transport.to_string().contains(SENTINEL));
}

#[test]
fn command_word_registry_contract_reserves_curl_but_accepts_curlget() {
    let declared = |word: &str| vec![("curl".to_owned(), vec![word.to_owned()])];
    let conflicts = command_word_conflicts(&declared("curl"));
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].kind, CommandWordConflictKind::Reserved);

    assert!(command_word_conflicts(&declared("curlget")).is_empty());

    let shaped = command_word_conflicts(&declared("curl-get"));
    assert_eq!(shaped.len(), 1);
    assert_eq!(shaped[0].kind, CommandWordConflictKind::CapabilityShaped);
}

#[test]
fn request_builder_never_inherits_process_network_state() {
    let mut request = None::<Request>;
    invoke_with(&capability(CAPABILITY), valid_input(), |built| {
        request = Some(built);
        Ok(empty_response(200))
    })
    .expect("request succeeds");
    let request = request.expect("one request");
    assert_eq!(request.method, "GET");
    assert!(request.body.is_empty());
    assert_eq!(request.headers.len(), 1);
    assert!(
        request
            .headers
            .iter()
            .all(|header| !header.name.eq_ignore_ascii_case("authorization"))
    );
}
