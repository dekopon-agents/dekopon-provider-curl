//! One bounded, unauthenticated, broker-authorized HTTP GET for Dekopon.
//!
//! The component has no transport of its own. Its sole import is
//! `dekopon:http/client@1.0.0`, which direct hosts intentionally do not link. The broker owns URL
//! canonicalization, DNS validation and pinning, exact authority/method constraints, timeouts,
//! response streaming limits, and the credential boundary. This guest adds a closed input shape,
//! conservative URI checks, a narrow request-header allowlist, and byte-preserving bounded output.
//!
//! Generated component bindings necessarily contain `unsafe` ABI shims. Hand-written code in this
//! crate contains no unsafe block.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dekopon_provider_http::{Header, HttpError, HttpErrorCode, Request, Response, method};
use dekopon_provider_sdk::{
    CapabilityId, ComponentResponse, EffectKind, Idempotency, Provider, ProviderApiVersion,
    ProviderCapability, ProviderError, ProviderManifest, RiskLevel,
};
use serde::Serialize;
use serde_json::{Value, json};

mod command;
mod uri;

const PROVIDER_ID: &str = "curl";
const CAPABILITY: &str = "curl.get";
const USER_AGENT: &str = "dekopon-provider-curl/0.1.0";

const MAX_REQUEST_HEADERS: usize = 32;
const MAX_HEADER_NAME_BYTES: usize = 64;
const MAX_HEADER_VALUE_BYTES: usize = 4_096;
const MAX_REQUEST_HEADER_BYTES: usize = 16_384;
const MAX_RESPONSE_HEADERS: usize = 128;
const MAX_RESPONSE_HEADER_BYTES: usize = 65_536;
const MAX_RETURNED_BODY_BYTES: usize = 65_536;
const MAX_BODY_TEXT_JSON_BYTES: usize = 131_072;
const MAX_SUCCESS_ENVELOPE_BYTES: usize = 524_288;

const ALLOWED_HEADERS: [&str; 6] = [
    "accept",
    "accept-language",
    "cache-control",
    "if-modified-since",
    "if-none-match",
    "range",
];

const UNSUPPORTED_CAPABILITY_MESSAGE: &str = "provider exposes only curl.get";
const INVALID_INPUT_MESSAGE: &str = "input does not match the curl.get contract";
const INVALID_URI_MESSAGE: &str = "URI does not match the curl.get policy";
const INVALID_HEADER_MESSAGE: &str = "request headers do not match the curl.get policy";
const HTTP_DENIED_MESSAGE: &str = "broker HTTP request was denied";
const REQUEST_TOO_LARGE_MESSAGE: &str = "broker HTTP request exceeded its limit";
const RESPONSE_TOO_LARGE_MESSAGE: &str = "broker HTTP response exceeded its limit";
const HTTP_TIMEOUT_MESSAGE: &str = "broker HTTP request timed out";
const HTTP_FAILED_MESSAGE: &str = "broker HTTP request failed";
const INVALID_RESPONSE_MESSAGE: &str = "broker HTTP response violated provider bounds";

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "provider",
        generate_all,
        pub_export_macro: true,
    });
}

/// The notices are part of the shipped bytes, not a detached build-side promise.
#[cfg(target_arch = "wasm32")]
#[used]
#[unsafe(link_section = "dekopon.third-party-notices")]
static THIRD_PARTY_NOTICES: [u8; include_bytes!("../THIRD_PARTY_NOTICES.md").len()] =
    *include_bytes!("../THIRD_PARTY_NOTICES.md");

struct Curl;

impl Provider for Curl {
    fn manifest() -> ProviderManifest {
        ProviderManifest {
            api_version: ProviderApiVersion::V1Alpha1,
            id: PROVIDER_ID.parse().expect("static provider ID is valid"),
            description: "Performs one bounded broker-authorized bodyless HTTP GET.".to_owned(),
            command_words: vec!["curlget".to_owned()],
            capabilities: vec![ProviderCapability {
                id: CAPABILITY
                    .parse()
                    .expect("static capability identifier is valid"),
                description: "Fetches one HTTPS URL, or explicit loopback HTTP test URL, and returns a bounded byte-preserving response."
                    .to_owned(),
                effect: EffectKind::ReadOnly,
                risk: RiskLevel::Medium,
                idempotency: Idempotency::Idempotent,
                input_schema: input_schema(),
            }],
        }
    }

    fn resolve_command(
        argv: &[String],
    ) -> Result<dekopon_provider_sdk::CommandInvocation, ProviderError> {
        command::resolve(argv)
    }

    fn invoke(capability: &CapabilityId, input: Value) -> Result<Value, ProviderError> {
        invoke_with(capability, input, dekopon_provider_http::send)
    }
}

/// Runs one invocation against an injected transport. Native tests use this seam; the component
/// passes the broker import. `FnMut` lets tests prove that success and failure never retry.
fn invoke_with<F>(
    capability: &CapabilityId,
    input: Value,
    mut send: F,
) -> Result<Value, ProviderError>
where
    F: FnMut(Request) -> Result<Response, HttpError>,
{
    if capability.as_str() != CAPABILITY {
        return Err(error(
            "unsupported-capability",
            UNSUPPORTED_CAPABILITY_MESSAGE,
        ));
    }

    let validated = validate_input(input)?;
    let request = build_request(validated)?;
    let response = send(request).map_err(map_http_error)?;
    project_response_with_limit(response, MAX_SUCCESS_ENVELOPE_BYTES)
}

struct ValidatedInput {
    uri: String,
    headers: Vec<Header>,
}

fn validate_input(input: Value) -> Result<ValidatedInput, ProviderError> {
    let Value::Object(mut fields) = input else {
        return Err(invalid_input());
    };
    if fields
        .keys()
        .any(|field| !matches!(field.as_str(), "uri" | "method" | "headers"))
    {
        return Err(invalid_input());
    }

    let uri = fields
        .remove("uri")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(invalid_input)?;
    if !uri::validate(&uri) {
        return Err(error("invalid-uri", INVALID_URI_MESSAGE));
    }

    if let Some(selected_method) = fields.remove("method")
        && selected_method.as_str() != Some(method::GET)
    {
        return Err(invalid_input());
    }

    let headers = match fields.remove("headers") {
        None => Vec::new(),
        Some(Value::Array(headers)) => validate_headers(headers)?,
        Some(_) => return Err(invalid_header()),
    };
    Ok(ValidatedInput { uri, headers })
}

fn validate_headers(values: Vec<Value>) -> Result<Vec<Header>, ProviderError> {
    if values.len() > MAX_REQUEST_HEADERS {
        return Err(invalid_header());
    }
    let mut total = 0_usize;
    let mut headers = Vec::with_capacity(values.len());
    for value in values {
        let Value::Object(mut fields) = value else {
            return Err(invalid_header());
        };
        if fields.len() != 2 || !fields.contains_key("name") || !fields.contains_key("value") {
            return Err(invalid_header());
        }
        let name = fields
            .remove("name")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(invalid_header)?;
        let value = fields
            .remove("value")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(invalid_header)?;
        if name.len() > MAX_HEADER_NAME_BYTES
            || value.len() > MAX_HEADER_VALUE_BYTES
            || !is_token(&name)
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(invalid_header());
        }
        let name = name.to_ascii_lowercase();
        if !ALLOWED_HEADERS.contains(&name.as_str()) {
            return Err(invalid_header());
        }
        total = total
            .checked_add(name.len())
            .and_then(|size| size.checked_add(value.len()))
            .and_then(|size| size.checked_add(4))
            .ok_or_else(invalid_header)?;
        if total > MAX_REQUEST_HEADER_BYTES {
            return Err(invalid_header());
        }
        headers.push(Header::new(name, value.into_bytes()).map_err(|_| invalid_header())?);
    }
    Ok(headers)
}

fn build_request(validated: ValidatedInput) -> Result<Request, ProviderError> {
    let mut request = Request::new(method::GET, validated.uri)
        .map_err(|_| error("invalid-uri", INVALID_URI_MESSAGE))?;
    request.headers = validated.headers;
    request
        .headers
        .push(Header::text("user-agent", USER_AGENT).map_err(|_| invalid_header())?);
    // `Request::new` starts empty and no later code has access to a body setter.
    debug_assert!(request.body.is_empty());
    Ok(request)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseHeader {
    name: String,
    value_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_text: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CurlOutput {
    status: u16,
    headers: Vec<ResponseHeader>,
    body_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_text: Option<String>,
    body_bytes: usize,
    body_returned_bytes: usize,
    body_truncated: bool,
}

fn project_response_with_limit(
    response: Response,
    envelope_limit: usize,
) -> Result<Value, ProviderError> {
    if response.headers.len() > MAX_RESPONSE_HEADERS {
        return Err(invalid_response());
    }
    let mut header_bytes = 0_usize;
    let mut headers = Vec::with_capacity(response.headers.len());
    for header in response.headers {
        if !is_token(&header.name) {
            return Err(invalid_response());
        }
        header_bytes = header_bytes
            .checked_add(header.name.len())
            .and_then(|size| size.checked_add(header.value.len()))
            .and_then(|size| size.checked_add(4))
            .ok_or_else(invalid_response)?;
        if header_bytes > MAX_RESPONSE_HEADER_BYTES {
            return Err(invalid_response());
        }
        headers.push(ResponseHeader {
            name: header.name,
            value_base64: STANDARD.encode(&header.value),
            value_text: core::str::from_utf8(&header.value).ok().map(str::to_owned),
        });
    }

    let returned = bounded_body_prefix(&response.body);
    let body_text = core::str::from_utf8(returned).ok().and_then(|text| {
        serde_json::to_vec(text)
            .ok()
            .filter(|encoded| encoded.len() <= MAX_BODY_TEXT_JSON_BYTES)
            .map(|_| text.to_owned())
    });
    let mut output = CurlOutput {
        status: response.status,
        headers,
        body_base64: STANDARD.encode(returned),
        body_text,
        body_bytes: response.body.len(),
        body_returned_bytes: returned.len(),
        body_truncated: returned.len() < response.body.len(),
    };

    let mut value = serde_json::to_value(&output).map_err(|_| invalid_response())?;
    if success_envelope_len(&value)? <= envelope_limit {
        return Ok(value);
    }

    // Optional UTF-8 projections are all-or-nothing under the complete SDK envelope ceiling. This
    // leaves the mandatory, byte-preserving base64 representation deterministic.
    output.body_text = None;
    for header in &mut output.headers {
        header.value_text = None;
    }
    value = serde_json::to_value(&output).map_err(|_| invalid_response())?;
    if success_envelope_len(&value)? <= envelope_limit {
        Ok(value)
    } else {
        Err(invalid_response())
    }
}

fn success_envelope_len(output: &Value) -> Result<usize, ProviderError> {
    serde_json::to_vec(&ComponentResponse::Succeeded {
        output: output.clone(),
    })
    .map(|bytes| bytes.len())
    .map_err(|_| invalid_response())
}

/// Returns a raw prefix, backing up only when the source as a whole is valid UTF-8 and the byte
/// cut would split its final scalar. Genuinely invalid input retains the full binary prefix.
fn bounded_body_prefix(body: &[u8]) -> &[u8] {
    if body.len() <= MAX_RETURNED_BODY_BYTES {
        return body;
    }
    let Ok(text) = core::str::from_utf8(body) else {
        return &body[..MAX_RETURNED_BODY_BYTES];
    };
    let mut end = MAX_RETURNED_BODY_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}

fn map_http_error(failure: HttpError) -> ProviderError {
    match failure.code {
        HttpErrorCode::Denied | HttpErrorCode::HostCallLimit => {
            error("http-denied", HTTP_DENIED_MESSAGE)
        }
        HttpErrorCode::RequestTooLarge => error("request-too-large", REQUEST_TOO_LARGE_MESSAGE),
        HttpErrorCode::ResponseTooLarge => error("response-too-large", RESPONSE_TOO_LARGE_MESSAGE),
        HttpErrorCode::Timeout => error("http-timeout", HTTP_TIMEOUT_MESSAGE),
        HttpErrorCode::InvalidUri => error("invalid-uri", INVALID_URI_MESSAGE),
        HttpErrorCode::InvalidHeader => error("invalid-header", INVALID_HEADER_MESSAGE),
        HttpErrorCode::InvalidMethod
        | HttpErrorCode::Dns
        | HttpErrorCode::Connect
        | HttpErrorCode::Tls
        | HttpErrorCode::Protocol
        | HttpErrorCode::Internal => error("http-failed", HTTP_FAILED_MESSAGE),
    }
}

fn input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "uri": {
                "type": "string",
                "format": "uri",
                "minLength": 1,
                "maxLength": 4096
            },
            "method": {
                "type": "string",
                "enum": ["GET"],
                "default": "GET"
            },
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
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn error(code: &'static str, message: &'static str) -> ProviderError {
    ProviderError::new(code, message)
}

fn invalid_input() -> ProviderError {
    error("invalid-input", INVALID_INPUT_MESSAGE)
}

fn invalid_header() -> ProviderError {
    error("invalid-header", INVALID_HEADER_MESSAGE)
}

fn invalid_response() -> ProviderError {
    error("invalid-response", INVALID_RESPONSE_MESSAGE)
}

dekopon_provider_sdk::export_provider_with_commands!(Curl, bindings);

#[cfg(test)]
mod tests;
