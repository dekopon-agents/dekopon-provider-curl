//! One broker-authorized bodyless GET. HTTP and stdio are SDK-owned imports.
//! Credentials are named only in the proposal; the broker resolves and injects them.
mod command;
mod uri;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dekopon_provider_sdk::provider::{
    self, Capability, Code, Failure, Http, Proposal, Provider, Stdout, Usage,
};
use dekopon_provider_sdk::provider::{Header, HttpError, HttpErrorCode, Request, Response, method};
use dekopon_provider_sdk::{EffectKind, RiskLevel};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{fmt, io::Write};

const USER_AGENT: &str = concat!("dekopon-provider-curl/", env!("CARGO_PKG_VERSION"));
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

/// The curl command provider.
pub struct Curl;
/// A single read-only GET capability.
pub struct Get;

impl Provider for Curl {
    const ID: &'static str = "curl";
    const COMMAND_WORDS: &'static [&'static str] = &["curl"];
    const DESCRIPTION: &'static str = "Performs one bounded broker-authorized bodyless HTTP GET.";
    type Args = command::CurlArgs;
    type Capabilities = (Get,);

    fn propose(args: Self::Args, stdin_piped: bool) -> Result<Proposal<Self>, Usage> {
        command::propose(args, stdin_piped)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Closed input for one authorized bodyless GET.
pub struct GetInput {
    #[schemars(length(min = 1, max = 4096))]
    uri: String,
    #[serde(default)]
    method: GetMethod,
    #[serde(default)]
    #[schemars(length(max = 32))]
    headers: Vec<InputHeader>,
    /// Set by -H @-; stdin is read at invocation, never during argv parsing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    stdin_headers: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stdin_header_index: Option<usize>,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
enum GetMethod {
    #[default]
    #[serde(rename = "GET")]
    Get,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct InputHeader {
    #[schemars(length(min = 1, max = 64))]
    name: String,
    #[schemars(length(max = 4096))]
    value: String,
}

#[derive(Debug)]
/// A fixed, credential-free invocation failure.
pub struct CurlError {
    code: Code,
    message: &'static str,
}
impl CurlError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code: Code::new(code),
            message,
        }
    }
    fn usage(message: &'static str) -> Self {
        Self {
            code: Code::USAGE,
            message,
        }
    }
}
impl fmt::Display for CurlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}
impl Failure for CurlError {
    fn code(&self) -> Code {
        self.code
    }
}

impl Capability for Get {
    type Provider = Curl;
    const NAME: &'static str = "get";
    const DESCRIPTION: &'static str =
        "Fetch one HTTPS URL, or explicit loopback HTTP test URL, using one bodyless GET.";
    const EFFECT: EffectKind = EffectKind::ReadOnly;
    const RISK: RiskLevel = RiskLevel::Medium;
    type Input = GetInput;
    type Needs = Http;
    type Error = CurlError;

    fn run(input: Self::Input, http: Http, out: &mut Stdout) -> Result<(), Self::Error> {
        // A bounded buffered-to-stdout bridge for CU-a. CU-b replaces this with open/splice.
        let response = invoke_with(input, |request| http.send(request))?;
        let mut bridge = project_response(response)?;
        bridge.push(b'\n');
        out.write_all(&bridge)
            .map_err(|_| CurlError::new("output-failed", "stdout write failed"))
    }
}

// CU-b deletes this bounded JSON-to-stdout bridge when open/splice replaces buffered send.
fn project_response(response: Response) -> Result<Vec<u8>, CurlError> {
    let invalid = || {
        CurlError::new(
            "invalid-response",
            "broker HTTP response violated provider bounds",
        )
    };
    if response.headers.len() > MAX_RESPONSE_HEADERS {
        return Err(invalid());
    }
    let mut header_bytes = 0_usize;
    let mut headers = Vec::new();
    for header in response.headers {
        header_bytes = header_bytes
            .checked_add(header.name.len() + header.value.len() + 4)
            .filter(|n| *n <= MAX_RESPONSE_HEADER_BYTES)
            .ok_or_else(invalid)?;
        if !is_token(&header.name) {
            return Err(invalid());
        }
        let mut entry = serde_json::json!({
            "name": header.name, "valueBase64": STANDARD.encode(&header.value),
        });
        if let Ok(value) = std::str::from_utf8(&header.value) {
            entry["valueText"] = value.into();
        }
        headers.push(entry);
    }
    let body_bytes = response.body.len();
    let prefix = bounded_body_prefix(&response.body);
    let body_text = std::str::from_utf8(prefix).ok().filter(|text| {
        serde_json::to_vec(text).is_ok_and(|bytes| bytes.len() <= MAX_BODY_TEXT_JSON_BYTES)
    });
    let mut output = serde_json::json!({
        "status": response.status, "headers": headers,
        "bodyBase64": STANDARD.encode(prefix),
        "bodyBytes": body_bytes, "bodyReturnedBytes": prefix.len(),
        "bodyTruncated": prefix.len() < body_bytes,
    });
    if let Some(text) = body_text {
        output["bodyText"] = text.into();
    }
    let mut serialized = serde_json::to_vec(&output).map_err(|_| invalid())?;
    if serialized.len() > MAX_SUCCESS_ENVELOPE_BYTES {
        output.as_object_mut().expect("output").remove("bodyText");
        for header in output["headers"].as_array_mut().expect("headers") {
            header.as_object_mut().expect("header").remove("valueText");
        }
        serialized = serde_json::to_vec(&output).map_err(|_| invalid())?;
    }
    if serialized.len() > MAX_SUCCESS_ENVELOPE_BYTES {
        return Err(invalid());
    }
    Ok(serialized)
}

fn bounded_body_prefix(body: &[u8]) -> &[u8] {
    if body.len() <= MAX_RETURNED_BODY_BYTES {
        return body;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return &body[..MAX_RETURNED_BODY_BYTES];
    };
    let mut end = MAX_RETURNED_BODY_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
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

fn invoke_with<F>(input: GetInput, mut send: F) -> Result<Response, CurlError>
where
    F: FnMut(Request) -> Result<Response, HttpError>,
{
    let request = build_request(input)?;
    send(request).map_err(map_http_error)
}

fn build_request(input: GetInput) -> Result<Request, CurlError> {
    if !uri::validate(&input.uri) {
        return Err(CurlError::new(
            "invalid-uri",
            "URI does not match the curl.get policy",
        ));
    }
    if input.method != GetMethod::Get {
        return Err(CurlError::usage(
            "input does not match the curl.get contract",
        ));
    }
    let mut headers = input.headers;
    if input.stdin_headers {
        let stdin = provider::stdin()
            .ok_or_else(|| CurlError::usage("curl: -H @-: nothing was piped in"))?;
        let mut consumed = 0_usize;
        let mut piped_headers = Vec::new();
        for line in stdin.lines() {
            let line = line.map_err(|_| CurlError::usage("curl: -H @-: invalid piped headers"))?;
            consumed = consumed
                .checked_add(line.len() + 1)
                .filter(|n| *n <= command::MAX_INPUT_BYTES)
                .ok_or_else(|| CurlError::usage("curl: -H @-: piped headers exceed input limit"))?;
            if !line.trim().is_empty() {
                piped_headers.push(
                    command::parse_header(&line)
                        .map_err(|_| CurlError::usage("curl: -H @-: invalid piped headers"))?,
                );
            }
        }
        if consumed == 0 {
            return Err(CurlError::usage("curl: -H @-: nothing was piped in"));
        }
        let index = input.stdin_header_index.unwrap_or(headers.len());
        if index > headers.len() {
            return Err(CurlError::usage(
                "input does not match the curl.get contract",
            ));
        }
        headers.splice(index..index, piped_headers);
    } else if input.stdin_header_index.is_some() {
        return Err(CurlError::usage(
            "input does not match the curl.get contract",
        ));
    }
    if headers.len() > MAX_REQUEST_HEADERS {
        return Err(CurlError::new(
            "invalid-header",
            "request headers do not match the curl.get policy",
        ));
    }
    let mut total = 0_usize;
    let mut request = Request::new(method::GET, input.uri)
        .map_err(|_| CurlError::new("invalid-uri", "URI does not match the curl.get policy"))?;
    for header in headers {
        let name = header.name.to_ascii_lowercase();
        if header.name.len() > MAX_HEADER_NAME_BYTES
            || header.value.len() > MAX_HEADER_VALUE_BYTES
            || !ALLOWED_HEADERS.contains(&name.as_str())
            || header.value.bytes().any(|b| b.is_ascii_control())
        {
            return Err(CurlError::new(
                "invalid-header",
                "request headers do not match the curl.get policy",
            ));
        }
        total = total
            .checked_add(name.len() + header.value.len() + 4)
            .filter(|n| *n <= MAX_REQUEST_HEADER_BYTES)
            .ok_or_else(|| {
                CurlError::new(
                    "invalid-header",
                    "request headers do not match the curl.get policy",
                )
            })?;
        request
            .headers
            .push(Header::text(name, header.value).map_err(|_| {
                CurlError::new(
                    "invalid-header",
                    "request headers do not match the curl.get policy",
                )
            })?);
    }
    request
        .headers
        .push(Header::text("user-agent", USER_AGENT).expect("static header"));
    debug_assert!(request.body.is_empty());
    Ok(request)
}

fn map_http_error(error: HttpError) -> CurlError {
    match error.code {
        HttpErrorCode::Denied | HttpErrorCode::HostCallLimit => {
            CurlError::new("http-denied", "broker HTTP request was denied")
        }
        HttpErrorCode::RequestTooLarge => CurlError::new(
            "request-too-large",
            "broker HTTP request exceeded its limit",
        ),
        HttpErrorCode::ResponseTooLarge => CurlError::new(
            "response-too-large",
            "broker HTTP response exceeded its limit",
        ),
        HttpErrorCode::Timeout => CurlError::new("http-timeout", "broker HTTP request timed out"),
        HttpErrorCode::InvalidUri => {
            CurlError::new("invalid-uri", "URI does not match the curl.get policy")
        }
        HttpErrorCode::InvalidHeader => CurlError::new(
            "invalid-header",
            "request headers do not match the curl.get policy",
        ),
        _ => CurlError::new("http-failed", "broker HTTP request failed"),
    }
}

#[allow(unsafe_code)]
mod export {
    dekopon_provider_sdk::export!(super::Curl);
}
