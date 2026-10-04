//! One broker-authorized bodyless GET. HTTP and stdio are SDK-owned imports.
//! Credentials are named only in the proposal; the broker resolves and injects them.
mod command;
mod uri;

use dekopon_provider_sdk::provider::{
    self, Capability, Code, Failure, Http, Proposal, Provider, Stdout, Usage,
};
use dekopon_provider_sdk::provider::{Header, HttpError, HttpErrorCode, Request, method};
use dekopon_provider_sdk::{EffectKind, RiskLevel};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    fmt,
    io::{Read, Write},
};

const USER_AGENT: &str = concat!("dekopon-provider-curl/", env!("CARGO_PKG_VERSION"));
// Match the effective Pi GET/HEAD grant, not the broker's broader global ceiling.
const MAX_RESPONSE_BYTES: usize = 262_144;
const MAX_REQUEST_HEADERS: usize = 32;
const MAX_HEADER_NAME_BYTES: usize = 64;
const MAX_HEADER_VALUE_BYTES: usize = 4_096;
const MAX_REQUEST_HEADER_BYTES: usize = 16_384;
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
    /// Original argv byte count, set by run-command when -H @- is proposed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argv_bytes: Option<usize>,
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
    message: Cow<'static, str>,
}
impl CurlError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code: Code::new(code),
            message: message.into(),
        }
    }
    fn usage(message: &'static str) -> Self {
        Self {
            code: Code::USAGE,
            message: message.into(),
        }
    }
    fn http_status(status: u16) -> Self {
        Self {
            code: Code::new("http-status").exiting(22),
            message: format!("curl: HTTP status {status}").into(),
        }
    }
}
impl fmt::Display for CurlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
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
        let request = build_request(input)?;
        let response = http.send(request).map_err(map_http_error)?;
        // Never emit an untrusted body for a failing status or an oversized response.
        if response.status >= 400 {
            return Err(CurlError::http_status(response.status));
        }
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(CurlError::new(
                "response-too-large",
                "broker HTTP response exceeded its limit",
            ));
        }
        out.write_all(&response.body)
            .map_err(|_| CurlError::new("output-closed", "stdout's reader has gone"))
    }
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
        let remaining = command::MAX_INPUT_BYTES
            .checked_sub(input.argv_bytes.unwrap_or(0))
            .ok_or_else(|| CurlError::usage("curl: -H @-: piped headers exceed input limit"))?;
        // Read at most budget + 1 bytes, before any UTF-8 conversion or line allocation.
        // The extra byte distinguishes an exact-boundary EOF from an overflow.
        let mut raw = Vec::new();
        stdin
            .take((remaining + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|_| CurlError::usage("curl: -H @-: invalid piped headers"))?;
        if raw.len() > remaining {
            return Err(CurlError::usage(
                "curl: -H @-: piped headers exceed input limit",
            ));
        }
        if raw.is_empty() {
            return Err(CurlError::usage("curl: -H @-: nothing was piped in"));
        }
        let text = std::str::from_utf8(&raw)
            .map_err(|_| CurlError::usage("curl: -H @-: invalid piped headers"))?;
        let mut piped_headers = Vec::new();
        for line in text.split_terminator('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if !line.trim().is_empty() {
                piped_headers.push(
                    command::parse_header(line)
                        .map_err(|_| CurlError::usage("curl: -H @-: invalid piped headers"))?,
                );
            }
        }
        let index = input.stdin_header_index.unwrap_or(headers.len());
        if index > headers.len() {
            return Err(CurlError::usage(
                "input does not match the curl.get contract",
            ));
        }
        headers.splice(index..index, piped_headers);
    } else if input.stdin_header_index.is_some() || input.argv_bytes.is_some() {
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
