//! CU-b red/green contract: no JSON, status-before-body, and guest pipe semantics.
use dekopon_curl_provider::Curl;
use dekopon_provider_sdk::CommandRunOutcome;
use dekopon_provider_sdk::provider::{
    self, Body, Header, HttpError, HttpErrorCode, NativeStdio, OpenedResponse, Port, Request,
    Response, StreamedRequest, StreamedResponse,
};
use dekopon_provider_sdk_testkit::{Harness, HttpScript, Native, conformance};
use serde_json::json;
use std::{
    io::{self, Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("fresh component")
        .into()
}
fn script(status: u16, body: Vec<u8>) -> HttpScript {
    HttpScript::new(
        "example.com",
        "GET",
        Response {
            status,
            headers: vec![],
            body,
        },
    )
}
fn proposal_with_budget(stdin_len: usize) -> serde_json::Value {
    let url = "https://example.com/path";
    let flag_len = 24_576 - stdin_len - url.len() - 2 - 2;
    let flag = format!("-s{}", "S".repeat(flag_len - 2));
    let words = vec![flag, "-H".into(), "@-".into(), url.into()];
    let CommandRunOutcome::Proposed { input, .. } = provider::command::<Curl>(&words, true) else {
        panic!("budgeted proposal refused");
    };
    input
}
#[test]
fn combined_argv_and_raw_pipe_byte_limit_is_exact() {
    for bytes in [
        b"Accept: x".as_slice(), // no final terminator
        b"Accept: x\n".as_slice(),
        b"Accept: x\r\n".as_slice(),
    ] {
        let input = proposal_with_budget(bytes.len());
        assert_eq!(input["argv_bytes"], 24_576 - bytes.len());
        let native = Native::<Curl>::new()
            .stdin(bytes.to_vec())
            .http(script(200, vec![]));
        let result = native.call("curl.get", &input.to_string());
        assert_eq!(result.status, 0, "{}", result.stderr);
        assert_eq!(native.requests().len(), 1);
        let over = Native::<Curl>::new()
            .stdin([bytes, b"\n"].concat())
            .http(script(200, vec![]));
        let result = over.call("curl.get", &input.to_string());
        assert_eq!(
            result.status, 2,
            "CRLF and final terminators count as raw bytes"
        );
        assert!(over.requests().is_empty());
    }
}
struct Measured {
    source: io::Cursor<Vec<u8>>,
    count: Arc<AtomicUsize>,
}
impl Read for Measured {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.source.read(buf)?;
        self.count.fetch_add(n, Ordering::SeqCst);
        Ok(n)
    }
}
#[test]
fn oversized_unterminated_line_never_reads_unbounded_input_or_calls_http() {
    let read = Arc::new(AtomicUsize::new(0));
    let opened = Arc::new(AtomicUsize::new(0));
    let exit = provider::with_port(
        OpenOnly {
            opened: opened.clone(),
        },
        || {
            provider::invoke_native::<Curl>("curl.get",
            &json!({"uri":"https://example.com/path", "stdin_headers":true, "stdin_header_index":0}).to_string(),
            NativeStdio { stdin: Some(Box::new(Measured { source: io::Cursor::new(vec![b'x'; 1_048_576]), count: read.clone() })), stdout: Box::new(io::sink()) })
        },
    );
    assert_eq!(exit.status, 2);
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    assert!(
        read.load(Ordering::SeqCst) <= 24_577,
        "read {} bytes before refusing",
        read.load(Ordering::SeqCst)
    );
}
#[test]
fn clean_body_is_exact_bytes_not_a_json_envelope() {
    let body = b"first\n\x00\xfflast\n".to_vec();
    let result = Native::<Curl>::new().http(script(200, body.clone())).call(
        "curl.get",
        &json!({"uri":"https://example.com/path"}).to_string(),
    );
    assert_eq!(result.status, 0, "{}", result.stderr);
    assert_eq!(result.stdout, body);
    assert!(result.stderr.is_empty());
}
#[test]
fn failing_http_status_is_exit_22_and_discards_body_before_splice() {
    for status in [400, 404, 429, 500, 599] {
        let result = Native::<Curl>::new()
            .http(script(status, b"secret-body-never-written".to_vec()))
            .call(
                "curl.get",
                &json!({"uri":"https://example.com/path"}).to_string(),
            );
        assert_eq!(result.status, 22, "{status}: {}", result.stderr);
        assert!(result.stdout.is_empty(), "status {status}");
        assert_eq!(result.stderr.lines().count(), 1, "status {status}");
        assert!(result.stderr.contains(&status.to_string()));
        assert!(!result.stderr.contains("secret-body-never-written"));
    }
    for status in [200, 204, 301, 302, 399] {
        let result = Native::<Curl>::new()
            .http(script(status, b"ok".to_vec()))
            .call(
                "curl.get",
                &json!({"uri":"https://example.com/path"}).to_string(),
            );
        assert_eq!(result.status, 0, "{status}");
        assert_eq!(result.stdout, b"ok", "{status}");
    }
}
#[test]
fn required_headers_are_read_at_invoke_and_empty_stdin_is_usage_two() {
    let input = json!({"uri":"https://example.com/path", "headers":[{"name":"accept","value":"first"},{"name":"range","value":"bytes=0-9"}], "stdin_headers":true, "stdin_header_index":1});
    let native = Native::<Curl>::new()
        .stdin(b"Accept-Language: en\n".to_vec())
        .http(script(200, b"body".to_vec()));
    let result = native.call("curl.get", &input.to_string());
    assert_eq!(result.status, 0, "{}", result.stderr);
    assert_eq!(result.stdout, b"body");
    assert_eq!(
        native.requests()[0]
            .headers
            .iter()
            .map(|h| h.name.as_str())
            .collect::<Vec<_>>(),
        ["accept", "accept-language", "range", "user-agent"]
    );
    for native in [Native::<Curl>::new(), Native::new().stdin(Vec::new())] {
        let result = native.call("curl.get", &input.to_string());
        assert_eq!(result.status, 2);
        assert!(result.stdout.is_empty());
        assert!(native.requests().is_empty());
    }
}
struct Closed;
impl Write for Closed {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct OpenOnly {
    opened: Arc<AtomicUsize>,
}
impl Port for OpenOnly {
    fn now_unix_millis(&mut self) -> u64 {
        0
    }
    fn settings(&mut self) -> Option<String> {
        None
    }
    fn send(&mut self, _: Request) -> Result<Response, HttpError> {
        panic!("buffered send is retired")
    }
    fn open(&mut self, request: Request) -> Result<OpenedResponse, HttpError> {
        assert_eq!(request.method, "GET");
        assert!(request.body.is_empty());
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(OpenedResponse {
            status: 200,
            headers: vec![],
            body: Body::native(io::Cursor::new(b"first\nsecond\n".to_vec())),
        })
    }
    fn stream(&mut self, _: StreamedRequest<'_>) -> Result<StreamedResponse, HttpError> {
        Err(HttpError {
            code: HttpErrorCode::Denied,
            message: "no asset".into(),
        })
    }
}
#[test]
fn native_splice_to_closed_stdout_exits_141_without_error_text() {
    let opened = Arc::new(AtomicUsize::new(0));
    let exit = provider::with_port(
        OpenOnly {
            opened: opened.clone(),
        },
        || {
            provider::invoke_native::<Curl>(
                "curl.get",
                &json!({"uri":"https://example.com/path"}).to_string(),
                NativeStdio {
                    stdin: None,
                    stdout: Box::new(Closed),
                },
            )
        },
    );
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    assert_eq!(exit.status, 141);
    assert!(exit.stderr.is_empty());
}
// Local smoke only: the testkit does not wire two checked components into a pipe.
// Feed real-component curl bytes to the local rg executable when requested.
#[test]
fn local_curl_component_to_rg_pipe_smoke() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("DEKOPON_LOCAL_RG_PIPE").is_none() {
        return Ok(());
    }
    let run = Harness::<Curl>::get(component()).http(HttpScript::new(
        "localhost",
        "GET",
        Response {
            status: 200,
            headers: vec![],
            body: b"needle\nother\n".to_vec(),
        },
    ));
    let origin = run.origin().unwrap().to_owned();
    let curl = run.call("curl.get", json!({"uri":format!("{origin}/pipe")}))?;
    assert_eq!(curl.status, 0, "{}", curl.stderr);
    let mut rg = Command::new("rg")
        .args(["^needle$"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    rg.stdin.take().unwrap().write_all(&curl.stdout)?;
    let match_output = rg.wait_with_output()?;
    assert!(match_output.status.success());
    assert_eq!(match_output.stdout, b"needle\n");
    Ok(())
}
#[test]
fn checked_component_streams_clean_body_and_refuses_status_before_body()
-> Result<(), Box<dyn std::error::Error>> {
    conformance::<Curl>(component())?;
    let run = Harness::<Curl>::get(component()).http(HttpScript::new(
        "localhost",
        "GET",
        Response {
            status: 200,
            headers: vec![Header::text("x-value", "one")?],
            body: b"needle\nother\n".to_vec(),
        },
    ));
    let origin = run.origin().unwrap().to_owned();
    let ok = run.call("curl.get", json!({"uri":format!("{origin}/one")}))?;
    assert_eq!(ok.status, 0, "{}", ok.stderr);
    assert_eq!(ok.stdout, b"needle\nother\n");
    assert_eq!(ok.http_calls.len(), 1);
    let fail = Harness::<Curl>::get(component()).http(HttpScript::new(
        "localhost",
        "GET",
        Response {
            status: 404,
            headers: vec![],
            body: b"secret-body-never-written".to_vec(),
        },
    ));
    let origin = fail.origin().unwrap().to_owned();
    let denied = fail.call("curl.get", json!({"uri":format!("{origin}/missing")}))?;
    assert_eq!(denied.status, 22);
    assert!(denied.stdout.is_empty());
    assert!(!denied.stderr.contains("secret-body-never-written"));
    Ok(())
}
