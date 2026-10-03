//! Migrated pre-K argv, schema, and credential boundary assertions.
use dekopon_curl_provider::Curl;
use dekopon_provider_sdk::{CommandRunOutcome, SecretUseProposal, provider};
use serde_json::{Value, json};

fn command(words: &[&str], piped: bool) -> CommandRunOutcome {
    provider::command::<Curl>(
        &words.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        piped,
    )
}
fn input(words: &[&str], piped: bool) -> Value {
    let CommandRunOutcome::Proposed {
        capability,
        input,
        secret_use,
    } = command(words, piped)
    else {
        panic!("proposal expected: {words:?}")
    };
    assert_eq!(capability.as_str(), "curl.get");
    assert!(secret_use.is_none());
    input
}
fn usage(words: &[&str], piped: bool) {
    match command(words, piped) {
        CommandRunOutcome::Failed { error } => {
            assert_eq!(error.code, "usage");
            assert!(!error.message.is_empty());
        }
        CommandRunOutcome::Rendered {
            stdout,
            stderr,
            status,
        } => {
            assert_eq!(status, 2);
            assert!(stdout.is_empty());
            assert!(!stderr.is_empty());
        }
        other => panic!("{words:?}: unexpected {other:?}"),
    }
}
#[test]
fn help_invalid_argv_and_missing_url_are_rendered_by_clap() {
    for flag in ["--help", "-h"] {
        let CommandRunOutcome::Rendered {
            stdout,
            stderr,
            status,
        } = command(&[flag], false)
        else {
            panic!("help {flag}")
        };
        assert_eq!(status, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("bodyless HTTP GET"));
        for name in [
            "accept",
            "accept-language",
            "cache-control",
            "if-modified-since",
            "if-none-match",
            "range",
            "--oauth2-bearer",
            "--user",
        ] {
            assert!(stdout.contains(name), "help omitted {name}");
        }
    }
    for words in [
        vec![],
        vec!["--definitely-not-an-option", "https://example.com"],
    ] {
        let CommandRunOutcome::Rendered {
            stdout,
            stderr,
            status,
        } = command(&words, false)
        else {
            panic!("clap must render {words:?}")
        };
        assert_eq!(status, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("Usage:"));
    }
    usage(&["-s"], false);
    usage(&["https://one.example", "https://two.example"], false);
}
#[test]
fn all_old_supported_get_and_quiet_spellings_normalize() {
    for words in [
        vec!["-s", "https://example.com"],
        vec!["-S", "https://example.com"],
        vec!["-sSSss", "https://example.com"],
        vec!["--silent", "--show-error", "https://example.com"],
        vec!["-X", "get", "https://example.com"],
        vec!["--request", "GeT", "https://example.com"],
    ] {
        assert_eq!(input(&words, false)["method"], "GET", "{words:?}");
    }
    assert_eq!(input(&["https://example.com"], false)["headers"], json!([]));
}
#[test]
fn header_lines_split_once_trim_preserve_order_and_duplicate_names() {
    let value = input(
        &[
            "-H",
            " Accept : text/plain:version=1 ",
            "--header",
            "Accept: application/json",
            "https://example.com",
        ],
        false,
    );
    assert_eq!(
        value["headers"],
        json!([
            {"name":"Accept","value":"text/plain:version=1"},
            {"name":"Accept","value":"application/json"}
        ])
    );
    assert_eq!(
        input(&["-H", "Accept: --help", "https://example.com"], false)["headers"][0]["value"],
        "--help"
    );
    for args in [
        vec!["-H", "missing-colon", "https://example.com"],
        vec!["-H", " : value", "https://example.com"],
        vec!["-H", "@headers.txt", "https://example.com"],
    ] {
        usage(&args, false);
    }
}
#[test]
fn stdin_marker_is_proposed_once_without_pre_authorization_reads() {
    let proposal = input(
        &[
            "-H",
            "Accept: first",
            "-H",
            "@-",
            "-H",
            "Range: bytes=0-9",
            "https://example.com",
        ],
        true,
    );
    assert_eq!(
        proposal["headers"],
        json!([{"name":"Accept","value":"first"},{"name":"Range","value":"bytes=0-9"}])
    );
    assert_eq!(proposal["stdin_header_index"], 1);
    usage(&["-H", "@-", "https://example.com"], false);
    usage(&["-H", "@-", "-H", "@-", "https://example.com"], true);
    assert_eq!(input(&["https://example.com"], true)["headers"], json!([]));
}
#[test]
fn unlisted_options_and_non_get_methods_remain_refused() {
    for option in [
        "-G",
        "-I",
        "-L",
        "-f",
        "--data",
        "--data-binary",
        "--head",
        "--location",
        "--fail",
        "--retry",
        "--cookie",
        "--proxy",
        "--output",
        "--upload-file",
        "--config",
        "--compressed",
        "--insecure",
        "--netrc",
        "--anyauth",
        "--digest",
        "-XGET",
        "--request=POST",
        "--header=Accept:x",
        "--silent=true",
        "--hel",
    ] {
        usage(&[option, "https://example.com"], false);
    }
    for method in ["POST", "HEAD", "DELETE"] {
        usage(&["-X", method, "https://example.com"], false);
    }
    usage(&["-X", "GET", "-X", "GET", "https://example.com"], false);
}
#[test]
fn credential_flags_name_only_public_drns_and_do_not_enter_input() {
    const DRN: &str = "drn:com.xrl:secret:test:curl/token";
    let plain = input(&["https://example.com/a"], false);
    for (words, basic) in [
        (vec!["--oauth2-bearer", DRN, "https://example.com/a"], false),
        (
            vec![
                "-u",
                "user-a:drn:com.xrl:secret:test:curl/token",
                "https://example.com/a",
            ],
            true,
        ),
    ] {
        let CommandRunOutcome::Proposed {
            input, secret_use, ..
        } = command(&words, false)
        else {
            panic!("secret proposal")
        };
        assert_eq!(input, plain);
        assert!(!input.to_string().contains(DRN));
        match secret_use.unwrap() {
            SecretUseProposal::HttpBearer { secret } if !basic => assert_eq!(secret.as_str(), DRN),
            SecretUseProposal::HttpBasic { secret, username } if basic => {
                assert_eq!(secret.as_str(), DRN);
                assert_eq!(username, "user-a");
            }
            other => panic!("wrong secret use {other:?}"),
        }
    }
    for bad in [
        "${drn:com.xrl:secret:test:curl/token}",
        "drn:com.xrl:secret:Test:curl/token",
        "drn:com.xrl:secret:test:curl//token",
        "not-a-drn",
        "secret-sentinel-never-return",
    ] {
        usage(&["--oauth2-bearer", bad, "https://example.com"], false);
        let error = command(&["--oauth2-bearer", bad, "https://example.com"], false);
        assert!(
            !format!("{error:?}").contains(bad),
            "refusal echoed credential"
        );
    }
    for bad in ["", "user a\u{7f}", "user\na", "user-a".repeat(100).as_str()] {
        let user = format!("{bad}:{DRN}");
        usage(&["-u", &user, "https://example.com"], false);
    }
    usage(
        &[
            "--oauth2-bearer",
            DRN,
            "-u",
            "user-a:drn:com.xrl:secret:test:curl/token",
            "https://example.com",
        ],
        false,
    );
}
#[test]
fn command_arg_header_and_byte_limits_remain_bounded() {
    let many = vec!["-s"; 71];
    let mut argv = many;
    argv.push("https://example.com");
    usage(&argv, false);
    let mut headers = Vec::new();
    for _ in 0..32 {
        headers.extend(["-H", "Accept: x"]);
    }
    headers.push("https://example.com");
    assert_eq!(
        input(&headers, false)["headers"].as_array().unwrap().len(),
        32
    );
    headers.splice(0..0, ["-H", "Accept: x"]);
    usage(&headers, false);
    let long = "u".repeat(24_577);
    usage(&[&long], false);
}
#[test]
fn schema_is_closed_and_advertises_input_limits() {
    let schema = &provider::manifest::<Curl>().unwrap().capabilities[0].input_schema;
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["uri"]["minLength"], 1);
    assert_eq!(schema["properties"]["uri"]["maxLength"], 4096);
    assert_eq!(schema["properties"]["headers"]["maxItems"], 32);
    assert_eq!(
        schema["properties"]["headers"]["items"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["properties"]["headers"]["items"]["properties"]["name"]["maxLength"],
        64
    );
    assert_eq!(
        schema["properties"]["headers"]["items"]["properties"]["value"]["maxLength"],
        4096
    );
}
