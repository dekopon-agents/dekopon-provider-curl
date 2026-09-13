//! Pure command-line front end for the provider-owned `curl` word.

use dekopon_provider_sdk::{CommandInvocation, CommandRun, SecretDrn, SecretUseProposal};
use serde_json::{Map, Value, json};

use crate::{CAPABILITY, MAX_REQUEST_HEADERS};

pub(crate) const MAX_ARGV_ENTRIES: usize = 70;
pub(crate) const MAX_INPUT_BYTES: usize = 24_576;

/// The `-H` value that reads headers from the piped value instead of from argv.
///
/// Upstream curl spells reading an option's value from standard input `@-`; the same spelling is
/// the only stdin this provider has a use for, because `curl.get` is bodyless by construction.
const STDIN_HEADERS: &str = "@-";

pub(crate) const USAGE: &str = "\
usage: curl [-sS] [-X GET] [-H \"Name: value\"|-H @-]...
            [--oauth2-bearer DRN|-u USER:DRN] URL
try 'curl --help'
";

pub(crate) const HELP: &str = "\
curl: one bounded, broker-authorized, bodyless HTTP GET.

Usage: curl [options...] URL

  -H, --header <line>    Add one request header, spelled \"Name: value\"
  -H, --header @-        Read request headers from stdin, one per line
  -X, --request GET      Request method; only GET is accepted
      --oauth2-bearer <drn>
                         Propose sending this secret DRN as a Bearer token
  -u, --user <user>:<drn>
                         Propose this username and secret DRN as Basic credentials
  -s, --silent           Accepted and ignored; there is no progress meter
  -S, --show-error       Accepted and ignored
  -h, --help             Print this help page

URL must be HTTPS, or a literal loopback HTTP URL with an explicit port. Header names
are limited to the allowlist: accept, accept-language, cache-control,
if-modified-since, if-none-match, range.

A credential flag takes a bare public DRN, drn:<authority>:secret:<realm>:<path>, and
proposes its use; at most one of the two, once. The broker authorizes that use against
its own policy and the owner's binding, then renders the Authorization header itself.
Neither flag reaches the request this command proposes, and no secret ever reaches this
command.

The broker owns DNS, TLS, timeouts, and response limits. Redirects are returned as
data rather than followed, every status is data, and nothing is retried.
";

const NO_STDIN: &str = "curl: -H @-: nothing was piped in\n";
const STDIN_ALREADY_READ: &str = "curl: -H @-: the piped value is read once\n";
const CREDENTIAL_ONCE: &str = "curl: at most one of --oauth2-bearer and -u, at most once\n";
const BEARER_NOT_A_DRN: &str =
    "curl: --oauth2-bearer: value must be a bare DRN, drn:<authority>:secret:<realm>:<path>\n";
const USER_MALFORMED: &str =
    "curl: -u: value must be spelled <username>:<drn> with a bounded, control-free username\n";
const USER_NOT_A_DRN: &str = "curl: -u: value after the username must be a bare DRN, drn:<authority>:secret:<realm>:<path>\n";

/// Runs arguments after the command word as the upstream tool would.
///
/// Dekopon selects `curl` before entering the component, so `argv` deliberately excludes the word
/// itself. This performs no host call: a proposal is authorized later on exactly the path a direct
/// `cap curl.get {…}` call takes, and rendered text grants nothing.
pub(crate) fn run(argv: &[String], stdin: Option<&str>) -> CommandRun {
    match parse(argv, stdin) {
        Ok(run) => run,
        Err(message) => CommandRun::rendered_error(message, 2),
    }
}

fn parse(argv: &[String], stdin: Option<&str>) -> Result<CommandRun, &'static str> {
    if argv.len() > MAX_ARGV_ENTRIES
        || argv
            .iter()
            .map(String::len)
            .chain(stdin.map(str::len))
            .try_fold(0_usize, |total, length| total.checked_add(length))
            .is_none_or(|total| total > MAX_INPUT_BYTES)
    {
        return Err(USAGE);
    }

    let mut index = 0;
    let mut method_seen = false;
    let mut stdin_read = false;
    let mut headers = Vec::new();
    let mut uri = None;
    let mut secret_use = None;

    while index < argv.len() {
        let argument = argv[index].as_str();
        match argument {
            "-h" | "--help" => return Ok(CommandRun::rendered(HELP, 0)),
            "-s" | "-S" | "--silent" | "--show-error" => {
                // Structured execution has no progress meter. These compatibility flags are
                // intentionally documented no-ops.
                index += 1;
            }
            "-X" | "--request" => {
                if method_seen {
                    return Err(USAGE);
                }
                let value = take_separate(argv, &mut index)?;
                if !value.eq_ignore_ascii_case("GET") {
                    return Err(USAGE);
                }
                method_seen = true;
            }
            "-H" | "--header" => {
                let value = take_separate(argv, &mut index)?;
                if value == STDIN_HEADERS {
                    if stdin_read {
                        return Err(STDIN_ALREADY_READ);
                    }
                    stdin_read = true;
                    let piped = stdin.ok_or(NO_STDIN)?;
                    for line in piped.lines().filter(|line| !line.trim().is_empty()) {
                        push_header(&mut headers, line)?;
                    }
                } else {
                    push_header(&mut headers, value)?;
                }
            }
            "--oauth2-bearer" => {
                if secret_use.is_some() {
                    return Err(CREDENTIAL_ONCE);
                }
                let value = take_separate(argv, &mut index)?;
                let secret = drn(value).ok_or(BEARER_NOT_A_DRN)?;
                secret_use = Some(SecretUseProposal::HttpBearer { secret });
            }
            "-u" | "--user" => {
                if secret_use.is_some() {
                    return Err(CREDENTIAL_ONCE);
                }
                let value = take_separate(argv, &mut index)?;
                // The username may not itself contain a colon, so the first one is the separator
                // even though the DRN that follows is full of them.
                let (username, reference) = value.split_once(':').ok_or(USER_MALFORMED)?;
                let secret = drn(reference).ok_or(USER_NOT_A_DRN)?;
                secret_use = Some(basic(secret, username).ok_or(USER_MALFORMED)?);
            }
            short
                if short.starts_with('-')
                    && !short.starts_with("--")
                    && short.len() > 2
                    && short[1..].bytes().all(|byte| matches!(byte, b's' | b'S')) =>
            {
                index += 1;
            }
            option if option.starts_with('-') => return Err(USAGE),
            positional => {
                if uri.replace(positional.to_owned()).is_some() {
                    return Err(USAGE);
                }
                index += 1;
            }
        }
    }

    let uri = uri.ok_or(USAGE)?;
    let mut input = Map::new();
    input.insert("uri".to_owned(), Value::String(uri));
    input.insert("method".to_owned(), Value::String("GET".to_owned()));
    input.insert("headers".to_owned(), Value::Array(headers));
    Ok(CommandRun::Proposal(CommandInvocation {
        capability: CAPABILITY
            .parse()
            .expect("static capability identifier is valid"),
        input: Value::Object(input),
        secret_use,
    }))
}

/// Parses one credential flag's bare public DRN.
///
/// A DRN names a secret; it is not one, and nothing here resolves it. The retired shell builtin's
/// `${drn:…}` marker is not canonical and is refused with everything else that is not.
fn drn(value: &str) -> Option<SecretDrn> {
    value.parse::<SecretDrn>().ok()
}

/// Builds the Basic proposal through [`SecretUseProposal`]'s own deserializer.
///
/// The username rule this command enforces is then the one the broker decodes with rather than a
/// copy of it that can drift away from it.
fn basic(secret: SecretDrn, username: &str) -> Option<SecretUseProposal> {
    serde_json::from_value(json!({
        "kind": "httpBasic",
        "secret": secret.as_str(),
        "username": username,
    }))
    .ok()
}

/// Splits one `Name: value` line at its first colon, preserving later colons and duplicates.
fn push_header(headers: &mut Vec<Value>, line: &str) -> Result<(), &'static str> {
    if headers.len() == MAX_REQUEST_HEADERS {
        return Err(USAGE);
    }
    let (name, value) = line.split_once(':').ok_or(USAGE)?;
    let name = name.trim();
    if name.is_empty() {
        return Err(USAGE);
    }
    let mut header = Map::new();
    header.insert("name".to_owned(), Value::String(name.to_owned()));
    header.insert("value".to_owned(), Value::String(value.trim().to_owned()));
    headers.push(Value::Object(header));
    Ok(())
}

/// Takes an option's next argv. Attached and `--flag=value` forms never reach this helper because
/// only the exact option spelling dispatches here.
fn take_separate<'a>(argv: &'a [String], index: &mut usize) -> Result<&'a str, &'static str> {
    let value = argv.get(*index + 1).ok_or(USAGE)?;
    *index += 2;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use dekopon_provider_sdk::{CommandRun, SecretUseProposal};
    use serde_json::json;

    use super::{
        BEARER_NOT_A_DRN, CREDENTIAL_ONCE, HELP, MAX_ARGV_ENTRIES, MAX_INPUT_BYTES, NO_STDIN,
        STDIN_ALREADY_READ, USAGE, USER_MALFORMED, USER_NOT_A_DRN, run,
    };
    use crate::ALLOWED_HEADERS;

    const DRN: &str = "drn:com.xrl:secret:test:curl/token";

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn resolved(values: &[&str]) -> serde_json::Value {
        piped(values, None)
    }

    fn piped(values: &[&str], stdin: Option<&str>) -> serde_json::Value {
        let (input, secret_use) = proposed(values, stdin);
        assert_eq!(secret_use, None, "{values:?} names no secret");
        input
    }

    /// The whole proposal an argv produces: the input object and the secret use beside it.
    fn proposed(
        values: &[&str],
        stdin: Option<&str>,
    ) -> (serde_json::Value, Option<SecretUseProposal>) {
        match run(&strings(values), stdin) {
            CommandRun::Proposal(invocation) => {
                assert_eq!(invocation.capability.as_str(), "curl.get");
                (invocation.input, invocation.secret_use)
            }
            other => panic!("expected a proposal, got {other:?}"),
        }
    }

    fn rendered_error(values: &[&str], stdin: Option<&str>, expected: &str) {
        match run(&strings(values), stdin) {
            CommandRun::Rendered {
                stdout,
                stderr,
                status,
            } => {
                assert_eq!(stdout, "");
                assert_eq!(stderr, expected);
                assert_eq!(status, 2);
            }
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    fn rejected(values: &[&str]) {
        rendered_error(values, None, USAGE);
    }

    #[test]
    fn argv_excludes_the_selected_command_word() {
        assert_eq!(
            resolved(&["https://example.com/a"]),
            json!({
                "uri": "https://example.com/a",
                "method": "GET",
                "headers": []
            })
        );
        rejected(&["curl", "https://example.com/a"]);
    }

    #[test]
    fn help_renders_on_stdout_at_zero_and_names_every_allowed_header_and_credential_flag() {
        for args in [vec!["--help"], vec!["-h"], vec!["-s", "--help", "ignored"]] {
            match run(&strings(&args), None) {
                CommandRun::Rendered {
                    stdout,
                    stderr,
                    status,
                } => {
                    assert_eq!(stdout, HELP);
                    assert_eq!(stderr, "");
                    assert_eq!(status, 0);
                }
                other => panic!("expected a help page for {args:?}, got {other:?}"),
            }
        }
        for allowed in ALLOWED_HEADERS {
            assert!(HELP.contains(allowed), "help omits {allowed}");
        }
        for flag in ["--oauth2-bearer", "-u, --user"] {
            assert!(HELP.contains(flag), "help omits {flag}");
        }
    }

    #[test]
    fn an_option_value_spelled_like_help_stays_a_value() {
        assert_eq!(
            resolved(&["-H", "Accept: --help", "https://example.com"])["headers"],
            json!([{"name": "Accept", "value": "--help"}])
        );
    }

    #[test]
    fn quiet_and_get_spellings_normalize_without_changing_the_proposal() {
        for args in [
            vec!["-s", "https://example.com"],
            vec!["-S", "https://example.com"],
            vec!["-sSSss", "https://example.com"],
            vec!["--silent", "--show-error", "https://example.com"],
            vec!["-X", "get", "https://example.com"],
            vec!["--request", "GeT", "https://example.com"],
        ] {
            assert_eq!(resolved(&args)["method"], "GET", "{args:?}");
        }
    }

    #[test]
    fn headers_split_once_trim_and_preserve_order_duplicates_and_later_colons() {
        assert_eq!(
            resolved(&[
                "-H",
                " Accept : text/plain:version=1 ",
                "--header",
                "Accept: application/json",
                "https://example.com",
            ])["headers"],
            json!([
                {"name": "Accept", "value": "text/plain:version=1"},
                {"name": "Accept", "value": "application/json"}
            ])
        );
    }

    #[test]
    fn piped_headers_parse_per_line_and_interleave_with_argv_headers() {
        assert_eq!(
            piped(
                &["-H", "Accept: first", "-H", "@-", "https://example.com"],
                Some("Accept-Language: en\n\n Range : bytes=0-9 \n"),
            )["headers"],
            json!([
                {"name": "Accept", "value": "first"},
                {"name": "Accept-Language", "value": "en"},
                {"name": "Range", "value": "bytes=0-9"}
            ])
        );
    }

    #[test]
    fn stdin_is_ignored_unless_the_argv_asked_for_it() {
        assert_eq!(
            piped(&["https://example.com"], Some("Accept: ignored\n"))["headers"],
            json!([])
        );
    }

    #[test]
    fn piped_headers_need_a_pipe_and_are_read_once() {
        rendered_error(&["-H", "@-", "https://example.com"], None, NO_STDIN);
        rendered_error(
            &["-H", "@-", "-H", "@-", "https://example.com"],
            Some("Accept: x\n"),
            STDIN_ALREADY_READ,
        );
        rendered_error(
            &["-H", "@-", "https://example.com"],
            Some("missing-colon\n"),
            USAGE,
        );
        rendered_error(
            &["-H", "@-", "https://example.com"],
            Some(" : value\n"),
            USAGE,
        );
    }

    #[test]
    fn a_file_argument_other_than_stdin_has_no_filesystem_to_read() {
        rejected(&["-H", "@headers.txt", "https://example.com"]);
    }

    #[test]
    fn rejects_missing_or_multiple_urls_and_malformed_headers() {
        for args in [
            vec![],
            vec!["-s"],
            vec!["https://one.example", "https://two.example"],
            vec!["-H", "missing-colon", "https://example.com"],
            vec!["-H", " : value", "https://example.com"],
            vec!["-H"],
        ] {
            rejected(&args);
        }
    }

    #[test]
    fn method_must_appear_at_most_once_and_be_get() {
        for args in [
            vec!["-X", "POST", "https://example.com"],
            vec!["-X", "HEAD", "https://example.com"],
            vec!["-X", "GET", "--request", "GET", "https://example.com"],
            vec!["-X"],
        ] {
            rejected(&args);
        }
    }

    #[test]
    fn every_unlisted_or_attached_option_is_refused_with_one_fixed_error() {
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
            "--oauth2-bearer=x",
            "--user=x",
            "-ux",
            "--",
            "-",
            "-XGET",
            "-HAccept:x",
            "--request=GET",
            "--header=Accept:x",
            "--silent=true",
            "-sX",
            "--hel",
            "-help",
        ] {
            rejected(&[option, "https://example.com"]);
        }
    }

    /// Each credential flag proposes its own secret use beside the input `invoke` reads.
    ///
    /// The DRN rides the proposal; the input is byte for byte the one the same argv without a
    /// credential flag produces, so nothing about the secret reaches the capability.
    #[test]
    fn each_credential_flag_proposes_its_secret_use_beside_an_unchanged_input() {
        let plain = resolved(&["https://example.com/a"]);

        let (input, secret_use) =
            proposed(&["--oauth2-bearer", DRN, "https://example.com/a"], None);
        assert_eq!(input, plain);
        assert_eq!(
            secret_use,
            Some(SecretUseProposal::HttpBearer {
                secret: DRN.parse().expect("canonical DRN fixture"),
            })
        );

        let user = format!("user-a:{DRN}");
        for spelling in ["-u", "--user"] {
            let (input, secret_use) =
                proposed(&[spelling, user.as_str(), "https://example.com/a"], None);
            assert_eq!(input, plain, "{spelling}");
            assert_eq!(
                secret_use,
                Some(SecretUseProposal::HttpBasic {
                    secret: DRN.parse().expect("canonical DRN fixture"),
                    username: "user-a".to_owned(),
                }),
                "{spelling}"
            );
        }
    }

    /// A proposal names at most one secret use, so both flags together, or either twice, is a
    /// fixed usage error rather than a silent last-wins.
    #[test]
    fn a_second_credential_flag_is_refused_rather_than_overwriting_the_first() {
        let user = format!("user-a:{DRN}");
        let user = user.as_str();
        for args in [
            vec!["--oauth2-bearer", DRN, "-u", user, "https://example.com"],
            vec!["-u", user, "--oauth2-bearer", DRN, "https://example.com"],
            vec![
                "--oauth2-bearer",
                DRN,
                "--oauth2-bearer",
                DRN,
                "https://example.com",
            ],
            vec!["-u", user, "--user", user, "https://example.com"],
        ] {
            rendered_error(&args, None, CREDENTIAL_ONCE);
        }
    }

    /// Only a canonical bare DRN is a secret reference.
    ///
    /// The retired shell builtin's `${drn:…}` marker is the spelling a model is most likely to
    /// carry over, and it is not a DRN. Every refusal is one fixed sentence: a value given to a
    /// credential flag is exactly where a real token would land if one were pasted by mistake, so
    /// nothing here echoes it back.
    #[test]
    fn only_a_canonical_bare_drn_is_accepted_and_no_refusal_echoes_the_value() {
        const SENTINEL: &str = "secret-sentinel-never-return";
        for value in [
            "${drn:com.xrl:secret:test:curl/token}",
            "drn:com.xrl:secret:Test:curl/token",
            "drn:com.xrl:secret:test:curl//token",
            "not-a-drn",
            "",
            SENTINEL,
        ] {
            rendered_error(
                &["--oauth2-bearer", value, "https://example.com"],
                None,
                BEARER_NOT_A_DRN,
            );
            let user = format!("user-a:{value}");
            rendered_error(
                &["-u", user.as_str(), "https://example.com"],
                None,
                USER_NOT_A_DRN,
            );
        }
        assert!(!BEARER_NOT_A_DRN.contains(SENTINEL));
        assert!(!USER_NOT_A_DRN.contains(SENTINEL));
        assert!(!USER_MALFORMED.contains(SENTINEL));
    }

    /// `-u` is `<username>:<drn>`, and the username rule is the broker's own.
    ///
    /// Empty, oversized, colon-bearing, and control-bearing names are refused here because
    /// [`SecretUseProposal`]'s deserializer refuses them, which is the same code the broker
    /// decodes the proposal with.
    #[test]
    fn a_basic_username_must_satisfy_the_rule_the_broker_decodes_with() {
        for value in [
            "user-a".to_owned(),
            format!(":{DRN}"),
            format!("user a\u{7f}:{DRN}"),
            format!("user\na:{DRN}"),
            format!("{}:{DRN}", "u".repeat(257)),
        ] {
            rendered_error(
                &["-u", value.as_str(), "https://example.com"],
                None,
                USER_MALFORMED,
            );
        }
        // A username may hold anything else the rule permits, spaces included.
        let user = format!("user a:{DRN}");
        let (_, secret_use) = proposed(&["-u", user.as_str(), "https://example.com"], None);
        assert_eq!(secret_use.expect("a proposal").username(), Some("user a"));
    }

    #[test]
    fn a_credential_flag_still_needs_its_value_and_a_url() {
        for args in [
            vec!["--oauth2-bearer"],
            vec!["-u"],
            vec!["--oauth2-bearer", DRN],
        ] {
            rejected(&args);
        }
    }

    #[test]
    fn argv_count_boundary_is_exact() {
        let mut at_limit = vec!["-s"; MAX_ARGV_ENTRIES - 1];
        at_limit.push("https://example.com");
        assert!(matches!(
            run(&strings(&at_limit), None),
            CommandRun::Proposal(_)
        ));

        let mut over = at_limit;
        over.insert(0, "-S");
        assert_eq!(over.len(), MAX_ARGV_ENTRIES + 1);
        rejected(&over);
    }

    #[test]
    fn the_byte_boundary_counts_argv_and_the_piped_value_together() {
        let at_limit = "u".repeat(MAX_INPUT_BYTES);
        assert!(matches!(run(&[at_limit], None), CommandRun::Proposal(_)));
        rendered_error(&["u".repeat(MAX_INPUT_BYTES + 1).as_str()], None, USAGE);

        let url = "u".repeat(MAX_INPUT_BYTES - 11);
        assert!(matches!(
            run(std::slice::from_ref(&url), Some("Accept: abc")),
            CommandRun::Proposal(_)
        ));
        rendered_error(&[url.as_str()], Some("Accept: abcd"), USAGE);
    }

    #[test]
    fn request_header_count_cannot_outgrow_the_invocation_contract() {
        let mut at_limit = Vec::new();
        for _ in 0..32 {
            at_limit.extend(["-H", "Accept: x"]);
        }
        at_limit.push("https://example.com");
        assert!(matches!(
            run(&strings(&at_limit), None),
            CommandRun::Proposal(_)
        ));

        let mut over = at_limit;
        over.splice(0..0, ["-H", "Accept: x"]);
        rejected(&over);

        let piped_over = "Accept: x\n".repeat(33);
        rendered_error(
            &["-H", "@-", "https://example.com"],
            Some(&piped_over),
            USAGE,
        );
    }
}
