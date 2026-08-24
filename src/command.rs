//! Pure parser for the provider-owned `curlget` command word.

use dekopon_provider_sdk::{CommandInvocation, ProviderError};
use serde_json::{Map, Value};

use crate::{MAX_REQUEST_HEADERS, error};

pub(crate) const MAX_ARGV_ENTRIES: usize = 70;
pub(crate) const MAX_ARGV_BYTES: usize = 24_576;
pub(crate) const USAGE: &str = "usage: curlget [-sS] [-X GET] [-H \"Name: value\"]... URL";

/// Resolves arguments after the command word into one `curl.get` proposal.
///
/// Dekopon selects `curlget` before entering the component, so `argv` deliberately excludes the
/// word itself. This function performs no host call; policy and HTTP validation happen later.
pub(crate) fn resolve(argv: &[String]) -> Result<CommandInvocation, ProviderError> {
    if argv.len() > MAX_ARGV_ENTRIES
        || argv
            .iter()
            .try_fold(0_usize, |total, argument| total.checked_add(argument.len()))
            .is_none_or(|total| total > MAX_ARGV_BYTES)
    {
        return Err(usage());
    }

    let mut index = 0;
    let mut method_seen = false;
    let mut headers = Vec::new();
    let mut uri = None;

    while index < argv.len() {
        let argument = argv[index].as_str();
        match argument {
            "-s" | "-S" | "--silent" | "--show-error" => {
                // Structured execution has no progress meter. These compatibility flags are
                // intentionally documented no-ops.
                index += 1;
            }
            "-X" | "--request" => {
                if method_seen {
                    return Err(usage());
                }
                let value = take_separate(argv, &mut index)?;
                if !value.eq_ignore_ascii_case("GET") {
                    return Err(usage());
                }
                method_seen = true;
            }
            "-H" | "--header" => {
                if headers.len() == MAX_REQUEST_HEADERS {
                    return Err(usage());
                }
                let value = take_separate(argv, &mut index)?;
                let (name, value) = value.split_once(':').ok_or_else(usage)?;
                let name = name.trim();
                if name.is_empty() {
                    return Err(usage());
                }
                let mut header = Map::new();
                header.insert("name".to_owned(), Value::String(name.to_owned()));
                header.insert("value".to_owned(), Value::String(value.trim().to_owned()));
                headers.push(Value::Object(header));
            }
            short
                if short.starts_with('-')
                    && !short.starts_with("--")
                    && short.len() > 2
                    && short[1..].bytes().all(|byte| matches!(byte, b's' | b'S')) =>
            {
                index += 1;
            }
            option if option.starts_with('-') => return Err(usage()),
            positional => {
                if uri.replace(positional.to_owned()).is_some() {
                    return Err(usage());
                }
                index += 1;
            }
        }
    }

    let uri = uri.ok_or_else(usage)?;
    let mut input = Map::new();
    input.insert("uri".to_owned(), Value::String(uri));
    input.insert("method".to_owned(), Value::String("GET".to_owned()));
    input.insert("headers".to_owned(), Value::Array(headers));
    Ok(CommandInvocation {
        capability: "curl.get"
            .parse()
            .expect("static capability identifier is valid"),
        input: Value::Object(input),
    })
}

/// Takes an option's next argv. Attached and `--flag=value` forms never reach this helper because
/// only the exact option spelling dispatches here.
fn take_separate<'a>(argv: &'a [String], index: &mut usize) -> Result<&'a str, ProviderError> {
    let value = argv.get(*index + 1).ok_or_else(usage)?;
    *index += 2;
    Ok(value)
}

fn usage() -> ProviderError {
    error("usage", USAGE)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{MAX_ARGV_BYTES, MAX_ARGV_ENTRIES, USAGE, resolve};

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn resolved(values: &[&str]) -> serde_json::Value {
        resolve(&strings(values)).expect("command resolves").input
    }

    fn rejected(values: &[&str]) {
        let error = resolve(&strings(values)).expect_err("command is refused");
        assert_eq!(error.code(), "usage");
        assert_eq!(error.message(), USAGE);
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
        rejected(&["curlget", "https://example.com/a"]);
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
            "--user",
            "--cookie",
            "--proxy",
            "--output",
            "--upload-file",
            "--config",
            "--compressed",
            "--insecure",
            "--",
            "-",
            "-XGET",
            "-HAccept:x",
            "--request=GET",
            "--header=Accept:x",
            "--silent=true",
            "-sX",
        ] {
            rejected(&[option, "https://example.com"]);
        }
    }

    #[test]
    fn argv_count_boundary_is_exact() {
        let mut at_limit = vec!["-s"; MAX_ARGV_ENTRIES - 1];
        at_limit.push("https://example.com");
        assert!(resolve(&strings(&at_limit)).is_ok());

        let mut over = at_limit;
        over.insert(0, "-S");
        assert_eq!(over.len(), MAX_ARGV_ENTRIES + 1);
        rejected(&over);
    }

    #[test]
    fn argv_byte_boundary_is_exact() {
        let at_limit = "u".repeat(MAX_ARGV_BYTES);
        assert!(resolve(&[at_limit]).is_ok());
        let over = "u".repeat(MAX_ARGV_BYTES + 1);
        let error = resolve(&[over]).expect_err("aggregate limit + 1 is refused");
        assert_eq!(error.code(), "usage");
        assert_eq!(error.message(), USAGE);
    }

    #[test]
    fn request_header_count_cannot_outgrow_the_invocation_contract() {
        let mut at_limit = Vec::new();
        for _ in 0..32 {
            at_limit.extend(["-H", "Accept: x"]);
        }
        at_limit.push("https://example.com");
        assert!(resolve(&strings(&at_limit)).is_ok());

        let mut over = at_limit;
        over.splice(0..0, ["-H", "Accept: x"]);
        rejected(&over);
    }
}
