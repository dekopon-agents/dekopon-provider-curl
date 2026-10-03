//! Pure argv parsing. Clap renders help/unknown argv; the old strict grammar keeps exact flags.
use crate::{Curl, Get, GetInput, GetMethod, InputHeader, MAX_REQUEST_HEADERS};
use clap::{ArgMatches, Command, CommandFactory, Error, FromArgMatches, Parser, error::ErrorKind};
use dekopon_provider_sdk::provider::{Proposal, Usage};
use dekopon_provider_sdk::{SecretDrn, SecretUseProposal};
use serde_json::json;

pub(crate) const MAX_ARGV_ENTRIES: usize = 70;
pub(crate) const MAX_INPUT_BYTES: usize = 24_576;
const USAGE: &str = "usage: curl [-sS] [-X GET] [-H \"Name: value\"|-H @-]... [--oauth2-bearer DRN|-u USER:DRN] URL";

#[derive(Parser)]
#[command(
    name = "curl",
    about = "One bounded, broker-authorized, bodyless HTTP GET",
    after_help = "Headers are restricted to accept, accept-language, cache-control, if-modified-since, if-none-match, range.\n\
    --oauth2-bearer DRN and -u, --user USER:DRN propose public DRNs, not tokens.\n\
    The broker alone resolves and injects credentials.\n\
    Redirects and HTTP error statuses are returned as data; no request is retried."
)]
struct Raw {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1.., required = true)]
    words: Vec<String>,
}

pub struct CurlArgs {
    words: Vec<String>,
}
impl CommandFactory for CurlArgs {
    fn command() -> Command {
        Raw::command()
    }
    fn command_for_update() -> Command {
        Raw::command_for_update()
    }
}
impl FromArgMatches for CurlArgs {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
        let raw = Raw::from_arg_matches(matches)?;
        // An unknown option must be a clap-rendered usage error, not a Failed proposal. This
        // preserves the SDK's real-component help/usage conformance without accepting options.
        let mut index = 0;
        while let Some(word) = raw.words.get(index) {
            if matches!(
                word.as_str(),
                "-X" | "--request" | "-H" | "--header" | "--oauth2-bearer" | "-u" | "--user"
            ) {
                index += 2; // The following token is data, even if it resembles an option.
                continue;
            }
            if word.starts_with("--") && !matches!(word.as_str(), "--silent" | "--show-error") {
                return Err(Error::raw(
                    ErrorKind::UnknownArgument,
                    "unsupported curl option",
                ));
            }
            index += 1;
        }
        Ok(Self { words: raw.words })
    }
    fn from_arg_matches_mut(matches: &mut ArgMatches) -> Result<Self, Error> {
        Self::from_arg_matches(matches)
    }
    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
    fn update_from_arg_matches_mut(&mut self, matches: &mut ArgMatches) -> Result<(), Error> {
        self.update_from_arg_matches(matches)
    }
}
impl Parser for CurlArgs {}

pub(crate) fn propose(args: CurlArgs, stdin_piped: bool) -> Result<Proposal<Curl>, Usage> {
    let argv = args.words;
    if argv.len() > MAX_ARGV_ENTRIES
        || argv.iter().map(String::len).sum::<usize>() > MAX_INPUT_BYTES
    {
        return Err(Usage::new(USAGE));
    }
    let mut index = 0;
    let mut method_seen = false;
    let mut stdin_headers = false;
    let mut stdin_header_index = None;
    let mut headers = Vec::new();
    let mut uri = None;
    let mut secret_use = None;
    while index < argv.len() {
        match argv[index].as_str() {
            "-s" | "-S" | "--silent" | "--show-error" => index += 1,
            "-X" | "--request" => {
                if method_seen {
                    return Err(Usage::new(USAGE));
                }
                let value = take(&argv, &mut index)?;
                if !value.eq_ignore_ascii_case("GET") {
                    return Err(Usage::new(USAGE));
                }
                method_seen = true;
            }
            "-H" | "--header" => {
                let value = take(&argv, &mut index)?;
                if value == "@-" {
                    if stdin_headers {
                        return Err(Usage::new("curl: -H @-: the piped value is read once"));
                    }
                    if !stdin_piped {
                        return Err(Usage::new("curl: -H @-: nothing was piped in"));
                    }
                    stdin_headers = true;
                    stdin_header_index = Some(headers.len());
                } else {
                    headers.push(parse_header(value).map_err(|_| Usage::new(USAGE))?);
                }
                if headers.len() > MAX_REQUEST_HEADERS {
                    return Err(Usage::new(USAGE));
                }
            }
            "--oauth2-bearer" => {
                if secret_use.is_some() {
                    return Err(Usage::new("curl: at most one credential flag"));
                }
                let value = take(&argv, &mut index)?;
                let secret: SecretDrn = value
                    .parse()
                    .map_err(|_| Usage::new("curl: --oauth2-bearer: value must be a bare DRN"))?;
                secret_use = Some(SecretUseProposal::HttpBearer { secret });
            }
            "-u" | "--user" => {
                if secret_use.is_some() {
                    return Err(Usage::new("curl: at most one credential flag"));
                }
                let value = take(&argv, &mut index)?;
                let (username, reference) = value
                    .split_once(':')
                    .ok_or_else(|| Usage::new("curl: -u: malformed username or DRN"))?;
                let secret: SecretDrn = reference
                    .parse()
                    .map_err(|_| Usage::new("curl: -u: value must name a bare DRN"))?;
                secret_use = Some(
                    serde_json::from_value(
                        json!({"kind":"httpBasic", "secret":secret.as_str(), "username":username}),
                    )
                    .map_err(|_| Usage::new("curl: -u: malformed username or DRN"))?,
                );
            }
            flag if flag.starts_with('-')
                && !flag.starts_with("--")
                && flag.len() > 2
                && flag[1..].bytes().all(|b| matches!(b, b's' | b'S')) =>
            {
                index += 1
            }
            flag if flag.starts_with('-') => return Err(Usage::new(USAGE)),
            value => {
                if uri.replace(value.to_owned()).is_some() {
                    return Err(Usage::new(USAGE));
                }
                index += 1;
            }
        }
    }
    let input = GetInput {
        uri: uri.ok_or_else(|| Usage::new(USAGE))?,
        method: GetMethod::Get,
        headers,
        stdin_headers,
        stdin_header_index,
    };
    let proposal = Proposal::to::<Get>(input);
    Ok(match secret_use {
        Some(secret) => proposal.with_secret_use(secret),
        None => proposal,
    })
}
pub(crate) fn parse_header(line: &str) -> Result<InputHeader, ()> {
    let (name, value) = line.split_once(':').ok_or(())?;
    let name = name.trim();
    if name.is_empty() {
        return Err(());
    }
    Ok(InputHeader {
        name: name.to_owned(),
        value: value.trim().to_owned(),
    })
}
fn take<'a>(argv: &'a [String], index: &mut usize) -> Result<&'a str, Usage> {
    let value = argv.get(*index + 1).ok_or_else(|| Usage::new(USAGE))?;
    *index += 2;
    Ok(value)
}
