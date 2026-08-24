//! Conservative, allocation-free URI policy checks.
//!
//! These checks deliberately do not try to reproduce the broker's WHATWG parser. They reject
//! ambiguous authorities locally, preserve the original URI bytes, and leave canonical authority,
//! DNS, destination, and pinning enforcement to the broker host.

use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) const MAX_URI_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Host {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Dns,
}

/// Checks the guest half of the `curl.get` URI policy.
pub(crate) fn validate(uri: &str) -> bool {
    if uri.is_empty()
        || uri.len() > MAX_URI_BYTES
        || uri.contains(['#', '\\'])
        || uri
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }

    let Some((scheme, remainder)) = uri.split_once("://") else {
        return false;
    };
    let is_https = scheme.eq_ignore_ascii_case("https");
    let is_http = scheme.eq_ignore_ascii_case("http");
    if (!is_https && !is_http) || remainder.is_empty() {
        return false;
    }

    let authority_end = remainder
        .bytes()
        .position(|byte| matches!(byte, b'/' | b'?'))
        .unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let suffix = &remainder[authority_end..];
    if authority.is_empty()
        || authority.contains(['@', '%'])
        || !authority.is_ascii()
        || !valid_percent_encoding(suffix)
    {
        return false;
    }

    let Some((host, port)) = parse_authority(authority) else {
        return false;
    };
    if is_https {
        return true;
    }

    // Plaintext is a test-only escape hatch: literal loopback, explicit nonzero port. The broker
    // still has to opt into plaintext loopback and grant this exact canonical authority.
    port.is_some()
        && match host {
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
            Host::Dns => false,
        }
}

fn parse_authority(authority: &str) -> Option<(Host, Option<u16>)> {
    if let Some(after_open) = authority.strip_prefix('[') {
        let close = after_open.find(']')?;
        let literal = &after_open[..close];
        let remainder = &after_open[close + 1..];
        let address = literal.parse::<Ipv6Addr>().ok()?;
        let port = if remainder.is_empty() {
            None
        } else {
            Some(parse_port(remainder.strip_prefix(':')?)?)
        };
        return Some((Host::Ipv6(address), port));
    }

    if authority.contains(['[', ']']) || authority.matches(':').count() > 1 {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(parse_port(port)?)),
        None => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Some((Host::Ipv4(address), port));
    }
    // Do not reinterpret non-canonical numeric IPv4 spellings as DNS. WHATWG accepts several
    // historical numeric forms; refusing them keeps the guest and authoritative host parsers from
    // disagreeing over whether an authority is loopback.
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !valid_dns_name(host)
    {
        return None;
    }
    Some((Host::Dns, port))
}

fn parse_port(value: &str) -> Option<u16> {
    if value.is_empty() || value.len() > 5 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = value.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

fn valid_dns_name(host: &str) -> bool {
    if host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn valid_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{MAX_URI_BYTES, validate};

    #[test]
    fn accepts_https_and_only_explicit_literal_loopback_http() {
        for uri in [
            "https://example.com",
            "HTTPS://EXAMPLE.COM:443/path?x=1%202",
            "https://127.0.0.1/private",
            "https://[::1]/private",
            "http://127.0.0.1:8080/path?x=1",
            "http://127.255.255.254:1/",
            "http://[::1]:65535/",
            "http://[0:0:0:0:0:0:0:1]:80/?x=%23",
        ] {
            assert!(validate(uri), "expected URI to pass: {uri}");
        }
    }

    #[test]
    fn rejects_plaintext_names_non_loopback_and_missing_ports() {
        for uri in [
            "http://localhost:8080/",
            "http://example.com:8080/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://0.0.0.0:8080/",
            "http://192.168.1.1:8080/",
            "http://[::ffff:127.0.0.1]:8080/",
            "http://2130706433:8080/",
            "http://127.1:8080/",
            "http://127.0.0.01:8080/",
        ] {
            assert!(!validate(uri), "expected URI to fail: {uri}");
        }
    }

    #[test]
    fn rejects_userinfo_fragments_zero_ports_and_ambiguous_authorities() {
        for uri in [
            "https://user@example.com/",
            "https://@example.com/",
            "https://user%40example.com/",
            "https://%75ser@example.com/",
            "https://example.com/#fragment",
            "https://example.com/#",
            "https://example.com:0/",
            "https://example.com:00000/",
            "https://example.com:/",
            "https://example.com:65536/",
            "https://[::1]:0/",
            "https://[::1]extra/",
            "https://::1/",
            "https://exa_mple.com/",
            "https://-example.com/",
            "https://example.com./",
            "https://%65xample.com/",
        ] {
            assert!(!validate(uri), "expected URI to fail: {uri}");
        }
    }

    #[test]
    fn rejects_non_absolute_other_scheme_controls_whitespace_and_bad_escapes() {
        for uri in [
            "",
            "/relative",
            "example.com/path",
            "ftp://example.com/",
            "file:///tmp/secret",
            "https:/example.com/",
            "https://",
            "https://example.com/a b",
            "https://example.com/a\tb",
            "https://example.com/a\nb",
            "https://example.com/a\\b",
            "https://example.com/%",
            "https://example.com/%0",
            "https://example.com/%gg",
        ] {
            assert!(!validate(uri), "expected URI to fail: {uri:?}");
        }
    }

    #[test]
    fn uri_byte_boundary_is_exact() {
        let prefix = "https://example.com/";
        let at_limit = format!("{prefix}{}", "a".repeat(MAX_URI_BYTES - prefix.len()));
        assert_eq!(at_limit.len(), MAX_URI_BYTES);
        assert!(validate(&at_limit));

        let over = format!("{at_limit}a");
        assert_eq!(over.len(), MAX_URI_BYTES + 1);
        assert!(!validate(&over));
    }
}
