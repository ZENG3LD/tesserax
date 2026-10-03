//! [`Endpoint`]: where a peer is reached.

use std::fmt;
use std::path::PathBuf;

use crate::error::TransportError;

/// Where a peer is reached.
///
/// The locality rule: a peer on the same host is reached over an owner-only
/// local socket or pipe ([`Endpoint::Local`], see [`local`](crate::local)),
/// a peer elsewhere over HTTP(S) or WebSocket. Nothing here dials; the value
/// only says which transport a client should use.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Endpoint {
    /// Absolute socket path (Unix) or pipe name `\\.\pipe\…` (Windows).
    Local(PathBuf),
    /// `http://` or `https://` base URL.
    Http(String),
    /// `ws://` or `wss://` URL.
    Ws(String),
}

impl Endpoint {
    /// Parses `unix:<path>`, an absolute path, a `\\.\pipe\` name, or an
    /// `http(s)://` / `ws(s)://` URL with a non-empty authority.
    pub fn parse(s: &str) -> Result<Self, TransportError> {
        let bad = |reason| TransportError::Endpoint {
            input: s.to_owned(),
            reason,
        };
        if s.is_empty() {
            return Err(bad("empty"));
        }
        if s.chars().any(char::is_control) {
            return Err(bad("contains a control character"));
        }
        let url_rest = |scheme_len: usize| {
            let rest = &s[scheme_len..];
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            !authority.is_empty()
        };
        for (scheme, ws) in [
            ("https://", false),
            ("http://", false),
            ("wss://", true),
            ("ws://", true),
        ] {
            if s.len() >= scheme.len() && s[..scheme.len()].eq_ignore_ascii_case(scheme) {
                if !url_rest(scheme.len()) {
                    return Err(bad("URL has no host"));
                }
                return Ok(if ws {
                    Endpoint::Ws(s.to_owned())
                } else {
                    Endpoint::Http(s.to_owned())
                });
            }
        }
        let path = s.strip_prefix("unix:").unwrap_or(s);
        if path.starts_with(r"\\.\pipe\") && path.len() > r"\\.\pipe\".len() {
            return Ok(Endpoint::Local(PathBuf::from(path)));
        }
        if path.starts_with('/') && path.len() > 1 {
            return Ok(Endpoint::Local(PathBuf::from(path)));
        }
        Err(bad(
            "expected an absolute socket path, a pipe name or an http(s) / ws(s) URL",
        ))
    }

    /// True for [`Endpoint::Local`].
    pub fn is_local(&self) -> bool {
        matches!(self, Endpoint::Local(_))
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Local(p) => write!(f, "unix:{}", p.display()),
            Endpoint::Http(u) | Endpoint::Ws(u) => f.write_str(u),
        }
    }
}

impl std::str::FromStr for Endpoint {
    type Err = TransportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_kind() {
        assert_eq!(
            Endpoint::parse("/run/app/n.sock").unwrap(),
            Endpoint::Local("/run/app/n.sock".into())
        );
        assert_eq!(
            Endpoint::parse("unix:/run/app/n.sock").unwrap(),
            Endpoint::Local("/run/app/n.sock".into())
        );
        assert_eq!(
            Endpoint::parse(r"\\.\pipe\app-node").unwrap(),
            Endpoint::Local(r"\\.\pipe\app-node".into())
        );
        assert!(matches!(
            Endpoint::parse("https://198.51.100.7:8443/api").unwrap(),
            Endpoint::Http(_)
        ));
        assert!(matches!(
            Endpoint::parse("WSS://example.org/feed").unwrap(),
            Endpoint::Ws(_)
        ));
        assert!(Endpoint::parse("/x").unwrap().is_local());
    }

    #[test]
    fn refuses_relative_empty_and_hostless() {
        for s in [
            "",
            "n.sock",
            "unix:n.sock",
            "http://",
            "ws:///x",
            "/",
            "ftp://h/x",
            "/a\nb",
        ] {
            assert!(Endpoint::parse(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn display_round_trips() {
        for s in ["unix:/run/a.sock", "http://127.0.0.1:1/x", "ws://h/y"] {
            let e: Endpoint = s.parse().unwrap();
            assert_eq!(e.to_string(), s);
            assert_eq!(e.to_string().parse::<Endpoint>().unwrap(), e);
        }
    }
}
