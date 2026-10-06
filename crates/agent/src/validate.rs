//! Validation helpers for the route table.
//!
//! - App names match `[a-z0-9][a-z0-9-]{0,31}`.
//! - Reserved names are rejected at route registration to avoid
//!   collisions with tooling and phishing.
//! - Upstreams must be loopback-only. The host is resolved once at
//!   registration; the forwarder re-checks on every dial (belt + braces
//!   against a poisoned `/etc/hosts`).

use std::net::{IpAddr, ToSocketAddrs};

use thiserror::Error;
use url::Url;

/// Reserved app names. Kept here as the single source of truth; the
/// agent rejects any route whose `name` matches (case-insensitively,
/// though names are lowercase-only anyway) at registration and logs
/// the rejection.
pub const RESERVED_APP_NAMES: &[&str] = &[
    "www", "api", "admin", "auth", "login", "account", "accounts", "mail", "ftp", "ssh", "p2claw",
    "peer", "sys", "internal", "static", "status", "health", "default",
];

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ValidateError {
    #[error("app name must be 1–32 chars of [a-z0-9-], start with alphanumeric, no trailing `-`")]
    AppName,
    #[error("app name `{0}` is reserved")]
    ReservedAppName(String),
    #[error("upstream URL must be parseable as an absolute URL: {0}")]
    UpstreamParse(String),
    #[error("upstream scheme must be http (only http upstreams are proxied)")]
    UpstreamScheme,
    #[error("upstream must include a host")]
    UpstreamNoHost,
    #[error("upstream path must be `/` or empty (got `{0}`)")]
    UpstreamPath(String),
    #[error("upstream port is required")]
    UpstreamNoPort,
    #[error(
        "upstream host `{0}` resolves to non-loopback address {1}; only 127.0.0.1 / ::1 allowed"
    )]
    UpstreamNonLoopback(String, IpAddr),
    #[error("upstream host `{0}` did not resolve to any address")]
    UpstreamResolveEmpty(String),
    #[error("upstream host `{0}` resolution failed: {1}")]
    UpstreamResolve(String, String),
    #[error("unix upstream path must be absolute (got `{0}`)")]
    UpstreamUnixNotAbsolute(String),
    #[error("unix upstreams are only allowed on private routes")]
    UpstreamUnixNotAllowed,
    #[error("private routes cannot carry auth methods (shares are the only gate)")]
    PrivateWithAuth,
}

/// Validate an app `name` against the grammar and the reserved list.
pub fn validate_app_name(name: &str) -> Result<(), ValidateError> {
    if name.is_empty() || name.len() > 32 {
        return Err(ValidateError::AppName);
    }
    let bytes = name.as_bytes();
    // First char: [a-z0-9].
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(ValidateError::AppName);
    }
    // No trailing hyphen.
    if bytes[bytes.len() - 1] == b'-' {
        return Err(ValidateError::AppName);
    }
    // Interior chars: [a-z0-9-]. No uppercase, no underscore, no dot.
    for &b in &bytes[1..] {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(ValidateError::AppName);
        }
    }
    if RESERVED_APP_NAMES.contains(&name) {
        return Err(ValidateError::ReservedAppName(name.to_string()));
    }
    Ok(())
}

/// Parse and validate an upstream URL string. On success returns the
/// parsed `Url` along with the resolved `(host, port)` — resolution
/// has happened and all resolved addresses are loopback.
///
/// The returned `Url` is not normalized further; callers should use it
/// verbatim to build hyper requests so the upstream sees exactly the
/// host/port the caller registered.
pub fn validate_upstream(upstream: &str) -> Result<Url, ValidateError> {
    let url = Url::parse(upstream).map_err(|e| ValidateError::UpstreamParse(e.to_string()))?;
    if url.scheme() == "unix" {
        // Public routes keep the loopback-TCP-only rule; only
        // private routes may hand off over a Unix socket.
        return Err(ValidateError::UpstreamUnixNotAllowed);
    }
    if url.scheme() != "http" {
        return Err(ValidateError::UpstreamScheme);
    }
    let host_str = url
        .host_str()
        .ok_or(ValidateError::UpstreamNoHost)?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or(ValidateError::UpstreamNoPort)?;
    // Must have an explicit port or one from the scheme (http → 80).
    // Port number in [1, 65535] is guaranteed by url parser.
    let path = url.path();
    if !matches!(path, "" | "/") {
        return Err(ValidateError::UpstreamPath(path.to_string()));
    }
    check_loopback_resolution(&host_str, port)?;
    Ok(url)
}

/// Validate an upstream for a private route: either a `unix:` URL
/// with an absolute socket path, or the same loopback-HTTP shape
/// public routes require.
pub fn validate_private_upstream(upstream: &str) -> Result<Url, ValidateError> {
    let url = Url::parse(upstream).map_err(|e| ValidateError::UpstreamParse(e.to_string()))?;
    if url.scheme() == "unix" {
        // `unix:/run/x.sock` parses as a cannot-be-a-base URL whose
        // path is the socket path. Reject the `unix://host/...` form
        // (a host is meaningless for a local socket) and relative
        // paths.
        if url.host_str().is_some() {
            return Err(ValidateError::UpstreamUnixNotAbsolute(upstream.to_string()));
        }
        let path = url.path();
        if !path.starts_with('/') || path.len() < 2 {
            return Err(ValidateError::UpstreamUnixNotAbsolute(path.to_string()));
        }
        return Ok(url);
    }
    validate_upstream(upstream)
}

/// Socket path of a validated `unix:` upstream URL, `None` for TCP
/// upstreams.
pub fn unix_upstream_path(url: &Url) -> Option<&str> {
    (url.scheme() == "unix").then(|| url.path())
}

/// Re-verify at forward time that `host` resolves only to loopback.
/// Returns the resolved loopback `SocketAddr`s on success so the
/// caller can hand them straight to `TcpStream::connect`, skipping a
/// second DNS round-trip inside hyper.
pub fn resolve_loopback(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, ValidateError> {
    // `url::Url::host_str` returns IPv6 literals wrapped in `[...]`
    // (e.g. `"[::1]"`). `ToSocketAddrs::to_socket_addrs` doesn't
    // accept that form and will punt it to DNS, which then fails.
    // Strip the brackets before handing it off.
    let lookup_host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let addrs: Vec<std::net::SocketAddr> = (lookup_host, port)
        .to_socket_addrs()
        .map_err(|e| ValidateError::UpstreamResolve(host.to_string(), e.to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(ValidateError::UpstreamResolveEmpty(host.to_string()));
    }
    for a in &addrs {
        if !a.ip().is_loopback() {
            return Err(ValidateError::UpstreamNonLoopback(host.to_string(), a.ip()));
        }
    }
    Ok(addrs)
}

fn check_loopback_resolution(host: &str, port: u16) -> Result<(), ValidateError> {
    resolve_loopback(host, port).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_name_accepts_valid_examples() {
        for name in ["recipes", "my-app", "a", "a1", "app-42-v2", "r1"] {
            validate_app_name(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn app_name_rejects_uppercase() {
        assert!(matches!(
            validate_app_name("Recipes"),
            Err(ValidateError::AppName)
        ));
    }

    #[test]
    fn app_name_rejects_leading_hyphen() {
        assert!(matches!(
            validate_app_name("-recipes"),
            Err(ValidateError::AppName)
        ));
    }

    #[test]
    fn app_name_rejects_trailing_hyphen() {
        assert!(matches!(
            validate_app_name("recipes-"),
            Err(ValidateError::AppName)
        ));
    }

    #[test]
    fn app_name_rejects_underscore_and_dot() {
        assert!(validate_app_name("my_app").is_err());
        assert!(validate_app_name("my.app").is_err());
    }

    #[test]
    fn app_name_rejects_too_long() {
        let long = "a".repeat(33);
        assert!(matches!(
            validate_app_name(&long),
            Err(ValidateError::AppName)
        ));
    }

    #[test]
    fn app_name_rejects_reserved_names() {
        for n in RESERVED_APP_NAMES {
            let got = validate_app_name(n);
            assert!(
                matches!(got, Err(ValidateError::ReservedAppName(_))),
                "{n} should be reserved: got {got:?}"
            );
        }
    }

    #[test]
    fn upstream_accepts_127_0_0_1_with_port() {
        validate_upstream("http://127.0.0.1:5173").unwrap();
        validate_upstream("http://127.0.0.1:5173/").unwrap();
    }

    #[test]
    fn upstream_accepts_localhost_with_port() {
        // `localhost` must resolve to loopback (which it always does
        // on the CI boxes we target — Linux/macOS).
        validate_upstream("http://localhost:5173").unwrap();
    }

    #[test]
    fn upstream_accepts_ipv6_loopback() {
        validate_upstream("http://[::1]:5173").unwrap();
    }

    #[test]
    fn upstream_rejects_https_scheme() {
        assert!(matches!(
            validate_upstream("https://127.0.0.1:5173"),
            Err(ValidateError::UpstreamScheme)
        ));
    }

    #[test]
    fn upstream_rejects_non_loopback_ip() {
        let e = validate_upstream("http://8.8.8.8:80").unwrap_err();
        assert!(
            matches!(e, ValidateError::UpstreamNonLoopback(_, _)),
            "{e:?}"
        );
    }

    #[test]
    fn upstream_rejects_private_lan_ip() {
        let e = validate_upstream("http://192.168.1.1:80").unwrap_err();
        assert!(
            matches!(e, ValidateError::UpstreamNonLoopback(_, _)),
            "{e:?}"
        );
    }

    #[test]
    fn upstream_rejects_non_root_path() {
        let e = validate_upstream("http://127.0.0.1:5173/recipes").unwrap_err();
        assert!(matches!(e, ValidateError::UpstreamPath(_)), "{e:?}");
    }

    #[test]
    fn upstream_rejects_malformed_url() {
        let e = validate_upstream("not a url").unwrap_err();
        assert!(matches!(e, ValidateError::UpstreamParse(_)), "{e:?}");
    }

    #[test]
    fn public_upstream_rejects_unix_scheme() {
        let e = validate_upstream("unix:/run/user/1000/mysvc.sock").unwrap_err();
        assert!(matches!(e, ValidateError::UpstreamUnixNotAllowed), "{e:?}");
    }

    #[test]
    fn private_upstream_accepts_absolute_unix_path() {
        let url = validate_private_upstream("unix:/run/user/1000/mysvc.sock").unwrap();
        assert_eq!(url.scheme(), "unix");
        assert_eq!(unix_upstream_path(&url), Some("/run/user/1000/mysvc.sock"));
    }

    #[test]
    fn private_upstream_rejects_relative_unix_path() {
        let e = validate_private_upstream("unix:mysvc.sock").unwrap_err();
        assert!(
            matches!(e, ValidateError::UpstreamUnixNotAbsolute(_)),
            "{e:?}"
        );
    }

    #[test]
    fn private_upstream_rejects_unix_url_with_host() {
        let e = validate_private_upstream("unix://etc/passwd").unwrap_err();
        assert!(
            matches!(e, ValidateError::UpstreamUnixNotAbsolute(_)),
            "{e:?}"
        );
    }

    #[test]
    fn private_upstream_still_accepts_loopback_http() {
        validate_private_upstream("http://127.0.0.1:5173").unwrap();
    }

    #[test]
    fn private_upstream_rejects_non_loopback_http() {
        let e = validate_private_upstream("http://8.8.8.8:80").unwrap_err();
        assert!(
            matches!(e, ValidateError::UpstreamNonLoopback(_, _)),
            "{e:?}"
        );
    }

    #[test]
    fn unix_upstream_path_is_none_for_tcp() {
        let url = validate_upstream("http://127.0.0.1:5173").unwrap();
        assert_eq!(unix_upstream_path(&url), None);
    }
}
