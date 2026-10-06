//! p2claw URL parsing.
//!
//! Given a URL and the operator's parent domain, produces a
//! [`P2clawUrl`] with the optional app, alias label, path, and
//! query.
//!
//! Two peer-label shapes are accepted (via [`parse_peer_label`]):
//!
//! - **Haiku** — `[app-]adj-noun-num4+`, where `adj` and `noun` are
//!   non-empty lowercase-alpha runs and `num` is at least four
//!   digits. Coord auto-assigns this form at registration.
//! - **Vanity** — `[app-]vanity`, where `vanity` is a single
//!   hyphen-free label (1–63 chars, lowercase ASCII letters +
//!   digits, at least one letter).
//!
//! Parse algorithm (mirrored on the edge and in `bootstrap/src/url.ts`):
//!
//! 1. Try the haiku peel right-to-left. The 4+-digit numeric tail
//!    anchors the `app-alias` split unambiguously.
//! 2. On haiku failure, split on the last hyphen: the tail must be a
//!    valid vanity, and the head (if any) is the optional app label.
//!
//! Grammar lives in [`p2claw_identity::is_valid_vanity_label`] /
//! [`p2claw_identity::RESERVED_TOKENS`]; every parser consults the
//! same definitions.

use thiserror::Error;
use url::Url;

/// A parsed p2claw URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2clawUrl {
    /// Optional app label. `None` is the apex form
    /// (`adj-noun-NNNN.parent`), which addresses the box's listing
    /// page — not a "default app".
    pub app: Option<String>,
    /// Alias label — haiku `adj-noun-NNNN` or operator-granted
    /// vanity. Shape rules live in
    /// [`p2claw_identity::is_valid_alias_label`].
    pub alias_label: String,
    /// Parent domain the URL was resolved against (e.g. `p2claw.com`).
    pub parent_domain: String,
    /// Path + query + fragment as it will travel on the peer wire
    /// (starts with `/`). Does not include the leading host.
    pub path_and_query: String,
}

/// Default operator parent domain when `--parent-domain` is unset.
pub const DEFAULT_PARENT_DOMAIN: &str = "p2claw.com";

/// Reserved app labels. Re-export of
/// [`p2claw_identity::RESERVED_TOKENS`] so every parser consults the
/// same list. `pub` because the TS-side parity test indexes it.
pub const RESERVED_APP_NAMES: &[&str] = p2claw_identity::RESERVED_TOKENS;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UrlParseError {
    #[error("not a valid URL: {0}")]
    Malformed(String),
    #[error("scheme must be https (got {0:?})")]
    NotHttps(String),
    #[error("URL has no host")]
    NoHost,
    #[error("uppercase not allowed in hostname (got {0:?})")]
    UppercaseHost(String),
    #[error("hostname does not end with parent domain {0:?}")]
    WrongParent(String),
    #[error("peer-label must be a single DNS label (no `.` beneath the parent domain)")]
    TooManyLabels,
    #[error("hostname is the parent apex, not a peer URL")]
    ApexOnly,
    #[error("invalid alias label {0:?}")]
    BadAlias(String),
    #[error("invalid app label {0:?}")]
    BadApp(String),
    #[error("reserved app label {0:?}")]
    ReservedApp(String),
}

impl P2clawUrl {
    /// Parse a p2claw URL against the given parent domain.
    pub fn parse(raw: &str, parent_domain: &str) -> Result<Self, UrlParseError> {
        // Extract the raw host substring from the URL before `url` crate
        // lowercases it, so we can enforce that hostnames
        // are ASCII lowercase only. We accept `https://`, find the
        // authority component, and inspect it case-sensitively.
        let after_scheme = raw
            .strip_prefix("https://")
            .or_else(|| raw.strip_prefix("http://"))
            .ok_or_else(|| UrlParseError::Malformed("missing scheme".to_string()))?;
        let authority_end = after_scheme
            .find(['/', '?', '#'])
            .unwrap_or(after_scheme.len());
        let authority = &after_scheme[..authority_end];
        // Strip optional userinfo (shouldn't be present in p2claw URLs
        // but be explicit) and optional port.
        let host_raw = authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority);
        let host_raw = host_raw
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_raw);
        if host_raw.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(UrlParseError::UppercaseHost(host_raw.to_string()));
        }

        let url = Url::parse(raw).map_err(|e| UrlParseError::Malformed(e.to_string()))?;
        if url.scheme() != "https" {
            return Err(UrlParseError::NotHttps(url.scheme().to_string()));
        }
        let host = url.host_str().ok_or(UrlParseError::NoHost)?;
        // Defensive re-normalisation — `url` crate already lowercases
        // ASCII hosts, but this keeps the downstream code honest.
        let host_lower = host.to_ascii_lowercase();

        let peer_label = peer_label_for(&host_lower, parent_domain)?;
        let (app, alias_label) = parse_peer_label(peer_label)?;
        if let Some(ref a) = app {
            validate_app(a)?;
        }

        // Reassemble path + query + fragment as a single string.
        // `url::Url::path()` always starts with `/`; query/fragment come
        // along if present.
        let mut path_and_query = String::from(url.path());
        if let Some(q) = url.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }
        if let Some(f) = url.fragment() {
            path_and_query.push('#');
            path_and_query.push_str(f);
        }

        Ok(P2clawUrl {
            app,
            alias_label,
            parent_domain: parent_domain.to_string(),
            path_and_query,
        })
    }
}

/// A parsed p2claw host. Same `(app, alias_label, parent_domain)`
/// shape as [`P2clawUrl`] but with no path / query / fragment — the
/// natural surface for callers that have a bare hostname (SNI, `Host:`
/// header, etc.) and want it validated against the addressing grammar.
///
/// Strict-by-default: a single trailing FQDN dot is tolerated; IP
/// literals, port suffixes, and userinfo are not — callers strip
/// those upstream. Uppercase ASCII in the host is rejected (the
/// addressing grammar is canonical lowercase).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2clawHost {
    /// Optional app label. `None` is the apex / listing-page form.
    pub app: Option<String>,
    /// Alias label `adj-noun-NNNN`.
    pub alias_label: String,
    /// Parent domain the host was resolved against.
    pub parent_domain: String,
}

impl P2clawHost {
    /// Parse a bare hostname against the operator's `parent_domain`.
    ///
    /// The host string is expected to be free of port, userinfo, and
    /// brackets (no `[::1]`-style IPv6 literals): peeling those off
    /// is the caller's job — both because they're transport-layer
    /// concerns and because the SNI hot path in the agent already
    /// has the raw host substring sliced off the ClientHello before
    /// it ever reaches us.
    pub fn parse(host: &str, parent_domain: &str) -> Result<Self, UrlParseError> {
        // RFC-compliant FQDNs may carry a single trailing dot
        // (`recipes-blue-otter-7392.p2claw.com.`). Strip exactly one
        // before doing anything else; multiple trailing dots are
        // illegal and we don't try to "be helpful" about that.
        let host = host.strip_suffix('.').unwrap_or(host);

        // Reject empty after dot-strip — both `""` and `"."` land
        // here, and neither is a valid hostname.
        if host.is_empty() {
            return Err(UrlParseError::NoHost);
        }

        // Case-sensitive uppercase scan first. We want a clear error
        // before falling through to the (lowercase-required) suffix
        // match below, where uppercase would just look like
        // WrongParent and confuse the diagnostic.
        if host.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(UrlParseError::UppercaseHost(host.to_string()));
        }

        let peer_label = peer_label_for(host, parent_domain)?;
        let (app, alias_label) = parse_peer_label(peer_label)?;
        if let Some(ref a) = app {
            validate_app(a)?;
        }

        Ok(P2clawHost {
            app,
            alias_label,
            parent_domain: parent_domain.to_string(),
        })
    }
}

/// Strip `parent_domain` from the right of `host` and return the
/// peer-label. Host must end with `.{parent_domain}`, and the
/// remainder must be a single DNS label.
fn peer_label_for<'a>(host: &'a str, parent_domain: &str) -> Result<&'a str, UrlParseError> {
    let pd = parent_domain.trim_start_matches('.').to_ascii_lowercase();
    if host == pd {
        return Err(UrlParseError::ApexOnly);
    }
    let suffix = format!(".{pd}");
    let Some(peer_label) = host.strip_suffix(&suffix) else {
        return Err(UrlParseError::WrongParent(pd));
    };
    if peer_label.is_empty() {
        return Err(UrlParseError::ApexOnly);
    }
    if peer_label.contains('.') {
        return Err(UrlParseError::TooManyLabels);
    }
    Ok(peer_label)
}

/// Split the peer-label into `(app, alias)`.
///
/// Two shapes:
///
/// 1. **Haiku** — `[app-]adj-noun-num4+`. The 4+-digit tail anchors
///    the split; multi-token apps like `recipes-v2` survive.
/// 2. **Vanity** — `[app-]vanity`. Vanity is hyphen-free, so a single
///    split on the LAST hyphen unambiguously separates app from alias.
///
/// Tries haiku first (tighter shape), falls through to vanity on miss.
///
/// Public so SNI hot paths can call this directly. App *validation*
/// (grammar + reserved-list) is NOT performed here — use
/// [`P2clawHost::parse`] / [`P2clawUrl::parse`] for that. Reserved-
/// alias filtering happens at insert time inside coord.
pub fn parse_peer_label(label: &str) -> Result<(Option<String>, String), UrlParseError> {
    // ----- Haiku branch first.
    if let Some(out) = try_peel_haiku(label) {
        return Ok(out);
    }

    // ----- Vanity branch. Split on the LAST hyphen (None if there
    // isn't one — then the whole label is the candidate vanity).
    // The vanity grammar's hyphen-free rule makes this unambiguous.
    let (app_slice, tail) = match label.rfind('-') {
        Some(i) => (Some(&label[..i]), &label[i + 1..]),
        None => (None, label),
    };
    if !p2claw_identity::is_valid_vanity_label(tail) {
        return Err(UrlParseError::BadAlias(label.to_string()));
    }
    if let Some(app) = app_slice {
        // Empty head means a leading hyphen on the input (e.g.
        // `-acme`). That's not a meaningful URL — surface as
        // BadApp so the diagnostic distinguishes from a shape
        // problem on the alias side.
        if app.is_empty() {
            return Err(UrlParseError::BadApp(app.to_string()));
        }
    }
    Ok((app_slice.map(str::to_string), tail.to_string()))
}

/// Try the haiku peel `[app-]adj-noun-num4+`. Returns `Some((app, alias))`
/// when every haiku constraint holds; returns `None` so the caller
/// can fall through to the vanity branch.
fn try_peel_haiku(label: &str) -> Option<(Option<String>, String)> {
    // Step 1: peel off the 4+-digit numeric suffix.
    let last_dash = label.rfind('-')?;
    let num = &label[last_dash + 1..];
    if num.len() < 4 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let before_num = &label[..last_dash];

    // Step 2: peel off the noun token.
    let noun_start = before_num.rfind('-')?;
    let noun = &before_num[noun_start + 1..];
    if noun.is_empty() || !noun.bytes().all(|b| b.is_ascii_lowercase()) {
        return None;
    }
    let before_noun = &before_num[..noun_start];

    // Step 3: peel off the adjective token. Anything still to the
    // left of it (with the separating `-`) is the app label. `None`
    // means apex form — no app prefix at all.
    let (app, adj) = match before_noun.rfind('-') {
        Some(idx) => (Some(&before_noun[..idx]), &before_noun[idx + 1..]),
        None => (None, before_noun),
    };
    if adj.is_empty() || !adj.bytes().all(|b| b.is_ascii_lowercase()) {
        return None;
    }

    let alias = format!("{adj}-{noun}-{num}");
    Some((app.map(str::to_string), alias))
}

fn validate_app(label: &str) -> Result<(), UrlParseError> {
    // Grammar: `[a-z0-9][a-z0-9-]{0,31}`.
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return Err(UrlParseError::BadApp(label.to_string()));
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(UrlParseError::BadApp(label.to_string()));
    }
    if *bytes.last().unwrap() == b'-' {
        return Err(UrlParseError::BadApp(label.to_string()));
    }
    for &b in bytes {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
        if !ok {
            return Err(UrlParseError::BadApp(label.to_string()));
        }
    }
    if RESERVED_APP_NAMES.contains(&label) {
        return Err(UrlParseError::ReservedApp(label.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PD: &str = "p2claw.com";

    // Happy-path vectors.

    #[test]
    fn parses_app_plus_alias() {
        let u = P2clawUrl::parse("https://recipes-blue-otter-7392.p2claw.com/", PD).unwrap();
        assert_eq!(u.app.as_deref(), Some("recipes"));
        assert_eq!(u.alias_label, "blue-otter-7392");
        assert_eq!(u.parent_domain, "p2claw.com");
        assert_eq!(u.path_and_query, "/");
    }

    #[test]
    fn parses_apex_alias() {
        // Apex form — listing page (app directory), not "default app".
        let u = P2clawUrl::parse("https://blue-otter-7392.p2claw.com/", PD).unwrap();
        assert_eq!(u.app, None);
        assert_eq!(u.alias_label, "blue-otter-7392");
    }

    #[test]
    fn parses_multi_hyphen_app() {
        // `my-app` contains a hyphen; right-to-left peeling keeps the
        // three haiku hyphens out of the app label.
        let u = P2clawUrl::parse("https://my-app-blue-otter-7392.p2claw.com/", PD).unwrap();
        assert_eq!(u.app.as_deref(), Some("my-app"));
        assert_eq!(u.alias_label, "blue-otter-7392");
    }

    #[test]
    fn parses_app_with_version_suffix() {
        // `recipes-v2` — two-token app with a versioned suffix.
        let u = P2clawUrl::parse("https://recipes-v2-quiet-river-3847.p2claw.com/", PD).unwrap();
        assert_eq!(u.app.as_deref(), Some("recipes-v2"));
        assert_eq!(u.alias_label, "quiet-river-3847");
    }

    #[test]
    fn parses_extended_five_digit_tail() {
        // Forward-compat: coord currently emits 4 digits, but the
        // parser accepts 4+ so a later 5-digit extension doesn't need
        // a client release.
        let u = P2clawUrl::parse("https://blue-otter-73925.p2claw.com/", PD).unwrap();
        assert_eq!(u.app, None);
        assert_eq!(u.alias_label, "blue-otter-73925");
    }

    #[test]
    fn preserves_path_query_fragment() {
        let u = P2clawUrl::parse(
            "https://recipes-blue-otter-7392.p2claw.com/api/items?q=stew#frag",
            PD,
        )
        .unwrap();
        assert_eq!(u.path_and_query, "/api/items?q=stew#frag");
    }

    // Rejection vectors.

    #[test]
    fn rejects_uppercase_app_label() {
        let err = P2clawUrl::parse("https://RECIPES-blue-otter-7392.p2claw.com/", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::UppercaseHost(_)));
    }

    #[test]
    fn rejects_uppercase_alias_label() {
        let err = P2clawUrl::parse("https://Blue-otter-7392.p2claw.com/", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::UppercaseHost(_)));
    }

    #[test]
    fn rejects_leading_hyphen() {
        // Leading `-` → the `url` crate may reject the hostname
        // outright (DNS labels can't start with `-`) or pass it
        // through with an empty app in our split. Both are acceptable
        // rejections.
        let err = P2clawUrl::parse("https://-recipes-blue-otter-7392.p2claw.com/", PD).unwrap_err();
        match err {
            UrlParseError::Malformed(_) | UrlParseError::BadApp(_) => {}
            other => panic!("unexpected error for leading `-`: {other:?}"),
        }
    }

    #[test]
    fn rejects_reserved_app_admin() {
        let err = P2clawUrl::parse("https://admin-blue-otter-7392.p2claw.com/", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::ReservedApp(s) if s == "admin"));
    }

    #[test]
    fn rejects_historical_two_label_form() {
        // Pre-hyphen grammar `app.alias.parent` — retired because
        // public-CA wildcards don't cover two subdomain levels.
        let err = P2clawUrl::parse("https://recipes.blue-otter-7392.p2claw.com/", PD).unwrap_err();
        assert_eq!(err, UrlParseError::TooManyLabels);
    }

    #[test]
    fn alphabetic_num_token_parses_as_vanity() {
        // A haiku-only parser would error here (it requires a
        // 4-digit tail). The vanity fallback kicks in: split on
        // the last hyphen → app=`blue-otter`,
        // alias=`abc` (valid hyphen-free vanity). The historical
        // BadAlias outcome is replaced by a successful parse;
        // coord's `get_by_alias` will 404 on `abc` if no row
        // exists, which is where the routing rejection happens
        // now.
        let u = P2clawUrl::parse("https://blue-otter-abc.p2claw.com/", PD).unwrap();
        assert_eq!(u.app.as_deref(), Some("blue-otter"));
        assert_eq!(u.alias_label, "abc");
    }

    #[test]
    fn rejects_three_digit_num_token() {
        // `099` is only 3 digits; grammar requires 4+.
        let err = P2clawUrl::parse("https://blue-otter-099.p2claw.com/", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::BadAlias(_)));
    }

    #[test]
    fn rejects_empty_num_token() {
        // Trailing `-` → empty num token after split. The `url` crate
        // may also reject the trailing-hyphen DNS label outright, so
        // accept either rejection shape.
        let err = P2clawUrl::parse("https://blue-otter-.p2claw.com/", PD).unwrap_err();
        match err {
            UrlParseError::Malformed(_) | UrlParseError::BadAlias(_) => {}
            other => panic!("unexpected error for empty num token: {other:?}"),
        }
    }

    #[test]
    fn bare_reserved_label_parses_as_vanity() {
        // A haiku-only parser would error here as BadAlias because
        // it demands a haiku shape with three hyphens. The vanity
        // parser accepts a bare hyphen-free label as a valid
        // vanity at the parse
        // layer — `peer` parses to (None, "peer"). The
        // reserved-alias gate is enforced at INSERT time (coord's
        // upgrade endpoint + grant-vanity); coord won't have a
        // `peer` row, so the downstream lookup 404s.
        let u = P2clawUrl::parse("https://peer.p2claw.com/", PD).unwrap();
        assert_eq!(u.app, None);
        assert_eq!(u.alias_label, "peer");
    }

    #[test]
    fn rejects_many_extra_labels() {
        let err = P2clawUrl::parse("https://too.many.labels.blue-otter-7392.p2claw.com/", PD)
            .unwrap_err();
        assert_eq!(err, UrlParseError::TooManyLabels);
    }

    #[test]
    fn rejects_plain_apex() {
        let err = P2clawUrl::parse("https://p2claw.com/", PD).unwrap_err();
        assert_eq!(err, UrlParseError::ApexOnly);
    }

    #[test]
    fn rejects_non_https() {
        let err = P2clawUrl::parse("http://blue-otter-7392.p2claw.com/", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::NotHttps(s) if s == "http"));
    }

    #[test]
    fn rejects_wrong_parent_domain() {
        let err = P2clawUrl::parse("https://blue-otter-7392.example.com/", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::WrongParent(_)));
    }

    #[test]
    fn accepts_alternate_parent_domain() {
        let u = P2clawUrl::parse(
            "https://recipes-blue-otter-7392.example.net/",
            "example.net",
        )
        .unwrap();
        assert_eq!(u.app.as_deref(), Some("recipes"));
        assert_eq!(u.alias_label, "blue-otter-7392");
        assert_eq!(u.parent_domain, "example.net");
    }

    // P2clawHost::parse — bare-hostname surface for SNI / Host: header
    // callers. Same grammar coverage as P2clawUrl::parse, minus the
    // path/query bits and plus trailing-dot tolerance.

    #[test]
    fn host_parses_app_plus_alias() {
        let h = P2clawHost::parse("recipes-blue-otter-7392.p2claw.com", PD).unwrap();
        assert_eq!(h.app.as_deref(), Some("recipes"));
        assert_eq!(h.alias_label, "blue-otter-7392");
        assert_eq!(h.parent_domain, "p2claw.com");
    }

    #[test]
    fn host_parses_apex_alias() {
        let h = P2clawHost::parse("blue-otter-7392.p2claw.com", PD).unwrap();
        assert_eq!(h.app, None);
        assert_eq!(h.alias_label, "blue-otter-7392");
    }

    #[test]
    fn host_tolerates_trailing_dot_fqdn() {
        // RFC-legal — a single trailing dot marks the FQDN as fully
        // qualified. Should round-trip as if the dot weren't there.
        let h = P2clawHost::parse("recipes-blue-otter-7392.p2claw.com.", PD).unwrap();
        assert_eq!(h.app.as_deref(), Some("recipes"));
        assert_eq!(h.alias_label, "blue-otter-7392");
    }

    #[test]
    fn host_rejects_uppercase() {
        let err = P2clawHost::parse("Recipes-Blue-Otter-7392.p2claw.com", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::UppercaseHost(_)));
    }

    #[test]
    fn host_rejects_wrong_parent() {
        let err = P2clawHost::parse("blue-otter-7392.example.com", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::WrongParent(_)));
    }

    #[test]
    fn host_rejects_apex_only() {
        let err = P2clawHost::parse("p2claw.com", PD).unwrap_err();
        assert_eq!(err, UrlParseError::ApexOnly);
    }

    #[test]
    fn host_rejects_multi_label() {
        // More than one label between the haiku and the parent domain
        // is rejected.
        let err = P2clawHost::parse("foo.blue-otter-7392.p2claw.com", PD).unwrap_err();
        assert_eq!(err, UrlParseError::TooManyLabels);
    }

    #[test]
    fn host_rejects_three_digit_haiku_tail() {
        // Three-digit numeric tail violates the haiku grammar (need
        // 4+). Vanity fallback also rejects: split → vanity=`099`
        // is pure digits, which the vanity grammar bans.
        let err = P2clawHost::parse("blue-otter-099.p2claw.com", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::BadAlias(_)));
    }

    #[test]
    fn host_rejects_reserved_app() {
        let err = P2clawHost::parse("admin-blue-otter-7392.p2claw.com", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::ReservedApp(s) if s == "admin"));
    }

    #[test]
    fn host_rejects_empty_string() {
        let err = P2clawHost::parse("", PD).unwrap_err();
        assert_eq!(err, UrlParseError::NoHost);
    }

    #[test]
    fn host_rejects_lone_dot() {
        // After trailing-dot strip this is empty → NoHost. Caller
        // shouldn't be feeding us this anyway, but be explicit.
        let err = P2clawHost::parse(".", PD).unwrap_err();
        assert_eq!(err, UrlParseError::NoHost);
    }

    // parse_peer_label — public low-level helper. Cover the same
    // shapes the higher-level surfaces fold into; consumers using this
    // directly are (per the docstring) skipping app validation.

    #[test]
    fn peer_label_apex_form() {
        let (app, alias) = parse_peer_label("blue-otter-7392").unwrap();
        assert_eq!(app, None);
        assert_eq!(alias, "blue-otter-7392");
    }

    #[test]
    fn peer_label_with_app() {
        let (app, alias) = parse_peer_label("recipes-blue-otter-7392").unwrap();
        assert_eq!(app.as_deref(), Some("recipes"));
        assert_eq!(alias, "blue-otter-7392");
    }

    #[test]
    fn peer_label_does_not_validate_app() {
        // Reserved app `admin` passes through `parse_peer_label` —
        // validation is the higher-level surface's job. Locking this
        // in so a future "be helpful" refactor doesn't move the check
        // down here and surprise SNI callers who rely on the
        // hot-path zero-validation contract.
        let (app, alias) = parse_peer_label("admin-blue-otter-7392").unwrap();
        assert_eq!(app.as_deref(), Some("admin"));
        assert_eq!(alias, "blue-otter-7392");
    }

    #[test]
    fn peer_label_rejects_bad_haiku_three_digit_tail() {
        // `blue-otter-099` — haiku branch fails (3 digits), vanity
        // fallback fails (`099` is pure digits).
        let err = parse_peer_label("blue-otter-099").unwrap_err();
        assert!(matches!(err, UrlParseError::BadAlias(_)));
    }

    // ---- vanity branch ----
    //
    // The cases below mirror byte-for-byte the canonical-matrix
    // tests in `crates/identity/src/alias_label.rs` and the
    // hostname-parse matrix in `crates/edge/src/hostname.rs`.
    // bootstrap-dev's TS test suite mirrors the same set; when you
    // add a case here, mirror it there.

    #[test]
    fn peer_label_apex_vanity() {
        // Bare hyphen-free vanity label, e.g. `acme.p2claw.com`.
        let (app, alias) = parse_peer_label("acme").unwrap();
        assert_eq!(app, None);
        assert_eq!(alias, "acme");
        let (_, alias) = parse_peer_label("acme").unwrap();
        assert_eq!(alias, "acme");
        let (_, alias) = parse_peer_label("myco").unwrap();
        assert_eq!(alias, "myco");
        let (_, alias) = parse_peer_label("a").unwrap();
        assert_eq!(alias, "a");
    }

    #[test]
    fn peer_label_app_plus_vanity() {
        // Single-token app + vanity — the shape a curl against
        // `recipes-acme.p2claw.com` hits.
        let (app, alias) = parse_peer_label("recipes-acme").unwrap();
        assert_eq!(app.as_deref(), Some("recipes"));
        assert_eq!(alias, "acme");
    }

    #[test]
    fn peer_label_multi_token_app_plus_vanity() {
        // Multi-token app + vanity, e.g. `vibecode-drop-acme.p2claw.com`.
        // Splits on the LAST hyphen: app=`vibecode-drop`, vanity=`acme`.
        let (app, alias) = parse_peer_label("vibecode-drop-acme").unwrap();
        assert_eq!(app.as_deref(), Some("vibecode-drop"));
        assert_eq!(alias, "acme");
    }

    #[test]
    fn peer_label_vanity_with_digits() {
        let (_, alias) = parse_peer_label("photo7").unwrap();
        assert_eq!(alias, "photo7");
        let (_, alias) = parse_peer_label("v3").unwrap();
        assert_eq!(alias, "v3");
    }

    #[test]
    fn peer_label_vanity_at_max_length() {
        let max = "a".repeat(63);
        let (_, alias) = parse_peer_label(&max).unwrap();
        assert_eq!(alias, max);
    }

    #[test]
    fn peer_label_vanity_over_max_length_is_rejected() {
        let too_long = "a".repeat(64);
        let err = parse_peer_label(&too_long).unwrap_err();
        assert!(matches!(err, UrlParseError::BadAlias(_)));
    }

    #[test]
    fn peer_label_pure_digit_vanity_is_rejected() {
        // DNS allows pure-digit labels but the vanity grammar bans
        // them as a footgun.
        let err = parse_peer_label("12345").unwrap_err();
        assert!(matches!(err, UrlParseError::BadAlias(_)));
        // And in the app+vanity slot too.
        let err = parse_peer_label("recipes-12345").unwrap_err();
        assert!(matches!(err, UrlParseError::BadAlias(_)));
    }

    #[test]
    fn peer_label_leading_hyphen_is_rejected() {
        // `-acme` → vanity fallback yields app="" → BadApp. The
        // distinct error (vs. BadAlias) helps the diagnostic.
        let err = parse_peer_label("-acme").unwrap_err();
        assert!(matches!(err, UrlParseError::BadApp(_)));
    }

    #[test]
    fn peer_label_trailing_hyphen_is_rejected() {
        let err = parse_peer_label("acme-").unwrap_err();
        assert!(matches!(err, UrlParseError::BadAlias(_)));
    }

    #[test]
    fn peer_label_empty_is_rejected() {
        let err = parse_peer_label("").unwrap_err();
        assert!(matches!(err, UrlParseError::BadAlias(_)));
    }

    // ---- end-to-end through P2clawHost::parse — what the agent's
    //      forwarder actually drives.

    #[test]
    fn host_parses_app_plus_vanity() {
        let h = P2clawHost::parse("recipes-acme.p2claw.com", PD).unwrap();
        assert_eq!(h.app.as_deref(), Some("recipes"));
        assert_eq!(h.alias_label, "acme");
    }

    #[test]
    fn host_parses_multi_token_app_plus_vanity() {
        let h = P2clawHost::parse("vibecode-drop-acme.p2claw.com", PD).unwrap();
        assert_eq!(h.app.as_deref(), Some("vibecode-drop"));
        assert_eq!(h.alias_label, "acme");
    }

    #[test]
    fn host_parses_apex_vanity() {
        let h = P2clawHost::parse("acme.p2claw.com", PD).unwrap();
        assert_eq!(h.app, None);
        assert_eq!(h.alias_label, "acme");
    }

    #[test]
    fn host_rejects_reserved_app_with_vanity_alias() {
        // App-slot reserved check fires regardless of whether the
        // alias is haiku or vanity. `admin-acme` → ReservedApp.
        let err = P2clawHost::parse("admin-acme.p2claw.com", PD).unwrap_err();
        assert!(matches!(err, UrlParseError::ReservedApp(s) if s == "admin"));
    }

    #[test]
    fn host_parses_bare_reserved_alias_no_app() {
        // `admin.p2claw.com` — vanity branch, no app to check
        // against the reserved-app list. The alias slot is not
        // gated at parse time; coord 404s the lookup.
        let h = P2clawHost::parse("admin.p2claw.com", PD).unwrap();
        assert_eq!(h.app, None);
        assert_eq!(h.alias_label, "admin");
    }
}
