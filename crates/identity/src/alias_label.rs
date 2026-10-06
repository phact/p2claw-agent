//! Alias-label grammar — shared by every peer that has to parse or
//! validate an alias label.
//!
//! Two shapes are valid:
//!
//! - **Haiku**: `adj-noun-num` where `adj` and `noun` are non-empty
//!   lowercase ASCII letter runs and `num` is at least 4 digits.
//!   Coord auto-assigns this form on registration. The numeric tail
//!   anchors the `app-alias` split for `[app-]alias` hostnames.
//! - **Vanity**: single hyphen-free label, 1–63 chars, lowercase
//!   ASCII letters + digits, with at least one letter (pure numeric
//!   labels are a DNS-edge-case lever). Hyphens are forbidden so
//!   `app-alias` split-on-last-hyphen survives an app prefix.
//!
//! Both shapes go through [`RESERVED_TOKENS`]. The filter is
//! whole-label for vanity and token-by-token (split on `-`) for
//! haiku, since the upgrade endpoint takes user-chosen adj/noun
//! strings that could otherwise land on a reserved word.
//!
//! The grammar must match the TS implementation in
//! `bootstrap/src/url.ts` exactly; the test matrix below mirrors
//! bootstrap's case-for-case.

/// Reserved labels — applied as an app reserved-name filter at the
/// edge and as an alias reserved-name filter at coord. One source of
/// truth across crates so additions don't drift.
///
/// Trademark / brand reservations are a separate filter layered on
/// top of this baseline.
pub const RESERVED_TOKENS: &[&str] = &[
    "www", "api", "admin", "auth", "login", "account", "accounts", "mail", "ftp", "ssh", "p2claw",
    "peer", "sys", "internal", "static", "status", "health", "default",
];

/// Maximum length of any alias label, per DNS RFC 1035 §2.3.4
/// (DNS label limit). Applies to both shapes; vanity is the only one
/// that gets close in practice.
pub const ALIAS_LABEL_MAX_LEN: usize = 63;

/// Minimum digits in the haiku numeric tail. Coord emits exactly 4
/// today; the parser is permissive (`≥ 4`) so future collision
/// extension lands without a deploy lockstep.
pub const HAIKU_NUM_MIN_DIGITS: usize = 4;

/// True if `s` is a haiku-shaped alias: `[a-z]+-[a-z]+-[0-9]{4,}`
/// with exactly two internal hyphens. Mirrors the previous
/// `coordination::haiku::is_valid_haiku_shape` byte-for-byte —
/// existing call sites just route through here now.
pub fn is_valid_haiku_label(s: &str) -> bool {
    // Length cap applies to haiku too — RFC 1035 §2.3.4.
    if s.len() > ALIAS_LABEL_MAX_LEN {
        return false;
    }
    // Find the last '-' — that separates the numeric tail.
    let Some(last) = s.rfind('-') else {
        return false;
    };
    let num = &s[last + 1..];
    if num.len() < HAIKU_NUM_MIN_DIGITS || !num.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let adj_noun = &s[..last];
    let Some(mid) = adj_noun.find('-') else {
        return false;
    };
    let adj = &adj_noun[..mid];
    let noun = &adj_noun[mid + 1..];
    if adj.is_empty() || noun.is_empty() {
        return false;
    }
    if noun.contains('-') {
        // Extra separator → not a clean adj-noun-NNNN.
        return false;
    }
    adj.bytes().all(|b| b.is_ascii_lowercase()) && noun.bytes().all(|b| b.is_ascii_lowercase())
}

/// True if `s` is a vanity-shaped alias: 1–63 chars,
/// lowercase ASCII letters + digits, at least one letter, no
/// hyphens, no underscores, no dots.
///
/// "At least one letter" rejects pure-digit labels — DNS permits
/// them but they're a footgun (some resolvers treat all-digit
/// labels specially; legacy software gets weird with them). If a
/// future iteration wants them, relax the `saw_letter` check.
pub fn is_valid_vanity_label(s: &str) -> bool {
    if s.is_empty() || s.len() > ALIAS_LABEL_MAX_LEN {
        return false;
    }
    let mut saw_letter = false;
    for ch in s.chars() {
        match ch {
            'a'..='z' => saw_letter = true,
            '0'..='9' => {}
            _ => return false,
        }
    }
    saw_letter
}

/// True if `s` is a valid alias label in either supported shape
/// (haiku or vanity). The reserved-token filter is **not** applied
/// here — `s` may be `admin` and pass shape validation. Callers
/// that need the reserved-name check call [`is_reserved_alias`]
/// after this; the upgrade endpoint and the parser both do so as
/// distinct steps to make the rejection path explicit.
pub fn is_valid_alias_label(s: &str) -> bool {
    is_valid_haiku_label(s) || is_valid_vanity_label(s)
}

/// True if `s`, considered as an alias label, hits the
/// reserved-token list.
///
/// Two policies:
///
/// - **Vanity** (hyphen-free): whole-string match against
///   [`RESERVED_TOKENS`]. `admin` rejects; `admiral` doesn't.
/// - **Haiku** (`adj-noun-num`): hyphen-split-tokens match.
///   Catches `admin-otter-0001` (operator-chosen vanity in the
///   haiku slot containing a reserved adj/noun word) and
///   `blue-admin-0001`. The auto-assignment path can't produce
///   these because adj/noun pools are curated, but the upgrade
///   endpoint takes user-chosen strings — defence in depth.
///
/// Inputs that pass neither shape return `false` here; the shape
/// check is the caller's responsibility.
pub fn is_reserved_alias(s: &str) -> bool {
    if is_valid_vanity_label(s) {
        return RESERVED_TOKENS.contains(&s);
    }
    if is_valid_haiku_label(s) {
        return s.split('-').any(|tok| RESERVED_TOKENS.contains(&tok));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- haiku ----

    #[test]
    fn haiku_happy_path() {
        assert!(is_valid_haiku_label("blue-otter-7392"));
        assert!(is_valid_haiku_label("quiet-river-3847"));
        assert!(is_valid_haiku_label("swift-falcon-0001"));
        // 5+ digit tail (future collision extension).
        assert!(is_valid_haiku_label("blue-otter-73925"));
    }

    #[test]
    fn haiku_rejects_malformed() {
        assert!(!is_valid_haiku_label(""));
        assert!(!is_valid_haiku_label("blue-otter"));
        assert!(!is_valid_haiku_label("blue-otter-99")); // < 4 digits
        assert!(!is_valid_haiku_label("blue-otter-abcd")); // non-digit tail
        assert!(!is_valid_haiku_label("BLUE-otter-7392")); // uppercase
        assert!(!is_valid_haiku_label("blue--otter-7392")); // double hyphen
        assert!(!is_valid_haiku_label("-otter-7392")); // leading hyphen
        assert!(!is_valid_haiku_label("blue-otter-7392-")); // trailing hyphen
                                                            // Over the DNS label cap is rejected even with haiku shape.
        let too_long = format!("{}-otter-1234", "x".repeat(60));
        assert!(!is_valid_haiku_label(&too_long));
    }

    // ---- vanity ----

    #[test]
    fn vanity_happy_path() {
        assert!(is_valid_vanity_label("widgetco"));
        assert!(is_valid_vanity_label("acme"));
        assert!(is_valid_vanity_label("myco"));
        assert!(is_valid_vanity_label("a")); // 1-char OK
        assert!(is_valid_vanity_label("photo7")); // digits OK after letters
        assert!(is_valid_vanity_label("v3"));
        let max = "a".repeat(ALIAS_LABEL_MAX_LEN);
        assert!(is_valid_vanity_label(&max)); // 63 chars OK
    }

    #[test]
    fn vanity_rejects_malformed() {
        assert!(!is_valid_vanity_label("")); // empty
        assert!(!is_valid_vanity_label("Acme")); // uppercase
        assert!(!is_valid_vanity_label("ac me")); // whitespace
        assert!(!is_valid_vanity_label("ac.me")); // dot
        assert!(!is_valid_vanity_label("ac_me")); // underscore
        assert!(!is_valid_vanity_label("ac-me")); // hyphen
        assert!(!is_valid_vanity_label("12345")); // pure digits
        assert!(!is_valid_vanity_label("0")); // pure digits, 1 char
        let too_long = "a".repeat(ALIAS_LABEL_MAX_LEN + 1);
        assert!(!is_valid_vanity_label(&too_long)); // 64 chars too long
    }

    // ---- combined ----

    #[test]
    fn is_valid_alias_label_accepts_both_shapes() {
        assert!(is_valid_alias_label("blue-otter-7392")); // haiku
        assert!(is_valid_alias_label("acme")); // vanity
        assert!(!is_valid_alias_label("")); // neither
        assert!(!is_valid_alias_label("just-two")); // neither
        assert!(!is_valid_alias_label("Acme")); // neither (uppercase)
        assert!(!is_valid_alias_label("ac-me")); // neither (hyphen but not haiku shape)
    }

    // ---- reserved tokens ----

    #[test]
    fn reserved_vanity_whole_string_match() {
        assert!(is_reserved_alias("admin"));
        assert!(is_reserved_alias("api"));
        assert!(is_reserved_alias("www"));
        // Substring match must NOT fire — `admiral` is fine.
        assert!(!is_reserved_alias("admiral"));
        assert!(!is_reserved_alias("apicultural"));
        assert!(!is_reserved_alias("acme"));
    }

    #[test]
    fn reserved_haiku_token_split_match() {
        // Token in the adj slot.
        assert!(is_reserved_alias("admin-otter-0001"));
        // Token in the noun slot.
        assert!(is_reserved_alias("blue-admin-0001"));
        // Non-reserved haiku.
        assert!(!is_reserved_alias("blue-otter-7392"));
        // Substring-not-token must NOT fire — `administer` isn't
        // tokenised to `admin` by hyphen-split.
        assert!(!is_reserved_alias("administer-falcon-0001"));
    }

    #[test]
    fn reserved_rejects_invalid_shapes() {
        // Inputs that aren't a valid alias at all: the reserved
        // check returns `false`; the caller's shape check rejects
        // them upstream with a clearer error.
        assert!(!is_reserved_alias(""));
        assert!(!is_reserved_alias("ADMIN")); // shape-invalid: no whole-string match
        assert!(!is_reserved_alias("admin-only")); // shape-invalid (no num tail)
    }
}
