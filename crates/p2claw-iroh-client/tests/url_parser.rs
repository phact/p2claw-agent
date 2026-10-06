//! Integration-level assertions on URL parsing. Complements the
//! unit tests inside `src/url.rs` — mainly here to be exercised as
//! part of `cargo test --tests`.
//!
//! Vectors cover both the haiku and vanity grammars. The haiku grammar
//! `[app "-"] adj "-" noun "-" NNNN` is parsed right-to-left with
//! the 4+-digit tail fixing the alias boundary; the vanity grammar
//! is a single hyphen-free label, accepted on haiku-peel miss via
//! a single split on the last hyphen.

use p2claw_iroh_client::{P2clawUrl, UrlParseError, DEFAULT_PARENT_DOMAIN};

#[test]
fn happy_path_vectors() {
    let cases: &[(&str, Option<&str>, &str)] = &[
        // With app label.
        (
            "https://recipes-blue-otter-7392.p2claw.com/",
            Some("recipes"),
            "blue-otter-7392",
        ),
        // Apex "listing page" form.
        (
            "https://blue-otter-7392.p2claw.com/",
            None,
            "blue-otter-7392",
        ),
        // App label contains its own hyphens (`my-app`) — the
        // right-to-left haiku parser peels the last three tokens as
        // `adj-noun-NNNN` and keeps everything before it as the app.
        (
            "https://my-app-blue-otter-7392.p2claw.com/",
            Some("my-app"),
            "blue-otter-7392",
        ),
        // Multi-hyphen app (`recipes-v2`) survives intact.
        (
            "https://recipes-v2-quiet-river-3847.p2claw.com/",
            Some("recipes-v2"),
            "quiet-river-3847",
        ),
        // The numeric tail may grow past 4 digits; accept any
        // digit-run of length ≥ 4.
        (
            "https://blue-otter-73925.p2claw.com/",
            None,
            "blue-otter-73925",
        ),
        // Vanity: bare hyphen-free single label.
        ("https://acme.p2claw.com/", None, "acme"),
        // Vanity: single-token app + vanity.
        ("https://recipes-acme.p2claw.com/", Some("recipes"), "acme"),
        // Multi-token app + vanity — `vibecode-drop-acme.p2claw.com`
        // shape (multi-token app name plus a hyphen-free vanity alias).
        (
            "https://vibecode-drop-acme.p2claw.com/",
            Some("vibecode-drop"),
            "acme",
        ),
    ];

    for (url, expected_app, expected_alias) in cases {
        let parsed = P2clawUrl::parse(url, DEFAULT_PARENT_DOMAIN)
            .unwrap_or_else(|e| panic!("failed to parse {url}: {e}"));
        assert_eq!(parsed.app.as_deref(), *expected_app, "url = {url}");
        assert_eq!(&parsed.alias_label, expected_alias, "url = {url}");
    }
}

type Predicate = fn(&UrlParseError) -> bool;

#[test]
fn rejection_vectors() {
    // (url, predicate over the error).
    let cases: &[(&str, Predicate)] = &[
        ("https://RECIPES-blue-otter-7392.p2claw.com/", |e| {
            matches!(e, UrlParseError::UppercaseHost(_))
        }),
        // Uppercase inside the alias body itself.
        ("https://Blue-otter-7392.p2claw.com/", |e| {
            matches!(e, UrlParseError::UppercaseHost(_))
        }),
        // Leading `-` → empty app label or rejected by `url` crate's
        // DNS-label check; either is acceptable.
        ("https://-recipes-blue-otter-7392.p2claw.com/", |e| {
            matches!(e, UrlParseError::Malformed(_) | UrlParseError::BadApp(_))
        }),
        ("https://admin-blue-otter-7392.p2claw.com/", |e| {
            matches!(e, UrlParseError::ReservedApp(_))
        }),
        // Historical two-label `app.alias.parent` grammar — retired in
        // favour of the single-label hyphen form. Must reject.
        ("https://recipes.blue-otter-7392.p2claw.com/", |e| {
            matches!(e, UrlParseError::TooManyLabels)
        }),
        // Numeric tail shorter than 4 digits. Haiku-only failure;
        // the vanity fallback also rejects because `739` is pure
        // digits (vanity grammar bans pure-digit labels).
        ("https://blue-otter-739.p2claw.com/", |e| {
            matches!(e, UrlParseError::BadAlias(_))
        }),
        // Note: a haiku-only parser would reject
        // `blue-otter-seven.p2claw.com`, `blueotter.p2claw.com`,
        // and `peer.p2claw.com` as BadAlias (no valid haiku split).
        // The vanity fallback accepts them cleanly — `seven`,
        // `blueotter`, `peer` are valid hyphen-free vanity labels at
        // the parse layer. The reserved-alias gate (for `peer`)
        // lives at INSERT time only; coord 404s the lookup if the
        // row doesn't exist. Positive-parse coverage for these
        // shapes is in `happy_path_vectors` and `src/url.rs::tests`.
    ];
    for (url, pred) in cases {
        let err = P2clawUrl::parse(url, DEFAULT_PARENT_DOMAIN)
            .expect_err(&format!("expected rejection for {url}"));
        assert!(pred(&err), "wrong error for {url}: {err:?}");
    }
}

#[test]
fn preserves_query_and_fragment() {
    let u = P2clawUrl::parse(
        "https://recipes-blue-otter-7392.p2claw.com/items?sort=asc&limit=10#x",
        DEFAULT_PARENT_DOMAIN,
    )
    .unwrap();
    assert_eq!(u.path_and_query, "/items?sort=asc&limit=10#x");
}
