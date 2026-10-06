//! Pulling the two facts the owner needs out of a Gmail forwarding
//! confirmation: which account wants to forward, and the link that
//! approves it.
//!
//! Gmail's confirmation names the account in the subject ("… Receive
//! Mail from <account>") and again in the body ("<account> has
//! requested to automatically forward mail to …"), followed by one
//! confirmation link on `mail-settings.google.com`. The wording is
//! Google's and may change, so each fact is looked for in more than
//! one place and missing facts are left `None` rather than guessed.
//! The link is a bearer credential: callers must not log it.

use mail_parser::MessageParser;

use super::inbox::ForwardingRequest;
use super::normalize_address;

/// Facts extracted from a confirmation message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extracted {
    pub account: Option<String>,
    pub link: Option<String>,
}

/// `to` is the box address the confirmation was sent to; it is never
/// taken as the requesting account.
pub fn extract(raw: &[u8], to: &str) -> Extracted {
    let Some(m) = MessageParser::default().parse(raw) else {
        return Extracted::default();
    };
    let subject = m.subject().unwrap_or_default().to_string();
    let text = m.body_text(0).map(|c| c.into_owned()).unwrap_or_default();
    let html = m.body_html(0).map(|c| c.into_owned()).unwrap_or_default();
    let to = to.to_ascii_lowercase();

    let not_box = |a: &str| normalize_address(a).ok() != normalize_address(&to).ok();
    let account = account_after(&subject, "from ")
        .filter(|a| not_box(a))
        .or_else(|| account_before(&text, " has requested").filter(|a| not_box(a)))
        .or_else(|| {
            addresses_in(&text)
                .into_iter()
                .chain(addresses_in(&html))
                .find(|a| not_box(a) && !a.ends_with("@google.com"))
        });

    let link = links_in(&text)
        .into_iter()
        .chain(links_in(&html))
        .find(|l| is_google_settings_link(l))
        .or_else(|| links_in(&text).into_iter().next());

    Extracted { account, link }
}

/// Build the stored request for message `id`.
pub fn request(id: &str, received_at: u64, raw: &[u8], to: &str) -> ForwardingRequest {
    let ex = extract(raw, to);
    ForwardingRequest {
        id: id.to_string(),
        account: ex.account,
        link: ex.link,
        received_at,
    }
}

fn is_google_settings_link(l: &str) -> bool {
    l.strip_prefix("https://")
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .is_some_and(|host| host == "google.com" || host.ends_with(".google.com"))
}

fn account_after(s: &str, marker: &str) -> Option<String> {
    let idx = s.to_ascii_lowercase().rfind(marker)?;
    let tail = &s[idx + marker.len()..];
    addresses_in(tail).into_iter().next()
}

fn account_before(s: &str, marker: &str) -> Option<String> {
    let idx = s.find(marker)?;
    let head = &s[..idx];
    addresses_in(head).into_iter().last()
}

/// Every token that normalizes to an address, in order.
fn addresses_in(s: &str) -> Vec<String> {
    s.split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '(' | ')' | '"' | ',' | ';'))
        .filter(|t| t.contains('@'))
        .map(|t| t.trim_matches(|c: char| matches!(c, '.' | ':' | '\'' | '[' | ']')))
        .filter_map(|t| normalize_address(t).ok())
        .collect()
}

/// Every `https://` URL in `s`, in order.
fn links_in(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(idx) = rest.find("https://") {
        let tail = &rest[idx..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']'))
            .unwrap_or(tail.len());
        let url = tail[..end].trim_end_matches(['.', ',']);
        if url.len() > "https://".len() {
            out.push(url.to_string());
        }
        rest = &tail[end.max(1)..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "https://mail-settings.google.com/mail/vf-%5BANGjdJ8example%5D-abc123";

    fn confirmation(account: &str, link: &str) -> String {
        format!(
            "From: forwarding-noreply@google.com\r\n\
             To: alias@p2claw.com\r\n\
             Subject: (#123456789) Gmail Forwarding Confirmation - Receive Mail from {account}\r\n\
             X-Google-Address-Confirmation: 123456789\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/alternative; boundary=\"b\"\r\n\
             \r\n\
             --b\r\n\
             Content-Type: text/plain; charset=UTF-8\r\n\
             \r\n\
             {account} has requested to automatically forward mail to your email\r\n\
             address alias@p2claw.com.\r\n\
             \r\n\
             To allow them to do so, please click the link below to confirm the request:\r\n\
             \r\n\
             {link}\r\n\
             \r\n\
             If you click the link and it appears to be broken, please copy and paste it\r\n\
             into a new browser window.\r\n\
             \r\n\
             Thanks for using Gmail!\r\n\
             --b\r\n\
             Content-Type: text/html; charset=UTF-8\r\n\
             \r\n\
             <p>{account} has requested to automatically forward mail to <b>alias@p2claw.com</b>.</p>\r\n\
             <p><a href=\"{link}\">Confirm</a></p>\r\n\
             --b--\r\n"
        )
    }

    #[test]
    fn extracts_account_and_link() {
        let raw = confirmation("someone@gmail.com", LINK);
        let ex = extract(raw.as_bytes(), "alias@p2claw.com");
        assert_eq!(ex.account.as_deref(), Some("someone@gmail.com"));
        assert_eq!(ex.link.as_deref(), Some(LINK));
    }

    #[test]
    fn falls_back_to_the_body_when_the_subject_changes() {
        let raw = confirmation("someone@gmail.com", LINK)
            .replace("Receive Mail from someone@gmail.com", "Please confirm");
        let ex = extract(raw.as_bytes(), "alias@p2claw.com");
        assert_eq!(ex.account.as_deref(), Some("someone@gmail.com"));
    }

    #[test]
    fn never_reports_the_box_address_as_the_account() {
        let raw = confirmation("someone@gmail.com", LINK)
            .replace(
                "Receive Mail from someone@gmail.com",
                "Receive Mail from alias@p2claw.com",
            )
            .replacen("someone@gmail.com has requested", "A user has requested", 1);
        let ex = extract(raw.as_bytes(), "alias@p2claw.com");
        assert_eq!(
            ex.account.as_deref(),
            Some("someone@gmail.com"),
            "found in the html body"
        );
    }

    #[test]
    fn prefers_google_links_and_tolerates_none() {
        let raw = confirmation("someone@gmail.com", LINK).replace(
            "To allow them",
            "See https://support.google.com/mail/answer/10957 first. To allow them",
        );
        let ex = extract(raw.as_bytes(), "alias@p2claw.com");
        assert_eq!(
            ex.link.as_deref(),
            Some("https://support.google.com/mail/answer/10957")
        );

        let raw = confirmation("someone@gmail.com", "(no link)");
        let ex = extract(raw.as_bytes(), "alias@p2claw.com");
        assert_eq!(ex.link, None);
        assert_eq!(ex.account.as_deref(), Some("someone@gmail.com"));
    }

    #[test]
    fn garbage_yields_nothing() {
        assert_eq!(extract(b"", "alias@p2claw.com"), Extracted::default());
        let r = request("m_1", 7, b"\x00\x01", "alias@p2claw.com");
        assert_eq!(r.id, "m_1");
        assert_eq!(r.received_at, 7);
        assert!(r.account.is_none() && r.link.is_none());
    }
}
