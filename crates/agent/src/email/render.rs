//! Message records for the local API, parsed on demand from the
//! stored RFC 5322 bytes.
//!
//! A listing carries only the index row (no bodies); a single `GET`
//! adds the text and HTML bodies and the attachment table. Attachment
//! ids are `a_<n>`, the 1-based position in the message's attachment
//! list, so they are stable for a stored message without being kept
//! in the index.

use mail_parser::{MessageParser, MimeHeaders};
use p2claw_email_proto::Auth;
use serde::Serialize;

use super::inbox::{Entry, EntryKind};
use super::rfc3339;

/// What the inbox caches at store time.
pub struct Headline {
    pub subject: String,
    pub attachment_count: u32,
}

pub fn headline(raw: &[u8]) -> Headline {
    match MessageParser::default().parse(raw) {
        Some(m) => Headline {
            subject: m.subject().unwrap_or_default().to_string(),
            attachment_count: m.attachment_count() as u32,
        },
        None => Headline {
            subject: String::new(),
            attachment_count: 0,
        },
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AttachmentRecord {
    pub id: String,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub content_type: String,
    pub size: u64,
}

/// One message as the local API presents it. `text`, `html` and
/// `attachments` are present only on a full record.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MessageRecord {
    pub id: String,
    pub kind: EntryKind,
    pub received_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    pub from: String,
    pub forwarded_by: Option<String>,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<AttachmentRecord>>,
    pub attachment_count: u32,
    pub auth: Option<Auth>,
    pub acked: bool,
    pub size: u64,
}

/// The light form used by listings.
pub fn summary(e: &Entry) -> MessageRecord {
    MessageRecord {
        id: e.id.clone(),
        kind: e.kind,
        received_at: rfc3339(e.received_at),
        to: (e.kind == EntryKind::Message).then(|| e.to.clone()),
        from: e.from.clone(),
        forwarded_by: e.forwarded_by.clone(),
        subject: e.subject.clone(),
        text: None,
        html: None,
        attachments: None,
        attachment_count: e.attachment_count,
        auth: e.auth.clone(),
        acked: e.acked,
        size: e.size,
    }
}

/// The full form: bodies and attachment table parsed from `raw`.
pub fn full(e: &Entry, raw: &[u8]) -> MessageRecord {
    let mut rec = summary(e);
    let Some(m) = MessageParser::default().parse(raw) else {
        rec.attachments = Some(Vec::new());
        return rec;
    };
    rec.text = m.body_text(0).map(|c| c.into_owned());
    rec.html = m.body_html(0).map(|c| c.into_owned());
    rec.attachments = Some(
        m.attachments()
            .enumerate()
            .map(|(i, part)| AttachmentRecord {
                id: format!("a_{}", i + 1),
                name: part.attachment_name().map(str::to_string),
                content_type: content_type_of(part),
                size: part.contents().len() as u64,
            })
            .collect(),
    );
    rec
}

/// One attachment's bytes, by id.
pub struct Attachment {
    pub name: Option<String>,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

pub fn attachment(raw: &[u8], aid: &str) -> Option<Attachment> {
    let n: usize = aid.strip_prefix("a_")?.parse().ok()?;
    let m = MessageParser::default().parse(raw)?;
    let part = m.attachments().nth(n.checked_sub(1)?)?;
    Some(Attachment {
        name: part.attachment_name().map(str::to_string),
        content_type: content_type_of(part),
        bytes: part.contents().to_vec(),
    })
}

fn content_type_of(part: &mail_parser::MessagePart<'_>) -> String {
    match part.content_type() {
        Some(ct) => match ct.subtype() {
            Some(sub) => format!("{}/{}", ct.ctype(), sub).to_ascii_lowercase(),
            None => ct.ctype().to_ascii_lowercase(),
        },
        None => "application/octet-stream".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTIPART: &str = "From: You <you@gmail.com>\r\n\
To: alias@p2claw.com\r\n\
Subject: =?utf-8?q?Invoice_f=C3=BCr_dich?=\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b1\"\r\n\
\r\n\
--b1\r\n\
Content-Type: multipart/alternative; boundary=\"b2\"\r\n\
\r\n\
--b2\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hi there\r\n\
--b2\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Hi <b>there</b></p>\r\n\
--b2--\r\n\
--b1\r\n\
Content-Type: application/pdf; name=\"invoice.pdf\"\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQK\r\n\
--b1--\r\n";

    fn entry() -> Entry {
        let h = headline(MULTIPART.as_bytes());
        Entry {
            id: "m_1".into(),
            kind: EntryKind::Message,
            received_at: 1_791_126_131,
            stored_at: 1_791_126_200,
            to: "alias@p2claw.com".into(),
            from: "you@gmail.com".into(),
            forwarded_by: None,
            subject: h.subject,
            auth: Some(Auth {
                dkim: "pass".into(),
                dkim_domain: Some("gmail.com".into()),
                arc: "none".into(),
            }),
            acked: false,
            size: MULTIPART.len() as u64,
            attachment_count: h.attachment_count,
        }
    }

    #[test]
    fn headline_decodes_subject_and_counts_attachments() {
        let h = headline(MULTIPART.as_bytes());
        assert_eq!(h.subject, "Invoice für dich");
        assert_eq!(h.attachment_count, 1);
        let empty = headline(b"not a message");
        assert_eq!(empty.attachment_count, 0);
    }

    #[test]
    fn summary_has_no_bodies() {
        let v = serde_json::to_value(summary(&entry())).unwrap();
        assert_eq!(v["id"], "m_1");
        assert_eq!(v["kind"], "message");
        assert_eq!(v["received_at"], "2026-10-04T15:02:11Z");
        assert_eq!(v["to"], "alias@p2claw.com");
        assert_eq!(v["from"], "you@gmail.com");
        assert!(v["forwarded_by"].is_null());
        assert_eq!(v["subject"], "Invoice für dich");
        assert_eq!(v["auth"]["dkim"], "pass");
        assert_eq!(v["acked"], false);
        assert_eq!(v["attachment_count"], 1);
        assert!(v.get("text").is_none());
        assert!(v.get("html").is_none());
        assert!(v.get("attachments").is_none());
    }

    #[test]
    fn full_record_has_bodies_and_attachments() {
        let rec = full(&entry(), MULTIPART.as_bytes());
        assert_eq!(rec.text.as_deref(), Some("Hi there"));
        assert_eq!(rec.html.as_deref(), Some("<p>Hi <b>there</b></p>"));
        let atts = rec.attachments.unwrap();
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].id, "a_1");
        assert_eq!(atts[0].name.as_deref(), Some("invoice.pdf"));
        assert_eq!(atts[0].content_type, "application/pdf");
        assert_eq!(atts[0].size, 9);

        let a = attachment(MULTIPART.as_bytes(), "a_1").unwrap();
        assert_eq!(a.bytes, b"%PDF-1.4\n");
        assert!(attachment(MULTIPART.as_bytes(), "a_2").is_none());
        assert!(attachment(MULTIPART.as_bytes(), "a_0").is_none());
        assert!(attachment(MULTIPART.as_bytes(), "x").is_none());
    }

    #[test]
    fn expired_summary_omits_to() {
        let mut e = entry();
        e.kind = EntryKind::Expired;
        e.to.clear();
        let v = serde_json::to_value(summary(&e)).unwrap();
        assert_eq!(v["kind"], "expired");
        assert!(v.get("to").is_none());
    }
}
