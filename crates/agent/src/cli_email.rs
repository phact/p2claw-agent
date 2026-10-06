//! Client-side handlers for `p2claw email ...`. Thin HTTP calls
//! against the running agent's `/v1/email` endpoints over its Unix
//! socket; the server side lives in `local_api/email.rs`.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::UnixStream;

use crate::cli_client::{
    fail, format_age, print_server_error, resolve_sock, stdout_write_raw, uds_request, ClientError,
};
use p2claw_agent::email::normalize_address;

#[derive(Deserialize)]
struct Summary {
    enabled: bool,
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    allowlist: Vec<String>,
    #[serde(default)]
    unread: usize,
    #[serde(default)]
    total: usize,
    #[serde(default)]
    forwarding_requests: usize,
    #[serde(default)]
    config_error: Option<String>,
    #[serde(default)]
    rejections: Option<RejectionTotals>,
    #[serde(default)]
    pending_sync: bool,
}

#[derive(Deserialize)]
struct RejectionTotals {
    #[serde(default)]
    totals: BTreeMap<String, u64>,
    #[serde(default)]
    admitted_today: u32,
    #[serde(default)]
    daily_limit: u32,
}

#[derive(Deserialize)]
struct AllowlistResponse {
    allowlist: Vec<String>,
    #[serde(default)]
    pending_sync: bool,
}

#[derive(Deserialize)]
struct ForwardingBody {
    #[serde(default)]
    requests: Vec<ForwardingRequest>,
    #[serde(default)]
    approved: Vec<String>,
    #[serde(default)]
    pending_sync: bool,
}

#[derive(Deserialize)]
struct ForwardingRequest {
    account: Option<String>,
    link: Option<String>,
    received_at: u64,
}

#[derive(Deserialize)]
struct MessagesBody {
    messages: Vec<MessageRecord>,
}

#[derive(Deserialize)]
struct MessageRecord {
    id: String,
    kind: String,
    received_at: String,
    #[serde(default)]
    to: Option<String>,
    from: String,
    #[serde(default)]
    forwarded_by: Option<String>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    html: Option<String>,
    #[serde(default)]
    attachments: Vec<AttachmentRecord>,
    #[serde(default)]
    attachment_count: u32,
    #[serde(default)]
    auth: Option<serde_json::Value>,
    #[serde(default)]
    acked: bool,
}

#[derive(Deserialize)]
struct AttachmentRecord {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type")]
    content_type: String,
    size: u64,
}

#[derive(Deserialize)]
struct Rejections {
    #[serde(default)]
    totals: BTreeMap<String, u64>,
    #[serde(default)]
    recent: Vec<RejectedSender>,
    #[serde(default)]
    admitted_today: u32,
    #[serde(default)]
    daily_limit: u32,
}

#[derive(Deserialize)]
struct RejectedSender {
    from: String,
    reason: String,
    count: u64,
    last_seen: u64,
}

fn failed() -> ExitCode {
    ExitCode::from(2)
}

/// `p2claw email` → settings, addresses and counts.
pub async fn cmd_summary(json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let bytes = match get(&sock, "/v1/email").await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let s: Summary = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    print_summary(&s);
    ExitCode::SUCCESS
}

fn print_summary(s: &Summary) {
    println!(
        "email:       {}",
        if s.enabled { "enabled" } else { "disabled" }
    );
    if s.addresses.is_empty() {
        println!(
            "addresses:   {}",
            if s.enabled {
                "(none yet; waiting for coordination)"
            } else {
                "(none; run `p2claw email enable`)"
            }
        );
    } else {
        println!("addresses:   {}", s.addresses.join(", "));
    }
    if s.allowlist.is_empty() {
        println!("allowlist:   (empty; nothing is accepted until you `p2claw email allow <addr>`)");
    } else {
        println!("allowlist:   {} address(es)", s.allowlist.len());
        for a in &s.allowlist {
            println!("  - {a}");
        }
    }
    println!("messages:    {} unread of {}", s.unread, s.total);
    match &s.rejections {
        Some(r) => {
            let totals: Vec<String> = r.totals.iter().map(|(k, v)| format!("{k} {v}")).collect();
            println!(
                "rejected:    {}",
                if totals.is_empty() {
                    "none".to_string()
                } else {
                    totals.join(", ")
                }
            );
            println!(
                "today:       {} of {} admitted",
                r.admitted_today, r.daily_limit
            );
        }
        None => println!("rejected:    (unavailable; coordination unreachable)"),
    }
    if s.forwarding_requests > 0 {
        println!(
            "forwarding:  {} pending request(s); see `p2claw email forwarding`",
            s.forwarding_requests
        );
    }
    if let Some(err) = &s.config_error {
        println!("warning:     coordination refused the settings: {err}");
    }
    if s.pending_sync {
        println!("warning:     settings saved locally; coordination has not confirmed them yet");
    }
}

/// `p2claw email enable` / `disable`.
pub async fn cmd_set_enabled(enabled: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let body = Bytes::from(format!(r#"{{"enabled":{enabled}}}"#));
    let (status, bytes) = match uds_request(&sock, Method::PUT, "/v1/email", Some(body)).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return failed();
    }
    let s: Summary = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    print_summary(&s);
    ExitCode::SUCCESS
}

/// `p2claw email allow <addr>...` → merge into the allowlist.
pub async fn cmd_allow(addrs: Vec<String>) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let mut list = match current_allowlist(&sock).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    for a in addrs {
        let n = match normalize_address(&a) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("error: {e}");
                return failed();
            }
        };
        if !list.contains(&n) {
            list.push(n);
        }
    }
    put_allowlist(&sock, list).await
}

/// `p2claw email disallow <addr>` → remove from the allowlist.
pub async fn cmd_disallow(addr: String) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let target = match normalize_address(&addr) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: {e}");
            return failed();
        }
    };
    let mut list = match current_allowlist(&sock).await {
        Ok(l) => l,
        Err(code) => return code,
    };
    let before = list.len();
    list.retain(|a| a != &target);
    if list.len() == before {
        eprintln!("error: `{target}` is not on the allowlist");
        return failed();
    }
    put_allowlist(&sock, list).await
}

async fn current_allowlist(sock: &Path) -> Result<Vec<String>, ExitCode> {
    let bytes = get(sock, "/v1/email").await?;
    let s: Summary = parse(&bytes)?;
    Ok(s.allowlist)
}

async fn put_allowlist(sock: &Path, list: Vec<String>) -> ExitCode {
    let body = match serde_json::to_vec(&serde_json::json!({ "allowlist": list })) {
        Ok(b) => Bytes::from(b),
        Err(e) => return fail(&ClientError::Json(e)),
    };
    let (status, bytes) =
        match uds_request(sock, Method::PUT, "/v1/email/allowlist", Some(body)).await {
            Ok(v) => v,
            Err(e) => return fail(&e),
        };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return failed();
    }
    let r: AllowlistResponse = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if r.allowlist.is_empty() {
        println!("allowlist is empty; nothing is accepted");
    } else {
        println!("allowlist: {} address(es)", r.allowlist.len());
        for a in &r.allowlist {
            println!("  - {a}");
        }
    }
    if r.pending_sync {
        println!("warning: saved locally; coordination has not confirmed the change yet");
    }
    ExitCode::SUCCESS
}

/// `p2claw email forwarding` → pending confirmation requests and
/// approved forwarders.
pub async fn cmd_forwarding(json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let bytes = match get(&sock, "/v1/email/forwarding").await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let b: ForwardingBody = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    print_forwarding(&b);
    ExitCode::SUCCESS
}

fn print_forwarding(b: &ForwardingBody) {
    if b.requests.is_empty() {
        println!("no pending forwarding requests");
    } else {
        println!(
            "pending requests (open the link to confirm with Gmail, then approve the account):"
        );
        for r in &b.requests {
            let account = r
                .account
                .as_deref()
                .unwrap_or("(account not found in the message)");
            println!("  {account}  ({})", format_age(r.received_at as i64));
            match &r.link {
                Some(l) => println!("    link:    {l}"),
                None => println!("    link:    (not found in the message)"),
            }
            if let Some(a) = &r.account {
                println!("    approve: p2claw email forwarding approve {a}");
            }
        }
    }
    if b.approved.is_empty() {
        println!("approved forwarders: none");
    } else {
        println!("approved forwarders:");
        for a in &b.approved {
            println!("  - {a}");
        }
    }
    if b.pending_sync {
        println!("warning: saved locally; coordination has not confirmed the change yet");
    }
}

/// `p2claw email forwarding approve <account>` / `revoke <account>`.
pub async fn cmd_forwarding_set(account: String, approve: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let account = match normalize_address(&account) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: {e}");
            return failed();
        }
    };
    let method = if approve {
        Method::POST
    } else {
        Method::DELETE
    };
    let path = format!("/v1/email/forwarding/{account}");
    let (status, bytes) = match uds_request(&sock, method, &path, None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return failed();
    }
    let b: ForwardingBody = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    println!(
        "{account}: {}",
        if approve { "approved" } else { "revoked" }
    );
    print_forwarding(&b);
    ExitCode::SUCCESS
}

/// `p2claw email list [--unread]`.
pub async fn cmd_list(unread: bool, json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let path = if unread {
        "/v1/email/messages?unread=1"
    } else {
        "/v1/email/messages"
    };
    let bytes = match get(&sock, path).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let b: MessagesBody = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if b.messages.is_empty() {
        println!("{}", if unread { "no unread mail" } else { "no mail" });
        return ExitCode::SUCCESS;
    }
    println!(
        "{:<30}  {:<20}  {:<3}  {:<32}  SUBJECT",
        "ID", "RECEIVED", "", "FROM"
    );
    for m in &b.messages {
        let flag = match (m.kind.as_str(), m.acked) {
            ("expired", _) => "exp",
            (_, false) => "new",
            (_, true) => "",
        };
        let mut subject = m.subject.clone();
        if m.attachment_count > 0 {
            subject.push_str(&format!(" [{} attachment(s)]", m.attachment_count));
        }
        println!(
            "{:<30}  {:<20}  {:<3}  {:<32}  {}",
            m.id,
            m.received_at,
            flag,
            truncate(&m.from, 32),
            subject
        );
    }
    println!("\n{} message(s)", b.messages.len());
    ExitCode::SUCCESS
}

/// `p2claw email show <id> [--raw]`.
pub async fn cmd_show(id: String, raw: bool, json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    if raw {
        let bytes = match get(&sock, &format!("/v1/email/messages/{id}?format=raw")).await {
            Ok(b) => b,
            Err(code) => return code,
        };
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        let _ = lock.write_all(&bytes);
        return ExitCode::SUCCESS;
    }
    let bytes = match get(&sock, &format!("/v1/email/messages/{id}")).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let m: MessageRecord = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    println!("id:        {}", m.id);
    if m.kind == "expired" {
        println!(
            "kind:      expired (coordination dropped the body before this machine fetched it)"
        );
    }
    println!("received:  {}", m.received_at);
    println!("from:      {}", m.from);
    if let Some(to) = &m.to {
        println!("to:        {to}");
    }
    if let Some(f) = &m.forwarded_by {
        println!("forwarded: by {f}");
    }
    println!("subject:   {}", m.subject);
    if let Some(auth) = &m.auth {
        let dkim = auth.get("dkim").and_then(|v| v.as_str()).unwrap_or("?");
        let domain = auth
            .get("dkim_domain")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let arc = auth.get("arc").and_then(|v| v.as_str()).unwrap_or("?");
        println!("auth:      dkim {dkim} ({domain}), arc {arc}");
    }
    println!("status:    {}", if m.acked { "acked" } else { "unread" });
    if !m.attachments.is_empty() {
        println!("attachments:");
        for a in &m.attachments {
            println!(
                "  {}  {}  {}  {} bytes",
                a.id,
                a.name.as_deref().unwrap_or("(unnamed)"),
                a.content_type,
                a.size
            );
        }
    }
    if m.kind != "expired" {
        println!();
        match (&m.text, &m.html) {
            (Some(t), _) => println!("{t}"),
            (None, Some(h)) => println!("{h}"),
            (None, None) => println!("(no body)"),
        }
    }
    ExitCode::SUCCESS
}

/// `p2claw email attachment <id> <aid> [--output PATH]`: bytes to
/// stdout, or to a file.
pub async fn cmd_attachment(id: String, aid: String, output: Option<PathBuf>) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let bytes = match get(&sock, &format!("/v1/email/messages/{id}/attachments/{aid}")).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    match output {
        Some(path) => match std::fs::write(&path, &bytes) {
            Ok(()) => {
                println!("wrote {} bytes to {}", bytes.len(), path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: could not write {}: {e}", path.display());
                failed()
            }
        },
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            let _ = lock.write_all(&bytes);
            ExitCode::SUCCESS
        }
    }
}

/// `p2claw email ack <id>`.
pub async fn cmd_ack(id: String) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let path = format!("/v1/email/messages/{id}/ack");
    let (status, bytes) = match uds_request(&sock, Method::POST, &path, None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return failed();
    }
    println!("{id}: acked");
    ExitCode::SUCCESS
}

/// `p2claw email rm <id>`.
pub async fn cmd_rm(id: String) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let path = format!("/v1/email/messages/{id}");
    let (status, bytes) = match uds_request(&sock, Method::DELETE, &path, None).await {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    if status != StatusCode::NO_CONTENT && status != StatusCode::OK {
        print_server_error(status, &bytes);
        return failed();
    }
    println!("{id}: deleted");
    ExitCode::SUCCESS
}

/// `p2claw email watch`: print each new message id as JSON lines
/// until the agent goes away or the user interrupts.
pub async fn cmd_watch() -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let stream = match UnixStream::connect(&sock).await {
        Ok(s) => s,
        Err(e) => {
            return fail(&ClientError::Connect {
                path: sock.display().to_string(),
                source: e,
            })
        }
    };
    let (mut sender, conn) = match http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream)).await {
        Ok(v) => v,
        Err(e) => return fail(&ClientError::Hyper(e)),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = match Request::builder()
        .method(Method::GET)
        .uri("/v1/email/messages?watch=1")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
    {
        Ok(r) => r,
        Err(e) => return fail(&ClientError::Build(e)),
    };
    let resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => return fail(&ClientError::Hyper(e)),
    };
    if resp.status() != StatusCode::OK {
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        print_server_error(status, &body);
        return failed();
    }
    let mut body = resp.into_body();
    let stdout = io::stdout();
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(f) => {
                if let Some(data) = f.data_ref() {
                    let mut lock = stdout.lock();
                    let _ = lock.write_all(data);
                    let _ = lock.flush();
                }
            }
            Err(e) => {
                eprintln!("error: watch stream ended: {e}");
                return failed();
            }
        }
    }
    ExitCode::SUCCESS
}

/// `p2claw email rejected`: senders coord turned away, an over-limit
/// sender first, each with the command that silences it.
pub async fn cmd_rejected(json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let bytes = match get(&sock, "/v1/email/rejected").await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let r: Rejections = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    print_rejections(&r);
    ExitCode::SUCCESS
}

fn print_rejections(r: &Rejections) {
    println!("today: {} of {} admitted", r.admitted_today, r.daily_limit);
    if r.totals.is_empty() {
        println!("totals: none rejected");
    } else {
        let totals: Vec<String> = r.totals.iter().map(|(k, v)| format!("{k} {v}")).collect();
        println!("totals: {}", totals.join(", "));
    }
    if r.recent.is_empty() {
        println!("no rejected senders");
        return;
    }
    println!();
    println!(
        "{:<40}  {:<16}  {:>6}  LAST SEEN",
        "FROM", "REASON", "COUNT"
    );
    for s in order_rejected(&r.recent) {
        println!(
            "{:<40}  {:<16}  {:>6}  {}",
            truncate(&s.from, 40),
            s.reason,
            s.count,
            format_age(s.last_seen as i64)
        );
        if s.reason == "over_limit" {
            println!(
                "  over the daily limit; stop it with: p2claw email disallow {}",
                s.from
            );
        }
    }
}

/// Over-limit senders first (they are costing legitimate mail), then
/// the rest in coord's newest-first order.
fn order_rejected(recent: &[RejectedSender]) -> Vec<&RejectedSender> {
    let mut v: Vec<&RejectedSender> = recent.iter().collect();
    v.sort_by_key(|s| s.reason != "over_limit");
    v
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

async fn get(sock: &Path, path: &str) -> Result<Bytes, ExitCode> {
    let (status, bytes) = match uds_request(sock, Method::GET, path, None).await {
        Ok(v) => v,
        Err(e) => return Err(fail(&e)),
    };
    if status != StatusCode::OK {
        print_server_error(status, &bytes);
        return Err(failed());
    }
    Ok(bytes)
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ExitCode> {
    serde_json::from_slice(bytes).map_err(|e| {
        eprintln!("error: agent returned unexpected JSON: {e}");
        failed()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn over_limit_senders_sort_first() {
        let recent = vec![
            RejectedSender {
                from: "a@x.org".into(),
                reason: "not_allowed".into(),
                count: 1,
                last_seen: 3,
            },
            RejectedSender {
                from: "b@x.org".into(),
                reason: "over_limit".into(),
                count: 900,
                last_seen: 2,
            },
            RejectedSender {
                from: "c@x.org".into(),
                reason: "unauthenticated".into(),
                count: 1,
                last_seen: 1,
            },
        ];
        let order: Vec<&str> = order_rejected(&recent)
            .iter()
            .map(|s| s.from.as_str())
            .collect();
        assert_eq!(order, ["b@x.org", "a@x.org", "c@x.org"]);
    }

    #[test]
    fn truncate_keeps_short_strings() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdefgh", 5), "abcd…");
    }
}
