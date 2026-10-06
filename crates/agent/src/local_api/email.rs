//! `/v1/email` handlers.
//!
//! Two groups, kept apart so they can later be served on different
//! sockets: owner operations (enable/disable, allowlist, forwarding
//! requests and approvals, rejection stats) and mail access (list,
//! get, raw, attachments, ack, delete, watch).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt as _;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use super::{full_body, json_response, ApiBody, ErrorBody, LocalApi};
use crate::email_link::LinkError;
use p2claw_agent::email::inbox::validate_id;
use p2claw_agent::email::{render, EntryKind, InboxError, SettingsError};

/// How long a settings change waits for coord's `email_config_ack`
/// before answering with `pending_sync: true`.
const CONFIG_WAIT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long `GET /v1/email` and `/v1/email/rejected` wait for coord.
const REJECTED_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn dispatch(
    api: &Arc<LocalApi>,
    req: Request<Incoming>,
    method: &Method,
    path: &str,
) -> Response<ApiBody> {
    let query = req.uri().query().unwrap_or("").to_string();
    let rest = path.strip_prefix("/v1/email").unwrap_or("");
    match (method, rest) {
        (&Method::GET, "") => summary_handler(api, false).await,
        (&Method::PUT, "") => put_settings_handler(api, req).await,
        (&Method::PUT, "/allowlist") => put_allowlist_handler(api, req).await,
        (&Method::GET, "/forwarding") => forwarding_handler(api).await,
        (&Method::GET, "/rejected") => rejected_handler(api).await,
        (&Method::GET, "/messages") => {
            if has_flag(&query, "watch") {
                watch_handler(api)
            } else {
                list_handler(api, has_flag(&query, "unread")).await
            }
        }
        _ => {
            if let Some(account) = rest.strip_prefix("/forwarding/") {
                if account.is_empty() || account.contains('/') {
                    return not_found();
                }
                return match *method {
                    Method::POST => approve_handler(api, account).await,
                    Method::DELETE => revoke_handler(api, account).await,
                    _ => method_not_allowed(),
                };
            }
            if let Some(tail) = rest.strip_prefix("/messages/") {
                let (id, sub) = tail.split_once('/').unwrap_or((tail, ""));
                if id.is_empty() || validate_id(id).is_err() {
                    return not_found();
                }
                return match (method, sub) {
                    (&Method::GET, "") => {
                        if query_value(&query, "format") == Some("raw") {
                            raw_handler(api, id).await
                        } else {
                            get_handler(api, id).await
                        }
                    }
                    (&Method::DELETE, "") => delete_handler(api, id).await,
                    (&Method::POST, "ack") => ack_handler(api, id).await,
                    (&Method::GET, s) if s.starts_with("attachments/") => {
                        let aid = &s["attachments/".len()..];
                        if aid.is_empty() || aid.contains('/') {
                            return not_found();
                        }
                        attachment_handler(api, id, aid).await
                    }
                    (_, "") | (_, "ack") => method_not_allowed(),
                    _ => not_found(),
                };
            }
            not_found()
        }
    }
}

// ---------- owner operations -------------------------------------------

/// Body of `GET /v1/email` and of the `PUT`s that change settings.
#[derive(Serialize)]
struct SummaryBody {
    enabled: bool,
    addresses: Vec<String>,
    allowlist: Vec<String>,
    unread: usize,
    total: usize,
    forwarding_requests: usize,
    /// Coord's objection to the last config, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    config_error: Option<String>,
    /// Rejection totals per reason; `None` when coord was unreachable.
    rejections: Option<RejectionTotals>,
    rejections_available: bool,
    /// `true` when the settings were saved locally but coord has not
    /// acknowledged them yet.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pending_sync: bool,
}

#[derive(Serialize)]
struct RejectionTotals {
    totals: std::collections::BTreeMap<String, u64>,
    admitted_today: u32,
    daily_limit: u32,
}

async fn summary(api: &LocalApi, pending_sync: bool) -> SummaryBody {
    let s = api.email.settings.snapshot();
    let rejections = match api.email_link.rejected(REJECTED_WAIT_TIMEOUT).await {
        Ok(r) => Some(RejectionTotals {
            totals: r.totals,
            admitted_today: r.admitted_today,
            daily_limit: r.daily_limit,
        }),
        Err(_) => None,
    };
    SummaryBody {
        enabled: s.enabled,
        addresses: s.addresses,
        allowlist: s.allowlist,
        unread: api.email.inbox.unread_count(),
        total: api.email.inbox.list(false).len(),
        forwarding_requests: api.email.inbox.forwarding_requests().len(),
        config_error: s.config_error,
        rejections_available: rejections.is_some(),
        rejections,
        pending_sync,
    }
}

async fn summary_handler(api: &LocalApi, pending_sync: bool) -> Response<ApiBody> {
    json_response(StatusCode::OK, &summary(api, pending_sync).await)
}

#[derive(Deserialize)]
struct SettingsBody {
    enabled: bool,
}

async fn put_settings_handler(api: &LocalApi, req: Request<Incoming>) -> Response<ApiBody> {
    let body: SettingsBody = match read_json(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    if let Err(e) = api.email.settings.set_enabled(body.enabled).await {
        return settings_error(e);
    }
    let pending = sync_config(api).await;
    summary_handler(api, pending).await
}

#[derive(Deserialize)]
struct AllowlistBody {
    allowlist: Vec<String>,
}

#[derive(Serialize)]
struct AllowlistResponse {
    allowlist: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pending_sync: bool,
}

async fn put_allowlist_handler(api: &LocalApi, req: Request<Incoming>) -> Response<ApiBody> {
    let body: AllowlistBody = match read_json(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let saved = match api.email.settings.replace_allowlist(body.allowlist).await {
        Ok(v) => v,
        Err(e) => return settings_error(e),
    };
    let pending_sync = sync_config(api).await;
    json_response(
        StatusCode::OK,
        &AllowlistResponse {
            allowlist: saved,
            pending_sync,
        },
    )
}

#[derive(Serialize)]
struct ForwardingBody {
    requests: Vec<p2claw_agent::email::ForwardingRequest>,
    approved: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pending_sync: bool,
}

fn forwarding_body(api: &LocalApi, pending_sync: bool) -> ForwardingBody {
    ForwardingBody {
        requests: api.email.inbox.forwarding_requests(),
        approved: api.email.settings.snapshot().forwarders,
        pending_sync,
    }
}

async fn forwarding_handler(api: &LocalApi) -> Response<ApiBody> {
    json_response(StatusCode::OK, &forwarding_body(api, false))
}

async fn approve_handler(api: &LocalApi, account: &str) -> Response<ApiBody> {
    let account = match api.email.settings.approve_forwarder(account).await {
        Ok(a) => a,
        Err(e) => return settings_error(e),
    };
    if let Err(e) = api.email.inbox.remove_forwarding_requests(&account).await {
        return inbox_error(e);
    }
    let pending = sync_config(api).await;
    json_response(StatusCode::OK, &forwarding_body(api, pending))
}

async fn revoke_handler(api: &LocalApi, account: &str) -> Response<ApiBody> {
    match api.email.settings.revoke_forwarder(account).await {
        Ok(true) => {}
        Ok(false) => {
            return json_response(
                StatusCode::NOT_FOUND,
                &ErrorBody {
                    error: "not_found",
                    detail: Some(format!("`{account}` is not an approved forwarder")),
                },
            )
        }
        Err(e) => return settings_error(e),
    }
    let pending = sync_config(api).await;
    json_response(StatusCode::OK, &forwarding_body(api, pending))
}

async fn rejected_handler(api: &LocalApi) -> Response<ApiBody> {
    match api.email_link.rejected(REJECTED_WAIT_TIMEOUT).await {
        Ok(r) => json_response(StatusCode::OK, &r),
        Err(LinkError::Pending) => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &ErrorBody {
                error: "coord_unreachable",
                detail: Some("the agent is not connected to coordination".into()),
            },
        ),
        Err(LinkError::Coord(msg)) => json_response(
            StatusCode::BAD_GATEWAY,
            &ErrorBody {
                error: "coord_error",
                detail: Some(msg),
            },
        ),
    }
}

/// Push the settings to coord; `true` when the ack didn't arrive in
/// time (the next reconnect re-sends the snapshot).
async fn sync_config(api: &LocalApi) -> bool {
    api.email_link
        .send_config_and_wait(CONFIG_WAIT_TIMEOUT)
        .await
        .is_err()
}

// ---------- mail access -------------------------------------------------

#[derive(Serialize)]
struct MessagesBody {
    messages: Vec<render::MessageRecord>,
}

async fn list_handler(api: &LocalApi, unread_only: bool) -> Response<ApiBody> {
    let messages = api
        .email
        .inbox
        .list(unread_only)
        .iter()
        .map(render::summary)
        .collect();
    json_response(StatusCode::OK, &MessagesBody { messages })
}

async fn get_handler(api: &LocalApi, id: &str) -> Response<ApiBody> {
    let Some(entry) = api.email.inbox.get(id) else {
        return not_found();
    };
    if entry.kind == EntryKind::Expired {
        return json_response(StatusCode::OK, &render::summary(&entry));
    }
    match api.email.inbox.raw(id).await {
        Ok(raw) => json_response(StatusCode::OK, &render::full(&entry, &raw)),
        Err(e) => inbox_error(e),
    }
}

async fn raw_handler(api: &LocalApi, id: &str) -> Response<ApiBody> {
    match api.email.inbox.raw(id).await {
        Ok(raw) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "message/rfc822")
            .body(full_body(Bytes::from(raw)))
            .expect("raw response"),
        Err(e) => inbox_error(e),
    }
}

async fn attachment_handler(api: &LocalApi, id: &str, aid: &str) -> Response<ApiBody> {
    let raw = match api.email.inbox.raw(id).await {
        Ok(raw) => raw,
        Err(e) => return inbox_error(e),
    };
    let aid = aid.to_string();
    let found = tokio::task::spawn_blocking(move || render::attachment(&raw, &aid))
        .await
        .ok()
        .flatten();
    let Some(a) = found else {
        return not_found();
    };
    let filename: String = a
        .name
        .as_deref()
        .unwrap_or("attachment")
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", a.content_type)
        .header(
            "content-disposition",
            format!("attachment; filename=\"{filename}\""),
        )
        .body(full_body(Bytes::from(a.bytes)))
        .expect("attachment response")
}

async fn ack_handler(api: &LocalApi, id: &str) -> Response<ApiBody> {
    match api.email.inbox.ack(id).await {
        Ok(entry) => json_response(StatusCode::OK, &render::summary(&entry)),
        Err(e) => inbox_error(e),
    }
}

async fn delete_handler(api: &LocalApi, id: &str) -> Response<ApiBody> {
    match api.email.inbox.delete(id).await {
        Ok(()) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(full_body(Bytes::new()))
            .expect("no-content response"),
        Err(e) => inbox_error(e),
    }
}

/// `?watch=1`: one JSON object per line, `{"id": ...}` for each entry
/// stored from now on. A subscriber that falls too far behind gets
/// `{"lagged": n}` and should re-list unread mail.
fn watch_handler(api: &LocalApi) -> Response<ApiBody> {
    let mut ids = api.email.inbox.subscribe();
    let (tx, rx) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        loop {
            let line = tokio::select! {
                r = ids.recv() => match r {
                    Ok(id) => format!("{{\"id\":{}}}\n", serde_json::Value::String(id)),
                    Err(broadcast::error::RecvError::Lagged(n)) => format!("{{\"lagged\":{n}}}\n"),
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = tx.closed() => break,
            };
            if tx.send(Bytes::from(line)).await.is_err() {
                break;
            }
        }
    });
    let body = BodyExt::boxed(StreamBody::new(
        ReceiverStream::new(rx).map(|b| Ok(Frame::data(b))),
    ));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-cache")
        .body(body)
        .expect("watch response")
}

// ---------- helpers -----------------------------------------------------

// The error is the response to send back, built only on the error path.
#[allow(clippy::result_large_err)]
async fn read_json<T: serde::de::DeserializeOwned>(
    req: Request<Incoming>,
) -> Result<T, Response<ApiBody>> {
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return Err(json_response(
                StatusCode::BAD_REQUEST,
                &ErrorBody {
                    error: "bad_body",
                    detail: Some(e.to_string()),
                },
            ))
        }
    };
    serde_json::from_slice(&body).map_err(|e| {
        json_response(
            StatusCode::BAD_REQUEST,
            &ErrorBody {
                error: "bad_json",
                detail: Some(e.to_string()),
            },
        )
    })
}

fn settings_error(e: SettingsError) -> Response<ApiBody> {
    match e {
        SettingsError::Address(a) => json_response(
            StatusCode::BAD_REQUEST,
            &ErrorBody {
                error: "bad_address",
                detail: Some(a.to_string()),
            },
        ),
        e @ SettingsError::Io { .. } => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &ErrorBody {
                error: "internal",
                detail: Some(e.to_string()),
            },
        ),
    }
}

fn inbox_error(e: InboxError) -> Response<ApiBody> {
    match e {
        InboxError::NotFound(_) | InboxError::BadId(_) => not_found(),
        e @ InboxError::Io { .. } => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &ErrorBody {
                error: "internal",
                detail: Some(e.to_string()),
            },
        ),
    }
}

fn not_found() -> Response<ApiBody> {
    json_response(
        StatusCode::NOT_FOUND,
        &ErrorBody {
            error: "not_found",
            detail: None,
        },
    )
}

fn method_not_allowed() -> Response<ApiBody> {
    json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        &ErrorBody {
            error: "method_not_allowed",
            detail: None,
        },
    )
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('=').or(Some((kv, ""))))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// `?key=1`, `?key=true` or a bare `?key`.
fn has_flag(query: &str, key: &str) -> bool {
    matches!(query_value(query, key), Some("1") | Some("true") | Some(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_flags() {
        assert!(has_flag("unread=1", "unread"));
        assert!(has_flag("watch", "watch"));
        assert!(has_flag("a=2&unread=true", "unread"));
        assert!(!has_flag("unread=0", "unread"));
        assert!(!has_flag("", "unread"));
        assert_eq!(query_value("format=raw&x=1", "format"), Some("raw"));
        assert_eq!(query_value("x=1", "format"), None);
    }
}
