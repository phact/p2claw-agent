//! `/v1/oauth-grants` handlers: consent flows and grants through
//! p2claw Connect.
//!
//! Flows: `POST /flows` starts one, `GET /flows/{id}[?wait=1]` reports
//! or long-polls for the callback, `POST /flows/{id}/exchange` turns
//! it into an access token plus either the grant (app-managed) or a
//! stored grant id (agent-managed). `POST /refresh` serves app-managed
//! grants; `GET /`, `GET /{id}/token` and `DELETE /{id}` serve stored
//! ones. `GET /providers` proxies the broker's list.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};

use super::{json_response, ApiBody, ErrorBody, LocalApi};
use p2claw_agent::oauth_grants::{BrokerError, FlowRefusal, GrantError, StartRequest};

/// Longest a `?wait=1` poll holds the request before answering
/// `pending`; clients loop.
const MAX_WAIT: Duration = Duration::from_secs(55);

pub(super) async fn dispatch(
    api: &Arc<LocalApi>,
    req: Request<Incoming>,
    method: &Method,
    path: &str,
) -> Response<ApiBody> {
    let query = req.uri().query().unwrap_or("").to_string();
    let rest = path.strip_prefix("/v1/oauth-grants").unwrap_or("");
    match (method, rest) {
        (&Method::GET, "") => list_handler(api),
        (&Method::GET, "/providers") => providers_handler(api).await,
        (&Method::POST, "/flows") => start_handler(api, req).await,
        (&Method::POST, "/refresh") => refresh_handler(api, req).await,
        (_, "" | "/providers" | "/flows" | "/refresh") => method_not_allowed(),
        _ => {
            if let Some(tail) = rest.strip_prefix("/flows/") {
                let (id, sub) = tail.split_once('/').unwrap_or((tail, ""));
                if !valid_id(id) {
                    return not_found();
                }
                return match (method, sub) {
                    (&Method::GET, "") => flow_handler(api, id, &query).await,
                    (&Method::POST, "exchange") => exchange_handler(api, id, req).await,
                    (_, "" | "exchange") => method_not_allowed(),
                    _ => not_found(),
                };
            }
            if let Some(tail) = rest.strip_prefix('/') {
                let (id, sub) = tail.split_once('/').unwrap_or((tail, ""));
                if !valid_id(id) {
                    return not_found();
                }
                return match (method, sub) {
                    (&Method::GET, "token") => token_handler(api, id).await,
                    (&Method::DELETE, "") => revoke_handler(api, id).await,
                    (_, "" | "token") => method_not_allowed(),
                    _ => not_found(),
                };
            }
            not_found()
        }
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// ---------- providers and flows ----------------------------------------

#[derive(Serialize)]
struct ProvidersBody {
    providers: Vec<p2claw_agent::oauth_grants::Provider>,
}

async fn providers_handler(api: &LocalApi) -> Response<ApiBody> {
    match api.oauth_grants.providers().await {
        Ok(providers) => json_response(StatusCode::OK, &ProvidersBody { providers }),
        Err(e) => grant_error(e),
    }
}

#[derive(Deserialize)]
struct StartBody {
    provider: String,
    #[serde(default)]
    scopes: Vec<String>,
    code_challenge: String,
    nonce_hash: String,
}

async fn start_handler(api: &LocalApi, req: Request<Incoming>) -> Response<ApiBody> {
    let body: StartBody = match read_json(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let started = api
        .oauth_grants
        .start(StartRequest {
            provider: body.provider,
            scopes: body.scopes,
            code_challenge: body.code_challenge,
            nonce_hash: body.nonce_hash,
        })
        .await;
    match started {
        Ok(s) => json_response(StatusCode::OK, &s),
        Err(e) => grant_error(e),
    }
}

async fn flow_handler(api: &LocalApi, id: &str, query: &str) -> Response<ApiBody> {
    let view = if has_flag(query, "wait") {
        let timeout = query_value(query, "timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(MAX_WAIT)
            .min(MAX_WAIT);
        api.oauth_grants.flows().wait(id, timeout).await
    } else {
        api.oauth_grants.flows().get(id)
    };
    match view {
        Some(v) => json_response(StatusCode::OK, &v),
        None => not_found(),
    }
}

#[derive(Deserialize)]
struct ExchangeBody {
    code_verifier: String,
    #[serde(default)]
    store: bool,
}

async fn exchange_handler(api: &LocalApi, id: &str, req: Request<Incoming>) -> Response<ApiBody> {
    let body: ExchangeBody = match read_json(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    match api
        .oauth_grants
        .exchange(id, &body.code_verifier, body.store)
        .await
    {
        Ok(ex) => json_response(StatusCode::OK, &ex),
        Err(e) => grant_error(e),
    }
}

#[derive(Deserialize)]
struct RefreshBody {
    provider: String,
    grant: String,
}

async fn refresh_handler(api: &LocalApi, req: Request<Incoming>) -> Response<ApiBody> {
    let body: RefreshBody = match read_json(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    match api.oauth_grants.refresh(&body.provider, &body.grant).await {
        Ok(tok) => json_response(StatusCode::OK, &tok),
        Err(e) => grant_error(e),
    }
}

// ---------- stored grants ----------------------------------------------

#[derive(Serialize)]
struct GrantsBody {
    grants: Vec<p2claw_agent::oauth_grants::GrantSummary>,
}

fn list_handler(api: &LocalApi) -> Response<ApiBody> {
    json_response(
        StatusCode::OK,
        &GrantsBody {
            grants: api.oauth_grants.list(),
        },
    )
}

async fn token_handler(api: &LocalApi, id: &str) -> Response<ApiBody> {
    match api.oauth_grants.token(id).await {
        Ok(t) => json_response(StatusCode::OK, &t),
        Err(e) => grant_error(e),
    }
}

async fn revoke_handler(api: &LocalApi, id: &str) -> Response<ApiBody> {
    match api.oauth_grants.revoke(id).await {
        Ok(r) => json_response(StatusCode::OK, &r),
        Err(e) => grant_error(e),
    }
}

// ---------- helpers -----------------------------------------------------

fn grant_error(e: GrantError) -> Response<ApiBody> {
    let (status, error, detail) = match e {
        GrantError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", Some(m)),
        GrantError::NotFound | GrantError::Flow(FlowRefusal::Unknown) => {
            (StatusCode::NOT_FOUND, "not_found", None)
        }
        GrantError::InvalidGrant | GrantError::Broker(BrokerError::InvalidGrant) => (
            StatusCode::GONE,
            "invalid_grant",
            Some("the provider rejected the grant; consent again".into()),
        ),
        GrantError::Flow(FlowRefusal::Pending) => (
            StatusCode::CONFLICT,
            "flow_pending",
            Some("the flow has no callback yet; wait for it first".into()),
        ),
        GrantError::Flow(FlowRefusal::Failed(err)) => (
            StatusCode::CONFLICT,
            "flow_failed",
            Some(format!("the provider returned an error: {err}")),
        ),
        GrantError::Flow(FlowRefusal::Expired) => (
            StatusCode::GONE,
            "flow_expired",
            Some("the flow expired; start again".into()),
        ),
        GrantError::Flow(FlowRefusal::Consumed) => (
            StatusCode::CONFLICT,
            "flow_consumed",
            Some("the flow was already exchanged".into()),
        ),
        GrantError::Broker(BrokerError::Provider { detail }) => {
            (StatusCode::BAD_GATEWAY, "provider_error", Some(detail))
        }
        GrantError::Broker(BrokerError::Rejected { status, detail }) if status < 500 => (
            StatusCode::BAD_REQUEST,
            "broker_rejected",
            Some(format!("{detail} (broker answered {status})")),
        ),
        GrantError::Broker(BrokerError::Unreachable(m)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "broker_unreachable",
            Some(m),
        ),
        GrantError::Broker(e) => (StatusCode::BAD_GATEWAY, "broker_error", Some(e.to_string())),
        GrantError::Store(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            Some(e.to_string()),
        ),
    };
    json_response(status, &ErrorBody { error, detail })
}

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

fn has_flag(query: &str, key: &str) -> bool {
    matches!(query_value(query, key), Some("1") | Some("true") | Some(""))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{body_json, http_over_uds, make_api_with_broker, request};
    use super::super::{serve, LocalApi};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
    use base64::Engine as _;
    use p2claw_identity::{verify_box_request, PeerId, Signature};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tokio::sync::watch;

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const NONCE_HASH: &str = "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg";

    /// Broker stand-in: verifies every signed request against the
    /// `peer` header exactly as the real broker does, then answers
    /// with canned bodies. It also plays the provider's revoke
    /// endpoint.
    #[derive(Default)]
    struct MockBroker {
        url: Mutex<String>,
        refreshes: AtomicUsize,
        /// Lifetime of tokens the exchange hands out.
        exchange_expires_in: AtomicU64,
        last_exchange: Mutex<Option<Value>>,
        dead_grants: Mutex<HashSet<String>>,
        revoked_tokens: Mutex<Vec<String>>,
        /// Peer ids seen on signed requests.
        signers: Mutex<HashSet<String>>,
    }

    // The error is the response to send back, built only on failure.
    #[allow(clippy::result_large_err)]
    fn verify(
        headers: &HeaderMap,
        method: &Method,
        uri: &Uri,
        body: &[u8],
    ) -> Result<String, Response> {
        let unauthorized = |why: &str| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "bad_signature", "detail": why})),
            )
                .into_response()
        };
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let peer = header("x-p2claw-peer").ok_or_else(|| unauthorized("missing peer"))?;
        let ts: u64 = header("x-p2claw-timestamp")
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| unauthorized("missing timestamp"))?;
        let sig = header("x-p2claw-signature").ok_or_else(|| unauthorized("missing signature"))?;
        let host = header("host").ok_or_else(|| unauthorized("missing host"))?;
        let pid = PeerId::from_z32(&peer).map_err(|_| unauthorized("bad peer"))?;
        let sig_bytes: [u8; 64] = B64_URL
            .decode(&sig)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| unauthorized("bad signature encoding"))?;
        let path = uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| uri.path().to_string());
        let digest: [u8; 32] = Sha256::digest(body).into();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        verify_box_request(
            &pid,
            &host,
            method.as_str(),
            &path,
            ts,
            &digest,
            &Signature::from_bytes(&sig_bytes),
            now,
        )
        .map_err(|e| unauthorized(&e.to_string()))?;
        Ok(peer)
    }

    async fn providers(State(b): State<Arc<MockBroker>>) -> Json<Value> {
        let url = b.url.lock().unwrap().clone();
        Json(json!({"providers": [{
            "name": "google",
            "scopes": ["calendar.app.created", "calendar.events.freebusy"],
            "revoke_url": format!("{url}/revoke"),
        }]}))
    }

    async fn flows(
        State(b): State<Arc<MockBroker>>,
        Path(provider): Path<String>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let peer = match verify(&headers, &method, &uri, &body) {
            Ok(p) => p,
            Err(r) => return r,
        };
        b.signers.lock().unwrap().insert(peer);
        if provider != "google" {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "unknown_provider"})),
            )
                .into_response();
        }
        let v: Value = serde_json::from_slice(&body).unwrap();
        let flow_id = v["flow_id"].as_str().unwrap();
        assert_eq!(v["code_challenge"], CHALLENGE);
        assert_eq!(v["nonce_hash"], NONCE_HASH);
        Json(json!({
            "authorize_url": format!("https://accounts.google.com/o/oauth2/v2/auth?state=s1.{flow_id}.sig")
        }))
        .into_response()
    }

    async fn exchange(
        State(b): State<Arc<MockBroker>>,
        Path(_provider): Path<String>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        if let Err(r) = verify(&headers, &method, &uri, &body) {
            return r;
        }
        let v: Value = serde_json::from_slice(&body).unwrap();
        *b.last_exchange.lock().unwrap() = Some(v.clone());
        Json(json!({
            "access_token": format!("at-{}", v["code"].as_str().unwrap()),
            "expires_in": b.exchange_expires_in.load(Ordering::SeqCst),
            "scope": "calendar.app.created",
            "grant": format!("g1.k1.{}", v["flow_id"].as_str().unwrap()),
        }))
        .into_response()
    }

    async fn refresh(
        State(b): State<Arc<MockBroker>>,
        Path(_provider): Path<String>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        if let Err(r) = verify(&headers, &method, &uri, &body) {
            return r;
        }
        let n = b.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
        let v: Value = serde_json::from_slice(&body).unwrap();
        let grant = v["grant"].as_str().unwrap();
        if b.dead_grants.lock().unwrap().contains(grant) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_grant"})),
            )
                .into_response();
        }
        Json(json!({"access_token": format!("fresh-{n}"), "expires_in": 3600})).into_response()
    }

    async fn revoke(State(b): State<Arc<MockBroker>>, body: String) -> StatusCode {
        let token = body
            .split('&')
            .find_map(|kv| kv.strip_prefix("token="))
            .unwrap_or("")
            .to_string();
        b.revoked_tokens.lock().unwrap().push(token);
        StatusCode::OK
    }

    async fn spawn_broker() -> Arc<MockBroker> {
        let state = Arc::new(MockBroker {
            exchange_expires_in: AtomicU64::new(3600),
            ..Default::default()
        });
        let app = Router::new()
            .route("/connect/providers", get(providers))
            .route("/connect/:provider/flows", post(flows))
            .route("/connect/:provider/exchange", post(exchange))
            .route("/connect/:provider/refresh", post(refresh))
            .route("/revoke", post(revoke))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        *state.url.lock().unwrap() = format!("http://{addr}");
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        state
    }

    async fn with_broker_server<F, Fut>(f: F)
    where
        F: FnOnce(PathBuf, Arc<LocalApi>, Arc<MockBroker>) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let broker = spawn_broker().await;
        let url = broker.url.lock().unwrap().clone();
        let (api, _acker, _tmp) =
            make_api_with_broker(super::super::tests::AckMode::AcceptAll, &url);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let api_cl = Arc::clone(&api);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api_cl, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(sock.exists(), "socket did not appear");
        f(sock, api, broker).await;
        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    fn start_body() -> String {
        json!({
            "provider": "google",
            "scopes": ["calendar.app.created"],
            "code_challenge": CHALLENGE,
            "nonce_hash": NONCE_HASH,
        })
        .to_string()
    }

    async fn start_flow(sock: &std::path::Path) -> String {
        let text = http_over_uds(
            sock,
            &request("POST", "/v1/oauth-grants/flows", Some(&start_body())),
        )
        .await;
        assert!(text.contains("200 OK"), "{text}");
        let v = body_json(&text);
        let flow_id = v["flow_id"].as_str().unwrap().to_string();
        assert!(flow_id.starts_with("f_"));
        assert!(v["authorize_url"].as_str().unwrap().contains(&flow_id));
        flow_id
    }

    #[tokio::test]
    async fn providers_proxy_the_broker() {
        with_broker_server(|sock, _api, broker| async move {
            let text =
                http_over_uds(&sock, &request("GET", "/v1/oauth-grants/providers", None)).await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            assert_eq!(v["providers"][0]["name"], "google");
            let url = broker.url.lock().unwrap().clone();
            assert_eq!(v["providers"][0]["revoke_url"], format!("{url}/revoke"));
        })
        .await;
    }

    #[tokio::test]
    async fn flow_waits_for_the_callback_and_exchanges_app_managed() {
        with_broker_server(|sock, api, broker| async move {
            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    "/v1/oauth-grants/flows",
                    Some(r#"{"provider":"google"}"#),
                ),
            )
            .await;
            assert!(text.contains("400 Bad Request"), "{text}");

            let flow_id = start_flow(&sock).await;
            assert_eq!(broker.signers.lock().unwrap().len(), 1);
            let text = http_over_uds(
                &sock,
                &request("GET", &format!("/v1/oauth-grants/flows/{flow_id}"), None),
            )
            .await;
            assert_eq!(body_json(&text)["status"], "pending");

            // A bounded wait returns pending when nothing arrives.
            let text = http_over_uds(
                &sock,
                &request(
                    "GET",
                    &format!("/v1/oauth-grants/flows/{flow_id}?wait=1&timeout=1"),
                    None,
                ),
            )
            .await;
            assert_eq!(body_json(&text)["status"], "pending");

            // Exchange before the callback is refused.
            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    &format!("/v1/oauth-grants/flows/{flow_id}/exchange"),
                    Some(r#"{"code_verifier":"v","store":false}"#),
                ),
            )
            .await;
            assert!(text.contains("409 Conflict"), "{text}");
            assert_eq!(body_json(&text)["error"], "flow_pending");

            // Long-poll, then deliver the callback the way the control
            // handler does.
            let waiter = {
                let sock = sock.clone();
                let flow_id = flow_id.clone();
                tokio::spawn(async move {
                    http_over_uds(
                        &sock,
                        &request(
                            "GET",
                            &format!("/v1/oauth-grants/flows/{flow_id}?wait=1"),
                            None,
                        ),
                    )
                    .await
                })
            };
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!api.oauth_grants.flows().deliver(
                "f_unknown",
                Some("x".into()),
                None,
                "s".into()
            ));
            assert!(api.oauth_grants.flows().deliver(
                &flow_id,
                Some("c0de".into()),
                None,
                "s1.p.sig".into()
            ));
            let v = body_json(&waiter.await.unwrap());
            assert_eq!(v["status"], "ready");
            assert_eq!(v["code"], "c0de");
            assert_eq!(v["state"], "s1.p.sig");

            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    &format!("/v1/oauth-grants/flows/{flow_id}/exchange"),
                    Some(r#"{"code_verifier":"the-verifier"}"#),
                ),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            assert_eq!(v["access_token"], "at-c0de");
            assert_eq!(v["expires_in"], 3600);
            assert_eq!(v["provider"], "google");
            assert_eq!(v["grant"], format!("g1.k1.{flow_id}"));
            assert!(v.get("grant_id").is_none());
            let sent = broker.last_exchange.lock().unwrap().clone().unwrap();
            assert_eq!(sent["flow_id"], flow_id);
            assert_eq!(sent["code"], "c0de");
            assert_eq!(sent["code_verifier"], "the-verifier");
            assert_eq!(sent["state"], "s1.p.sig");
            assert_eq!(sent["nonce_hash"], NONCE_HASH);
            assert!(api.oauth_grants.list().is_empty());

            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    &format!("/v1/oauth-grants/flows/{flow_id}/exchange"),
                    Some(r#"{"code_verifier":"the-verifier"}"#),
                ),
            )
            .await;
            assert!(text.contains("409 Conflict"), "{text}");
            assert_eq!(body_json(&text)["error"], "flow_consumed");
            let text = http_over_uds(
                &sock,
                &request("GET", &format!("/v1/oauth-grants/flows/{flow_id}"), None),
            )
            .await;
            let v = body_json(&text);
            assert_eq!(v["status"], "consumed");
            assert!(v.get("code").is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn provider_errors_and_unknown_flows() {
        with_broker_server(|sock, api, _broker| async move {
            let flow_id = start_flow(&sock).await;
            assert!(api.oauth_grants.flows().deliver(
                &flow_id,
                None,
                Some("access_denied".into()),
                "s".into()
            ));
            let text = http_over_uds(
                &sock,
                &request(
                    "GET",
                    &format!("/v1/oauth-grants/flows/{flow_id}?wait=1"),
                    None,
                ),
            )
            .await;
            let v = body_json(&text);
            assert_eq!(v["status"], "error");
            assert_eq!(v["error"], "access_denied");
            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    &format!("/v1/oauth-grants/flows/{flow_id}/exchange"),
                    Some(r#"{"code_verifier":"v"}"#),
                ),
            )
            .await;
            assert!(text.contains("409 Conflict"), "{text}");
            assert_eq!(body_json(&text)["error"], "flow_failed");

            let text = http_over_uds(
                &sock,
                &request("GET", "/v1/oauth-grants/flows/f_nope", None),
            )
            .await;
            assert!(text.contains("404 Not Found"), "{text}");
            let text =
                http_over_uds(&sock, &request("GET", "/v1/oauth-grants/flows/../x", None)).await;
            assert!(text.contains("404 Not Found"), "{text}");
            let text = http_over_uds(&sock, &request("PUT", "/v1/oauth-grants/flows", None)).await;
            assert!(text.contains("405 Method Not Allowed"), "{text}");

            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    "/v1/oauth-grants/flows",
                    Some(&start_body().replace("google", "github")),
                ),
            )
            .await;
            assert!(text.contains("400 Bad Request"), "{text}");
            assert_eq!(body_json(&text)["error"], "broker_rejected");
        })
        .await;
    }

    #[tokio::test]
    async fn agent_managed_grants_list_token_and_revoke() {
        with_broker_server(|sock, api, broker| async move {
            // Short-lived exchange token so the first `token` refreshes.
            broker.exchange_expires_in.store(30, Ordering::SeqCst);
            let flow_id = start_flow(&sock).await;
            assert!(api.oauth_grants.flows().deliver(
                &flow_id,
                Some("c0de".into()),
                None,
                "s".into()
            ));
            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    &format!("/v1/oauth-grants/flows/{flow_id}/exchange"),
                    Some(r#"{"code_verifier":"v","store":true}"#),
                ),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            let id = v["grant_id"].as_str().unwrap().to_string();
            assert!(id.starts_with("gr_"));
            assert!(v.get("grant").is_none());
            assert_eq!(v["access_token"], "at-c0de");

            let text = http_over_uds(&sock, &request("GET", "/v1/oauth-grants", None)).await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            assert_eq!(v["grants"][0]["id"], id);
            assert_eq!(v["grants"][0]["provider"], "google");
            assert_eq!(v["grants"][0]["scopes"], json!(["calendar.app.created"]));
            assert!(v["grants"][0].get("grant").is_none(), "{v}");
            assert!(!text.contains("g1.k1."), "grant blob leaked:\n{text}");

            let text = http_over_uds(
                &sock,
                &request("GET", &format!("/v1/oauth-grants/{id}/token"), None),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            assert_eq!(v["access_token"], "fresh-1");
            assert_eq!(broker.refreshes.load(Ordering::SeqCst), 1);
            // Cached now.
            let text = http_over_uds(
                &sock,
                &request("GET", &format!("/v1/oauth-grants/{id}/token"), None),
            )
            .await;
            assert_eq!(body_json(&text)["access_token"], "fresh-1");
            assert_eq!(broker.refreshes.load(Ordering::SeqCst), 1);

            let text = http_over_uds(
                &sock,
                &request("DELETE", &format!("/v1/oauth-grants/{id}"), None),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            let v = body_json(&text);
            assert_eq!(v["provider_revoked"], true);
            assert_eq!(
                *broker.revoked_tokens.lock().unwrap(),
                vec!["fresh-1".to_string()]
            );
            let text = http_over_uds(&sock, &request("GET", "/v1/oauth-grants", None)).await;
            assert_eq!(body_json(&text)["grants"], json!([]));
            let text = http_over_uds(
                &sock,
                &request("DELETE", &format!("/v1/oauth-grants/{id}"), None),
            )
            .await;
            assert!(text.contains("404 Not Found"), "{text}");
            let text = http_over_uds(
                &sock,
                &request("GET", "/v1/oauth-grants/gr_nope/token", None),
            )
            .await;
            assert!(text.contains("404 Not Found"), "{text}");
        })
        .await;
    }

    #[tokio::test]
    async fn invalid_grant_is_a_410_and_drops_stored_grants() {
        with_broker_server(|sock, api, broker| async move {
            // App-managed refresh.
            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    "/v1/oauth-grants/refresh",
                    Some(r#"{"provider":"google","grant":"g1.k1.live"}"#),
                ),
            )
            .await;
            assert!(text.contains("200 OK"), "{text}");
            assert_eq!(body_json(&text)["access_token"], "fresh-1");
            broker
                .dead_grants
                .lock()
                .unwrap()
                .insert("g1.k1.dead".into());
            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    "/v1/oauth-grants/refresh",
                    Some(r#"{"provider":"google","grant":"g1.k1.dead"}"#),
                ),
            )
            .await;
            assert!(text.contains("410 Gone"), "{text}");
            assert_eq!(body_json(&text)["error"], "invalid_grant");

            // Agent-managed: the stored grant is dropped.
            broker.exchange_expires_in.store(30, Ordering::SeqCst);
            let flow_id = start_flow(&sock).await;
            assert!(api.oauth_grants.flows().deliver(
                &flow_id,
                Some("c0de".into()),
                None,
                "s".into()
            ));
            let text = http_over_uds(
                &sock,
                &request(
                    "POST",
                    &format!("/v1/oauth-grants/flows/{flow_id}/exchange"),
                    Some(r#"{"code_verifier":"v","store":true}"#),
                ),
            )
            .await;
            let id = body_json(&text)["grant_id"].as_str().unwrap().to_string();
            broker
                .dead_grants
                .lock()
                .unwrap()
                .insert(format!("g1.k1.{flow_id}"));
            let text = http_over_uds(
                &sock,
                &request("GET", &format!("/v1/oauth-grants/{id}/token"), None),
            )
            .await;
            assert!(text.contains("410 Gone"), "{text}");
            assert_eq!(body_json(&text)["error"], "invalid_grant");
            assert!(api.oauth_grants.list().is_empty());
        })
        .await;
    }

    #[tokio::test]
    async fn unreachable_broker_is_a_503() {
        let (api, _acker, _tmp) = make_api_with_broker(
            super::super::tests::AckMode::AcceptAll,
            "http://127.0.0.1:9",
        );
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let sock_cl = sock.clone();
        let handle = tokio::spawn(async move { serve(&sock_cl, api, sd_rx).await });
        for _ in 0..40 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let text = http_over_uds(
            &sock,
            &request("POST", "/v1/oauth-grants/flows", Some(&start_body())),
        )
        .await;
        assert!(text.contains("503 Service Unavailable"), "{text}");
        assert_eq!(body_json(&text)["error"], "broker_unreachable");
        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }
}
