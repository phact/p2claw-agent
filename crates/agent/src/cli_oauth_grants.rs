//! Client-side handlers for `p2claw oauth-grants ...`. Thin HTTP
//! calls against the running agent's `/v1/oauth-grants` endpoints
//! over its Unix socket; the server side lives in
//! `local_api/oauth_grants.rs`.

use std::io::Read as _;
use std::path::Path;
use std::process::ExitCode;

use bytes::Bytes;
use hyper::{Method, StatusCode};
use serde::Deserialize;

use crate::cli_client::{
    fail, print_server_error, resolve_sock, stdout_write_raw, uds_request, ClientError,
};
use p2claw_agent::email::rfc3339;

#[derive(Deserialize)]
struct ProvidersBody {
    providers: Vec<Provider>,
}

#[derive(Deserialize)]
struct Provider {
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct Started {
    flow_id: String,
    authorize_url: String,
}

#[derive(Deserialize)]
struct FlowView {
    status: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenBody {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    grant: Option<String>,
    #[serde(default)]
    grant_id: Option<String>,
}

#[derive(Deserialize)]
struct GrantsBody {
    grants: Vec<GrantSummary>,
}

#[derive(Deserialize)]
struct GrantSummary {
    id: String,
    provider: String,
    #[serde(default)]
    scopes: Vec<String>,
    created_at: u64,
}

#[derive(Deserialize)]
struct Revoked {
    provider_revoked: bool,
    #[serde(default)]
    provider_error: Option<String>,
}

fn failed() -> ExitCode {
    ExitCode::from(2)
}

/// `p2claw oauth-grants providers`.
pub async fn cmd_providers(json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let bytes = match call(&sock, Method::GET, "/v1/oauth-grants/providers", None).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let body: ProvidersBody = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if body.providers.is_empty() {
        println!("no providers available");
        return ExitCode::SUCCESS;
    }
    for p in &body.providers {
        println!("{}", p.name);
        for s in &p.scopes {
            println!("  - {s}");
        }
    }
    ExitCode::SUCCESS
}

/// `p2claw oauth-grants start <provider> --scope … --challenge … --nonce-hash …`.
pub async fn cmd_start(
    provider: String,
    scopes: Vec<String>,
    challenge: String,
    nonce_hash: String,
    json: bool,
) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let body = serde_json::json!({
        "provider": provider,
        "scopes": scopes,
        "code_challenge": challenge,
        "nonce_hash": nonce_hash,
    });
    let bytes = match call(&sock, Method::POST, "/v1/oauth-grants/flows", Some(body)).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let s: Started = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    println!("flow:  {}", s.flow_id);
    println!("open:  {}", s.authorize_url);
    println!();
    println!(
        "then: p2claw oauth-grants wait {} && p2claw oauth-grants exchange {} --verifier <verifier>",
        s.flow_id, s.flow_id
    );
    ExitCode::SUCCESS
}

/// `p2claw oauth-grants wait <flow_id>`: poll until the flow leaves
/// `pending`. Exit 0 only when a code arrived.
pub async fn cmd_wait(flow_id: String, json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let path = format!("/v1/oauth-grants/flows/{flow_id}?wait=1");
    loop {
        let bytes = match call(&sock, Method::GET, &path, None).await {
            Ok(b) => b,
            Err(code) => return code,
        };
        let v: FlowView = match parse(&bytes) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if v.status == "pending" {
            continue;
        }
        if json {
            stdout_write_raw(&bytes);
        } else {
            println!("status: {}", v.status);
            if let Some(c) = &v.code {
                println!("code:   {c}");
            }
            if let Some(s) = &v.state {
                println!("state:  {s}");
            }
        }
        return match v.status.as_str() {
            "ready" => ExitCode::SUCCESS,
            "error" => {
                eprintln!(
                    "error: the provider returned {}",
                    v.error.as_deref().unwrap_or("an error")
                );
                failed()
            }
            "expired" => {
                eprintln!("error: the flow expired; start again");
                failed()
            }
            "consumed" => {
                eprintln!("error: the flow was already exchanged");
                failed()
            }
            other => {
                eprintln!("error: unexpected flow status `{other}`");
                failed()
            }
        };
    }
}

/// `p2claw oauth-grants exchange <flow_id> --verifier … [--store]`.
pub async fn cmd_exchange(flow_id: String, verifier: String, store: bool, json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let body = serde_json::json!({ "code_verifier": verifier, "store": store });
    let path = format!("/v1/oauth-grants/flows/{flow_id}/exchange");
    let bytes = match call(&sock, Method::POST, &path, Some(body)).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let t: TokenBody = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    print_token(&t);
    if let Some(id) = &t.grant_id {
        println!("grant id:      {id}");
        println!();
        println!("the agent keeps this grant; get tokens with: p2claw oauth-grants token {id}");
    }
    if let Some(g) = &t.grant {
        println!("grant:         {g}");
        println!();
        println!(
            "keep the grant; refresh with: p2claw oauth-grants refresh <provider> < grant.txt"
        );
    }
    ExitCode::SUCCESS
}

/// `p2claw oauth-grants refresh <provider>` with the grant on stdin.
pub async fn cmd_refresh(provider: String, json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let mut grant = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut grant) {
        eprintln!("error: could not read the grant from stdin: {e}");
        return failed();
    }
    let grant = grant.trim();
    if grant.is_empty() {
        eprintln!("error: pass the grant on stdin");
        return failed();
    }
    let body = serde_json::json!({ "provider": provider, "grant": grant });
    let bytes = match call(&sock, Method::POST, "/v1/oauth-grants/refresh", Some(body)).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let t: TokenBody = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    print_token(&t);
    if let Some(g) = &t.grant {
        println!("grant:         {g}");
        println!("(the provider rotated the grant; replace the stored one)");
    }
    ExitCode::SUCCESS
}

/// `p2claw oauth-grants list`.
pub async fn cmd_list(json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let bytes = match call(&sock, Method::GET, "/v1/oauth-grants", None).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let body: GrantsBody = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if body.grants.is_empty() {
        println!("no stored grants");
        return ExitCode::SUCCESS;
    }
    println!(
        "{:<30}  {:<10}  {:<20}  SCOPES",
        "ID", "PROVIDER", "CREATED"
    );
    for g in &body.grants {
        println!(
            "{:<30}  {:<10}  {:<20}  {}",
            g.id,
            g.provider,
            rfc3339(g.created_at),
            g.scopes.join(" ")
        );
    }
    ExitCode::SUCCESS
}

/// `p2claw oauth-grants token <id>`: the token alone on stdout, so it
/// can be piped.
pub async fn cmd_token(id: String, json: bool) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let path = format!("/v1/oauth-grants/{id}/token");
    let bytes = match call(&sock, Method::GET, &path, None).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if json {
        stdout_write_raw(&bytes);
        return ExitCode::SUCCESS;
    }
    let t: TokenBody = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    println!("{}", t.access_token);
    ExitCode::SUCCESS
}

/// `p2claw oauth-grants revoke <id>`.
pub async fn cmd_revoke(id: String) -> ExitCode {
    let sock = match resolve_sock() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let path = format!("/v1/oauth-grants/{id}");
    let bytes = match call(&sock, Method::DELETE, &path, None).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    let r: Revoked = match parse(&bytes) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if r.provider_revoked {
        println!("revoked {id} at the provider and removed it");
    } else {
        println!("removed {id}");
        println!(
            "warning: the provider did not confirm the revocation{}",
            r.provider_error
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        );
    }
    ExitCode::SUCCESS
}

fn print_token(t: &TokenBody) {
    println!("access token:  {}", t.access_token);
    println!("expires in:    {} s", t.expires_in);
    if let Some(s) = &t.scope {
        println!("scope:         {s}");
    }
}

async fn call(
    sock: &Path,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<Bytes, ExitCode> {
    let body = match body {
        Some(v) => match serde_json::to_vec(&v) {
            Ok(b) => Some(Bytes::from(b)),
            Err(e) => return Err(fail(&ClientError::Json(e))),
        },
        None => None,
    };
    let (status, bytes) = match uds_request(sock, method, path, body).await {
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
