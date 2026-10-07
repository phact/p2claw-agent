//! p2claw: on-box daemon + local CLI, same binary.
//!
//! The daemon (`p2claw run`) owns the identity keypair, registers
//! with coordination, holds a persistent control WebSocket, and
//! exposes a Unix-domain local API. The CLI subcommands
//! (`p2claw expose / unexpose / routes`) are thin HTTP clients
//! against that same local API — keeping them in this binary means
//! one install, one socket-path resolver, one set of invariants.

#![deny(rust_2018_idioms)]

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("p2claw supports Linux and macOS only. Windows is a non-goal.");

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use p2claw_identity::SigningKey;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

// `forwarder`, `hostname`, `routes`, and `validate` live in the lib
// target (see `src/lib.rs`) so downstream integration tests can
// compose against the real route-resolution + forwarding path.
// Everything below is bin-private — there's no public API for
// in-process use of the agent outside of the `p2claw` binary
// itself.
mod cli_client;
mod cli_email;
mod cli_oauth_grants;
mod config;
mod connect;
mod coord_conn;
mod email_link;
mod fd_count;
use p2claw_agent::iroh_listener;
#[cfg(target_os = "linux")]
mod linux_install;
mod local_api;
#[cfg(target_os = "macos")]
mod macos_install;
mod register;
// Compiles cross-platform (no module-level cfg gate) so the pure
// render-function tests run on Linux dev boxes.
// Runtime install/uninstall ops are PowerShell-shells-out and
// surface `WrongPlatform` on non-Windows hosts.
mod route_announcer;
mod service;
mod signal_handler;
mod state_store;
mod supervisor;
mod windows_install;

// MagicDNS pipeline modules live in the lib target (see
// `crates/agent/src/lib.rs`) so integration tests can compose
// them in-process. Re-aliased here so `cmd_run`'s spawn closures
// can keep their `local_ca::`, `dns_resolver::`, etc. paths.
use p2claw_agent::dns_resolver;
use p2claw_agent::local_ca;
use p2claw_agent::peer_dialer;
use p2claw_agent::priv_drop;
use p2claw_agent::sni_listener;

use p2claw_agent::auto_upgrade;
use p2claw_agent::forwarder::Forwarder;
use p2claw_agent::routes::RouteTable;

/// Compiled-in default coordination FQDN. Override with `--coord-domain`
/// or the `P2CLAW_COORD_DOMAIN` env var.
const DEFAULT_COORD_DOMAIN: &str = "coord.p2claw.com";

/// Compile-time default for the `--parent-domain` flag.
///
/// Resolution order on the install modules + any other site that
/// takes a `--parent-domain` flag:
///
/// 1. Explicit `--parent-domain` value (CLI flag, if passed).
/// 2. `<data_dir>/agent.state::parent_domain` (if registered).
/// 3. This compile-time default.
///
/// Build-time override: set `P2CLAW_DEFAULT_PARENT_DOMAIN=...`
/// at compile time. Self-hosters who fork the binary to point
/// at their own coord (e.g., a private p2claw fleet at
/// `claw.example.com`) compile with their own default and ship
/// the resulting binary. The canonical build picks `p2claw.com`
/// so `sudo p2claw service install --system` works on a fresh
/// box without forcing the user to pass `--parent-domain`
/// before they've ever registered.
pub const DEFAULT_PARENT_DOMAIN: &str = match option_env!("P2CLAW_DEFAULT_PARENT_DOMAIN") {
    Some(s) => s,
    None => "p2claw.com",
};

#[derive(Parser, Debug)]
#[command(
    name = "p2claw",
    version,
    about = "p2claw agent: publish local apps peer-to-peer (daemon and CLI)"
)]
struct Cli {
    /// Coordination FQDN. Bound into the registration signature —
    /// must match the host coordination expects to verify against.
    /// Only used by `run` and `register`; client subcommands ignore it.
    #[arg(long, env = "P2CLAW_COORD_DOMAIN", default_value = DEFAULT_COORD_DOMAIN)]
    coord_domain: String,

    /// Full scheme+host for the coordination HTTP endpoint. Defaults
    /// to `https://<coord_domain>`. Override for local tests against
    /// `http://127.0.0.1:8081`.
    #[arg(long, env = "P2CLAW_COORD_URL")]
    coord_url: Option<String>,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the agent in the foreground (default). Does registration
    /// on first start, holds the control connection, serves the
    /// local API.
    Run,
    /// Print the current peer_id and, if registered, the assigned
    /// alias. Does not talk to the network.
    Identity,
    /// Print a live status summary of the running agent: version,
    /// uptime, coord control-connection state, and route count. Talks
    /// to the running agent's local API over a Unix-domain socket.
    Status {
        /// Emit the raw JSON from the local API instead of the
        /// human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// List the active visitor sessions — transport path and age.
    /// Talks to the running agent's local API over a Unix-domain
    /// socket.
    Sessions {
        /// Emit the raw JSON from the local API instead of the table.
        #[arg(long)]
        json: bool,
    },
    /// Force re-registration against coordination. Overwrites the
    /// existing `agent.state` on success.
    Register,
    /// Per-app management: `expose`, `unexpose`, `list`, `show`,
    /// `set-auth`, `clear-auth`. Talks to the running agent's
    /// local API over a Unix-domain socket; the agent must be
    /// running (`p2claw run`).
    Apps {
        #[command(subcommand)]
        command: AppsCmd,
    },
    /// Manage the agent as a user-scope OS service so it survives
    /// logout / reboot. macOS uses launchd, Linux uses
    /// `systemd --user`. No `sudo` required.
    Service {
        #[command(subcommand)]
        command: ServiceCmd,
    },
    /// Inbound email for this machine: `<alias>@<parent>` accepts mail
    /// only from senders you allow. With no subcommand, prints the
    /// addresses, allowlist size, unread count and rejection totals.
    /// Talks to the running agent's local API.
    Email {
        #[command(subcommand)]
        command: Option<EmailCmd>,
        /// Emit the raw JSON from the local API instead of the
        /// human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// OAuth grants for apps on this machine through p2claw Connect:
    /// a user consents once to a provider (Google Calendar first) and
    /// apps here get access tokens without an OAuth client of their
    /// own. Talks to the running agent's local API.
    OauthGrants {
        #[command(subcommand)]
        command: OauthGrantsCmd,
    },
    /// Auto-upgrade orchestrator surface. The running daemon
    /// checks for the latest GitHub release hourly under its
    /// supervisor; this CLI
    /// exposes the same code path manually + the operator-facing
    /// pin / disable knobs. Pass exactly one of the operation
    /// flags below.
    Upgrade {
        /// Print the orchestrator's decision against the latest
        /// GitHub release and exit. Read-only — no download, no swap,
        /// no restart trigger. Useful for ops debugging ("would
        /// my agent upgrade right now?").
        #[arg(long)]
        check: bool,
        /// Run the full orchestrator: release lookup → decide →
        /// download → verify → atomic_swap → trigger supervised
        /// restart of the agent service. The agent daemon (a
        /// separate process) restarts to pick up the new binary.
        #[arg(long)]
        apply: bool,
        /// Pin auto-upgrade to this SemVer. Releases past the
        /// pin are skipped until `--unpin`. Persists at
        /// `<data_dir>/upgrade-pin.json`.
        #[arg(long, value_name = "VERSION")]
        pin: Option<String>,
        /// Remove an existing pin so normal upgrade flow resumes.
        #[arg(long)]
        unpin: bool,
        /// Disable auto-upgrade entirely. The supervised hourly
        /// task and `--apply` both short-circuit while the
        /// sentinel is in place. Persists as
        /// `<data_dir>/upgrade-disabled`.
        #[arg(long)]
        disable: bool,
        /// Re-enable auto-upgrade (removes the disabled
        /// sentinel).
        #[arg(long)]
        enable: bool,
        /// Print current pin + disabled state and exit. No
        /// network IO.
        #[arg(long)]
        status: bool,
    },
}

/// Subcommand tree for OAuth grants.
#[derive(Subcommand, Debug)]
enum OauthGrantsCmd {
    /// Providers and scopes available through p2claw Connect.
    Providers {
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
    /// Start a consent flow: prints the flow id and the URL the user
    /// opens to approve. The PKCE challenge and nonce hash come from
    /// the app; keep the verifier and nonce for `exchange`.
    Start {
        /// Provider name, as listed by `providers` (e.g. `google`).
        provider: String,
        /// Scope to request. Repeat for several.
        #[arg(long = "scope", required = true, value_name = "SCOPE")]
        scopes: Vec<String>,
        /// PKCE S256 code challenge: base64url SHA-256 of the verifier.
        #[arg(long, value_name = "CHALLENGE")]
        challenge: String,
        /// base64url SHA-256 of the app's one-time nonce.
        #[arg(long, value_name = "HASH")]
        nonce_hash: String,
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
    /// Wait for the user to finish consenting, then print the
    /// callback's code and state. Exits non-zero if the flow failed
    /// or expired.
    Wait {
        /// Flow id, as printed by `start`.
        flow_id: String,
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
    /// Exchange a finished flow for an access token. Without
    /// `--store` the grant is printed for the app to keep; with it
    /// the agent keeps the grant and prints its id.
    Exchange {
        /// Flow id, as printed by `start`.
        flow_id: String,
        /// The PKCE verifier the challenge was derived from.
        #[arg(long, value_name = "VERIFIER")]
        verifier: String,
        /// Keep the grant in the agent; use `token <id>` afterwards.
        #[arg(long)]
        store: bool,
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
    /// Refresh an app-managed grant read from stdin. Prints the new
    /// access token and, if the provider rotated it, the new grant.
    Refresh {
        /// Provider the grant belongs to.
        provider: String,
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
    /// Grants the agent keeps: id, provider, scopes, creation time.
    List {
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
    /// Print a current access token for a stored grant, refreshing
    /// it if needed.
    Token {
        /// Grant id, as listed by `list`.
        id: String,
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
    /// Revoke a stored grant at the provider and forget it.
    Revoke {
        /// Grant id, as listed by `list`.
        id: String,
    },
}

/// Subcommand tree for inbound email.
#[derive(Subcommand, Debug)]
enum EmailCmd {
    /// Turn email on: coordination assigns `<alias>@<parent>` for each
    /// of this machine's aliases. Nothing is accepted until the allowlist
    /// has entries.
    Enable,
    /// Turn email off. Mail to this machine is rejected; the inbox is kept.
    Disable,
    /// Allow mail from these senders. Addresses are lower-cased and
    /// plus-tags are dropped (`you+x@gmail.com` is `you@gmail.com`).
    /// Mail is still accepted only when its DKIM signature matches
    /// the sender's domain.
    Allow {
        /// Sender address, e.g. `you@gmail.com`. Repeat for several.
        #[arg(required = true, value_name = "ADDR")]
        addrs: Vec<String>,
    },
    /// Stop accepting mail from a sender.
    Disallow {
        /// Sender address to remove from the allowlist.
        #[arg(value_name = "ADDR")]
        addr: String,
    },
    /// Gmail forwarding: pending confirmation requests (with the link
    /// that confirms them) and the accounts approved to forward.
    Forwarding {
        #[command(subcommand)]
        command: Option<ForwardingCmd>,
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
    /// List mail in the inbox, newest first.
    List {
        /// Only messages that haven't been acked.
        #[arg(long)]
        unread: bool,
        /// Emit the raw JSON from the local API instead of the table.
        #[arg(long)]
        json: bool,
    },
    /// Show one message: headers, attachments and the text body.
    Show {
        /// Message id, as listed by `list`.
        id: String,
        /// Write the original RFC 5322 message to stdout.
        #[arg(long, conflicts_with = "json")]
        raw: bool,
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
    /// Fetch one attachment by id (see `show`). Bytes go to stdout
    /// unless `--output` names a file.
    Attachment {
        /// Message id, as listed by `list`.
        id: String,
        /// Attachment id, e.g. `a_1`.
        aid: String,
        /// Write to this file instead of stdout.
        #[arg(short, long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
    },
    /// Mark a message handled. It stays in the inbox until removed.
    Ack {
        /// Message id, as listed by `list`.
        id: String,
    },
    /// Remove a message from the inbox.
    Rm {
        /// Message id, as listed by `list`.
        id: String,
    },
    /// Print the id of each message as it arrives, one JSON object
    /// per line, until interrupted.
    Watch,
    /// Senders coordination turned away: totals per reason and the
    /// most recent senders. No content is kept for rejected mail.
    Rejected {
        /// Emit the raw JSON from the local API.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ForwardingCmd {
    /// Admit mail that this Gmail account forwards here. Open the
    /// request's link first so Gmail confirms the forward.
    Approve {
        /// Gmail address, as shown by `p2claw email forwarding`.
        #[arg(value_name = "ACCOUNT")]
        account: String,
    },
    /// Stop admitting mail forwarded by this Gmail account.
    Revoke {
        /// Gmail address to revoke.
        #[arg(value_name = "ACCOUNT")]
        account: String,
    },
}

/// Subcommand tree for per-app management.
#[derive(Subcommand, Debug)]
enum AppsCmd {
    /// Register or replace an app — the agent advertises it to
    /// coord and forwards `https://<name>-<alias>.<parent>/`
    /// traffic to your loopback upstream.
    Expose {
        /// Route name: lowercase LDH, 1-32 chars, not on the
        /// reserved list.
        name: String,
        /// Localhost port the upstream is bound to. The upstream
        /// URL becomes `http://127.0.0.1:<port>`.
        #[arg(long, required_unless_present = "socket", conflicts_with = "socket")]
        port: Option<u16>,
        /// Unix socket the upstream listens on, instead of a port.
        /// Implies `--private`: socket upstreams are only allowed for
        /// private apps.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["public", "auth_oauth"])]
        socket: Option<std::path::PathBuf>,
        /// Emit the raw JSON the agent returned instead of the
        /// human-friendly summary.
        #[arg(long)]
        json: bool,
        /// Suppress the inline QR code (shown by default so a
        /// phone can scan the URL).
        #[arg(long)]
        no_qr: bool,
        /// Gate this app behind p2claw OAuth. Pass with no value
        /// to allow any provider the broker has configured, or
        /// with a comma-separated list (`--auth-oauth
        /// github,google`) to restrict to those keys.
        ///
        /// Providers must be known to the broker — unknown
        /// names are rejected at registration. Pass no value
        /// (just `--auth-oauth`) for "all configured"; an empty
        /// list (`--auth-oauth ""`) is rejected because it
        /// describes an unsatisfiable gate.
        ///
        /// When the request authenticates, your app receives
        /// these headers:
        ///
        /// X-P2claw-User       Upstream user id (always)
        /// X-P2claw-Email      Upstream email (always)
        /// X-P2claw-Provider   "github" / "google" / etc (always)
        /// X-P2claw-Name       Display name (if provided by upstream)
        /// X-P2claw-Picture    Avatar URL (if provided by upstream)
        ///
        /// Incoming `X-P2claw-*` headers are always stripped from
        /// requests before forwarding, regardless of whether
        /// auth is on — defense-in-depth against spoofing. Apps
        /// can trust the values they see.
        ///
        /// Unauthenticated requests get `401 P2claw-Auth-Required:
        /// true` (or `503 P2claw-Auth-Required: true` when the
        /// broker's JWKS is unreachable). CLI clients reading
        /// responses can branch on that header to drive
        /// retry / re-auth logic without parsing the body.
        #[arg(
            long,
            value_name = "PROVIDERS",
            value_delimiter = ',',
            num_args = 0..=1,
            // Preserve the per-line layout of the X-P2claw-*
            // header table above — without this clap collapses
            // each single line-break to a space and the table
            // arrives as one giant run-on. `verbatim_doc_comment`
            // disables clap's paragraph-flow re-wrap on this
            // arg's help text and emits the doc comment verbatim.
            // The prose paragraphs still read fine because each
            // is short enough to fit a terminal line on its own.
            verbatim_doc_comment,
        )]
        auth_oauth: Option<Vec<String>>,
        /// Register the app as a private route: reachable only by
        /// peers you share it with (`p2claw apps share`), never by
        /// browsers or the public edge. Private apps get no public
        /// URL, are never announced to coordination, and don't
        /// count against your app quota. Cannot be combined with
        /// `--auth-oauth`.
        #[arg(long, conflicts_with = "auth_oauth")]
        private: bool,
        /// Explicitly make the app public. Only needed to flip an
        /// existing private route: re-exposing without either flag
        /// preserves the route's current visibility, so a private
        /// app can't be made public (and its name announced) by
        /// accident.
        #[arg(long, conflicts_with = "private")]
        public: bool,
    },
    /// Use a private app another machine shared with you: serve it on
    /// a local port, forwarding HTTP and WebSocket traffic through the
    /// agent on this machine. Runs in the foreground until Ctrl-C.
    Connect {
        /// `<peer>/<app>`: the other machine's alias (or peer id) and the
        /// app name it shared.
        target: String,
        /// Local address to listen on. Port 0 picks a free port.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: std::net::SocketAddr,
    },
    /// Print the route's current state, including its auth method
    /// list. Useful for confirming a `set-auth` took effect or
    /// for scripting against the JSON shape.
    Show {
        /// Route name.
        name: String,
        /// Emit the raw JSON entry instead of the human-friendly
        /// summary.
        #[arg(long)]
        json: bool,
    },
    /// Replace this app's auth method list in place. Same
    /// `--auth-oauth` flag shape as `apps expose`. Pass no
    /// `--auth-oauth` flag at all to clear (equivalent to
    /// `apps clear-auth`).
    SetAuth {
        /// Route name.
        name: String,
        /// OAuth gate spec. See `apps expose --auth-oauth` for
        /// the value grammar and for the `X-P2claw-*` identity
        /// headers your app receives on authenticated requests.
        #[arg(long, value_name = "PROVIDERS", value_delimiter = ',', num_args = 0..=1)]
        auth_oauth: Option<Vec<String>>,
    },
    /// Clear this app's auth gate (set back to public). Shortcut
    /// for `apps set-auth <name>` with no methods specified.
    ClearAuth {
        /// Route name.
        name: String,
    },
    /// Remove an app by name. 404 if it was already gone.
    Unexpose {
        /// Route name (same grammar as `expose`).
        name: String,
    },
    /// List all registered apps. Default output is a human-friendly
    /// table; `--json` emits the raw local-API response, `--qr`
    /// appends a scannable QR per app.
    List {
        /// Emit the raw JSON the agent returned instead of the
        /// human-friendly table.
        #[arg(long)]
        json: bool,
        /// Append a QR code for each app's URL after the table.
        #[arg(long)]
        qr: bool,
    },
    /// Share a private app with a peer, so the machine behind that
    /// peer id can call it over p2claw. Repeatable `--with` shares
    /// with several peers at once.
    Share {
        /// Private app name (as registered with `apps expose
        /// --private`).
        name: String,
        /// Peer id (z-base-32) to share with. Repeat for multiple
        /// peers. Find a machine's peer id by running `p2claw identity`
        /// on it.
        #[arg(long = "with", value_name = "PEER", required = true)]
        with: Vec<String>,
    },
    /// Remove sharing for a private app: a specific peer with
    /// `--with`, or every peer when `--with` is omitted.
    ///
    /// Takes effect on the peer's next request. Connections already
    /// established — an open WebSocket, an in-flight streaming
    /// response — run until they close on their own.
    Unshare {
        /// Private app name.
        name: String,
        /// Peer id (z-base-32) to remove. Omit to unshare from all
        /// peers.
        #[arg(long = "with", value_name = "PEER")]
        with: Option<String>,
    },
    /// List the current shares: which private apps are shared with
    /// which peers.
    Shares {
        /// Emit the raw JSON from the local API instead of the
        /// table.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceCmd {
    /// Install the service unit and start it. The unit embeds the
    /// absolute path of the running binary by default; use
    /// `--bin-path` to point it elsewhere.
    ///
    /// ## Default: publish-only, no sudo
    ///
    /// `p2claw service install` (no flags) installs a user-scope
    /// service (user systemd / LaunchAgent) and starts it. The agent
    /// registers with coord and accepts inbound HTTP from anywhere
    /// — browsers via WebRTC peer-HTTP, CLI / webhooks / file
    /// uploads via the edge tunnel. Apps you publish via
    /// `p2claw apps expose ...` become reachable at
    /// `https://app-<alias>.<parent>/`.
    ///
    /// No privileged ports, no DNS resolver hijack, no system trust
    /// store changes, no sudo prompt.
    ///
    /// ## Optional: `--magicdns` (outbound direct-P2P)
    ///
    /// Adds the resolver-hijack scaffolding so `curl
    /// https://app-<other>.<parent>/...` from this machine dials the
    /// other machine directly via iroh instead of going through the
    /// public edge. Privacy upgrade for the outbound direction —
    /// edge sees nothing, end-to-end encrypted.
    ///
    /// Needs root once to install the SNI listener on 127.0.0.1:443,
    /// drop a resolver file under `/etc/resolver/` (macOS) or
    /// `systemd-resolved` (Linux) / NRPT rule (Windows), and add the
    /// local CA root to the OS trust store. The CLI prompts for sudo
    /// when this flag is set.
    ///
    /// Browser-visitor traffic doesn't need this — visitors reach
    /// your apps fine without `--magicdns`. Only operators who want
    /// to dial other machines from this one need it.
    ///
    /// ## `--system`
    ///
    /// System-scope install. Writes the unit / LaunchDaemon at the
    /// machine level rather than per-user. Includes the MagicDNS
    /// scaffolding (`--magicdns` is implied). Requires sudo.
    Install {
        /// Path to the `p2claw` binary the service should run.
        /// Defaults to the path of the running binary
        /// (`std::env::current_exe`).
        #[arg(long, value_name = "PATH")]
        bin_path: Option<std::path::PathBuf>,
        /// Write the unit file but skip the `bootstrap` / `enable
        /// --now` step. Useful when staging a config for later.
        #[arg(long)]
        no_start: bool,
        /// Install at system scope (LaunchDaemon / system-systemd /
        /// Service registered for the machine, not the user).
        /// `--system` implies the full MagicDNS scaffolding and is
        /// the right shape for operators provisioning a dedicated
        /// machine.
        ///
        /// Requires `sudo` (Unix) / admin elevation (Windows).
        #[arg(long)]
        system: bool,
        /// Opt into the MagicDNS install scaffolding: SNI listener
        /// on 127.0.0.1:443, `/etc/resolver` / NRPT / resolved
        /// hookup, CA root added to the OS trust store.
        ///
        /// Without this flag, the default install skips those
        /// pieces and runs no-sudo. Browser-visitor inbound and
        /// edge-tunnel inbound both work regardless. The flag only
        /// changes the OUTBOUND path: with `--magicdns`, `curl
        /// https://app-<other>.<parent>/` from THIS machine
        /// resolves to 127.0.0.1 → the agent's SNI listener →
        /// direct P2P iroh dial to the other machine (edge sees
        /// nothing, end-to-end encrypted). Without `--magicdns`,
        /// the same curl flows through public DNS → edge → edge
        /// tunnel → other machine (edge sees plaintext during
        /// forwarding, same as webhook traffic).
        ///
        /// Skip this flag if you don't dial other machines from this
        /// one, don't have sudo, or are sandboxed. Combines with
        /// `--system` (which implies `--magicdns`).
        #[arg(long)]
        magicdns: bool,
        /// Accepted for backward-compatibility with older scripts;
        /// has no effect. The current default install is already
        /// publish-only / no-MagicDNS, so this flag is redundant.
        /// Use `--magicdns` to opt into the MagicDNS scaffolding.
        #[arg(long, hide = true)]
        no_magicdns: bool,
        /// Parent domain coord assigned at registration. Used by
        /// `--system` to name `/etc/resolver/<parent_domain>` (or
        /// the equivalent NRPT rule on Windows / resolved drop-in
        /// on Linux). Resolution order:
        ///
        /// 1. This flag, if passed.
        /// 2. `<data_dir>/agent.state::parent_domain` (set on
        ///    successful registration).
        /// 3. Compile-time default (`p2claw.com`, or whatever was
        ///    baked in via `P2CLAW_DEFAULT_PARENT_DOMAIN` for a
        ///    self-hoster's fork).
        ///
        /// Fresh installs that haven't registered yet get step 3, so
        /// `sudo p2claw service install --system` doesn't nag for
        /// `--parent-domain` on first install of the canonical
        /// product.
        #[arg(long)]
        parent_domain: Option<String>,
        /// Print every action without running it. `--system` only.
        #[arg(long)]
        dry_run: bool,
    },
    /// Stop the service and remove the unit file. Pass `--system`
    /// to mirror `--system` install.
    Uninstall {
        #[arg(long)]
        system: bool,
        #[arg(long)]
        parent_domain: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Show the OS's view of the service (launchctl print / systemctl
    /// status).
    Status,
    /// Compare the installed service-config file (plist / unit) to
    /// the current `render_*` output and report drift. Drift means
    /// the agent code has shipped a fix that touches the service
    /// config (e.g. `LimitNOFILE=65536`) but the user hasn't
    /// re-run install. Pass `--rewrite` to fix it in place and
    /// reload the supervisor.
    ConfigCheck {
        /// Rewrite the service-config file with the current
        /// render and reload the supervisor. Default is read-only.
        #[arg(long)]
        rewrite: bool,
    },
}

fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();
    let cmd = cli.command.unwrap_or(Cmd::Run);

    let paths = match config::resolve() {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "could not resolve on-disk paths");
            return ExitCode::from(2);
        }
    };

    let coord_url = cli
        .coord_url
        .clone()
        .unwrap_or_else(|| format!("https://{}", cli.coord_domain));

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "could not start tokio runtime");
            return ExitCode::from(2);
        }
    };

    runtime.block_on(async move {
        match cmd {
            Cmd::Identity => cmd_identity(&paths).await,
            Cmd::Status { json } => cli_client::cmd_status(json).await,
            Cmd::Sessions { json } => cli_client::cmd_sessions(json).await,
            Cmd::Register => cmd_register(&paths, &coord_url, &cli.coord_domain).await,
            Cmd::Run => cmd_run(&paths, &coord_url, &cli.coord_domain).await,
            // Flat `unexpose` / `routes` were dropped; both now
            // live as `apps unexpose` / `apps list`.
            Cmd::Apps { command } => cmd_apps(command).await,
            Cmd::Email { command, json } => cmd_email(command, json).await,
            Cmd::OauthGrants { command } => cmd_oauth_grants(command).await,
            Cmd::Service { command } => cmd_service(command).await,
            Cmd::Upgrade {
                check,
                apply,
                pin,
                unpin,
                disable,
                enable,
                status,
            } => {
                cmd_upgrade(
                    &paths,
                    UpgradeOp {
                        check,
                        apply,
                        pin,
                        unpin,
                        disable,
                        enable,
                        status,
                    },
                )
                .await
            }
        }
    })
}

/// Dispatch the `apps` subcommand tree. Translates the clap
/// `--auth-oauth [providers]` shape into the `Vec<AuthMethod>`
/// the local-API expects:
///
/// - flag absent → `Vec::new()` (public).
/// - flag with no value → `vec![Oauth { providers: None }]` (any
///   configured provider).
/// - flag with a comma-separated value → `vec![Oauth { providers:
///   Some(vec![..]) }]` (restrict to those provider keys).
async fn cmd_apps(cmd: AppsCmd) -> ExitCode {
    match cmd {
        AppsCmd::Expose {
            name,
            port,
            socket,
            json,
            no_qr,
            auth_oauth,
            private,
            public,
        } => {
            let auth = oauth_flag_to_auth(auth_oauth);
            let upstream = match (port, socket) {
                (_, Some(path)) => match cli_client::socket_upstream(&path) {
                    Ok(u) => u,
                    Err(e) => {
                        eprintln!("error: {e}");
                        return ExitCode::from(2);
                    }
                },
                (Some(port), None) => format!("http://127.0.0.1:{port}"),
                (None, None) => unreachable!("clap requires --port or --socket"),
            };
            let private = private || upstream.starts_with("unix:");
            cli_client::cmd_expose(name, upstream, json, !no_qr, auth, private, public).await
        }
        AppsCmd::Connect { target, listen } => connect::cmd_connect(target, listen).await,
        AppsCmd::Show { name, json } => cli_client::cmd_show(name, json).await,
        AppsCmd::SetAuth { name, auth_oauth } => {
            let auth = oauth_flag_to_auth(auth_oauth);
            cli_client::cmd_set_auth(name, auth).await
        }
        AppsCmd::ClearAuth { name } => cli_client::cmd_clear_auth(name).await,
        AppsCmd::Unexpose { name } => cli_client::cmd_unexpose(name).await,
        AppsCmd::List { json, qr } => cli_client::cmd_routes(json, qr).await,
        AppsCmd::Share { name, with } => cli_client::cmd_share(name, with).await,
        AppsCmd::Unshare { name, with } => cli_client::cmd_unshare(name, with).await,
        AppsCmd::Shares { json } => cli_client::cmd_shares(json).await,
    }
}

async fn cmd_email(cmd: Option<EmailCmd>, json: bool) -> ExitCode {
    match cmd {
        None => cli_email::cmd_summary(json).await,
        Some(EmailCmd::Enable) => cli_email::cmd_set_enabled(true).await,
        Some(EmailCmd::Disable) => cli_email::cmd_set_enabled(false).await,
        Some(EmailCmd::Allow { addrs }) => cli_email::cmd_allow(addrs).await,
        Some(EmailCmd::Disallow { addr }) => cli_email::cmd_disallow(addr).await,
        Some(EmailCmd::Forwarding { command, json }) => match command {
            None => cli_email::cmd_forwarding(json).await,
            Some(ForwardingCmd::Approve { account }) => {
                cli_email::cmd_forwarding_set(account, true).await
            }
            Some(ForwardingCmd::Revoke { account }) => {
                cli_email::cmd_forwarding_set(account, false).await
            }
        },
        Some(EmailCmd::List { unread, json }) => cli_email::cmd_list(unread, json).await,
        Some(EmailCmd::Show { id, raw, json }) => cli_email::cmd_show(id, raw, json).await,
        Some(EmailCmd::Attachment { id, aid, output }) => {
            cli_email::cmd_attachment(id, aid, output).await
        }
        Some(EmailCmd::Ack { id }) => cli_email::cmd_ack(id).await,
        Some(EmailCmd::Rm { id }) => cli_email::cmd_rm(id).await,
        Some(EmailCmd::Watch) => cli_email::cmd_watch().await,
        Some(EmailCmd::Rejected { json }) => cli_email::cmd_rejected(json).await,
    }
}

async fn cmd_oauth_grants(cmd: OauthGrantsCmd) -> ExitCode {
    use cli_oauth_grants as og;
    match cmd {
        OauthGrantsCmd::Providers { json } => og::cmd_providers(json).await,
        OauthGrantsCmd::Start {
            provider,
            scopes,
            challenge,
            nonce_hash,
            json,
        } => og::cmd_start(provider, scopes, challenge, nonce_hash, json).await,
        OauthGrantsCmd::Wait { flow_id, json } => og::cmd_wait(flow_id, json).await,
        OauthGrantsCmd::Exchange {
            flow_id,
            verifier,
            store,
            json,
        } => og::cmd_exchange(flow_id, verifier, store, json).await,
        OauthGrantsCmd::Refresh { provider, json } => og::cmd_refresh(provider, json).await,
        OauthGrantsCmd::List { json } => og::cmd_list(json).await,
        OauthGrantsCmd::Token { id, json } => og::cmd_token(id, json).await,
        OauthGrantsCmd::Revoke { id } => og::cmd_revoke(id).await,
    }
}

/// Map the clap `--auth-oauth [providers]` flag onto the wire's
/// `Vec<AuthMethod>` shape. See `cmd_apps` doc for the three
/// cases. Lives at function scope (rather than buried in the
/// match arm) so both `Expose` and `SetAuth` share the same
/// translation — keeps the per-app flag semantics in lockstep.
fn oauth_flag_to_auth(flag: Option<Vec<String>>) -> Vec<p2claw_control_proto::AuthMethod> {
    match flag {
        None => Vec::new(),
        Some(p) if p.is_empty() => vec![p2claw_control_proto::AuthMethod::oauth_any()],
        Some(p) => vec![p2claw_control_proto::AuthMethod::oauth_with(p)],
    }
}

async fn cmd_service(cmd: ServiceCmd) -> ExitCode {
    match cmd {
        ServiceCmd::Install {
            bin_path,
            no_start,
            system,
            magicdns,
            no_magicdns,
            parent_domain,
            dry_run,
        } => cmd_install_dispatch(
            bin_path,
            no_start,
            system,
            magicdns,
            no_magicdns,
            parent_domain,
            dry_run,
        ),
        ServiceCmd::Uninstall {
            system,
            parent_domain,
            dry_run,
        } => {
            if system {
                cmd_uninstall_system(parent_domain, dry_run)
            } else {
                if parent_domain.is_some() || dry_run {
                    eprintln!(
                        "p2claw service uninstall: --parent-domain / --dry-run only \
                         apply with --system; ignoring"
                    );
                }
                map_unit(service::uninstall())
            }
        }
        ServiceCmd::Status => map_unit(service::status()),
        ServiceCmd::ConfigCheck { rewrite } => {
            match service::check_drift(rewrite) {
                Ok(report) => {
                    use service::DriftState;
                    match report.state {
                        DriftState::NotInstalled => {
                            println!(
                                "not installed (no service-config at {})",
                                report.path.display()
                            );
                        }
                        DriftState::Clean => {
                            println!(
                                "clean — service-config at {} matches current render",
                                report.path.display()
                            );
                        }
                        DriftState::Drifted { rewrote: false } => {
                            println!(
                                "drifted — service-config at {} differs from current render",
                                report.path.display()
                            );
                            println!("(re-run with --rewrite to fix in place + reload supervisor)");
                        }
                        DriftState::Drifted { rewrote: true } => {
                            println!("drifted + rewrote — service-config at {} updated; supervisor reloaded", report.path.display());
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    error!(error = %e, "service config-check failed");
                    ExitCode::from(2)
                }
            }
        }
    }
}

/// Top-level `p2claw service install` dispatch. Default is
/// publish-only / no-sudo; `--magicdns` opts into the privileged
/// scaffolding; `--system` implies `--magicdns` + machine-scope unit.
///
///   default (no flags)        → user-scope install, no sudo,
///                               publish-only.
///   `--magicdns`              → user-scope install + attempt the
///                               platform-specific elevation
///                               (Linux: `sudo setcap …`; macOS:
///                               recommend `--system`; Windows: not
///                               yet supported). On success →
///                               user-scope MagicDNS install. On
///                               decline → fall back to publish-only
///                               with the sudo-declined banner.
///   `--system`                → system-scope install with the full
///                               MagicDNS scaffolding (DNS resolver,
///                               CA root, 443 listener,
///                               LaunchDaemon / system-systemd /
///                               Service). Requires sudo.
///
/// `--no-magicdns` is accepted as a no-op (backward compat). It used
/// to suppress an opt-out MagicDNS attempt; the default is now
/// publish-only, so the flag is a no-op.
///
/// `parent_domain` / `dry_run` are `--system`-only — warned + ignored
/// on user-scope.
fn cmd_install_dispatch(
    bin_path: Option<std::path::PathBuf>,
    no_start: bool,
    system: bool,
    magicdns: bool,
    // Accepted for backward-compat; the default install is already
    // publish-only, so this flag has no effect today.
    _no_magicdns: bool,
    parent_domain: Option<String>,
    dry_run: bool,
) -> ExitCode {
    if !system && (parent_domain.is_some() || dry_run) {
        eprintln!(
            "p2claw service install: --parent-domain / --dry-run only \
             apply with --system; ignoring"
        );
    }

    // User-scope install as root is always a mistake: the unit lands
    // in /root/.config/systemd/user, `systemctl --user` has no bus
    // for root under sudo, and the agent would run (and linger) as
    // root instead of the invoking user.
    #[cfg(unix)]
    if !system && nix::unistd::geteuid().is_root() {
        match std::env::var("SUDO_USER") {
            Ok(invoker) if !invoker.is_empty() => eprintln!(
                "p2claw service install (user scope) creates a per-user \
                 service and must run as the user who owns the agent.\n\
                 Re-run without sudo (as {invoker}), or use \
                 `sudo p2claw service install --system` for a system-wide service."
            ),
            _ => eprintln!(
                "p2claw service install (user scope) creates a per-user \
                 service and must not run as root.\n\
                 Re-run as a regular user, or use \
                 `sudo p2claw service install --system` for a system-wide service."
            ),
        }
        return ExitCode::FAILURE;
    }

    if system {
        // System-scope install always includes the MagicDNS
        // scaffolding (resolver hookup, CA root, 443 listener,
        // LaunchDaemon / unit). `--magicdns` is implied; we accept
        // it explicitly without complaint.
        return cmd_install_system(bin_path, no_start, parent_domain, dry_run);
    }

    if magicdns {
        // User passed `--magicdns` → user-scope install with the
        // platform-specific elevation attempt. Falls back to
        // publish-only on decline with the sudo-declined banner.
        return cmd_install_user_with_magicdns(bin_path, no_start);
    }

    // Default install: publish-only, no sudo prompt. Apps the user
    // exposes are reachable via the public edge (browsers via
    // WebRTC, CLI / webhooks via the edge tunnel). `--magicdns` is
    // the upgrade for operators who also want this machine to dial
    // other boxes directly.
    map_unit(service::install(service::InstallOpts {
        bin_path,
        no_start,
        disable_magicdns: true,
    }))
}

/// Default user-scope install path that attempts platform-specific
/// elevation for the MagicDNS prereqs, falling back to publish-only
/// on failure with the sudo-declined banner. Per the locked
/// design (consolidated brief):
///
/// - **Linux**: `sudo setcap cap_net_bind_service+ep <bin>` once.
///   Success → install user-scope with magicdns=on (env var
///   cleared). Failure → fall back to publish-only with the
///   sudo-declined banner.
///
///   Caveat: setcap alone handles the 443 bind. The full
///   MagicDNS hookup (`/etc/systemd/resolved.conf.d/p2claw.conf`,
///   `/usr/local/share/ca-certificates`) still needs root and is
///   not yet wired as additional sudo invocations during the
///   user-scope MagicDNS install.
///   For now, the user-scope agent will bind 443 but local apps
///   on this machine won't actually route to it without those
///   pieces. Operators wanting fully-working MagicDNS today
///   should use `--system` (full scaffolding).
///
/// - **macOS**: no setcap analogue. Auto-degrade to publish-only
///   with a warning pointing at `sudo p2claw service install
///   --system` for full MagicDNS, OR `--no-magicdns` to suppress
///   this warning on subsequent runs.
///
/// - **Windows**: not yet supported on this path; suggest manual
///   `--system` from admin shell.
fn cmd_install_user_with_magicdns(
    bin_path: Option<std::path::PathBuf>,
    no_start: bool,
) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        let bin = match bin_path.clone().or_else(|| std::env::current_exe().ok()) {
            Some(p) => p.canonicalize().unwrap_or(p),
            None => {
                error!("could not resolve binary path for install");
                return ExitCode::from(2);
            }
        };
        // Internal: sudo setcap cap_net_bind_service+ep <bin>.
        // The tracing log here uses %bin_str so an operator
        // debugging a failed install sees what was attempted; the
        // user-facing banner does NOT leak this.
        let bin_str = bin.display().to_string();
        info!(bin = %bin_str, "service install: requesting sudo for setcap cap_net_bind_service+ep");
        let status = std::process::Command::new("sudo")
            .args(["setcap", "cap_net_bind_service+ep"])
            .arg(&bin)
            .status();
        let setcap_ok = matches!(status, Ok(s) if s.success());
        if setcap_ok {
            return map_unit(service::install(service::InstallOpts {
                bin_path,
                no_start,
                disable_magicdns: false,
            }));
        }
        // Sudo declined or setcap failed — fall back to publish-only.
        // Banner shows only user-facing commands;
        // does NOT leak the internal `setcap …` invocation.
        service::print_sudo_declined_banner();
        eprintln!();
        eprintln!("  Falling back to publish-only install...");
        map_unit(service::install(service::InstallOpts {
            bin_path,
            no_start,
            disable_magicdns: true,
        }))
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: no setcap analogue, and the user-scope launchd
        // can't bind ports < 1024 — so a user-scope `--magicdns`
        // install would crash-loop the agent every restart trying
        // to bind 443. Auto-degrade to publish-only and tell the
        // operator to re-run with `--system` if they really want
        // the MagicDNS scaffolding.
        eprintln!();
        eprintln!("⚠ MagicDNS isn't available on macOS without `--system`.");
        eprintln!("  Auto-degrading to the default publish-only install.");
        eprintln!();
        eprintln!("  Two ways forward:");
        eprintln!();
        eprintln!("  • Re-run as system-scope install to get MagicDNS:");
        eprintln!("      sudo p2claw service install --system");
        eprintln!();
        eprintln!("  • Drop `--magicdns` and keep the default user-scope install:");
        eprintln!("      p2claw service install");
        eprintln!();
        map_unit(service::install(service::InstallOpts {
            bin_path,
            no_start,
            disable_magicdns: true,
        }))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = bin_path;
        let _ = no_start;
        eprintln!(
            "service install: `--magicdns` is not yet supported on this \
             platform. Re-run without `--magicdns` for a publish-only \
             user-scope install, or `--system` from an admin shell for the \
             full MagicDNS scaffolding."
        );
        ExitCode::from(2)
    }
}

/// Dispatch `p2claw service install --system` to the platform-
/// specific implementation. macOS goes to `macos_install`,
/// Linux to `linux_install`. Windows errors out with a helpful
/// message until then.
fn cmd_install_system(
    bin_path: Option<std::path::PathBuf>,
    no_start: bool,
    parent_domain: Option<String>,
    dry_run: bool,
) -> ExitCode {
    #[cfg(target_os = "macos")]
    {
        let opts = macos_install::InstallSystemOpts {
            bin_path,
            parent_domain,
            data_dir: None,
            no_start,
            dry_run,
        };
        match macos_install::install_system(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!(error = %e, "macos system install failed");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let opts = linux_install::InstallSystemOpts {
            bin_path,
            parent_domain,
            data_dir: None,
            no_start,
            dry_run,
        };
        match linux_install::install_system(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!(error = %e, "linux system install failed");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let opts = windows_install::InstallSystemOpts {
            bin_path,
            parent_domain,
            data_dir: None,
            no_start,
            dry_run,
        };
        match windows_install::install_system(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!(error = %e, "windows system install failed");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        // Silence the unused-args warning on unsupported builds
        // without dragging in `_` everywhere.
        let _ = (bin_path, no_start, parent_domain, dry_run);
        eprintln!(
            "p2claw service install --system: not supported on this platform. \
             macOS / Linux / Windows are the supported targets."
        );
        ExitCode::from(2)
    }
}

fn cmd_uninstall_system(parent_domain: Option<String>, dry_run: bool) -> ExitCode {
    #[cfg(target_os = "macos")]
    {
        let opts = macos_install::UninstallSystemOpts {
            parent_domain,
            data_dir: None,
            dry_run,
        };
        match macos_install::uninstall_system(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!(error = %e, "macos system uninstall failed");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let opts = linux_install::UninstallSystemOpts {
            parent_domain,
            data_dir: None,
            dry_run,
        };
        match linux_install::uninstall_system(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!(error = %e, "linux system uninstall failed");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let opts = windows_install::UninstallSystemOpts {
            parent_domain,
            data_dir: None,
            dry_run,
        };
        match windows_install::uninstall_system(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!(error = %e, "windows system uninstall failed");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (parent_domain, dry_run);
        eprintln!("p2claw service uninstall --system: not supported on this platform.");
        ExitCode::from(2)
    }
}

/// Parse a boolean env var with the agent's standard semantics:
/// `"true"` / `"1"` (case-insensitive) → `true`; everything else
/// (including unset / empty) → `false`.
fn parse_bool_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "true" || v == "1"
        }
        Err(_) => false,
    }
}

/// Parse a u16-port env var. Returns `Ok(Some(port))` if present
/// and parses; `Ok(None)` if unset; `Err(value)` if present but
/// malformed (caller should warn + fall through to default rather
/// than crashing — a typo'd port shouldn't take the agent down at
/// boot when there's a sensible default to fall back to).
///
/// Used by `P2CLAW_DNS_PORT` — Windows installs bake `=53`
/// because NRPT routes queries to port 53 unconditionally
/// (`Add-DnsClientNrptRule` doesn't accept a port specifier). On
/// macOS / Linux the env var is unset so the agent keeps its
/// non-mDNS-conflicting default of 5354.
fn parse_u16_env(name: &str) -> Result<Option<u16>, String> {
    match std::env::var(name) {
        Ok(v) => {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            trimmed
                .parse::<u16>()
                .map(Some)
                .map_err(|_| trimmed.to_string())
        }
        Err(_) => Ok(None),
    }
}

fn map_unit(r: Result<(), service::ServiceError>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "service command failed");
            ExitCode::from(2)
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,p2claw_agent=debug"));
    // Default human-readable text format (no JSON flip). file:line
    // mirrors coord + edge for cross-service log triage.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_file(true)
        .with_line_number(true)
        .try_init();
}

async fn cmd_identity(paths: &config::Paths) -> ExitCode {
    let sk = match SigningKey::load_or_generate(&paths.identity_key()) {
        Ok(k) => k,
        Err(e) => {
            error!(error = %e, "identity error");
            return ExitCode::from(2);
        }
    };
    let state = state_store::load(&paths.agent_state()).ok().flatten();
    let alias = state
        .map(|s| s.alias)
        .unwrap_or_else(|| "<unregistered>".to_string());
    println!("peer_id: {}", sk.peer_id());
    println!("alias:   {alias}");
    ExitCode::SUCCESS
}

async fn cmd_register(paths: &config::Paths, coord_url: &str, coord_domain: &str) -> ExitCode {
    let sk = match SigningKey::load_or_generate(&paths.identity_key()) {
        Ok(k) => k,
        Err(e) => {
            error!(error = %e, "identity error");
            return ExitCode::from(2);
        }
    };
    info!(coord_url, "registering");
    match register::register(coord_url, coord_domain, &sk).await {
        Ok(resp) => {
            let state: state_store::AgentState = resp.into();
            if let Err(e) = state_store::save(&paths.agent_state(), &state) {
                error!(error = %e, "could not save agent.state");
                return ExitCode::from(2);
            }
            info!(alias = %state.alias, "registered");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "registration failed");
            ExitCode::from(2)
        }
    }
}

/// Broker the agent trusts for visitor sign-in and OAuth grants.
fn oauth_broker_url() -> String {
    std::env::var("P2CLAW_AGENT_OAUTH_BROKER_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| p2claw_agent::oauth::DEFAULT_BROKER_URL.to_string())
}

async fn cmd_run(paths: &config::Paths, coord_url: &str, coord_domain: &str) -> ExitCode {
    let sk = match SigningKey::load_or_generate(&paths.identity_key()) {
        Ok(k) => k,
        Err(e) => {
            error!(error = %e, "identity error");
            return ExitCode::from(2);
        }
    };
    info!(peer_id = %sk.peer_id(), "identity loaded");

    // Priv-drop happens later, after `local_ca::load_or_generate`
    // (root reads the on-disk key into memory) and after the SNI
    // listener pre-binds 443 (the only privileged action the agent
    // needs). The drop itself runs from `priv_drop::drop_to` —
    // search for "priv_drop:" in the log on a system-scope install
    // to see the transition. The flow either drops successfully
    // (info log) or refuses to start (error + exit 2).

    // Registration, if we don't already have state. The retry loop
    // makes initial registration tolerant of coord blips / startup-
    // ordering races (we may boot before the network is up).
    let (sd_tx, sd_rx) = watch::channel(false);

    let mut state = match state_store::load(&paths.agent_state()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "could not read agent.state; will re-register");
            None
        }
    };
    if state.is_none() {
        info!("no agent.state on disk; registering with retry");
        match register::register_with_retry(
            coord_url,
            coord_domain,
            &sk,
            register::RegisterRetryPolicy::default(),
            sd_rx.clone(),
        )
        .await
        {
            Ok(resp) => {
                let s: state_store::AgentState = resp.into();
                if let Err(e) = state_store::save(&paths.agent_state(), &s) {
                    error!(error = %e, "could not persist agent.state");
                    return ExitCode::from(2);
                }
                state = Some(s);
            }
            Err(register::RegisterError::Cancelled) => {
                info!("registration cancelled by shutdown");
                return ExitCode::SUCCESS;
            }
            Err(register::RegisterError::Permanent { status, error, .. }) => {
                error!(status, error = %error, "registration permanently failed");
                return ExitCode::from(2);
            }
            Err(e) => {
                error!(error = %e, "registration failed");
                return ExitCode::from(2);
            }
        }
    }
    let state = state.expect("state set above");
    info!(alias = %state.alias, "registered");

    // Shared identity (local-api reads it; control-conn owns another
    // copy re-derived from the on-disk seed).
    let identity = Arc::new(sk);
    // The iroh listener publishes its current relay/direct addrs here;
    // control-conn snapshots it for `Hello` and emits `addrs_update`
    // on every change.
    let (addrs_tx, addrs_rx) = watch::channel::<Vec<String>>(Vec::new());

    // Coord-connection liveness signal. The
    // post-upgrade watchdog watches this for the bonus
    // "got hello_ack within budget" → Healthy upgrade. Sender
    // lives in coord_conn; receiver lives in the watchdog task
    // (when an upgrade is in flight) and is otherwise dropped.
    let (coord_health_tx, coord_health_rx) = watch::channel(auto_upgrade::CoordHealth::Connecting);

    // Pick up an in-flight upgrade flag BEFORE spinning up
    // supervised tasks. Presence means "we are the freshly-
    // installed binary" and the watchdog will run a brief
    // health check after the local API binds, rolling back to
    // `<canonical>.previous` if anything fails to come up.
    let upgrade_in_progress = match auto_upgrade::read_upgrade_in_progress(&paths.data_dir) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "auto_upgrade: could not read upgrade-in-progress flag; treating as absent");
            None
        }
    };
    if let Some(flag) = upgrade_in_progress.as_ref() {
        info!(
            target_version = %flag.target_version,
            from_version = %flag.from_version,
            started_at_unix = flag.started_at_unix,
            "auto_upgrade: post-upgrade watchdog will run after local API binds"
        );
    }

    // Routes: loaded once at startup, shared across the local API
    // (mutation) and the forwarder (read-through via hot path).
    let routes = RouteTable::load_or_empty(paths.data_dir.join("routes.json"));

    // Shares: which peers may reach each private route. Shared
    // between the forwarder (per-request check) and the local API
    // (`GET/PUT /v1/shares`), so CLI edits apply live.
    let shares = p2claw_agent::shares::Shares::load_or_empty(paths.data_dir.join("shares.json"));

    // Bridge between local-API mutations and the control-connection's
    // `route_announce` emitter. The
    // announcer half is shared with `local_api`; the inbox half is
    // owned by the control-conn loop and drained per-session.
    let (announcer, announcer_inbox) = route_announcer::RouteAnnouncer::new();

    // Email: settings and inbox are shared between the local API and
    // the coord session; the link carries config pushes and rejection
    // lookups the same way the announcer carries route announces.
    let email = email_link::EmailShared::load(&paths.data_dir);
    let (email_link, email_link_inbox) = email_link::EmailLink::new();

    // OAuth grants: flows wait in memory for the callback coord
    // relays; agent-managed grants persist in the data directory.
    let oauth_broker_url = oauth_broker_url();
    let oauth_grants = {
        let broker = match p2claw_agent::oauth_grants::BrokerClient::new(
            &oauth_broker_url,
            Arc::clone(&identity),
        ) {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, url = %oauth_broker_url, "invalid OAuth broker URL");
                return ExitCode::from(2);
            }
        };
        let store = p2claw_agent::oauth_grants::GrantStore::load_or_empty(
            paths.data_dir.join("oauth-grants.json"),
        );
        Arc::new(p2claw_agent::oauth_grants::OauthGrants::new(broker, store))
    };

    // `GET /v1/status` inputs. `process_start` powers uptime;
    // `coord_state_since` tracks when the coord-health value last
    // changed (a lightweight watcher stamps it), so status can report
    // how long the current state has held. `session_source` is filled
    // once the signal registry is built (later in boot).
    let process_start = std::time::Instant::now();
    let coord_state_since = Arc::new(std::sync::Mutex::new(process_start));
    {
        let mut health_rx = coord_health_rx.clone();
        let since = Arc::clone(&coord_state_since);
        tokio::spawn(async move {
            while health_rx.changed().await.is_ok() {
                *since.lock().expect("coord_state_since mutex poisoned") =
                    std::time::Instant::now();
            }
        });
    }
    let session_source: Arc<std::sync::OnceLock<Arc<signal_handler::SignalRegistry>>> =
        Arc::new(std::sync::OnceLock::new());
    // The iroh registry has no construction-order constraint, so it
    // is built and wired up front; the listener task receives a clone.
    let iroh_sessions = p2claw_agent::iroh_listener::IrohSessionRegistry::new();
    let iroh_session_source: Arc<
        std::sync::OnceLock<Arc<p2claw_agent::iroh_listener::IrohSessionRegistry>>,
    > = Arc::new(std::sync::OnceLock::new());
    let _ = iroh_session_source.set(Arc::clone(&iroh_sessions));

    // `/v1/proxy` needs the agent's own iroh endpoint (built below)
    // so remote boxes see this box's peer id; wired via OnceLock.
    let peer_proxy_source: Arc<
        std::sync::OnceLock<Arc<p2claw_agent::peer_dialer::PeerClientCache>>,
    > = Arc::new(std::sync::OnceLock::new());

    let api = Arc::new(local_api::LocalApi::new(
        Arc::clone(&identity),
        Some(state.clone()),
        routes.clone(),
        announcer.clone(),
        process_start,
        coord_health_rx.clone(),
        Arc::clone(&coord_state_since),
        Arc::clone(&session_source),
        iroh_session_source,
        shares.clone(),
        Arc::clone(&peer_proxy_source),
        email.clone(),
        email_link.clone(),
        Arc::clone(&oauth_grants),
    ));

    // Construct the OAuth validator. Built unconditionally
    // — the per-request middleware always runs (header strip is
    // defense-in-depth even on public apps); the JWKS fetch only
    // happens lazily on the first auth-required request, so a
    // box with no auth-gated apps never pays the cost. Broker URL
    // overridable via env for self-hosters / tests; defaults to
    // the canonical `oauth::DEFAULT_BROKER_URL`.
    let oauth_validator = {
        let cfg = p2claw_agent::oauth::OAuthConfig {
            broker_url: oauth_broker_url,
            expected_aud_z32: identity.peer_id().to_z32(),
        };
        let v = std::sync::Arc::new(p2claw_agent::oauth::OAuthValidator::new(cfg));
        // Spawn the periodic refresh task — does nothing until
        // the first lazy fetch populates the cache; subsequent
        // ticks keep the keyset fresh against broker rotation.
        let _refresh_handle = v.spawn_refresh_task();
        v
    };

    // The forwarder is the translator `Handler` used by both
    // transports. Per-route hyper connection pools live inside it.
    // OAuth validator wired so `requires_auth=true` routes hit the
    // JWT middleware on every request. The identity key threads
    // through so the middleware can mint the attestation JWT that
    // upstream apps verify against the box's peer_id.
    let forwarder = Forwarder::new_with_shares(
        routes.clone(),
        state.parent_domain.clone(),
        Some(oauth_validator),
        Some(Arc::clone(&identity)),
        Some(shares.clone()),
    );

    // ---------- Supervised auxiliary subtasks --------------------
    //
    // Both the local API and the iroh listener are restarted on
    // panic / unexpected exit, with a "two panics inside
    // SUPERVISOR_RESTART_WINDOW ⇒ exit 1" guard so a real bug in
    // one of them stops the agent instead of looping forever.
    // Control-conn manages its own reconnect (see control_conn.rs)
    // and runs in its own JoinHandle (below) — its terminal outcome
    // drives the agent's exit code.
    let mut supervisor = supervisor::Supervisor::new();
    {
        let api = Arc::clone(&api);
        let sock = paths.agent_sock();
        let sd = sd_rx.clone();
        supervisor.spawn("local-api", move || {
            let api = Arc::clone(&api);
            let sock = sock.clone();
            let sd = sd.clone();
            async move {
                match local_api::serve(&sock, api, sd).await {
                    Ok(()) => {}
                    Err(e @ local_api::LocalApiError::AcceptFdLimit { .. }) => {
                        // The only honest recovery from
                        // EMFILE/ENFILE on the accept socket is a
                        // process restart. Panicking here drives the
                        // supervisor's panic-restart loop, which trips
                        // the 2-panics-in-60s fatal guard on the next
                        // accept (still EMFILE); main exits non-zero,
                        // launchd / systemd `KeepAlive` / `Restart=on-
                        // failure` bring us back with all FDs reclaimed.
                        error!(error = %e, "local API hit FD-limit; failing the agent so the OS supervisor restarts it");
                        panic!("{e}");
                    }
                    Err(e) => {
                        error!(error = %e, "local API terminated");
                    }
                }
            }
        });
    }
    // Build ONE Iroh endpoint up-front, reused across:
    //   - iroh_listener (inbound peer-HTTP via ALPN p2claw/1)
    //   - coord_conn (outbound dial to coord via ALPN p2claw-coord/1)
    // The endpoint advertises `P2CLAW_ALPN` for inbound; the coord
    // dial specifies `ALPN_COORD_V1` per-connect, no inbound
    // advertisement needed for that side. One UDP socket, one
    // identity, one set of relay registrations. Done eagerly so a
    // bind error surfaces at startup rather than first iroh
    // operation.
    // Iroh relay configuration (single source of
    // truth at coord). Two modes only:
    // - `state.coord_iroh_relay_url` is `None` → direct-only
    //   (`presets::Minimal` + `RelayMode::Disabled`). No n0 public-
    //   canary, no net_report beacon. This is the production
    //   default for agents that have never registered, or whose
    //   coord runs without a self-hosted relay.
    // - `state.coord_iroh_relay_url` is `Some(url)` → route relay-
    //   mediated traffic through that URL only
    //   (`RelayMode::Custom(RelayMap::from(url))`).
    //
    // The relay URL is set fleet-wide at coord
    // (`P2CLAW_COORD_IROH_RELAY_URL`) and propagated through
    // `/v1/register.iroh_relay_url` + `/v1/coord-self.relay_url`,
    // which `coord_conn::try_refresh_coord_self` and
    // `register::register` persist into `state.coord_iroh_relay_url`.
    // First boot of a new agent uses Disabled; the next process
    // start after registration / coord-self refresh picks up the
    // configured URL automatically — no per-agent env config, no
    // split-brain risk. (No per-agent env knob for relay-mode
    // override.)
    let relay_mode = match state.coord_iroh_relay_url.as_deref() {
        None => {
            info!("iroh: building endpoint (relay disabled — direct-only; coord has no relay configured or this is first boot)");
            iroh::RelayMode::Disabled
        }
        Some(url_str) => match url_str.parse::<iroh::RelayUrl>() {
            Ok(url) => {
                info!(
                    relay_url = %url,
                    "iroh: building endpoint (relay mode — URL from coord state)"
                );
                iroh::RelayMode::Custom(iroh::RelayMap::from(url))
            }
            Err(e) => {
                error!(
                    error = %e,
                    persisted = %url_str,
                    "state.coord_iroh_relay_url is invalid — coord-side bug or corrupted state file. Falling back to direct-only"
                );
                iroh::RelayMode::Disabled
            }
        },
    };
    let endpoint_builder =
        iroh::Endpoint::builder(iroh::endpoint::presets::Minimal).relay_mode(relay_mode);
    let iroh_endpoint = match endpoint_builder
        .secret_key(iroh::SecretKey::from_bytes(&identity.seed()))
        .alpns(vec![iroh_listener::P2CLAW_ALPN.to_vec()])
        .bind()
        .await
    {
        Ok(e) => e,
        Err(e) => {
            error!(error = %e, "could not bind iroh endpoint");
            let _ = sd_tx.send(true);
            return ExitCode::from(2);
        }
    };

    // `/v1/proxy` outbound cache. Dials with the agent's own iroh
    // endpoint — mandatory, not an optimization: the far side
    // authorizes the connection by the caller's peer id, which is
    // this endpoint's key.
    {
        let proxy_opts = p2claw_iroh_client::ClientOptions {
            parent_domain: state.parent_domain.clone(),
            coord_url: Some(coord_url.to_string()),
            timeout: std::time::Duration::from_secs(30),
            endpoint: Some(iroh_endpoint.clone()),
            relay_url: None,
        };
        let _ = peer_proxy_source.set(Arc::new(p2claw_agent::peer_dialer::PeerClientCache::new(
            proxy_opts,
        )));
    }
    {
        let endpoint = iroh_endpoint.clone();
        let sd = sd_rx.clone();
        let forwarder = forwarder.clone();
        // Iroh listener owns the sender side of the addrs watch.
        // Restarting it would need a fresh sender, so we hand the
        // task a single-use sender wrapped in an Option and only
        // restart if the listener returned a transient error before
        // ever sending. Production-day this almost never trips —
        // `serve_endpoint` is an async loop that only exits on
        // shutdown.
        let addrs_tx = std::sync::Mutex::new(Some(addrs_tx));
        supervisor.spawn("iroh-listener", move || {
            let endpoint = endpoint.clone();
            let sd = sd.clone();
            let forwarder = forwarder.clone();
            let iroh_sessions = iroh_sessions.clone();
            let tx = addrs_tx.lock().expect("addrs_tx mutex").take();
            async move {
                let Some(tx) = tx else {
                    error!("iroh listener restart skipped: addrs sender already consumed");
                    return;
                };
                // Per-connection handlers: the authenticated remote
                // peer id is bound into the Forwarder so private
                // routes can check shares and attribute the caller.
                let make_session = move |remote: iroh::EndpointId| {
                    let peer_forwarder = forwarder.for_peer(remote.to_z32());
                    let ws_handler: std::sync::Arc<dyn p2claw_translator::WsHandler> =
                        std::sync::Arc::new(p2claw_agent::ws_forwarder::WsForwarder::new(
                            peer_forwarder.clone(),
                        ));
                    (peer_forwarder, Some(ws_handler))
                };
                if let Err(e) = iroh_listener::serve_endpoint_per_peer(
                    endpoint,
                    tx,
                    sd,
                    make_session,
                    Some(iroh_sessions.clone()),
                )
                .await
                {
                    error!(error = %e, "iroh listener terminated");
                }
            }
        });
    }

    // ---------- MagicDNS pipeline ------------------
    //
    // Three new supervised tasks make `curl https://app-X.<parent>/`
    // from a local app on this box transparently route via Iroh to
    // the target box:
    //   - `dns_resolver` synthesizes A records pointing at 127.0.0.1
    //     for `*.<parent>` queries (forwards everything else upstream).
    //   - `local_ca` mints per-SNI leaf certs against a per-installation
    //     CA root that platform-install code installs into the system trust store.
    //   - `sni_listener` accepts TLS on 127.0.0.1:443, peeks the SNI,
    //     hands the in-flight handshake to `peer_dialer` which mints
    //     a cert + completes TLS + dials the target peer via Iroh.
    //
    // ## Publish-only mode
    //
    // The whole MagicDNS pipeline (CA load → 443 pre-bind → priv-drop
    // → DNS resolver spawn → SNI listener spawn) is gated on
    // `P2CLAW_AGENT_DISABLE_MAGICDNS=true` being unset. User-scope
    // installs (`p2claw service install` without `--system`) bake the
    // env var into their unit/plist because user launchd / user
    // systemd can't bind 443 anyway. In publish-only mode the agent:
    //   - Still accepts inbound peer-HTTP from visitors (Iroh QUIC on
    //     ephemeral UDP, no privileged ports needed). Apps published
    //     via `p2claw expose` work for outside callers.
    //   - Skips the SNI listener + DNS resolver. Local apps on this
    //     box can NOT dial OTHER boxes via
    //     `curl https://app-alias.<parent>/...` — the dial would
    //     resolve to 127.0.0.1 (default OS DNS) and fail with
    //     connection-refused, and the cert chain wouldn't validate
    //     anyway (no CA root in trust store).
    //   - Skips priv-drop. Nothing privileged to do; the agent just
    //     keeps the EUID it started with.
    //
    // The end-of-install upsell (`service::print_disable_magicdns_callout`)
    // tells operators what they're missing and how to fix it.
    let disable_magicdns = parse_bool_env("P2CLAW_AGENT_DISABLE_MAGICDNS");
    if disable_magicdns {
        info!(
            "P2CLAW_AGENT_DISABLE_MAGICDNS=true — skipping MagicDNS pipeline. \
             Inbound peer-HTTP works; outbound MagicDNS dials from local \
             apps will not. Re-install via `sudo p2claw service install \
             --system` for full functionality."
        );
    }

    let local_ca = if disable_magicdns {
        // Don't even mint the CA — there's no SNI listener to use it
        // for. Saves a small disk write on first start in publish-
        // only mode + avoids littering the data dir with material an
        // operator never asked for.
        None
    } else {
        match local_ca::LocalCa::load_or_generate(&paths.data_dir) {
            Ok(c) => Some(c),
            Err(e) => {
                error!(error = %e, "could not load/generate local CA root");
                let _ = sd_tx.send(true);
                return ExitCode::from(2);
            }
        }
    };

    // -- bind 443 + privilege drop --------------------------
    //
    // Order is load-bearing — see `priv_drop` module docs:
    //   1. local_ca already loaded above (root reads on-disk key
    //      into memory; cached for the rest of the process).
    //   2. Pre-bind 443 here while EUID==0 — the SNI listener's
    //      only privileged action.
    //   3. Resolve target user and drop privileges. Any failure
    //      is fatal: the security model assumes either "dropped"
    //      or "never was root", never "tried and failed".
    //   4. Hand the bound listener to the supervised SNI accept
    //      task (which spawns under the dropped user).
    //
    // Skipped on Linux + dev-mode runs where EUID is already
    // non-root: the bind still happens (so an operator running
    // dev-mode without 443 access surfaces the error early), but
    // priv_drop::drop_to is a no-op for the already-target case.
    //
    // ## data_dir file-access bucket map
    //
    // Anything the agent reads or writes from `paths.data_dir`
    // AFTER this point runs as the dropped user. Earlier code
    // assumed root-for-life; we sorted each access into one of:
    //
    // **Bucket A — load-once-cache-forever** (sensitive read-only):
    //   - `identity.key` — loaded into `Arc<SigningKey>` at line
    //     ~709 (cmd_run pre-drop), shared into coord_conn via
    //     Arc::clone. (A re-read post-drop would break with
    //     "Permission denied"; the Arc-share avoids that.)
    //   - `local_ca.key` — loaded via `local_ca::LocalCa::load_or_generate`
    //     at line ~897. LocalCa internally Arc-shares the key;
    //     leaf-mint reads from memory.
    //   Both files stay root-owned at 0600 on disk; the dropped
    //   user has no read access. Only root reads, only at startup.
    //
    // **Bucket B — needs-runtime-rw** (mutable state, dropped user
    // must own on disk):
    //   - `agent.state` — coord_conn re-registration writes this
    //     via `state_store::save`.
    //   - `routes.json` — local_api expose/unexpose writes via
    //     `RouteTable::upsert/remove`.
    //   - `upgrade-in-progress` / `upgrade-pin.json` /
    //     `upgrade-disabled` — auto_upgrade orchestrator + watchdog
    //     write these.
    //   These need the dropped user to own them on disk. The
    //   install's user-creation step chowns them at install time.
    //   For dev runs that don't go through the install scaffolding,
    //   the operator's environment
    //   needs to chown them post-init OR run as the file owner.
    //   Runtime check: see the per-write paths — IO errors surface
    //   as task-internal warnings (route registration / re-register
    //   logs) rather than agent-fatal crashes.
    //
    // **Bucket C — read-only, public** (no security concern):
    //   - `local_ca.crt` — public CA cert, world-readable.
    //   - `routes.json` (read path) — checked at startup before
    //     priv-drop into the in-memory RouteTable.
    // Bind + priv-drop only run when MagicDNS is enabled.
    // Publish-only mode skips both — there's nothing privileged to
    // do (no 443 bind), so no reason to drop or even resolve a
    // target user. The agent keeps the EUID it started with (whatever
    // user launchd / user systemd / `cargo run` gave it).
    let sni_listener_handle = if disable_magicdns {
        None
    } else {
        let sni_cfg =
            sni_listener::SniListenerConfig::with_parent_domain(state.parent_domain.clone());
        let listener = match sni_listener::bind(&sni_cfg).await {
            Ok(l) => Arc::new(l),
            Err(e) => {
                error!(error = %e, bind = %sni_cfg.bind, "could not bind SNI listener");
                let _ = sd_tx.send(true);
                return ExitCode::from(2);
            }
        };
        Some(listener)
    };
    let euid_before_drop = nix::unistd::geteuid();
    if !disable_magicdns && euid_before_drop.is_root() {
        // Resolve the runtime target user (env override → _p2claw
        // → SUDO_UID fallback). If none resolves, refuse — the
        // alternative would be "stay root", which silently widens
        // the threat model.
        let target = match priv_drop::resolve_for_runtime() {
            Ok(t) => t,
            Err(e) => {
                error!(
                    error = %e,
                    "priv_drop: could not resolve target user; refusing to continue as root \
                     (set {RUN_AS} or run install scaffolding to create the default user)",
                    RUN_AS = priv_drop::RUN_AS_USER_ENV
                );
                let _ = sd_tx.send(true);
                return ExitCode::from(2);
            }
        };
        if let Err(e) = priv_drop::drop_to(&target) {
            error!(
                error = %e,
                target = %target,
                "priv_drop: drop failed; refusing to continue (security model requires \
                 a clean drop, not a partial one)"
            );
            let _ = sd_tx.send(true);
            return ExitCode::from(2);
        }
        // Defensive log: a future code edit that breaks the
        // verify step in drop_to should surface here too. Cheap.
        if nix::unistd::geteuid().is_root() {
            error!("priv_drop: post-drop EUID is still 0; refusing to continue");
            let _ = sd_tx.send(true);
            return ExitCode::from(2);
        }
    } else if !disable_magicdns {
        info!(
            euid = euid_before_drop.as_raw(),
            "not running as root; priv_drop is a no-op (Linux CAP_NET_BIND_SERVICE \
             or dev-mode invocation)"
        );
    }
    // -- end priv-drop --------------------------------------

    if !disable_magicdns {
        let parent = state.parent_domain.clone();
        // Reserve the agent's own coord_domain so the resolver
        // forwards `coord.<parent>` upstream rather than
        // synthesizing 127.0.0.1 — without this, the agent's
        // peer_dialer's coord-discovery dial loops back to the
        // agent's OWN SNI listener (which then tries to parse
        // `coord` as an `<app>-<alias>` label and rejects).
        // Real bug-of-record.
        let coord_domain = state.coord_domain.clone();
        // Windows install bakes `P2CLAW_DNS_PORT=53` into the
        // Service registry's Environment block because NRPT can't
        // route to a non-53 nameserver. Read it here and override
        // the resolver's default 5354 bind. Malformed value: warn +
        // fall through to default (don't take the agent down for a
        // typo when there's a sane fallback). Unset: use default.
        let dns_port_override = match parse_u16_env("P2CLAW_DNS_PORT") {
            Ok(p) => p,
            Err(bad) => {
                warn!(
                    value = %bad,
                    default = dns_resolver::DEFAULT_BIND_PORT,
                    "P2CLAW_DNS_PORT did not parse as u16; falling back to default"
                );
                None
            }
        };
        let sd = sd_rx.clone();
        supervisor.spawn("dns-resolver", move || {
            let parent = parent.clone();
            let coord_domain = coord_domain.clone();
            let sd = sd.clone();
            async move {
                let mut cfg = dns_resolver::DnsResolverConfig::with_parent_domain(parent)
                    .with_reserved(coord_domain);
                if let Some(port) = dns_port_override {
                    info!(
                        port,
                        default = dns_resolver::DEFAULT_BIND_PORT,
                        "P2CLAW_DNS_PORT override active (Windows-NRPT or operator override)"
                    );
                    cfg = cfg.with_bind_port(port);
                }
                if let Err(e) = dns_resolver::serve(cfg, sd).await {
                    error!(error = %e, "DNS resolver terminated");
                }
            }
        });
    }
    // SNI listener spawn skipped under publish-only mode.
    // local_ca is None and sni_listener_handle is None in that
    // branch; we skip both the dialer construction (which needs
    // the CA) and the supervised serve task.
    if let (Some(ca), Some(listener_handle)) = (local_ca.as_ref(), sni_listener_handle.as_ref()) {
        let parent = state.parent_domain.clone();
        let ca = ca.clone();
        let sd = sd_rx.clone();
        // Thread the resolved coord_url through to the PeerDialer
        // so the iroh client's coord-discovery dial uses the right
        // host. In production this is usually
        // `https://<coord_domain>` (the same value the client
        // would derive on its own from `default_coord_url`); in
        // dev / e2e / self-hosted environments where coord lives
        // at a non-conventional URL, the operator-supplied
        // `P2CLAW_COORD_URL` lands here so the client doesn't
        // reach for the synthetic `https://coord.<parent>/`.
        let coord_url_for_dialer = coord_url.to_string();
        // Hand the pre-bound listener to the supervised
        // accept task. Arc-shared so supervisor's panic-restart
        // re-enters with the same FD (the listener was bound
        // under root before priv_drop ran; we cannot re-bind from
        // the now-dropped user). `serve_with_listener` takes
        // &Arc and accepts on a shared reference.
        let sni_listener_for_task = Arc::clone(listener_handle);
        supervisor.spawn("sni-listener", move || {
            let parent = parent.clone();
            let ca = ca.clone();
            let sd = sd.clone();
            let coord_url = coord_url_for_dialer.clone();
            let listener = Arc::clone(&sni_listener_for_task);
            async move {
                let dialer = std::sync::Arc::new(peer_dialer::PeerDialer::new(
                    ca.clone(),
                    parent.clone(),
                    Some(coord_url),
                ));
                if let Err(e) =
                    sni_listener::serve_with_listener(listener, &parent, dialer, sd).await
                {
                    error!(error = %e, "SNI listener terminated");
                }
            }
        });
    }

    // Signaling registry — shared between the control connection
    // (routes `signal_push` / `signal_relay` / `signal_end` frames
    // in) and the WebRTC session tasks (push `signal_relay` and
    // `signal_end` frames out). One registry persists across
    // control-WS reconnects; `shutdown_all()` clears its sessions
    // each time we disconnect, so new pushes always get a fresh
    // RTCPeerConnection.
    let (sig_out_tx, sig_out_rx) = mpsc::channel::<signal_handler::OutboundSignal>(64);
    let signal_registry = Arc::new(signal_handler::SignalRegistry::new(
        Arc::clone(&identity),
        sig_out_tx,
        forwarder,
    ));
    // Hand the registry to `GET /v1/sessions` now that it exists.
    let _ = session_source.set(Arc::clone(&signal_registry));

    // Coord connection: Iroh QUIC dial + length-prefixed
    // JSON envelopes over per-purpose streams.
    //
    // Was re-reading `identity.key` from disk here (via
    // `SigningKey::load_or_generate`) because SigningKey isn't
    // Clone. That worked while the agent held root for life;
    // post-priv-drop the file is unreadable to the dropped user
    // (`identity.key` stays root-owned at 0600 per the option-A
    // "read-once-cache-forever" posture). Now: clone the existing
    // `identity` Arc that was loaded in cmd_run before the drop.
    // Free — Arc::clone is a refcount bump.
    let state_path = paths.agent_state();
    let cc_handle = tokio::spawn({
        let state = state.clone();
        let sk = Arc::clone(&identity);
        let sd = sd_rx.clone();
        let addrs = addrs_rx.clone();
        let registry = Arc::clone(&signal_registry);
        let coord_url = coord_url.to_string();
        let coord_domain = coord_domain.to_string();
        let routes = routes.clone();
        let endpoint = iroh_endpoint.clone();
        let coord_health = coord_health_tx.clone();
        let email = email.clone();
        let oauth_grants = Arc::clone(&oauth_grants);
        async move {
            coord_conn::run(
                coord_url,
                coord_domain,
                state,
                state_path,
                sk,
                endpoint,
                addrs,
                sd,
                registry,
                sig_out_rx,
                routes,
                announcer_inbox,
                email,
                email_link_inbox,
                oauth_grants,
                coord_health,
            )
            .await
        }
    });

    // Spawn the post-upgrade watchdog if an upgrade-in-progress
    // flag was on disk at startup. Runs concurrently with the
    // supervised tasks; on Unhealthy it calls `restore_previous`
    // + clears the flag + (when running under a supervisor) calls
    // the platform restart trigger so the rolled-back binary
    // comes up.
    if upgrade_in_progress.is_some() {
        let socket = paths.agent_sock();
        let coord_health_rx = coord_health_rx.clone();
        let canonical = std::env::current_exe().unwrap_or_else(|e| {
            warn!(error = %e, "auto_upgrade: current_exe() failed; rollback path will be unavailable");
            std::path::PathBuf::new()
        });
        let data_dir = paths.data_dir.clone();
        tokio::spawn(async move {
            let outcome = auto_upgrade::watchdog::post_upgrade_health_check(
                auto_upgrade::watchdog::HealthCheckOpts {
                    local_api_socket: socket,
                    coord_health: coord_health_rx,
                    timeout: auto_upgrade::HEALTH_CHECK_TIMEOUT,
                },
            )
            .await;
            handle_watchdog_outcome(outcome, &canonical, &data_dir).await;
        });
    }

    // Hourly auto-upgrade orchestrator under supervisor only —
    // a dev iterating on `cargo run` shouldn't get auto-upgraded
    // out from under their build. See
    // `auto_upgrade::orchestrator::running_under_supervisor`.
    if auto_upgrade::orchestrator::running_under_supervisor() {
        let peer_id = identity.peer_id();
        let canonical = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::new());
        let data_dir = paths.data_dir.clone();
        let sd = sd_rx.clone();
        supervisor.spawn("auto-upgrade-orchestrator", move || {
            let peer_id = peer_id;
            let canonical = canonical.clone();
            let data_dir = data_dir.clone();
            let mut sd = sd.clone();
            async move {
                // Sleep first so a freshly-restarted agent doesn't
                // immediately re-poll. Hourly cadence per
                // `auto_upgrade::POLL_INTERVAL`.
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(auto_upgrade::POLL_INTERVAL) => {}
                        _ = sd.changed() => {
                            info!("auto_upgrade::orchestrator: shutdown");
                            return;
                        }
                    }
                    let opts = auto_upgrade::orchestrator::OrchestratorOpts {
                        release_repo: auto_upgrade::resolve_release_repo(),
                        self_version: env!("CARGO_PKG_VERSION").into(),
                        canonical_binary: canonical.clone(),
                        data_dir: data_dir.clone(),
                        restart_trigger: auto_upgrade::orchestrator::default_restart_trigger(),
                    };
                    // Unused by the orchestrator (GitHub Releases carry
                    // no rollout knob); kept in scope so the supervisor
                    // closure shape stays stable for a future phased rollout.
                    let _ = &peer_id;
                    match auto_upgrade::orchestrator::run_once(&opts).await {
                        Ok(outcome) => {
                            info!(?outcome, "auto_upgrade::orchestrator: cycle complete")
                        }
                        Err(e) => warn!(
                            error = %e,
                            "auto_upgrade::orchestrator: cycle failed; will retry next interval"
                        ),
                    }
                }
            }
        });
    } else {
        info!(
            "auto_upgrade: not running under a supervisor \
             (no INVOCATION_ID / XPC_SERVICE_NAME); orchestrator disabled"
        );
    }

    let outcome = wait_for_exit(cc_handle, &mut supervisor).await;

    let _ = sd_tx.send(true);
    supervisor.shutdown(Duration::from_secs(5)).await;

    outcome
}

/// Handle the post-upgrade watchdog's verdict. Healthy paths
/// clear the flag + best-effort drift-rewrite the service-config
/// (so service-config changes shipped alongside the binary
/// actually land). Unhealthy paths roll back the canonical binary
/// to `<canonical>.previous`, clear the flag, and (when running
/// under a supervisor) trigger a restart so the rolled-back
/// binary takes over.
async fn handle_watchdog_outcome(
    outcome: auto_upgrade::watchdog::HealthOutcome,
    canonical: &std::path::Path,
    data_dir: &std::path::Path,
) {
    use auto_upgrade::watchdog::HealthOutcome;
    match outcome {
        HealthOutcome::Healthy | HealthOutcome::HealthyCoordUnreachable => {
            info!(
                ?outcome,
                "auto_upgrade::watchdog: upgrade healthy; clearing flag + drift-rewriting service-config"
            );
            if let Err(e) = auto_upgrade::clear_upgrade_in_progress(data_dir) {
                warn!(error = %e, "auto_upgrade::watchdog: clear-flag failed");
            }
            // Service-config drift check + rewrite. Newly-shipped
            // service-config changes (e.g. a new
            // `LimitNOFILE=65536`) propagate alongside the binary
            // swap. Best-effort; failure here doesn't roll back.
            // Per the auto-upgrade contract.
            match service::check_drift(true) {
                Ok(report) => debug!(
                    state = ?report.state,
                    path = %report.path.display(),
                    "auto_upgrade::watchdog: post-upgrade service-config drift check"
                ),
                Err(e) => warn!(
                    error = %e,
                    "auto_upgrade::watchdog: service-config drift check failed (non-fatal)"
                ),
            }
        }
        HealthOutcome::Unhealthy { reason } => {
            error!(
                reason = %reason,
                canonical = %canonical.display(),
                "auto_upgrade::watchdog: UNHEALTHY — rolling back to .previous"
            );
            match auto_upgrade::restore_previous(canonical) {
                Ok(()) => info!(
                    canonical = %canonical.display(),
                    "auto_upgrade::watchdog: rollback restored .previous → canonical"
                ),
                Err(e) => error!(
                    error = %e,
                    "auto_upgrade::watchdog: rollback failed; broken binary remains in place"
                ),
            }
            if let Err(e) = auto_upgrade::clear_upgrade_in_progress(data_dir) {
                warn!(error = %e, "auto_upgrade::watchdog: clear-flag failed");
            }
            if auto_upgrade::orchestrator::running_under_supervisor() {
                let trigger = auto_upgrade::orchestrator::default_restart_trigger();
                match (trigger)() {
                    Ok(()) => info!("auto_upgrade::watchdog: rollback restart triggered; supervisor will bring up .previous"),
                    Err(e) => error!(error = %e, "auto_upgrade::watchdog: rollback restart trigger failed"),
                }
            } else {
                warn!(
                    "auto_upgrade::watchdog: not under supervisor; binary rolled back on disk \
                     but THIS process is still running the broken binary (manual restart required)"
                );
            }
        }
    }
}

/// Bag of all the `p2claw upgrade` flag values, decoded from
/// clap's `Cmd::Upgrade { ... }` shape. Centralises the
/// mutual-exclusion check + dispatch so each branch stays small.
struct UpgradeOp {
    check: bool,
    apply: bool,
    pin: Option<String>,
    unpin: bool,
    disable: bool,
    enable: bool,
    status: bool,
}

async fn cmd_upgrade(paths: &config::Paths, op: UpgradeOp) -> ExitCode {
    // Mutual exclusion: exactly one operation per invocation.
    // clap's `conflicts_with` chains get unwieldy at 7 flags;
    // hand-counting is clearer.
    let n = (op.check as u8)
        + (op.apply as u8)
        + (op.pin.is_some() as u8)
        + (op.unpin as u8)
        + (op.disable as u8)
        + (op.enable as u8)
        + (op.status as u8);
    if n != 1 {
        eprintln!(
            "p2claw upgrade: pass exactly one of \
             --check / --apply / --pin <V> / --unpin / --disable / --enable / --status"
        );
        return ExitCode::from(2);
    }

    // Pin / unpin / disable / enable / status are local-only —
    // no network, no identity load. Handle first to keep the
    // identity-load short-circuit only on the paths that need it.
    if let Some(version) = op.pin {
        // Sanity-check the user-supplied pin parses as SemVer
        // before persisting; we don't want a malformed pin to
        // surface as a runtime error in the orchestrator hours
        // later.
        if let Err(e) = semver::Version::parse(&version) {
            eprintln!("pin version `{version}` is not a valid SemVer: {e}");
            return ExitCode::from(2);
        }
        let pin = auto_upgrade::policy::UpgradePin {
            version: version.clone(),
        };
        match auto_upgrade::policy::write_pin(&paths.data_dir, &pin) {
            Ok(()) => {
                println!("pinned auto-upgrade to {version}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("could not write pin file: {e}");
                ExitCode::from(2)
            }
        }
    } else if op.unpin {
        match auto_upgrade::policy::clear_pin(&paths.data_dir) {
            Ok(()) => {
                println!("auto-upgrade unpinned");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("could not clear pin file: {e}");
                ExitCode::from(2)
            }
        }
    } else if op.disable {
        match auto_upgrade::policy::set_disabled(&paths.data_dir) {
            Ok(()) => {
                println!("auto-upgrade disabled");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("could not write disabled sentinel: {e}");
                ExitCode::from(2)
            }
        }
    } else if op.enable {
        match auto_upgrade::policy::clear_disabled(&paths.data_dir) {
            Ok(()) => {
                println!("auto-upgrade enabled");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("could not clear disabled sentinel: {e}");
                ExitCode::from(2)
            }
        }
    } else if op.status {
        let pin = match auto_upgrade::policy::read_pin(&paths.data_dir) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("could not read pin file: {e}");
                return ExitCode::from(2);
            }
        };
        let disabled = auto_upgrade::policy::is_disabled(&paths.data_dir);
        println!("self_version: {}", env!("CARGO_PKG_VERSION"));
        match pin {
            Some(p) => println!("pinned:       {}", p.version),
            None => println!("pinned:       (none)"),
        }
        println!("disabled:     {disabled}");
        ExitCode::SUCCESS
    } else if op.check || op.apply {
        // For --check we still need the peer_id to compute the
        // rollout-band decision honestly. Load from the on-disk
        // identity (no network).
        let sk = match p2claw_identity::SigningKey::load_or_generate(&paths.identity_key()) {
            Ok(k) => k,
            Err(e) => {
                error!(error = %e, "identity error");
                return ExitCode::from(2);
            }
        };
        let peer_id = sk.peer_id();
        let canonical = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "could not resolve current_exe()");
                return ExitCode::from(2);
            }
        };

        if op.check {
            let _ = peer_id; // unused by the upgrade path
            let release_repo = auto_upgrade::resolve_release_repo();
            match auto_upgrade::fetch_latest_release(&release_repo).await {
                Ok(latest) => {
                    let dec = match auto_upgrade::should_upgrade(env!("CARGO_PKG_VERSION"), &latest)
                    {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("release decision error: {e}");
                            return ExitCode::from(2);
                        }
                    };
                    let pin = auto_upgrade::policy::read_pin(&paths.data_dir)
                        .ok()
                        .flatten();
                    let disabled = auto_upgrade::policy::is_disabled(&paths.data_dir);
                    println!("self_version:    {}", env!("CARGO_PKG_VERSION"));
                    println!("release_repo:    {release_repo}");
                    println!("latest_version:  {}", latest.version);
                    println!("asset:           {}", latest.asset);
                    println!("decision:        {:?}", dec);
                    match pin {
                        Some(p) => println!("pin:             {}", p.version),
                        None => println!("pin:             (none)"),
                    }
                    println!("disabled:        {disabled}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("release fetch failed: {e}");
                    ExitCode::from(2)
                }
            }
        } else {
            // --apply: full orchestrator. The default restart
            // trigger SIGTERMs the agent's daemon process —
            // separate from this CLI process, so the CLI
            // returns normally.
            let _ = peer_id; // unused by the upgrade path
            let opts = auto_upgrade::orchestrator::OrchestratorOpts {
                release_repo: auto_upgrade::resolve_release_repo(),
                self_version: env!("CARGO_PKG_VERSION").into(),
                canonical_binary: canonical,
                data_dir: paths.data_dir.clone(),
                restart_trigger: auto_upgrade::orchestrator::default_restart_trigger(),
            };
            match auto_upgrade::orchestrator::run_once(&opts).await {
                Ok(
                    auto_upgrade::orchestrator::OrchestratorOutcome::StagedPendingManualRestart {
                        from,
                        to,
                    },
                ) => {
                    // Binary is swapped; only the supervised restart
                    // couldn't be triggered (no systemd/launchd unit —
                    // e.g. a manually-run `p2claw run`). Report success
                    // with a clear next step rather than a misleading
                    // error: the upgrade DID happen, it just needs a
                    // manual restart to take effect.
                    println!(
                        "p2claw upgraded {from} -> {to} and staged the new binary, but no \
                         service supervisor was found to restart the daemon.\n\
                         Restart the running daemon to apply: stop your `p2claw run` process \
                         and start it again (or `p2claw service install` to run it under a \
                         supervisor that auto-restarts on upgrade).\n\
                         The new version will run its health-check on the next start and roll \
                         back automatically if it fails to come up."
                    );
                    ExitCode::SUCCESS
                }
                Ok(outcome) => {
                    println!("upgrade outcome: {:?}", outcome);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("upgrade failed: {e}");
                    ExitCode::from(2)
                }
            }
        }
    } else {
        // Unreachable per the n != 1 check above; defensive.
        ExitCode::from(2)
    }
}

async fn wait_for_exit(
    cc_handle: tokio::task::JoinHandle<coord_conn::LoopOutcome>,
    supervisor: &mut supervisor::Supervisor,
) -> ExitCode {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "could not install SIGTERM handler");
            return ExitCode::from(2);
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "could not install SIGINT handler");
            return ExitCode::from(2);
        }
    };

    tokio::select! {
        _ = sigterm.recv() => {
            info!("SIGTERM received; shutting down");
            ExitCode::SUCCESS
        }
        _ = sigint.recv() => {
            info!("SIGINT received; shutting down");
            ExitCode::SUCCESS
        }
        fatal = supervisor.next_fatal() => {
            error!(
                task = %fatal.name,
                message = %fatal.message,
                "supervised subtask exceeded panic-limit; exiting"
            );
            ExitCode::from(1)
        }
        out = cc_handle => match out {
            Ok(coord_conn::LoopOutcome::Revoked) => {
                error!("peer_id revoked by coordination");
                ExitCode::from(3)
            }
            Ok(coord_conn::LoopOutcome::AuthFailedTooMany) => {
                error!(
                    "control: 4001 AUTH_FAILED hit the rate-limit guard — \
                     re-registration cannot recover"
                );
                ExitCode::from(4)
            }
            Ok(coord_conn::LoopOutcome::ReregisterPermanent { status, error }) => {
                error!(status, %error, "re-registration after 4001 returned a permanent failure");
                ExitCode::from(4)
            }
            Ok(coord_conn::LoopOutcome::Superseded) => {
                warn!("superseded by a newer agent instance");
                ExitCode::from(5)
            }
            Ok(coord_conn::LoopOutcome::Shutdown) => ExitCode::SUCCESS,
            Err(e) => {
                error!(error = %e, "control connection task panicked");
                ExitCode::from(2)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("p2claw").chain(args.iter().copied()))
    }

    #[test]
    fn expose_takes_port_or_socket_but_not_both() {
        assert!(parse(&["apps", "expose", "a", "--port", "8080"]).is_ok());
        assert!(parse(&["apps", "expose", "a", "--socket", "/run/a.sock"]).is_ok());
        assert!(parse(&["apps", "expose", "a"]).is_err());
        assert!(parse(&[
            "apps",
            "expose",
            "a",
            "--port",
            "1",
            "--socket",
            "/run/a.sock"
        ])
        .is_err());
    }

    #[test]
    fn expose_socket_rejects_public_and_oauth() {
        assert!(parse(&["apps", "expose", "a", "--socket", "/s", "--public"]).is_err());
        assert!(parse(&["apps", "expose", "a", "--socket", "/s", "--auth-oauth"]).is_err());
        assert!(parse(&["apps", "expose", "a", "--socket", "/s", "--private"]).is_ok());
    }

    #[test]
    fn connect_target_parses_alias_or_peer_id() {
        assert_eq!(
            connect::parse_target("blue-otter-7392/mysvc").unwrap(),
            ("blue-otter-7392".to_string(), "mysvc".to_string())
        );
        assert!(connect::parse_target("blue-otter-7392").is_err());
        assert!(connect::parse_target("blue-otter-7392/").is_err());
        assert!(connect::parse_target("Not An Alias/mysvc").is_err());
        assert!(connect::parse_target("blue-otter-7392/Bad_Name").is_err());
    }

    #[test]
    fn socket_upstream_is_absolute_and_url_safe() {
        assert_eq!(
            cli_client::socket_upstream(std::path::Path::new("/run/app.sock")).unwrap(),
            "unix:/run/app.sock"
        );
        let rel = cli_client::socket_upstream(std::path::Path::new("app.sock")).unwrap();
        let expected = std::env::current_dir().unwrap().join("app.sock");
        assert_eq!(rel, format!("unix:{}", expected.display()));
        assert!(cli_client::socket_upstream(std::path::Path::new("/tmp/my app.sock")).is_err());
        assert!(cli_client::socket_upstream(std::path::Path::new("/tmp/a#b.sock")).is_err());
    }

    /// Helper: set the env var for the lifetime of the closure,
    /// then unset. Avoids inter-test ordering bugs from leaking
    /// state across the process. NOT thread-safe across parallel
    /// tests — std env-var mutation is process-global, so each env
    /// test below uses a unique var name.
    fn with_env<R>(name: &str, value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let prev = std::env::var(name).ok();
        match value {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
        let r = f();
        match prev {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
        r
    }

    /// Pin `DEFAULT_PARENT_DOMAIN` to the canonical product
    /// when no build-time override was set. The canonical CI build
    /// ships with `P2CLAW_DEFAULT_PARENT_DOMAIN` unset, so this
    /// assertion holds. Self-hoster forks that bake in their own
    /// override get a different default at compile time, and this
    /// test will fail on their build (signalling that they must
    /// update the test or the override) — both arms of the
    /// `match` are covered.
    #[test]
    fn default_parent_domain_is_p2claw_com_when_env_unset() {
        // `option_env!` resolves at compile time. The const + the
        // test see the same compile-time value, so the assertion
        // is consistent within a single build.
        match option_env!("P2CLAW_DEFAULT_PARENT_DOMAIN") {
            None => assert_eq!(DEFAULT_PARENT_DOMAIN, "p2claw.com"),
            Some(override_) => assert_eq!(DEFAULT_PARENT_DOMAIN, override_),
        }
    }

    #[test]
    fn parse_u16_env_unset_returns_none() {
        with_env("P2CLAW_TEST_U16_UNSET", None, || {
            assert_eq!(parse_u16_env("P2CLAW_TEST_U16_UNSET"), Ok(None));
        });
    }

    #[test]
    fn parse_u16_env_valid_port_returns_some() {
        with_env("P2CLAW_TEST_U16_VALID", Some("53"), || {
            assert_eq!(parse_u16_env("P2CLAW_TEST_U16_VALID"), Ok(Some(53)));
        });
        // Trim whitespace — operators sometimes paste with leading
        // spaces from CSV / config copy-paste; parse should tolerate it.
        with_env("P2CLAW_TEST_U16_VALID2", Some("  443  "), || {
            assert_eq!(parse_u16_env("P2CLAW_TEST_U16_VALID2"), Ok(Some(443)));
        });
    }

    #[test]
    fn parse_u16_env_empty_treated_as_unset() {
        // An empty string MUST behave like unset, not an error.
        // Bash habit: `export FOO=` leaves FOO present-but-empty
        // in the child's env; we treat that as "operator didn't
        // set it" so the agent falls through to defaults.
        with_env("P2CLAW_TEST_U16_EMPTY", Some(""), || {
            assert_eq!(parse_u16_env("P2CLAW_TEST_U16_EMPTY"), Ok(None));
        });
        // Whitespace-only is the same case.
        with_env("P2CLAW_TEST_U16_WS", Some("   "), || {
            assert_eq!(parse_u16_env("P2CLAW_TEST_U16_WS"), Ok(None));
        });
    }

    #[test]
    fn parse_u16_env_malformed_returns_err_with_value() {
        // Non-numeric: caller logs the bad value + falls through
        // to the default. Returning Err rather than swallowing
        // means a typo'd port is observable in the logs.
        with_env("P2CLAW_TEST_U16_BAD", Some("not-a-number"), || {
            assert_eq!(
                parse_u16_env("P2CLAW_TEST_U16_BAD"),
                Err("not-a-number".to_string())
            );
        });
        // Out-of-range u16 (> 65535) — still an error, since u16
        // is the right type for a port.
        with_env("P2CLAW_TEST_U16_OOR", Some("70000"), || {
            assert_eq!(
                parse_u16_env("P2CLAW_TEST_U16_OOR"),
                Err("70000".to_string())
            );
        });
        // Negative: not a port. parse::<u16> rejects.
        with_env("P2CLAW_TEST_U16_NEG", Some("-1"), || {
            assert_eq!(parse_u16_env("P2CLAW_TEST_U16_NEG"), Err("-1".to_string()));
        });
    }

    #[test]
    fn parse_bool_env_recognizes_true_and_one_case_insensitive() {
        // Pin the existing semantics so the new parse_u16_env
        // sibling doesn't accidentally drift our env-parsing
        // conventions.
        with_env("P2CLAW_TEST_BOOL_T", Some("true"), || {
            assert!(parse_bool_env("P2CLAW_TEST_BOOL_T"));
        });
        with_env("P2CLAW_TEST_BOOL_TU", Some("TRUE"), || {
            assert!(parse_bool_env("P2CLAW_TEST_BOOL_TU"));
        });
        with_env("P2CLAW_TEST_BOOL_1", Some("1"), || {
            assert!(parse_bool_env("P2CLAW_TEST_BOOL_1"));
        });
        with_env("P2CLAW_TEST_BOOL_0", Some("0"), || {
            assert!(!parse_bool_env("P2CLAW_TEST_BOOL_0"));
        });
        with_env("P2CLAW_TEST_BOOL_FALSE", Some("false"), || {
            assert!(!parse_bool_env("P2CLAW_TEST_BOOL_FALSE"));
        });
        with_env("P2CLAW_TEST_BOOL_UNSET", None, || {
            assert!(!parse_bool_env("P2CLAW_TEST_BOOL_UNSET"));
        });
    }
}
