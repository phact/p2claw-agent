//! Local TLS terminator on `127.0.0.1:443` — the second half of the
//! MagicDNS pipeline (the first half is `dns_resolver.rs`).
//!
//! Flow on the box:
//!
//! ```text
//!   local app                         agent (this module)
//!     │                                     │
//!     │  curl https://app-X.<parent>/...    │
//!     │  ─── DNS A query ───►  dns_resolver │  → 127.0.0.1
//!     │  ─── TCP SYN/ACK ───►  port 443     │  ◄── this module
//!     │  ─── TLS ClientHello (SNI=app-X) ─► │
//!     │                                     │  read SNI via
//!     │                                     │  rustls::Acceptor
//!     │                                     │  validate SNI
//!     │                                     │
//!     │   (TLS terminate                     )
//!     │   (dial peer via Iroh                )
//!     │   (forward decrypted bytes peer→app  )
//! ```
//!
//! What this module owns: the bind, the per-connection SNI peek,
//! the validation, and the dispatch handoff. Cert-minting +
//! outbound dialing layer on top via the `Dispatcher` trait below
//! — anything implementing it receives `(stream, sni)` after this
//! module has confirmed the SNI is one we serve.
//!
//! # SNI extraction
//!
//! We don't hand-parse TLS records. `rustls::server::Acceptor` is
//! exactly the abstraction we want: it reads bytes incrementally,
//! parses the ClientHello when complete, and exposes
//! `Accepted::client_hello().server_name()` without committing to a
//! cipher / handshake / cert. We then either hand it off to the
//! dispatcher (which will layer a `ServerConfig` and complete the
//! handshake) or close the connection cleanly.
//!
//! # Validation
//!
//! Strict-by-default:
//! - Empty SNI → reject. Pre-TLS-1.3 clients sometimes omit SNI;
//!   modern HTTP clients always send it.
//! - IP-literal SNI (`127.0.0.1`, `[::1]`) → reject. Never a haiku
//!   peer label.
//! - Wrong parent (`app-X.example.com`) → reject. Defense in depth
//!   even though DNS scoping should make this unreachable.
//! - Non-haiku grammar → reject. Reuses
//!   [`crate::hostname::parse_peer_label`] so we share one parser
//!   with the inbound `Forwarder`.
//!
//! Rejected connections are dropped without a TLS Alert. Sending an
//! Alert would require a cert and partial handshake — overhead that
//! gives a misbehaving caller no useful signal beyond "the port
//! closed on me." A future addition could send `unrecognized_name`
//! (RFC 6066 §3) but the current "drop on close" is consistent with
//! how the local-API SO_PEERCRED rejection works.
//!
//! # FD hygiene
//!
//! Each accepted TCP stream is owned by its per-connection task;
//! drop on early-return paths releases the FD immediately. The
//! per-connection peek has its own bounded timeout
//! ([`PEEK_TIMEOUT`]) so a port-scan that opens a TCP connection but
//! never sends bytes can't pin an FD. Listener-level EMFILE is
//! handled the same way the local-API does (per-task panic surfaced
//! to the supervisor) — the EMFILE-on-accept handling layered into
//! the agent's `main.rs` pattern reuses the same guard.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::server::Acceptor;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{debug, info, warn};

use p2claw_iroh_client::url::{P2clawHost, UrlParseError};

/// Default TCP bind. Loopback-only — local apps connect via the DNS
/// synth at `127.0.0.1`. The platform-install code binds 443 with
/// `CAP_NET_BIND_SERVICE` (Linux) / LaunchDaemon (macOS) so this
/// constant is reachable from the actual production wire-up. Tests
/// override with an OS-assigned port.
pub const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);

/// Per-connection cap for "open the TCP connection, send something
/// resembling a TLS ClientHello." A port scan that opens a connection
/// but never writes a byte must NOT pin an FD here forever. 5s is
/// generous for a same-host TLS ClientHello round-trip and short
/// enough that the FD-budget under scan pressure stays bounded.
const PEEK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum SniListenerError {
    #[error("could not bind {bind}: {source}")]
    Bind {
        bind: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Configuration for [`serve`].
#[derive(Debug, Clone)]
pub struct SniListenerConfig {
    /// TCP bind. Default [`DEFAULT_BIND`].
    pub bind: SocketAddr,
    /// Parent domain whose haiku peer labels we accept (e.g.
    /// `"p2claw.com"`). Cross-checked against the SNI's parent in
    /// [`validate_sni`].
    pub parent_domain: String,
}

impl SniListenerConfig {
    pub fn with_parent_domain(parent_domain: impl Into<String>) -> Self {
        Self {
            bind: DEFAULT_BIND,
            parent_domain: parent_domain.into(),
        }
    }
}

/// Opaque handoff from the SNI listener to the next layer (the
/// TLS-terminating cert minter, then the peer dialer). Implementors
/// receive a still-pre-TLS stream + the validated SNI, and own
/// everything that comes next:
/// completing the rustls handshake against a per-SNI cert,
/// translating to a peer-HTTP request, dialing via Iroh, ferrying
/// bytes both ways.
///
/// Trait rather than a concrete fn type so test code can plug in a
/// no-op or assertion-driven dispatcher without dragging in the
/// real cert-minting machinery.
pub trait Dispatcher: Send + Sync + 'static {
    /// Take ownership of the validated connection. The implementer
    /// is responsible for completing the TLS handshake using the
    /// already-parsed `Accepted` (which carries the ClientHello +
    /// the buffered handshake bytes), running the request, and
    /// finally dropping the stream. This module's responsibility
    /// ends at the call.
    ///
    /// `accepted` is `tokio_rustls::StartHandshake` — the rustls
    /// async-handshake handle once the ClientHello has been read.
    /// It still needs a `ServerConfig` (which the cert-minter
    /// supplies) before it becomes a `TlsStream`.
    fn dispatch(
        &self,
        accepted: tokio_rustls::StartHandshake<TcpStream>,
        sni: P2clawHost,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

/// Bind the SNI listener at `config.bind` and return the
/// `TcpListener`, leaving the accept loop to a subsequent
/// [`serve_with_listener`] call.
///
/// **Why this is a separate step**: macOS system-scope
/// installs run the agent as root so the SNI listener can bind
/// 127.0.0.1:443 (ports < 1024 are root-only on Darwin). Once
/// bound, the agent's privilege-drop dance (`priv_drop::drop_to`)
/// permanently demotes the process to a dedicated `_p2claw`
/// system user. The drop has to happen BEFORE the accept loop
/// starts spawning per-connection tasks — those tasks inherit
/// the current EUID, so any task that spawns while we're still
/// root means an exploit in the TLS handshake or HTTP path runs
/// with root privilege. Splitting bind from accept lets cmd_run
/// pre-bind under root, drop, then hand the listener to the
/// supervised accept task.
///
/// Holds the file descriptor across the `await` of `drop_to` —
/// this is OK: the FD references the kernel's listening socket
/// and survives the EUID change unchanged. Subsequent
/// `accept()` calls run as the dropped user.
pub async fn bind(config: &SniListenerConfig) -> Result<TcpListener, SniListenerError> {
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|e| SniListenerError::Bind {
            bind: config.bind,
            source: e,
        })?;
    info!(bind = %config.bind, parent = %config.parent_domain, "sni: listener bound");
    Ok(listener)
}

/// Run the SNI listener until `shutdown` flips. Returns when shutdown
/// fires; bind errors surface before the loop starts. Convenience
/// wrapper around [`bind`] + [`serve_with_listener`] for callers
/// that don't need to separate the two phases (e.g., dev-mode where
/// 443 isn't bound and there's nothing to drop).
pub async fn serve<D: Dispatcher>(
    config: SniListenerConfig,
    dispatcher: Arc<D>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), SniListenerError> {
    let listener = Arc::new(bind(&config).await?);
    serve_with_listener(listener, &config.parent_domain, dispatcher, shutdown).await
}

/// Run the SNI accept loop on `listener` until `shutdown` flips.
/// Caller-supplied listener: lets `cmd_run` pre-bind 443 under
/// root, drop privileges, then hand the bound listener in.
///
/// Takes `parent_domain` separately rather than re-passing the
/// full `SniListenerConfig` because the bind has already happened
/// — `config.bind` would be confusing dead state at this point.
///
/// Listener arrives as `Arc<TcpListener>` rather than owned: the
/// supervisor in cmd_run restarts the spawned accept-task on
/// panic, and an owned listener would be consumed on first run.
/// Sharing via Arc lets restart re-enter with the same FD, and
/// `TcpListener::accept(&self)` is sound for shared use because
/// the kernel-side listening socket handles concurrent accepts
/// itself (there's only one accept at a time inside this loop
/// either way).
pub async fn serve_with_listener<D: Dispatcher>(
    listener: Arc<TcpListener>,
    parent_domain: &str,
    dispatcher: Arc<D>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), SniListenerError> {
    info!(parent = %parent_domain, "sni: listener up");

    let parent_domain: Arc<str> = Arc::from(parent_domain);

    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, peer)) => {
                        let dispatcher = Arc::clone(&dispatcher);
                        let parent_domain = Arc::clone(&parent_domain);
                        // Per-conn task so a slow ClientHello doesn't
                        // HoL-block the listener.
                        tokio::spawn(async move {
                            handle_connection(stream, peer, &parent_domain, dispatcher).await;
                        });
                    }
                    Err(e) => {
                        // Bubbling EMFILE up here is handled separately
                        // (the agent main.rs pattern turns the
                        // LocalApiError::AcceptFdLimit panic into a
                        // process-restart). For now: log and continue
                        // — non-FD-limit accept errors are transient.
                        warn!(error = %e, "sni: accept failed");
                    }
                }
            }
            _ = shutdown.changed() => {
                info!("sni: shutdown");
                return Ok(());
            }
        }
    }
}

/// Per-connection handler: SNI peek, validate, hand off OR close.
/// Errors are swallowed here — this is the boundary where misuse
/// turns into "drop the connection silently" rather than
/// propagating up to the listener.
async fn handle_connection<D: Dispatcher>(
    stream: TcpStream,
    peer: SocketAddr,
    parent_domain: &str,
    dispatcher: Arc<D>,
) {
    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);

    let accepted = match tokio::time::timeout(PEEK_TIMEOUT, acceptor).await {
        Ok(Ok(a)) => a,
        Ok(Err(e)) => {
            debug!(%peer, error = %e, "sni: TLS ClientHello read failed");
            return;
        }
        Err(_) => {
            debug!(%peer, timeout_secs = PEEK_TIMEOUT.as_secs(),
                "sni: ClientHello timed out; closing");
            return;
        }
    };

    // `client_hello()` exposes everything from the ClientHello — we
    // care about `server_name()` (SNI). Empty / missing SNI → reject.
    let sni_str = match accepted.client_hello().server_name() {
        Some(s) => s.to_string(),
        None => {
            debug!(%peer, "sni: ClientHello had no SNI; closing");
            close_with_eof(accepted).await;
            return;
        }
    };

    let parsed = match validate_sni(&sni_str, parent_domain) {
        Ok(p) => p,
        Err(e) => {
            debug!(%peer, sni = %sni_str, error = %e,
                "sni: rejected SNI; closing");
            close_with_eof(accepted).await;
            return;
        }
    };

    debug!(%peer, sni = %sni_str, app = ?parsed.app, alias = %parsed.alias_label,
        "sni: dispatching to next layer");
    dispatcher.dispatch(accepted, parsed).await;
}

/// Validate an SNI string per the strict-by-default rules in the
/// module docs. Returns the parsed haiku peer label on success,
/// rejection reason on failure.
fn validate_sni(sni: &str, parent_domain: &str) -> Result<P2clawHost, SniRejection> {
    if sni.is_empty() {
        return Err(SniRejection::Empty);
    }
    // IP literals are never haiku peer labels. `P2clawHost::parse`
    // would reject these too (no haiku grammar), but pre-checking
    // gives operators a clearer log line and avoids running the
    // grammar parser on obviously-out-of-scope input. Tested
    // explicitly against the IPv6 unbracketed form because rustls
    // can hand us `::1` without brackets.
    if sni.parse::<IpAddr>().is_ok() {
        return Err(SniRejection::IpLiteral);
    }
    // `P2clawHost::parse` is strict-by-default: rejects wrong
    // parent + bad haiku + multi-label labels. It tolerates a
    // trailing-dot FQDN
    // (RFC compliance). No port stripping — TLS SNI never carries
    // a port, so nothing to strip.
    let parsed = P2clawHost::parse(sni, parent_domain).map_err(SniRejection::Hostname)?;
    if parsed.app.is_none() {
        // Apex (`<alias>.<parent>`) is the listing page served by
        // edge; the agent never owns it.
        // A request reaching us at the apex is misrouted.
        return Err(SniRejection::ApexAtAgent);
    }
    Ok(parsed)
}

#[derive(Debug, Error)]
enum SniRejection {
    #[error("empty SNI")]
    Empty,
    #[error("SNI is an IP literal — never a haiku peer label")]
    IpLiteral,
    #[error("apex SNI; the agent doesn't own the listing page")]
    ApexAtAgent,
    #[error("hostname rejected: {0}")]
    Hostname(UrlParseError),
}

/// Close an `Accepted` cleanly without sending a TLS Alert. We send
/// no bytes (the underlying TCP just gets `shutdown()`-ed) — clients
/// see EOF before the handshake completes, which is the right signal
/// for "wrong destination, try elsewhere" without leaking which path
/// the rejection took.
async fn close_with_eof(accepted: tokio_rustls::StartHandshake<TcpStream>) {
    // `StartHandshake` consumes the underlying I/O on `into_stream`,
    // but we don't have a `ServerConfig` to actually drive that —
    // and even if we did, completing the handshake just to close it
    // adds overhead and gives the misbehaving caller no useful signal.
    // The handshake handle's `Drop` impl tears down the I/O for us.
    // We intentionally don't shutdown(): the rustls accept layer
    // already buffered some bytes, and a half-closed shutdown sequence
    // here is more confusion than clarity.
    drop(accepted);
}

/// Convenience for callers that want to send an explicit RST or FIN.
/// Currently unused — `close_with_eof` (drop) is the active path —
/// but kept around as an alternative for later if the silent-EOF
/// rejection turns out to confuse some HTTP clients.
#[allow(dead_code)]
async fn shutdown_stream(mut stream: TcpStream) {
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ---------- pure validate_sni() tests --------------------------

    #[test]
    fn validate_accepts_canonical_app_haiku() {
        let p = validate_sni("recipes-blue-otter-7392.p2claw.com", "p2claw.com").unwrap();
        assert_eq!(p.app.as_deref(), Some("recipes"));
        assert_eq!(p.alias_label, "blue-otter-7392");
    }

    #[test]
    fn validate_strips_trailing_dot_fqdn() {
        let p = validate_sni("recipes-blue-otter-7392.p2claw.com.", "p2claw.com").unwrap();
        assert_eq!(p.app.as_deref(), Some("recipes"));
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(matches!(
            validate_sni("", "p2claw.com").unwrap_err(),
            SniRejection::Empty
        ));
    }

    #[test]
    fn validate_rejects_ipv4_literal() {
        assert!(matches!(
            validate_sni("127.0.0.1", "p2claw.com").unwrap_err(),
            SniRejection::IpLiteral
        ));
    }

    #[test]
    fn validate_rejects_ipv6_literal() {
        assert!(matches!(
            validate_sni("::1", "p2claw.com").unwrap_err(),
            SniRejection::IpLiteral
        ));
    }

    #[test]
    fn validate_rejects_wrong_parent() {
        let err = validate_sni("recipes-blue-otter-7392.example.com", "p2claw.com").unwrap_err();
        assert!(matches!(err, SniRejection::Hostname(_)), "{err:?}");
    }

    #[test]
    fn validate_rejects_apex() {
        // Bare alias (no app prefix) under correct parent — the
        // listing-page form. Agent doesn't own it.
        let err = validate_sni("blue-otter-7392.p2claw.com", "p2claw.com").unwrap_err();
        assert!(matches!(err, SniRejection::ApexAtAgent), "{err:?}");
    }

    #[test]
    fn validate_rejects_non_haiku_alias() {
        // 3-digit numeric tail violates the haiku grammar (NNNN+).
        let err = validate_sni("recipes-blue-otter-739.p2claw.com", "p2claw.com").unwrap_err();
        assert!(matches!(err, SniRejection::Hostname(_)), "{err:?}");
    }

    // ---------- end-to-end: bind + accept + SNI peek ---------------

    /// Test dispatcher that records what it received and counts
    /// dispatches. Used to verify the listener actually hands valid
    /// SNIs through. Inner state behind an `Arc` so the returned
    /// `'static` future can move a clone in — avoids the
    /// `&self`-lifetime problem cleanly without `unsafe`.
    struct RecordingDispatcher {
        inner: Arc<RecordingInner>,
    }

    struct RecordingInner {
        seen: tokio::sync::Mutex<Vec<String>>,
        count: AtomicUsize,
    }

    impl RecordingDispatcher {
        fn new() -> Self {
            Self {
                inner: Arc::new(RecordingInner {
                    seen: tokio::sync::Mutex::new(Vec::new()),
                    count: AtomicUsize::new(0),
                }),
            }
        }

        fn count(&self) -> usize {
            self.inner.count.load(Ordering::SeqCst)
        }

        async fn seen(&self) -> Vec<String> {
            self.inner.seen.lock().await.clone()
        }
    }

    impl Dispatcher for RecordingDispatcher {
        fn dispatch(
            &self,
            accepted: tokio_rustls::StartHandshake<TcpStream>,
            sni: P2clawHost,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
            self.inner.count.fetch_add(1, Ordering::SeqCst);
            let label = format!("{}.{}", sni.app.as_deref().unwrap_or(""), sni.alias_label,);
            let inner = Arc::clone(&self.inner);
            Box::pin(async move {
                inner.seen.lock().await.push(label);
                // We don't actually drive the TLS handshake — the
                // test asserts on the SNI we extracted, then drops
                // the StartHandshake to close the underlying TCP.
                drop(accepted);
            })
        }
    }

    /// Build a minimal valid TLS ClientHello with the given SNI.
    /// Uses rustls's own client side as the easiest correct emitter
    /// — the test doesn't care about the rest of the handshake;
    /// only that the server sees the right `server_name()`.
    async fn send_client_hello_with_sni(addr: SocketAddr, sni: &str) {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let mut cfg = rustls::ClientConfig::builder()
            .dangerous() // we never complete the handshake; trust check is moot
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(cfg));
        let server_name = ServerName::try_from(sni.to_string()).unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();
        // We don't await completion — the connector starts the
        // handshake and the server task picks up the ClientHello.
        // The test doesn't actually need a finished handshake, just
        // the SNI peek.
        let _ = connector.connect(server_name, stream).await;
    }

    /// Cert verifier that accepts everything. Tests only — we don't
    /// complete a handshake against a real cert; the connector just
    /// sends the ClientHello and we then drop.
    #[derive(Debug)]
    struct NoVerifier;
    impl rustls::client::danger::ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_accepts_valid_sni_and_dispatches() {
        // Install rustls's default crypto provider (ring) — required
        // by 0.23 before any ClientConfig / ServerConfig builds.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // OS-assigned port so multiple test runs don't collide.
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let probe = TcpListener::bind(bind).await.unwrap();
        let actual_bind = probe.local_addr().unwrap();
        drop(probe);

        let dispatcher = Arc::new(RecordingDispatcher::new());
        let cfg = SniListenerConfig {
            bind: actual_bind,
            parent_domain: "p2claw.com".into(),
        };
        let (sd_tx, sd_rx) = watch::channel(false);
        let server = {
            let dispatcher = Arc::clone(&dispatcher);
            tokio::spawn(async move { serve(cfg, dispatcher, sd_rx).await })
        };

        // Wait for the listener to bind. No readiness signal back
        // from `serve()`; short sleep is the simplest pattern.
        tokio::time::sleep(Duration::from_millis(100)).await;

        send_client_hello_with_sni(actual_bind, "recipes-blue-otter-7392.p2claw.com").await;

        // Give the server task a beat to read the ClientHello and
        // dispatch.
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(dispatcher.count(), 1, "expected one dispatch");
        let seen = dispatcher.seen().await;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0], "recipes.blue-otter-7392");

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), server).await;
    }

    /// Pin the bind/serve_with_listener split: callers can
    /// pre-bind under one identity and run the accept loop after
    /// (e.g., as a non-root user post-priv-drop). Verifies the
    /// FD-survives-handoff invariant the priv-drop pattern depends
    /// on — without it, dropping privileges between bind + accept
    /// would invalidate the listener. We don't actually drop privs
    /// in this test (would need root) but we DO take the explicit
    /// two-step path to confirm the API works.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bind_then_serve_with_listener_round_trips() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let probe = TcpListener::bind(bind_addr).await.unwrap();
        let actual_bind = probe.local_addr().unwrap();
        drop(probe);

        let cfg = SniListenerConfig {
            bind: actual_bind,
            parent_domain: "p2claw.com".into(),
        };
        let dispatcher = Arc::new(RecordingDispatcher::new());
        let (sd_tx, sd_rx) = watch::channel(false);

        // Pre-bind. In production this happens while EUID==0 so we
        // can grab port 443.
        let listener = Arc::new(bind(&cfg).await.expect("pre-bind succeeds"));

        // Accept loop. In production priv_drop::drop_to runs between
        // the bind and this step.
        let parent_domain = cfg.parent_domain.clone();
        let server = {
            let dispatcher = Arc::clone(&dispatcher);
            tokio::spawn(async move {
                serve_with_listener(listener, &parent_domain, dispatcher, sd_rx).await
            })
        };

        tokio::time::sleep(Duration::from_millis(100)).await;
        send_client_hello_with_sni(actual_bind, "recipes-blue-otter-7392.p2claw.com").await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            dispatcher.count(),
            1,
            "two-step bind/serve must dispatch valid SNIs same as serve()"
        );
        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), server).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_rejects_bad_sni_without_dispatch() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let probe = TcpListener::bind(bind).await.unwrap();
        let actual_bind = probe.local_addr().unwrap();
        drop(probe);

        let dispatcher = Arc::new(RecordingDispatcher::new());
        let cfg = SniListenerConfig {
            bind: actual_bind,
            parent_domain: "p2claw.com".into(),
        };
        let (sd_tx, sd_rx) = watch::channel(false);
        let server = {
            let dispatcher = Arc::clone(&dispatcher);
            tokio::spawn(async move { serve(cfg, dispatcher, sd_rx).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send three rejection-class SNIs. None should dispatch.
        send_client_hello_with_sni(actual_bind, "evil.example.com").await;
        send_client_hello_with_sni(actual_bind, "blue-otter-7392.p2claw.com").await;
        send_client_hello_with_sni(actual_bind, "recipes-blue-otter-7.p2claw.com").await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            dispatcher.count(),
            0,
            "rejected SNIs must NOT dispatch — saw {} dispatches",
            dispatcher.count()
        );

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), server).await;
    }
}
