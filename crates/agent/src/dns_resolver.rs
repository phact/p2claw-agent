//! Local MagicDNS-style stub resolver — Tailscale's pattern.
//!
//! The agent binds a UDP socket on a configurable loopback port
//! (default `127.0.0.1:5354`). The OS resolver chain is configured
//! by the install-time platform integration to route
//! `*.<parent_domain>` queries here:
//!
//! - Linux + systemd-resolved: `Domains=~p2claw.com DNS=127.0.0.1:5354`.
//! - macOS: `/etc/resolver/p2claw.com` with `nameserver 127.0.0.1` +
//!   `port 5354`.
//! - Windows NRPT policy targeting `.p2claw.com` → `127.0.0.1`.
//!
//! For matching queries the resolver synthesizes responses entirely
//! locally — never round-trips to a real DNS server:
//!
//! - **A**: returns `127.0.0.1`, TTL [`SYNTH_TTL_SECS`]. The agent's
//!   443 listener is the next hop.
//! - **AAAA**: returns NODATA (NOERROR + zero answers). Forces apps
//!   that prefer IPv6 to fall back to A. Synthesizing `::1` would
//!   work too but adds another bind-target the install integration
//!   has to keep alive; we stick to IPv4-only loopback.
//! - **Any other RR type** (TXT, MX, NS, SRV, …): NODATA. We don't
//!   pretend to be authoritative for anything beyond loopback
//!   redirection.
//!
//! For everything else (queries that don't match `<parent_domain>`,
//! or that arrive with multiple questions, or are otherwise
//! malformed) the resolver forwards to a configured upstream — read
//! once at startup from the system resolver config via
//! [`hickory_resolver::system_conf`]. Forwarding is raw UDP relay:
//! we send the original query bytes upstream and return the
//! upstream's response bytes verbatim. That preserves transaction
//! ID, EDNS, DNSSEC bits, additional sections, and anything else the
//! upstream wants to ship — without us re-implementing a recursive
//! resolver.
//!
//! # Hot-path discipline
//!
//! Per-query behavior is bounded:
//! - One UDP `recv_from` to read the query (4 KiB buffer; per RFC 1035
//!   §4.2.1 a UDP query is ≤ 512 bytes pre-EDNS, ≤ 4 KiB post-EDNS).
//! - One in-process parse via `hickory-proto`.
//! - Either one synthesized encode + `send_to` (matching path), or
//!   one upstream UDP round-trip (forwarding path). Both bounded by
//!   the per-query timeout [`UPSTREAM_TIMEOUT`].
//!
//! Upstream forwarding spawns a per-query task so a slow upstream
//! doesn't head-of-line-block other in-flight queries on the shared
//! listener socket. Tasks are budgeted via the timeout — they cannot
//! pile up indefinitely.
//!
//! # FD hygiene
//!
//! Each forwarded query opens its own short-lived ephemeral UDP socket
//! against the upstream and drops it as soon as the response lands or
//! the timeout fires. No long-lived per-upstream pool; FD-budget is
//! `O(in-flight forwarded queries)`, bounded by [`UPSTREAM_TIMEOUT`]
//! × incoming query rate. The `header_read_timeout`-style discipline
//! used on the local API isn't directly reusable for UDP, but the
//! explicit per-query timeout serves the same purpose.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::system_conf;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// TTL on synthesized A records. Short enough that a config change
/// (parent_domain rotation, agent uninstall) propagates within
/// minutes, long enough that bursty connection setup doesn't pummel
/// the resolver. Mirrors Tailscale MagicDNS's choice.
const SYNTH_TTL_SECS: u32 = 60;

/// Per-query upstream forward timeout. A slow upstream must not pin
/// an FD or a per-query task indefinitely. 5s is generous for a
/// typical recursive resolver round-trip and short enough that a
/// dead upstream doesn't hide for minutes.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum DNS message size we'll buffer. RFC 1035 §4.2.1 puts UDP
/// at 512 bytes; EDNS extends to ~4 KiB advertised. We allocate at
/// 4 KiB to comfortably cover EDNS without TCP fallback.
const MAX_MSG_BYTES: usize = 4096;

/// Default loopback DNS port the resolver binds to. 5354 picked
/// to avoid the well-known 5353 mDNS port (Avahi / Bonjour),
/// which is conflict-prone on macOS. The per-platform install
/// modules (`linux_install`, `macos_install`) re-export this so
/// the systemd-resolved drop-in / `/etc/resolver/<parent>` file
/// they write points at the same port the resolver binds on.
/// Single source of truth — diverging would mean DNS queries
/// going to a port nothing's listening on (a real bug-of-record
/// from earlier e2e: harness installer wrote 5454, resolver bound
/// 5354, every box-A → box-B curl failed with "could not
/// resolve host"). Windows is the exception: NRPT can't take a
/// non-53 port spec, so the Windows install sets
/// `P2CLAW_DNS_PORT=53` in env (the agent reads it on startup).
pub const DEFAULT_BIND_PORT: u16 = 5354;

/// Default loopback bind. The OS resolver chain is configured to
/// route `*.<parent_domain>` queries here (per-platform install
/// integration).
pub const DEFAULT_BIND: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_BIND_PORT);

#[derive(Debug, Error)]
pub enum DnsResolverError {
    #[error("could not bind {bind}: {source}")]
    Bind {
        bind: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("could not load system resolver config: {0}")]
    SystemConf(#[source] std::io::Error),
    #[error("system resolver config returned no upstream nameservers")]
    NoUpstreams,
}

/// Configuration for [`serve`].
#[derive(Debug, Clone)]
pub struct DnsResolverConfig {
    /// Bind socket. Default [`DEFAULT_BIND`].
    pub bind: SocketAddr,
    /// Parent domain whose subdomains we synthesize. e.g.
    /// `"p2claw.com"`. Comparison is case-insensitive (DNS labels
    /// are by definition); the parsed `Name` we test against is
    /// canonicalized at startup.
    pub parent_domain: String,
    /// Fully-qualified subdomains-of-parent we should NOT
    /// synthesize, even though they match the parent — forward
    /// upstream instead.
    ///
    /// **Why this exists**: the agent's
    /// own peer_dialer constructs a coord-discovery URL of
    /// `https://<coord_domain>/v1/connect`, and `coord_domain` is
    /// typically a subdomain of `parent_domain`
    /// (`coord.p2claw.com` under `p2claw.com`). Without this
    /// reservation list, the agent's resolver synthesizes
    /// 127.0.0.1 for `coord.p2claw.com`, peer_dialer connects to
    /// its own SNI listener, the listener tries to parse
    /// `coord` as an `<app>-<alias>` label and rejects, and the
    /// dial fails with "no_such_peer". Reserving the coord_domain
    /// fixes the loop without disabling MagicDNS more broadly.
    ///
    /// Production: cmd_run populates this with the agent's
    /// coord_domain. Operators with multiple infra-host names
    /// under the parent domain (e.g. `status.p2claw.com`,
    /// `docs.p2claw.com`) can extend the list — those are then
    /// reachable via real DNS instead of being shadowed by the
    /// MagicDNS hijack.
    pub reserved_subdomains: Vec<String>,
}

impl DnsResolverConfig {
    pub fn with_parent_domain(parent_domain: impl Into<String>) -> Self {
        Self {
            bind: DEFAULT_BIND,
            parent_domain: parent_domain.into(),
            reserved_subdomains: Vec::new(),
        }
    }

    /// Builder-style chain to add a reserved subdomain. Production
    /// use case: `cmd_run` chains `.with_reserved(state.coord_domain)`
    /// after `with_parent_domain(state.parent_domain)` so the
    /// agent's own coord-discovery URL bypasses synthesis.
    pub fn with_reserved(mut self, name: impl Into<String>) -> Self {
        self.reserved_subdomains.push(name.into());
        self
    }

    /// Override the loopback bind port. Default is
    /// [`DEFAULT_BIND_PORT`] (5354 — picked to dodge mDNS at 5353
    /// on macOS).
    ///
    /// Why this exists: Windows NRPT
    /// (`Add-DnsClientNrptRule -NameServers 127.0.0.1`) routes
    /// queries to UDP/TCP **53** unconditionally — the cmdlet
    /// doesn't accept a port specifier. So a Windows install MUST
    /// have the agent's resolver bound on 53, not the default
    /// 5354. The Windows install scaffold writes
    /// `Environment=P2CLAW_DNS_PORT=53` into the Service registry's
    /// Environment MultiString; `cmd_run` reads the env var and
    /// calls this builder if it parses as a valid u16.
    ///
    /// macOS / Linux installs don't need this: macOS's
    /// `/etc/resolver/<parent>` file accepts a `port` directive,
    /// and Linux's `systemd-resolved` drop-in references the
    /// agent's bind directly. Both default to 5354 unless the
    /// operator explicitly opts into 53 (which then needs
    /// `CAP_NET_BIND_SERVICE` on Linux + root on macOS).
    pub fn with_bind_port(mut self, port: u16) -> Self {
        self.bind = SocketAddr::new(self.bind.ip(), port);
        self
    }
}

/// Run the resolver until `shutdown` flips. Returns when the
/// shutdown signal fires; bind / system-config errors surface
/// before the loop starts.
pub async fn serve(
    config: DnsResolverConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), DnsResolverError> {
    let parent = parse_parent_domain(&config.parent_domain)?;
    let reserved = parse_reserved(&config.reserved_subdomains);
    let upstreams = load_upstreams()?;
    info!(
        bind = %config.bind,
        parent = %config.parent_domain,
        upstream_count = upstreams.len(),
        reserved_count = reserved.len(),
        // Dump the parsed reserved Names so a runtime mismatch
        // (synthesizing what should forward) is debuggable without
        // a rebuild — the operator can see exactly what the
        // resolver will compare against.
        reserved = ?reserved,
        "dns: resolver starting"
    );

    let socket = UdpSocket::bind(config.bind)
        .await
        .map_err(|e| DnsResolverError::Bind {
            bind: config.bind,
            source: e,
        })?;
    let socket = Arc::new(socket);
    let upstreams = Arc::new(upstreams);
    let reserved = Arc::new(reserved);

    let mut buf = vec![0u8; MAX_MSG_BYTES];
    loop {
        tokio::select! {
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, src)) => {
                        let query = buf[..n].to_vec();
                        let socket = Arc::clone(&socket);
                        let upstreams = Arc::clone(&upstreams);
                        let reserved = Arc::clone(&reserved);
                        let parent = parent.clone();
                        // Per-query task so a slow upstream forward
                        // doesn't HoL-block other in-flight queries.
                        // Bounded by UPSTREAM_TIMEOUT; tasks cannot
                        // pile up indefinitely.
                        tokio::spawn(async move {
                            handle_query(&socket, src, &query, &parent, &reserved, &upstreams).await;
                        });
                    }
                    Err(e) => {
                        // recv_from on a UDP socket only fails for
                        // catastrophic errors; per-packet errors
                        // surface as the next iteration's data. Log
                        // and continue rather than tear down.
                        warn!(error = %e, "dns: recv_from failed");
                    }
                }
            }
            _ = shutdown.changed() => {
                info!("dns: shutdown");
                return Ok(());
            }
        }
    }
}

/// Per-query dispatch: parse, decide synthesize-vs-forward, send.
/// All errors absorbed — a malformed query is silently dropped (the
/// client will retry on its own; replying with FORMERR risks
/// reflection-amplification and provides no useful signal).
async fn handle_query(
    socket: &UdpSocket,
    src: SocketAddr,
    query_bytes: &[u8],
    parent: &Name,
    reserved: &[Name],
    upstreams: &[SocketAddr],
) {
    let parsed = match Message::from_vec(query_bytes) {
        Ok(m) => m,
        Err(e) => {
            debug!(src = %src, error = %e, "dns: malformed query; dropping");
            return;
        }
    };

    if let Some(synth) = try_synthesize(&parsed, parent, reserved) {
        match synth.to_vec() {
            Ok(bytes) => {
                if let Err(e) = socket.send_to(&bytes, src).await {
                    warn!(src = %src, error = %e, "dns: send_to (synth) failed");
                }
            }
            Err(e) => {
                warn!(src = %src, error = %e, "dns: synth response encode failed");
            }
        }
        return;
    }

    // Forward path. Try each upstream in order until one answers.
    match forward_upstream(query_bytes, upstreams).await {
        Ok(response) => {
            if let Err(e) = socket.send_to(&response, src).await {
                warn!(src = %src, error = %e, "dns: send_to (forward) failed");
            }
        }
        Err(e) => {
            debug!(src = %src, error = %e, "dns: upstream forward failed");
            // Do NOT synthesize a SERVFAIL — the client's local
            // resolver will time out and retry, which preserves the
            // "system resolution still works if our agent is dead"
            // failure mode.
        }
    }
}

/// If `msg` is a single-question query for `<anything>.<parent>`
/// in a recordtype we serve, build the synthesized response.
/// Returns `None` for queries that should be forwarded —
/// including any name on the `reserved` list (typically the
/// agent's own coord_domain; see `DnsResolverConfig::reserved_subdomains`).
fn try_synthesize(msg: &Message, parent: &Name, reserved: &[Name]) -> Option<Message> {
    // Multi-question messages are theoretically valid (RFC 1035 §4.1.2)
    // but in practice no recursive resolver ever sends them, and
    // synthesizing per-question while forwarding the rest is more
    // complexity than it's worth. Fall through to the forward path.
    if msg.queries.len() != 1 {
        return None;
    }
    if msg.metadata.message_type != MessageType::Query {
        return None;
    }
    let q = &msg.queries[0];
    let qname = q.name();
    if !is_subdomain_of(qname, parent) {
        return None;
    }
    // Reserved-subdomain bypass — the agent's own coord_domain
    // (and any other infra hostname under parent the operator
    // wants to reach via real DNS rather than the local hijack).
    // `Name` PartialEq is case-insensitive per hickory's
    // implementation, so this matches DNS's case-insensitive
    // comparison rules for free.
    for r in reserved {
        if qname == r {
            return None;
        }
    }

    // Build the response shell. `Message::response` echoes the
    // request's id + op_code per RFC 6895 §2; we then mirror the
    // request's RD bit (`recursion_desired`) and set our
    // response-side flags (RA, AA, RCODE NoError).
    let mut response = Message::response(msg.metadata.id, msg.metadata.op_code);
    response.metadata.recursion_desired = msg.metadata.recursion_desired;
    // We serve loopback synthesis; from the client's POV that's
    // "recursion available" — the next hop (the agent's 443
    // listener) is local.
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.authoritative = true;
    // `Query` is `Clone`-able; echo back exactly what we got so
    // the client's resolver matches the question section.
    response.add_query(q.clone());

    // AAAA and everything else: NODATA (NOERROR + zero answers), so
    // apps that prefer IPv6 fall back to A.
    if q.query_type() == RecordType::A {
        let rdata = RData::A(A::from(Ipv4Addr::LOCALHOST));
        let rec = Record::from_rdata(qname.clone(), SYNTH_TTL_SECS, rdata);
        response.add_answer(rec);
    }

    Some(response)
}

/// Forward `query_bytes` to the first upstream that answers within
/// [`UPSTREAM_TIMEOUT`]. Returns the upstream's raw response bytes,
/// or an error if every upstream timed out / errored.
async fn forward_upstream(
    query_bytes: &[u8],
    upstreams: &[SocketAddr],
) -> Result<Vec<u8>, std::io::Error> {
    let mut last_err: Option<std::io::Error> = None;
    for upstream in upstreams {
        match forward_one(query_bytes, *upstream).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                debug!(%upstream, error = %e, "dns: upstream attempt failed");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("no upstreams configured")))
}

async fn forward_one(query_bytes: &[u8], upstream: SocketAddr) -> std::io::Result<Vec<u8>> {
    // Ephemeral per-query socket — see module-level "FD hygiene"
    // notes. The socket goes out of scope (and its FD is reclaimed)
    // as soon as this function returns, whether by Ok or by the
    // tokio::time::timeout-driven Err below.
    let bind = match upstream {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(query_bytes).await?;

    let mut buf = vec![0u8; MAX_MSG_BYTES];
    let n = tokio::time::timeout(UPSTREAM_TIMEOUT, socket.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream timeout"))??;
    buf.truncate(n);
    Ok(buf)
}

/// Read system upstream nameservers via hickory-resolver's per-OS
/// loaders (Linux: `/etc/resolv.conf`; macOS: SCDynamicStore; Windows:
/// GetAdaptersAddresses + NRPT). Returns the deduplicated socket
/// addresses for raw UDP forwarding.
///
/// `NameServerConfig` carries just `IpAddr` plus per-protocol
/// connection configs (UDP, TCP, TLS, ...). We always forward over
/// UDP/53 — the standard system-resolver port — so we ignore the
/// connection-config side and pair `ip` with port 53.
fn load_upstreams() -> Result<Vec<SocketAddr>, DnsResolverError> {
    let (config, _opts) = system_conf::read_system_conf()
        .map_err(|e| DnsResolverError::SystemConf(std::io::Error::other(e.to_string())))?;
    let mut out: Vec<SocketAddr> = Vec::new();
    for ns in config.name_servers() {
        let addr = SocketAddr::new(ns.ip, 53);
        // Skip our own bind address if it's somehow in the system
        // config — would form an infinite forwarding loop.
        if addr == DEFAULT_BIND {
            continue;
        }
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    if out.is_empty() {
        return Err(DnsResolverError::NoUpstreams);
    }
    Ok(out)
}

fn parse_parent_domain(s: &str) -> Result<Name, DnsResolverError> {
    // hickory's `Name::from_utf8("")` returns Ok(root_name) — useful
    // for some callers but a foot-gun here: we'd happily synthesize
    // EVERY query as a subdomain of the empty parent. Reject early.
    if s.trim().is_empty() {
        return Err(DnsResolverError::SystemConf(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "parent_domain must not be empty",
        )));
    }
    Name::from_utf8(s).map_err(|e| {
        DnsResolverError::SystemConf(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid parent_domain `{s}`: {e}"),
        ))
    })
}

/// `qname` is a subdomain of `parent` iff `parent` is a proper
/// suffix of `qname` AND `qname.len() > parent.len()`. We deliberately
/// reject `qname == parent` itself — the apex (`p2claw.com`) is owned
/// by the marketing site / coord, not by individual agents. Anyone
/// querying it should reach the public DNS; our resolver passes
/// through.
///
/// Note on hickory's API: `Name::zone_of_case` is the case-SENSITIVE
/// variant (the `_case` suffix in their naming means "honors case",
/// not "ignores case"). DNS labels are case-insensitive per RFC 1035
/// §2.3.3, so we use `Name::zone_of` instead. Argument order is
/// `parent.zone_of(qname)` — the parent zone is `self`.
fn is_subdomain_of(qname: &Name, parent: &Name) -> bool {
    if qname.num_labels() <= parent.num_labels() {
        return false;
    }
    parent.zone_of(qname)
}

/// Parse the operator-supplied reserved-subdomain strings into
/// `Name`s and **normalize each to FQDN** (`set_fqdn(true)`).
///
/// FQDN normalization is load-bearing: hickory's `Name`
/// `PartialEq` is FQDN-sensitive. A wire-arrived qname comes off
/// `Message::from_vec` with the implicit DNS root → FQDN=true. A
/// `Name::from_utf8("coord.p2claw.test")` produces FQDN=false. So
/// without the normalization pass, runtime equality `qname == r`
/// is `FQDN(true) == FQDN(false)` which is `false` — the bypass
/// arm never fires + the resolver synthesizes the loopback
/// address it should have forwarded. (Real bug-of-record;
/// the corresponding unit tests pre-this-fix passed because
/// `build_query` ALSO produces FQDN=false names, so both sides
/// of the comparison were non-FQDN and matched by happenstance —
/// see `runtime_shape_fqdn_qname_matches_non_fqdn_reserved_input`.)
///
/// Malformed entries are warned + skipped — under-reserve > fail-
/// to-start.
fn parse_reserved(strings: &[String]) -> Vec<Name> {
    strings
        .iter()
        .filter_map(|s| {
            // hickory's `Name::from_utf8("")` returns Ok(root) —
            // see the same foot-gun guard in `parse_parent_domain`.
            // An empty reserved entry would otherwise match the
            // root name + bypass synthesis for *every* query
            // (since every name is a subdomain of root). Reject
            // explicitly + warn.
            if s.trim().is_empty() {
                warn!("dns: ignoring empty reserved_subdomain entry (matches root → would block all synthesis)");
                return None;
            }
            match Name::from_utf8(s) {
                Ok(mut n) => {
                    n.set_fqdn(true);
                    Some(n)
                }
                Err(e) => {
                    warn!(
                        reserved = %s,
                        error = %e,
                        "dns: ignoring malformed reserved_subdomain entry"
                    );
                    None
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};

    fn parent() -> Name {
        Name::from_utf8("p2claw.com").unwrap()
    }

    fn build_query(qname: &str, qtype: RecordType) -> Message {
        let name = Name::from_utf8(qname).unwrap();
        let q = Query::query(name, qtype);
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(q);
        msg
    }

    #[test]
    fn synth_a_returns_127_0_0_1_with_short_ttl() {
        let q = build_query("recipes-blue-otter-7392.p2claw.com", RecordType::A);
        let resp = try_synthesize(&q, &parent(), &[]).expect("synthesize");
        assert_eq!(resp.metadata.id, 0x1234, "transaction id must echo");
        assert_eq!(resp.metadata.message_type, MessageType::Response);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.metadata.authoritative, "we own the synthesized name");
        assert!(resp.metadata.recursion_available);
        assert_eq!(resp.answers.len(), 1);
        let rec = &resp.answers[0];
        assert_eq!(rec.ttl, SYNTH_TTL_SECS);
        match &rec.data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::LOCALHOST),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn synth_aaaa_returns_nodata() {
        let q = build_query("recipes-blue-otter-7392.p2claw.com", RecordType::AAAA);
        let resp = try_synthesize(&q, &parent(), &[]).expect("synthesize");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(
            resp.answers.is_empty(),
            "AAAA must be NODATA so apps fall back to A; got {:?}",
            resp.answers
        );
    }

    #[test]
    fn synth_other_rrtype_returns_nodata() {
        for qtype in [
            RecordType::TXT,
            RecordType::MX,
            RecordType::SRV,
            RecordType::NS,
        ] {
            let q = build_query("foo.p2claw.com", qtype);
            let resp = try_synthesize(&q, &parent(), &[]).expect("synthesize");
            assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
            assert!(
                resp.answers.is_empty(),
                "{qtype:?} must be NODATA, got {:?}",
                resp.answers
            );
        }
    }

    #[test]
    fn unrelated_domain_falls_through_to_forward() {
        let q = build_query("example.com", RecordType::A);
        assert!(try_synthesize(&q, &parent(), &[]).is_none());
        let q = build_query("p2claw.com.example.com", RecordType::A);
        assert!(
            try_synthesize(&q, &parent(), &[]).is_none(),
            "subdomain check must guard against `parent` appearing as a label \
             elsewhere in the name (poisoned suffix)"
        );
    }

    #[test]
    fn apex_query_falls_through() {
        // The apex `p2claw.com` is the marketing site / coord, NOT
        // an agent target. Forwarding lets public DNS answer.
        let q = build_query("p2claw.com", RecordType::A);
        assert!(
            try_synthesize(&q, &parent(), &[]).is_none(),
            "apex must fall through to upstream"
        );
    }

    #[test]
    fn case_insensitive_subdomain_match() {
        // DNS labels are case-insensitive (RFC 1035 §2.3.3). A
        // query for `App-X.P2Claw.Com` must still synthesize.
        let q = build_query("App-X.P2Claw.Com", RecordType::A);
        let resp = try_synthesize(&q, &parent(), &[]).expect("case-insensitive match");
        assert_eq!(resp.answers.len(), 1);
    }

    #[test]
    fn multi_question_falls_through() {
        // Multi-question messages are valid per RFC 1035 §4.1.2 but
        // never sent by recursive resolvers in practice; we don't
        // synthesize partial answers.
        let mut msg = build_query("a.p2claw.com", RecordType::A);
        let q2 = Query::query(Name::from_utf8("b.p2claw.com").unwrap(), RecordType::A);
        msg.add_query(q2);
        assert!(try_synthesize(&msg, &parent(), &[]).is_none());
    }

    #[test]
    fn response_message_type_is_not_synthesized() {
        // Defensive: a packet that arrives flagged as a Response is
        // either spoofed or a misconfigured client; never synthesize.
        let mut msg = build_query("a.p2claw.com", RecordType::A);
        msg.metadata.message_type = MessageType::Response;
        assert!(try_synthesize(&msg, &parent(), &[]).is_none());
    }

    #[test]
    fn reserved_subdomain_is_not_synthesized() {
        // A real bug-of-record from e2e: the agent's
        // own coord_domain (typically `coord.<parent>`) needs to
        // forward upstream rather than synthesize 127.0.0.1, or
        // the agent's peer_dialer's `/v1/connect` GET loops back
        // to the agent's own SNI listener + dies parsing `coord`
        // as an `<app>-<alias>` label.
        let coord = Name::from_utf8("coord.p2claw.com").unwrap();
        let q = build_query("coord.p2claw.com", RecordType::A);
        assert!(
            try_synthesize(&q, &parent(), &[coord]).is_none(),
            "reserved subdomain MUST forward upstream, not synthesize"
        );
    }

    #[test]
    fn reserved_subdomain_match_is_case_insensitive() {
        // DNS labels are case-insensitive (RFC 1035 §2.3.3); the
        // reserved-list check has to honour that. `Name`'s
        // `PartialEq` is case-insensitive in hickory-proto, so
        // this test mostly pins that we depend on it.
        let coord = Name::from_utf8("coord.p2claw.com").unwrap();
        let q = build_query("CoOrD.P2Claw.CoM", RecordType::A);
        assert!(
            try_synthesize(&q, &parent(), &[coord]).is_none(),
            "reserved-subdomain match must be case-insensitive — DNS labels are by definition"
        );
    }

    #[test]
    fn unrelated_subdomain_with_reserved_list_still_synthesizes() {
        // Sanity: a normal `*.<parent>` query still synthesizes
        // when there's a reserved list. Reservation is precise,
        // not "anything that happens to contain a reserved label".
        let coord = Name::from_utf8("coord.p2claw.com").unwrap();
        let q = build_query("recipes-blue-otter-7392.p2claw.com", RecordType::A);
        let resp = try_synthesize(&q, &parent(), &[coord]).expect("synthesize");
        assert_eq!(resp.answers.len(), 1);
    }

    #[test]
    fn runtime_shape_fqdn_qname_matches_non_fqdn_reserved_input() {
        // Pre-fix bug-of-record from e2e iteration: hickory's
        // `Name: PartialEq` is FQDN-sensitive. A wire-arrived
        // qname (from `Message::from_vec`) is FQDN=true; a
        // `Name::from_utf8("coord.p2claw.test")` is FQDN=false.
        // Direct equality is therefore false, the reserved arm
        // never fires at runtime, the resolver synthesizes
        // 127.0.0.1, the agent's peer_dialer loops back to its
        // own SNI listener, dial fails. The fix is to normalize
        // reserved Names to FQDN at parse time via
        // `parse_reserved` (which calls `set_fqdn(true)`).
        //
        // This test exercises the runtime shape: build a
        // FQDN qname (mimicking what hickory hands us off the
        // wire) + the same parse-pipeline as `serve()` for the
        // reserved input. Without the normalization in
        // `parse_reserved`, this test would FAIL.
        let reserved = parse_reserved(&["coord.p2claw.com".to_string()]);
        assert_eq!(reserved.len(), 1);
        assert!(
            reserved[0].is_fqdn(),
            "parse_reserved must FQDN-normalize so wire-side equality works"
        );

        // Construct an FQDN qname the way hickory does on the
        // wire — `from_utf8` then `set_fqdn(true)`.
        let mut fqdn_qname = Name::from_utf8("coord.p2claw.com").unwrap();
        fqdn_qname.set_fqdn(true);
        let q = Query::query(fqdn_qname, RecordType::A);
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(q);

        assert!(
            try_synthesize(&msg, &parent(), &reserved).is_none(),
            "FQDN-shaped qname must match parse_reserved-normalized reserved entry"
        );
    }

    #[test]
    fn parse_reserved_skips_malformed_keeps_valid() {
        // "" + invalid IDN + label > 63 bytes are all bad
        // inputs hickory rejects; the helper warns + skips them
        // rather than failing the whole startup. Pin the keep-
        // valid behavior so an ops typo on one line doesn't
        // wipe the whole list.
        let reserved = parse_reserved(&[
            "coord.p2claw.com".to_string(),
            "".to_string(),
            "a".repeat(64),
            "status.p2claw.com".to_string(),
        ]);
        assert_eq!(reserved.len(), 2, "should keep the 2 valid entries");
        assert!(
            reserved.iter().all(|n| n.is_fqdn()),
            "all entries normalized"
        );
    }

    #[test]
    fn reserved_subdomain_does_not_apply_to_non_subdomain_query() {
        // A query for `coord.example.com` (NOT under our parent)
        // would already fall through via the subdomain check —
        // the reserved list shouldn't affect that path. Pin it
        // so a future refactor doesn't accidentally widen the
        // reservation to all domains.
        let coord = Name::from_utf8("coord.p2claw.com").unwrap();
        let q = build_query("coord.example.com", RecordType::A);
        assert!(
            try_synthesize(&q, &parent(), &[coord]).is_none(),
            "non-parent query falls through regardless of reservation"
        );
    }

    #[test]
    fn parse_parent_domain_rejects_garbage() {
        assert!(parse_parent_domain("").is_err());
        // Labels with embedded NUL or > 63 bytes are rejected by Name::from_utf8.
        assert!(parse_parent_domain(&"a".repeat(64)).is_err());
    }

    #[test]
    fn with_bind_port_overrides_default_keeps_loopback_ip() {
        // Windows-install regression guard: Windows installs need the resolver bound
        // on 53 because NRPT can't route to a non-53 nameserver.
        // The builder swaps the port in-place but MUST preserve
        // the loopback IP — binding 53 on a public interface would
        // be a security regression.
        let cfg = DnsResolverConfig::with_parent_domain("p2claw.com").with_bind_port(53);
        assert_eq!(cfg.bind.port(), 53);
        assert_eq!(
            cfg.bind.ip(),
            DEFAULT_BIND.ip(),
            "loopback IP must be preserved"
        );
    }

    #[test]
    fn with_bind_port_chains_with_with_reserved() {
        // Builder methods are independent — chaining with_bind_port
        // before or after with_reserved must produce the same
        // config. Pin both orderings to guard against a future edit
        // that introduces ordering-dependent state.
        let a = DnsResolverConfig::with_parent_domain("p2claw.com")
            .with_bind_port(53)
            .with_reserved("coord.p2claw.com");
        let b = DnsResolverConfig::with_parent_domain("p2claw.com")
            .with_reserved("coord.p2claw.com")
            .with_bind_port(53);
        assert_eq!(a.bind, b.bind);
        assert_eq!(a.parent_domain, b.parent_domain);
        assert_eq!(a.reserved_subdomains, b.reserved_subdomains);
    }

    #[test]
    fn default_bind_port_is_5354_not_5353() {
        // Pin the choice: 5353 is mDNS (Avahi / Bonjour); colliding
        // would be conflict-prone on macOS. Test fails immediately
        // if a future edit drops the constant down by accident.
        assert_eq!(DEFAULT_BIND_PORT, 5354);
        assert_ne!(DEFAULT_BIND_PORT, 5353);
    }

    /// End-to-end: bind a resolver on a free loopback port, send a
    /// synth-eligible query, verify the synthesized A record comes
    /// back. Validates the full bind → recv → parse → synth →
    /// encode → send pipeline that the per-component tests above
    /// don't exercise as a unit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_synthesizes_a_record_on_loopback() {
        // Bind on an OS-assigned port so multiple test runs don't
        // collide on 5354.
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        // Skip if we can't load system DNS config (CI sandboxes
        // sometimes lack /etc/resolv.conf). The synth path doesn't
        // touch upstreams, but `serve()` validates them at startup.
        if system_conf::read_system_conf().is_err() {
            eprintln!(
                "skipping end_to_end_synthesizes_a_record_on_loopback: \
                 no system DNS config (likely sandboxed CI)"
            );
            return;
        }

        // Pre-bind so we know the actual port before serve() runs.
        let probe = UdpSocket::bind(bind).await.unwrap();
        let actual_bind = probe.local_addr().unwrap();
        drop(probe);

        let (sd_tx, sd_rx) = watch::channel(false);
        let cfg = DnsResolverConfig {
            bind: actual_bind,
            parent_domain: "p2claw.com".into(),
            reserved_subdomains: Vec::new(),
        };
        let server = tokio::spawn(async move { serve(cfg, sd_rx).await });

        // Wait briefly for the server to bind. There's no readiness
        // signal back from `serve()`; a short sleep is the simplest
        // "give the listener a chance to be up" pattern.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Build a query on the client side and shoot it at the server.
        let query = build_query("recipes-blue-otter-7392.p2claw.com", RecordType::A);
        let bytes = query.to_vec().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(actual_bind).await.unwrap();
        client.send(&bytes).await.unwrap();

        let mut buf = vec![0u8; MAX_MSG_BYTES];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("response within 2s")
            .expect("recv");
        buf.truncate(n);
        let resp = Message::from_vec(&buf).expect("decode response");
        assert_eq!(resp.metadata.id, query.metadata.id);
        assert_eq!(resp.answers.len(), 1, "expected one A answer");
        match &resp.answers[0].data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::LOCALHOST),
            other => panic!("expected A, got {other:?}"),
        }

        let _ = sd_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), server).await;
    }
}
