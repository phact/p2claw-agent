//! Where a forwarded request came from, and the `X-Forwarded-For`
//! the upstream app sees.
//!
//! Every request reaches an app from the agent on 127.0.0.1, so the
//! agent says who is really on the other end. On every forwarded
//! request (plain HTTP and WebSocket upgrades alike):
//!
//! - Any inbound `X-Forwarded-For` is removed: a visitor can put
//!   anything there.
//! - It is set to the real remote address when the agent knows it:
//!   - WebRTC: the remote address of the selected ICE candidate
//!     pair;
//!   - iroh: the remote address of the connection's selected path;
//!   - edge (the public HTTPS tunnel, an iroh peer coord names in
//!     `hello_ack`): the visitor address the edge passes along. The
//!     edge sets `X-Forwarded-For` itself, one entry, from the TCP
//!     connection or the hop its trusted proxy added; the agent
//!     keeps the last entry, so an older edge that appended to the
//!     visitor's value still can't be fooled.
//! - When the path is relayed (TURN, or the iroh relay) the address
//!   the agent sees is the relay's, not the visitor's. Rather than
//!   pass that off as the visitor, `X-Forwarded-For` is left out and
//!   `X-P2claw-Relayed` says which relay: `turn` or `iroh-relay`. An
//!   edge request without an address gets `X-P2claw-Relayed: edge`.
//!
//! Neither header can be forged: the agent strips every inbound
//! `X-P2claw-*` header before it adds its own, and `X-Forwarded-For`
//! is replaced here. With neither header present, the agent doesn't
//! know yet (no network path selected).

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};

use bytes::Bytes;

/// The standard header, carrying a bare IP (no port), as apps and
/// proxies expect it.
pub const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";

/// Set instead of `X-Forwarded-For` when a relay hides the visitor's
/// address. Value: `turn`, `iroh-relay` or `edge`. Shares the
/// `x-p2claw-` prefix, so the inbound identity strip covers it.
pub const RELAYED_HEADER: &str = "x-p2claw-relayed";

/// The relay a session's path goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relay {
    /// A WebRTC session on a TURN relay candidate.
    Turn,
    /// An iroh connection whose selected path is the iroh relay.
    Iroh,
}

impl Relay {
    pub fn as_str(self) -> &'static str {
        match self {
            Relay::Turn => "turn",
            Relay::Iroh => "iroh-relay",
        }
    }
}

/// The network path a session is on, and the remote address when
/// it's the peer's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Remote {
    /// No path selected yet.
    #[default]
    Unknown,
    /// Peer-to-peer. `None` when the agent can't read the address
    /// (best-effort: status must never perturb the data path).
    Direct(Option<SocketAddr>),
    /// Through a relay: the address the agent sees is the relay's,
    /// so none is kept.
    Relayed(Relay),
}

impl Remote {
    /// `direct` / `relay` / `unknown`, the `transport` field of
    /// `GET /v1/sessions`.
    pub fn transport(self) -> &'static str {
        match self {
            Remote::Unknown => "unknown",
            Remote::Direct(_) => "direct",
            Remote::Relayed(_) => "relay",
        }
    }

    /// The peer's own address. Never a relay's. IPv4-mapped IPv6
    /// (from a dual-stack socket) is shown as plain IPv4.
    pub fn addr(self) -> Option<SocketAddr> {
        match self {
            Remote::Direct(Some(a)) => Some(SocketAddr::new(a.ip().to_canonical(), a.port())),
            _ => None,
        }
    }
}

/// A transport the forwarder can ask, per request, where the request
/// came from. Sampled per request rather than once per connection
/// because a path can change under a live connection (a relayed
/// start that later goes direct).
pub trait RemoteSource: Send + Sync {
    fn remote(&self) -> Remote;
}

/// A [`Remote`] that a transport task keeps up to date and the
/// forwarder reads. WebRTC sessions use it: the session task learns
/// the selected candidate pair, the forwarder serves the requests.
#[derive(Debug, Clone, Default)]
pub struct SharedRemote(Arc<Mutex<Remote>>);

impl SharedRemote {
    pub fn get(&self) -> Remote {
        *self.0.lock().expect("remote mutex poisoned")
    }

    pub fn set(&self, remote: Remote) {
        *self.0.lock().expect("remote mutex poisoned") = remote;
    }
}

impl RemoteSource for SharedRemote {
    fn remote(&self) -> Remote {
        self.get()
    }
}

/// z-base-32 peer ids of the operator's edge, as coord lists them in
/// `hello_ack`. An iroh connection from one of these carries traffic
/// for many visitors, and its `X-Forwarded-For` is the edge speaking
/// (it replaces the visitor's), so it is kept rather than replaced. Empty until
/// the first `hello_ack` (and with a coord that doesn't list them):
/// the edge is then treated like any other iroh peer.
#[derive(Debug, Clone, Default)]
pub struct EdgePeers(Arc<RwLock<HashSet<String>>>);

impl EdgePeers {
    /// Replace the set (each `hello_ack` is authoritative).
    pub fn replace(&self, peers: impl IntoIterator<Item = String>) {
        *self.0.write().expect("edge peers lock poisoned") = peers.into_iter().collect();
    }

    pub fn contains(&self, peer_z32: &str) -> bool {
        self.0
            .read()
            .expect("edge peers lock poisoned")
            .contains(peer_z32)
    }
}

/// Replace the request's `X-Forwarded-For` per the module rules.
/// `from_edge` means the caller is a peer in [`EdgePeers`]; then
/// `remote` (the edge server's own address) is not used. Call after
/// the inbound `X-P2claw-*` strip, which also removes any forged
/// `X-P2claw-Relayed`.
pub fn set_forwarded_for(headers: &mut Vec<(Bytes, Bytes)>, remote: Remote, from_edge: bool) {
    let edge_says = from_edge.then(|| last_forwarded_for(headers)).flatten();
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(FORWARDED_FOR_HEADER.as_bytes()));
    let (ip, relayed) = if from_edge {
        match edge_says {
            Some(ip) => (Some(ip), None),
            None => (None, Some("edge")),
        }
    } else {
        match remote {
            Remote::Relayed(relay) => (None, Some(relay.as_str())),
            other => (other.addr().map(|a| a.ip()), None),
        }
    };
    if let Some(ip) = ip {
        headers.push((
            Bytes::from_static(FORWARDED_FOR_HEADER.as_bytes()),
            Bytes::from(ip.to_string()),
        ));
    }
    if let Some(via) = relayed {
        headers.push((
            Bytes::from_static(RELAYED_HEADER.as_bytes()),
            Bytes::from_static(via.as_bytes()),
        ));
    }
}

/// The last entry of the request's `X-Forwarded-For` (across repeated
/// header lines), if it is an IP address: the hop closest to the
/// agent, the only one the edge vouches for.
fn last_forwarded_for(headers: &[(Bytes, Bytes)]) -> Option<IpAddr> {
    let value = headers
        .iter()
        .rev()
        .find(|(name, _)| name.eq_ignore_ascii_case(FORWARDED_FOR_HEADER.as_bytes()))?
        .1
        .clone();
    let last = std::str::from_utf8(&value).ok()?.rsplit(',').next()?.trim();
    last.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(Bytes, Bytes)> {
        pairs
            .iter()
            .map(|(n, v)| {
                (
                    Bytes::copy_from_slice(n.as_bytes()),
                    Bytes::copy_from_slice(v.as_bytes()),
                )
            })
            .collect()
    }

    fn values<'a>(h: &'a [(Bytes, Bytes)], name: &str) -> Vec<&'a str> {
        h.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| std::str::from_utf8(v).unwrap())
            .collect()
    }

    fn direct(addr: &str) -> Remote {
        Remote::Direct(Some(addr.parse().unwrap()))
    }

    #[test]
    fn forged_forwarded_for_is_replaced_with_the_direct_address() {
        let mut h = headers(&[
            ("host", "app-x.p2claw.com"),
            ("X-Forwarded-For", "1.1.1.1"),
            ("x-forwarded-for", "2.2.2.2, 3.3.3.3"),
        ]);
        set_forwarded_for(&mut h, direct("203.0.113.7:51234"), false);
        assert_eq!(values(&h, FORWARDED_FOR_HEADER), vec!["203.0.113.7"]);
        assert!(values(&h, RELAYED_HEADER).is_empty());
        assert_eq!(values(&h, "host"), vec!["app-x.p2claw.com"]);
    }

    #[test]
    fn direct_ipv6_and_mapped_ipv4() {
        let mut h = Vec::new();
        set_forwarded_for(&mut h, direct("[2001:db8::7]:4433"), false);
        assert_eq!(values(&h, FORWARDED_FOR_HEADER), vec!["2001:db8::7"]);

        let mut h = Vec::new();
        set_forwarded_for(&mut h, direct("[::ffff:198.51.100.4]:4433"), false);
        assert_eq!(values(&h, FORWARDED_FOR_HEADER), vec!["198.51.100.4"]);
    }

    #[test]
    fn relayed_omits_forwarded_for_and_says_which_relay() {
        for (relay, via) in [(Relay::Turn, "turn"), (Relay::Iroh, "iroh-relay")] {
            let mut h = headers(&[("x-forwarded-for", "1.1.1.1")]);
            set_forwarded_for(&mut h, Remote::Relayed(relay), false);
            assert!(values(&h, FORWARDED_FOR_HEADER).is_empty(), "{via}");
            assert_eq!(values(&h, RELAYED_HEADER), vec![via]);
        }
    }

    #[test]
    fn unknown_path_strips_and_sets_nothing() {
        for remote in [Remote::Unknown, Remote::Direct(None)] {
            let mut h = headers(&[("x-forwarded-for", "1.1.1.1")]);
            set_forwarded_for(&mut h, remote, false);
            assert!(h.is_empty(), "{remote:?}: {h:?}");
        }
    }

    #[test]
    fn edge_keeps_the_hop_its_front_proxy_added() {
        // The edge server's own address is not the visitor's.
        let edge_server = direct("192.0.2.10:443");
        let mut h = headers(&[("x-forwarded-for", "203.0.113.7")]);
        set_forwarded_for(&mut h, edge_server, true);
        assert_eq!(values(&h, FORWARDED_FOR_HEADER), vec!["203.0.113.7"]);

        // A front proxy that appends: the visitor's own entries are
        // to the left of the one it added.
        let mut h = headers(&[
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-for", "1.1.1.1, 203.0.113.7"),
        ]);
        set_forwarded_for(&mut h, edge_server, true);
        assert_eq!(values(&h, FORWARDED_FOR_HEADER), vec!["203.0.113.7"]);
    }

    #[test]
    fn edge_without_an_address_is_marked() {
        for h in [headers(&[]), headers(&[("x-forwarded-for", "not-an-ip")])] {
            let mut h = h;
            set_forwarded_for(&mut h, direct("192.0.2.10:443"), true);
            assert!(values(&h, FORWARDED_FOR_HEADER).is_empty());
            assert_eq!(values(&h, RELAYED_HEADER), vec!["edge"]);
        }
    }

    #[test]
    fn transport_and_addr() {
        assert_eq!(Remote::Unknown.transport(), "unknown");
        assert_eq!(Remote::Direct(None).transport(), "direct");
        assert_eq!(Remote::Relayed(Relay::Turn).transport(), "relay");
        assert_eq!(Remote::Relayed(Relay::Iroh).addr(), None);
        assert_eq!(
            direct("203.0.113.7:51234").addr(),
            Some("203.0.113.7:51234".parse().unwrap())
        );
    }

    #[test]
    fn edge_peers_replace() {
        let e = EdgePeers::default();
        assert!(!e.contains("edge1"));
        e.replace(["edge1".to_string()]);
        assert!(e.contains("edge1"));
        e.replace(["edge2".to_string()]);
        assert!(!e.contains("edge1"));
        assert!(e.contains("edge2"));
    }
}
