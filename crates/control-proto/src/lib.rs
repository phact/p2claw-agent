//! Wire-protocol types for the box ↔ infrastructure control plane.
//!
//! QUIC connection over Iroh; messages framed as length-prefixed
//! JSON on bidi streams. The first frame on every stream is a
//! [`StreamHelloEnvelope`] tagging the stream's role. Edge ↔ box
//! tunneled HTTP rides a separate ALPN and is not modelled here.
//!
//! Pure-sync: schema + framing math. Async I/O lives upstack.

#![deny(rust_2018_idioms)]

use serde::{Deserialize, Serialize};

pub const ENVELOPE_V: u32 = 1;

// Close codes — carried through to QUIC application-close. Numeric
// values overlap RFC 6455 WebSocket close codes so cross-transport
// reaction logic shares the same constants.

pub const CLOSE_NORMAL: u16 = 1000;
pub const CLOSE_MALFORMED: u16 = 1002;
pub const CLOSE_POLICY_VIOLATION: u16 = 1008;
pub const CLOSE_AUTH_FAILED: u16 = 4001;
pub const CLOSE_PROTOCOL_ERROR: u16 = 4002;
pub const CLOSE_POLICY_REPLACED_BY_NEWER: u16 = 4009;
pub const CLOSE_REVOKED: u16 = 4010;

/// ALPN for the box ↔ coord control plane. Distinct from the box's
/// native peer-HTTP ALPN (`p2claw/1`) so the box-side dispatcher
/// can route on ALPN alone.
pub const ALPN_COORD_V1: &[u8] = b"p2claw-coord/1";

/// A single JSON-framed control-protocol message. `v` is the
/// envelope version; body is one of [`Message`]'s variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub v: u32,
    #[serde(flatten)]
    pub body: Message,
}

impl Envelope {
    pub fn new(body: Message) -> Self {
        Self {
            v: ENVELOPE_V,
            body,
        }
    }

    /// Parse from a JSON text frame.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serialize to a JSON text frame.
    pub fn to_json(&self) -> String {
        // `serde_json::to_string` never fails for well-formed types.
        serde_json::to_string(self).expect("Envelope serialization")
    }
}

// ---------- Message body -----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// C → S. First frame after stream-hello on the control stream.
    /// Identifies the agent and announces its iroh address set.
    /// The box is authenticated at the QUIC transport layer (Iroh's
    /// TLS binds the connection to the dialer's NodeID); no
    /// application-level bearer. `iroh_node_id` is informational
    /// and a defensive cross-check against the QUIC-derived
    /// peer_id; coord validates only when non-empty.
    Hello {
        agent_version: String,
        iroh_node_id: String,
        iroh_addrs: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        hostname_hint: Option<String>,
    },

    /// S → C. Coord accepts the hello. No `token_refresh` field
    /// (no token to rotate) and no `heartbeat_interval_s` (QUIC's
    /// idle timeout handles liveness).
    HelloAck { server_time: u64 },

    /// C → S. Box's iroh addresses changed.
    AddrsUpdate { iroh_addrs: Vec<String> },

    /// S → C. A visitor is connecting; prepare to relay signaling.
    SignalPush {
        session_id: String,
        visitor_kind: VisitorKind,
    },

    /// C ↔ S. Opaque signaling payload, keyed by `session_id`.
    SignalRelay {
        session_id: String,
        seq: u32,
        payload_b64: String,
    },

    /// C ↔ S. End a signaling session.
    SignalEnd {
        session_id: String,
        reason: SignalEndReason,
    },

    /// S → C. Box is being revoked; close the connection next.
    Revoke {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    /// C → S. Box is shutting down cleanly.
    Goodbye {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    /// C → S. Authoritative snapshot of the box's route table. Sent
    /// after `hello_ack` on every (re)connect and after each
    /// successful local mutation. Coord deletes any name not in the
    /// snapshot from the peer's `apps` set.
    RouteAnnounce { routes: Vec<RouteAnnounceEntry> },

    /// S → C. Coord's verdict on a `route_announce`: the accepted
    /// names, per-name rejection reasons, and quota counters.
    RouteAnnounceAck {
        accepted: Vec<String>,
        rejected: Vec<RejectedRoute>,
        max_apps: u32,
        used_apps: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        daily_changes: Option<DailyChanges>,
        /// Per-app authoritative state coord persisted (paired with
        /// `accepted` by `name`). Empty on quota/daily-limit reject
        /// paths where no apps were accepted.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        accepted_apps: Vec<AcceptedRoute>,
    },

    /// C → S. Authoritative snapshot of the box's email settings. Sent
    /// after `hello_ack` on every (re)connect and after each local
    /// change. Addresses are lower-cased; coord stores them hashed.
    EmailConfig {
        enabled: bool,
        allowlist: Vec<String>,
        /// Approved Gmail accounts whose forwarded mail is admitted.
        forwarders: Vec<String>,
    },

    /// S → C. Coord stored an `email_config`. `addresses` are the box's
    /// email addresses (one per live alias); empty while disabled.
    EmailConfigAck {
        addresses: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },

    /// S → C. Mail is queued for the box. Sent after `hello_ack` when
    /// the queue is non-empty and whenever new mail arrives. The box
    /// drains the queue over an [`StreamKind::Email`] stream.
    EmailPending { count: u32 },
}

/// One row of a [`Message::RouteAnnounce`]. `registered_at` is Unix
/// seconds when the agent first accepted the route locally; coord
/// uses it to order quota-trimming (oldest wins).
///
/// `auth` is the per-app method list. Empty = public; otherwise the
/// daemon middleware tries each method in order per request and
/// 401s if none succeed. Only `Oauth` is implemented today; other
/// variants get a 501 from the daemon.
///
/// `requires_auth` is a legacy boolean kept readable on the wire
/// for one deprecation cycle so older agents that don't know
/// `auth` keep working. Senders serialize it only when there's no
/// `auth` to send. Consumers should call [`resolved_auth`] rather
/// than reading either field directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteAnnounceEntry {
    pub name: String,
    pub registered_at: u64,
    #[serde(default)]
    pub auth: Vec<AuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_auth: Option<bool>,
}

impl RouteAnnounceEntry {
    /// Canonical method list: `auth` wins if non-empty; else legacy
    /// `requires_auth=Some(true)` maps to a single
    /// `AuthMethod::oauth_any()`; else empty (= public).
    pub fn resolved_auth(&self) -> Vec<AuthMethod> {
        if !self.auth.is_empty() {
            self.auth.clone()
        } else if self.requires_auth == Some(true) {
            vec![AuthMethod::oauth_any()]
        } else {
            Vec::new()
        }
    }
}

/// One entry in `RouteAnnounceAck::accepted_apps` — coord's
/// post-persist per-app state, paired with the matching entry in
/// `accepted` by `name`.
///
/// Coord emits both `auth` and the legacy `requires_auth` during
/// the deprecation cycle; `requires_auth = Some(!auth.is_empty())`
/// so older daemons still see the right gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptedRoute {
    pub name: String,
    #[serde(default)]
    pub auth: Vec<AuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_auth: Option<bool>,
}

impl AcceptedRoute {
    /// Same precedence rules as
    /// [`RouteAnnounceEntry::resolved_auth`]; daemons should call
    /// this rather than reading `auth` / `requires_auth` directly.
    pub fn resolved_auth(&self) -> Vec<AuthMethod> {
        if !self.auth.is_empty() {
            self.auth.clone()
        } else if self.requires_auth == Some(true) {
            vec![AuthMethod::oauth_any()]
        } else {
            Vec::new()
        }
    }
}

/// Authentication method a daemon validates against incoming
/// requests. Forward-compatible: new variants can land without a
/// wire break — daemons that don't recognise a variant 501 it,
/// daemons that do can short-circuit on the first match.
///
/// Wire shape: `{"kind": "oauth", "providers": ["github"]}`, or
/// `{"kind": "oauth"}` for "any configured provider".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMethod {
    /// OAuth via the p2claw broker. `providers = None` means "any
    /// configured at the broker"; `Some(["github", "google"])`
    /// restricts to those keys.
    Oauth {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        providers: Option<Vec<String>>,
    },
}

impl AuthMethod {
    pub fn oauth_any() -> Self {
        AuthMethod::Oauth { providers: None }
    }

    pub fn oauth_with(providers: Vec<String>) -> Self {
        AuthMethod::Oauth {
            providers: Some(providers),
        }
    }
}

/// One rejected name in a [`Message::RouteAnnounceAck`]. `retry_after_s`
/// is only set when `reason == "daily_limit_exceeded"` (seconds until
/// the next UTC-midnight reset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectedRoute {
    pub name: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

/// Per-UTC-day route-change counter. `limit` is `None` ⇒ unlimited;
/// `resets_at` is Unix seconds of the next UTC midnight.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DailyChanges {
    pub used: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    pub resets_at: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VisitorKind {
    Browser,
    Native,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignalEndReason {
    Connected,
    Aborted,
    Timeout,
    Error,
}

// ---------- Stream hello (QUIC) -----------------------------------------

/// First frame on every new bidirectional QUIC stream on the
/// box ↔ coord connection. Identifies the stream's role; subsequent
/// frames use the per-role schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamHelloEnvelope {
    pub v: u32,
    #[serde(flatten)]
    pub kind: StreamKind,
}

impl StreamHelloEnvelope {
    pub fn new(kind: StreamKind) -> Self {
        Self {
            v: ENVELOPE_V,
            kind,
        }
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("StreamHelloEnvelope serialization")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamKind {
    /// Long-lived control stream. Box opens this first, follows with
    /// [`Message::Hello`], and exchanges control envelopes over it.
    /// Closing it tears the logical session down.
    Control,
    /// Per-visitor signaling stream. Coord opens one when minting a
    /// session; first frame is [`Message::SignalPush`], then both
    /// ends exchange [`Message::SignalRelay`] until either emits a
    /// terminal [`Message::SignalEnd`].
    Signaling { session_id: String },
    /// Mail queue access. Box opens one when it has mail to pull (after
    /// [`Message::EmailPending`]) or needs rejection stats; it sends
    /// [`EmailRequest`] frames and reads one [`EmailResponse`] each.
    Email,
}

// ---------- Email stream -----------------------------------------------------

/// Box → coord request on an [`StreamKind::Email`] stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum EmailRequest {
    /// Everything queued for this box, oldest first.
    List,
    /// One sealed message. The [`EmailResponse::Fetch`] frame is followed
    /// by `size` raw bytes, sent as length-prefixed frames of at most
    /// [`MAX_FRAME_BYTES`] each.
    Fetch { id: String },
    /// The box stored `id` (or recorded it as expired); coord deletes
    /// its copy and summary.
    Ack { id: String },
    /// Rejection stats for this box.
    Rejected,
}

/// Coord → box response on an [`StreamKind::Email`] stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmailResponse {
    List { items: Vec<QueuedEmail> },
    Fetch { id: String, size: u64 },
    Ack { id: String },
    Rejected(EmailRejections),
    Error { message: String },
}

/// One queued message. When `expired`, the body is gone and only the
/// summary remains; the box records it as an `expired` entry and acks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueuedEmail {
    pub id: String,
    /// Unix seconds, as stamped by coord on delivery.
    pub received_at: u64,
    /// Sealed message size in bytes; 0 when expired.
    pub size: u64,
    #[serde(default)]
    pub expired: bool,
    /// Sealed summary (`p2claw-email-proto`), base64url without padding.
    pub summary_b64: String,
}

/// Coord's bounded rejection state for one box.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailRejections {
    /// Totals per reason: `not_allowed`, `unauthenticated`,
    /// `no_such_user`, `too_large`, `over_limit`.
    pub totals: std::collections::BTreeMap<String, u64>,
    /// Up to 50 most recently seen distinct senders, newest first.
    pub recent: Vec<RejectedSender>,
    /// Messages admitted today (UTC) and the daily cap.
    pub admitted_today: u32,
    pub daily_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectedSender {
    pub from: String,
    pub reason: String,
    pub count: u64,
    /// Unix seconds.
    pub last_seen: u64,
}

// ---------- Length-prefixed JSON framing (QUIC) -------------------------

/// Hard cap on a single framed payload (1 MiB). Frames announcing a
/// larger length MUST be rejected before allocation.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Encode a JSON payload as `[u32 BE length][bytes]`. Returns
/// `Err(FrameTooLarge)` if the payload exceeds `MAX_FRAME_BYTES`.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FramingError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FramingError::FrameTooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode the length prefix at the head of a buffer. Returns the
/// payload length to read next, or an error if the header is
/// oversize. Caller does the payload `read_exact`.
pub fn decode_frame_length(header: [u8; 4]) -> Result<usize, FramingError> {
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FramingError::FrameTooLarge(len));
    }
    Ok(len)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FramingError {
    #[error("frame size {0} exceeds MAX_FRAME_BYTES")]
    FrameTooLarge(usize),
}

// ---------- Tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(env: Envelope) {
        let j = env.to_json();
        let parsed = Envelope::from_json(&j).expect("parse");
        assert_eq!(parsed, env, "roundtrip mismatch via JSON: {j}");
    }

    #[test]
    fn hello_roundtrip_full() {
        roundtrip(Envelope::new(Message::Hello {
            agent_version: "0.1.0".into(),
            iroh_node_id: "y9abcdefghijk".into(),
            iroh_addrs: vec!["udp:198.51.100.7:54321".into()],
            hostname_hint: Some("alice-laptop".into()),
        }));
    }

    #[test]
    fn hello_roundtrip_minimal() {
        roundtrip(Envelope::new(Message::Hello {
            agent_version: "0.0.0".into(),
            iroh_node_id: "n".into(),
            iroh_addrs: vec![],
            hostname_hint: None,
        }));
    }

    #[test]
    fn hello_omits_token_field() {
        // Auth is bound at the QUIC layer (Iroh's NodeID), so a
        // bearer field must never land on the wire.
        let j = Envelope::new(Message::Hello {
            agent_version: "test".into(),
            iroh_node_id: "n".into(),
            iroh_addrs: vec![],
            hostname_hint: None,
        })
        .to_json();
        assert!(
            !j.contains("\"token\""),
            "token must not be on the wire: {j}"
        );
    }

    #[test]
    fn hello_ack_shape() {
        let env = Envelope::new(Message::HelloAck {
            server_time: 1_767_312_000,
        });
        let j = env.to_json();
        assert!(!j.contains("token_refresh"), "should omit: {j}");
        assert!(
            !j.contains("heartbeat_interval_s"),
            "should omit heartbeat_interval_s: {j}"
        );
        roundtrip(env);
    }

    #[test]
    fn signal_push_browser_native() {
        roundtrip(Envelope::new(Message::SignalPush {
            session_id: "01HW3QABCDEFGHJKMNPQRSTVWX".into(),
            visitor_kind: VisitorKind::Browser,
        }));
        roundtrip(Envelope::new(Message::SignalPush {
            session_id: "01HW3QABCDEFGHJKMNPQRSTVWX".into(),
            visitor_kind: VisitorKind::Native,
        }));
    }

    #[test]
    fn signal_relay_roundtrip() {
        roundtrip(Envelope::new(Message::SignalRelay {
            session_id: "01HW3QABCDEFGHJKMNPQRSTVWX".into(),
            seq: 42,
            payload_b64: "eyJ0eXBlIjoib2ZmZXIifQ==".into(),
        }));
    }

    #[test]
    fn signal_end_reasons() {
        for r in [
            SignalEndReason::Connected,
            SignalEndReason::Aborted,
            SignalEndReason::Timeout,
            SignalEndReason::Error,
        ] {
            roundtrip(Envelope::new(Message::SignalEnd {
                session_id: "sess".into(),
                reason: r,
            }));
        }
    }

    #[test]
    fn revoke_goodbye_no_reason() {
        roundtrip(Envelope::new(Message::Revoke { reason: None }));
        roundtrip(Envelope::new(Message::Goodbye { reason: None }));
    }

    #[test]
    fn addrs_update_roundtrip() {
        roundtrip(Envelope::new(Message::AddrsUpdate {
            iroh_addrs: vec![
                "relay:https://relay.example.net/".into(),
                "udp:198.51.100.7:54321".into(),
                "udp:[2001:db8::1]:54321".into(),
            ],
        }));
    }

    #[test]
    fn envelope_carries_version_marker() {
        let env = Envelope::new(Message::Goodbye { reason: None });
        let j = env.to_json();
        assert!(j.contains("\"v\":1"), "envelope should include v=1: {j}");
    }

    #[test]
    fn unknown_type_errors() {
        let j = r#"{"v":1,"type":"mystery","foo":"bar"}"#;
        assert!(Envelope::from_json(j).is_err());
    }

    #[test]
    fn visitor_kind_wire_format() {
        let j = serde_json::to_string(&VisitorKind::Browser).unwrap();
        assert_eq!(j, "\"browser\"");
        let j = serde_json::to_string(&VisitorKind::Native).unwrap();
        assert_eq!(j, "\"native\"");
    }

    #[test]
    fn route_announce_roundtrip_empty_and_full() {
        roundtrip(Envelope::new(Message::RouteAnnounce { routes: vec![] }));
        roundtrip(Envelope::new(Message::RouteAnnounce {
            routes: vec![
                RouteAnnounceEntry {
                    name: "recipes".into(),
                    registered_at: 1_767_312_000,
                    auth: Vec::new(),
                    requires_auth: None,
                },
                RouteAnnounceEntry {
                    name: "homelab".into(),
                    registered_at: 1_767_315_400,
                    auth: Vec::new(),
                    requires_auth: None,
                },
            ],
        }));
    }

    #[test]
    fn route_announce_wire_shape_matches_doc() {
        let env = Envelope::new(Message::RouteAnnounce {
            routes: vec![RouteAnnounceEntry {
                name: "recipes".into(),
                registered_at: 1_767_312_000,
                auth: Vec::new(),
                requires_auth: None,
            }],
        });
        let j = env.to_json();
        assert!(j.contains("\"type\":\"route_announce\""));
        assert!(j.contains("\"name\":\"recipes\""));
        assert!(j.contains("\"registered_at\":1767312000"));
    }

    #[test]
    fn route_announce_ack_roundtrip_full() {
        roundtrip(Envelope::new(Message::RouteAnnounceAck {
            accepted: vec!["recipes".into(), "homelab".into()],
            rejected: vec![RejectedRoute {
                name: "experiments".into(),
                reason: "quota_exceeded".into(),
                retry_after_s: None,
            }],
            max_apps: 3,
            used_apps: 3,
            daily_changes: Some(DailyChanges {
                used: 7,
                limit: Some(20),
                resets_at: 1_767_398_400,
            }),
            accepted_apps: vec![
                AcceptedRoute {
                    name: "recipes".into(),
                    auth: Vec::new(),
                    requires_auth: None,
                },
                AcceptedRoute {
                    name: "homelab".into(),
                    auth: vec![AuthMethod::oauth_any()],
                    requires_auth: None,
                },
            ],
        }));
    }

    #[test]
    fn route_announce_ack_roundtrip_minimal() {
        // No `daily_changes`, no `rejected`, unlimited daily.
        roundtrip(Envelope::new(Message::RouteAnnounceAck {
            accepted: vec!["recipes".into()],
            rejected: vec![],
            max_apps: 10,
            used_apps: 1,
            daily_changes: None,
            accepted_apps: vec![AcceptedRoute {
                name: "recipes".into(),
                auth: Vec::new(),
                requires_auth: None,
            }],
        }));
    }

    #[test]
    fn rejected_route_with_retry_after_roundtrip() {
        roundtrip(Envelope::new(Message::RouteAnnounceAck {
            accepted: vec![],
            rejected: vec![RejectedRoute {
                name: "fresh".into(),
                reason: "daily_limit_exceeded".into(),
                retry_after_s: Some(43_200),
            }],
            max_apps: 3,
            used_apps: 0,
            daily_changes: Some(DailyChanges {
                used: 20,
                limit: Some(20),
                resets_at: 1_767_398_400,
            }),
            accepted_apps: vec![],
        }));
    }

    #[test]
    fn rejected_route_omits_retry_after_when_none() {
        let env = Envelope::new(Message::RouteAnnounceAck {
            accepted: vec![],
            rejected: vec![RejectedRoute {
                name: "experiments".into(),
                reason: "quota_exceeded".into(),
                retry_after_s: None,
            }],
            max_apps: 3,
            used_apps: 3,
            daily_changes: None,
            accepted_apps: vec![],
        });
        let j = env.to_json();
        assert!(
            !j.contains("retry_after_s"),
            "should omit retry_after_s when None: {j}"
        );
        assert!(
            !j.contains("daily_changes"),
            "should omit daily_changes when None: {j}"
        );
    }

    #[test]
    fn daily_changes_unlimited_omits_limit() {
        let env = Envelope::new(Message::RouteAnnounceAck {
            accepted: vec![],
            rejected: vec![],
            max_apps: 3,
            used_apps: 0,
            daily_changes: Some(DailyChanges {
                used: 0,
                limit: None,
                resets_at: 1_767_398_400,
            }),
            accepted_apps: vec![],
        });
        let j = env.to_json();
        assert!(!j.contains("\"limit\""), "limit should be omitted: {j}");
    }

    #[test]
    fn route_announce_ack_omits_accepted_apps_when_empty() {
        // Legacy daemons don't know `accepted_apps`; skip-if-empty
        // keeps the wire parser-compatible.
        let env = Envelope::new(Message::RouteAnnounceAck {
            accepted: vec![],
            rejected: vec![],
            max_apps: 3,
            used_apps: 0,
            daily_changes: None,
            accepted_apps: vec![],
        });
        let j = env.to_json();
        assert!(
            !j.contains("accepted_apps"),
            "should omit accepted_apps when empty: {j}"
        );
    }

    #[test]
    fn route_announce_ack_accepted_apps_carries_auth_methods() {
        let env = Envelope::new(Message::RouteAnnounceAck {
            accepted: vec!["gated".into()],
            rejected: vec![],
            max_apps: 10,
            used_apps: 1,
            daily_changes: None,
            accepted_apps: vec![AcceptedRoute {
                name: "gated".into(),
                auth: vec![AuthMethod::oauth_with(vec!["github".into()])],
                requires_auth: None,
            }],
        });
        let j = env.to_json();
        assert!(
            j.contains("\"accepted_apps\""),
            "should emit accepted_apps when non-empty: {j}"
        );
        assert!(j.contains("\"kind\":\"oauth\""), "{j}");
        assert!(j.contains("\"providers\":[\"github\"]"), "{j}");
    }

    #[test]
    fn auth_method_oauth_any_omits_providers_field() {
        let m = AuthMethod::oauth_any();
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(j, r#"{"kind":"oauth"}"#);
    }

    #[test]
    fn auth_method_roundtrip_with_providers() {
        let m = AuthMethod::oauth_with(vec!["github".into(), "google".into()]);
        let j = serde_json::to_string(&m).unwrap();
        let back: AuthMethod = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn route_announce_entry_absent_auth_parses_as_empty_vec() {
        // Back-compat: older agents that don't ship `auth` at
        // all must still parse; their apps come up as public.
        let j = r#"{"name":"r","registered_at":1}"#;
        let entry: RouteAnnounceEntry = serde_json::from_str(j).unwrap();
        assert!(entry.auth.is_empty());
    }

    // ---- stream-hello + framing tests ----

    #[test]
    fn stream_hello_control_roundtrip() {
        let h = StreamHelloEnvelope::new(StreamKind::Control);
        let j = h.to_json();
        assert_eq!(j, r#"{"v":1,"kind":"control"}"#);
        let parsed = StreamHelloEnvelope::from_json(&j).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn stream_hello_signaling_carries_session_id() {
        let h = StreamHelloEnvelope::new(StreamKind::Signaling {
            session_id: "01HV8T6N7K8M9P0Q1R2S3T4U5V".into(),
        });
        let j = h.to_json();
        assert_eq!(
            j,
            r#"{"v":1,"kind":"signaling","session_id":"01HV8T6N7K8M9P0Q1R2S3T4U5V"}"#
        );
        let parsed = StreamHelloEnvelope::from_json(&j).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn stream_hello_unknown_kind_fails_to_parse() {
        let bad = r#"{"v":1,"kind":"future_kind","extra":"data"}"#;
        assert!(StreamHelloEnvelope::from_json(bad).is_err());
    }

    #[test]
    fn frame_encode_then_decode_length_roundtrip() {
        let payload = b"{\"v\":1,\"type\":\"hello\"}";
        let framed = encode_frame(payload).unwrap();
        assert_eq!(framed[..4], (payload.len() as u32).to_be_bytes());
        assert_eq!(&framed[4..], payload);
        let mut header = [0u8; 4];
        header.copy_from_slice(&framed[..4]);
        let decoded_len = decode_frame_length(header).unwrap();
        assert_eq!(decoded_len, payload.len());
    }

    #[test]
    fn frame_too_large_on_encode_is_rejected() {
        let payload = vec![0u8; MAX_FRAME_BYTES + 1];
        let err = encode_frame(&payload).unwrap_err();
        assert_eq!(err, FramingError::FrameTooLarge(MAX_FRAME_BYTES + 1));
    }

    #[test]
    fn frame_too_large_on_decode_is_rejected() {
        let big = (MAX_FRAME_BYTES + 1) as u32;
        let header = big.to_be_bytes();
        let err = decode_frame_length(header).unwrap_err();
        assert_eq!(err, FramingError::FrameTooLarge(MAX_FRAME_BYTES + 1));
    }

    #[test]
    fn frame_empty_payload_is_legal() {
        let framed = encode_frame(&[]).unwrap();
        assert_eq!(framed, [0, 0, 0, 0]);
        let mut header = [0u8; 4];
        header.copy_from_slice(&framed);
        assert_eq!(decode_frame_length(header).unwrap(), 0);
    }
}
