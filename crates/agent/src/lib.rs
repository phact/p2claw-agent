//! Library facet of the `p2claw-agent` crate (binary: `p2claw`).
//!
//! The agent is predominantly a binary — it owns its own main, its
//! own signal handler, its own control-WS reconnect loop, etc. We
//! expose only the pieces that integration tests (on other crates)
//! need to exercise the *real* on-box behaviour byte-for-byte rather
//! than re-implement it and drift over time.
//!
//! Anything re-exported here becomes part of a stability surface for
//! downstream tests — add with care. Production consumers (the
//! coordination e2e harness, the iroh-client, the bootstrap loopback
//! suite) import these modules directly.
//!
//! The agent is a named-routes reverse proxy: `routes.json` on
//! disk, four local-API endpoints, and a forwarder that dials
//! 127.0.0.1 upstreams. No app supervision, no build step, no port
//! allocation. Callers that need an in-process handler should compose
//! a `Forwarder` against a `RouteTable` they control.

#![deny(rust_2018_idioms)]

pub mod attestation;
pub mod auto_upgrade;
pub mod dc_stream;
pub mod email;
pub mod forwarder;
pub mod oauth;
pub mod shares;
// The haiku-grammar parser lives in `p2claw-iroh-client::url`.
// One canonical parser; one place to change.
pub mod iroh_listener;
pub mod routes;
pub mod validate;
pub mod ws_forwarder;

// MagicDNS pipeline modules — promoted to the lib facet so
// `tests/two_box_outbound.rs` can compose them in-process. Production
// wires them through `main::cmd_run`.
pub mod dns_resolver;
pub mod local_ca;
pub mod peer_dialer;
pub mod priv_drop;
pub mod sni_listener;
