# p2claw-identity-verify

Verify p2claw box-attested identity JWTs against a known `peer_id`.

When an application is deployed behind `p2claw apps expose`, the
p2claw daemon authenticates the user and attaches identity headers
to every forwarded request. The plain `X-P2claw-User-*` headers are
forgeable by any process that reaches the upstream port directly.
The daemon also attaches an `X-P2claw-Identity-Token` — an EdDSA
JWT signed with the box's identity key — that an upstream
application can verify against the box's `peer_id` to confirm the
request really came through the agent.

This crate is the Rust reference verifier; the cross-language
fixture in `../test-vectors.json` pins the wire format.

## Usage

```toml
[dependencies]
p2claw-identity-verify = "0.1"
```

```rust
use p2claw_identity_verify::{verify, VerifyError};
use std::time::SystemTime;

fn handle(headers: &[(String, String)], trusted_peer_id: &str) {
    match verify(headers, trusted_peer_id, SystemTime::now()) {
        Ok(claims) => {
            // Trust the claims; serve as the authenticated user.
            println!("authenticated as {}", claims.sub);
        }
        Err(VerifyError::TokenMissing) => {
            // No attestation — serve as anonymous.
        }
        Err(e) => {
            // Token present but invalid; serve as anonymous + log.
            eprintln!("attestation verify failed: {e}");
        }
    }
}
```

`trusted_peer_id` is the 52-character z-base-32 string from the
box's `p2claw status` output. Store it in your app's config; never
read it from a request header (the convenience `X-P2claw-Box-Id`
header that arrives alongside the token is not a trust anchor).

## Cross-language libraries

This crate is part of a four-language family — Rust, TypeScript,
Python, Go — all of which verify the same on-wire format. The
canonical test fixture is at
`libs/identity-verify/test-vectors.json`. If your verifier accepts
every fixture vector, it is wire-compatible with the daemon's
output. Bindings in other languages live alongside this crate at
`libs/identity-verify/{ts,python,go}/`.

## License

MIT. See [`LICENSE`](LICENSE).
