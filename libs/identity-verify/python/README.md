# p2claw-identity-verify

Verify the `X-P2claw-Identity-Token` (EdDSA JWT) that a p2claw agent
attaches to forwarded requests. Cryptographically pins the request to
the issuing box's identity — your app stops having to trust the plain
`X-P2claw-*` headers.

Thin wrapper
over [`PyJWT`](https://pyjwt.readthedocs.io/) + `cryptography`; the
crypto is theirs, the package's value is the API shape and the
cross-language test-vector fidelity that matches the Rust, TypeScript,
and Go reference libs.

## Install

```sh
pip install p2claw-identity-verify
```

## Operator setup

Copy the box's peer_id from `p2claw status` (or the install transcript)
into your app config. The peer_id is a 52-character z-base-32 string —
it IS the box's Ed25519 public key, no certificate authority involved.

```yaml
# Example app config
p2claw:
  trusted_peer_id: ya4ud9rqcfpoz5q4d6cobh1ce6obtemf5hxhq86bf83udipuxisy
```

## Verify recipe

```python
from p2claw_identity_verify import verify, VerifyError

def handle_request(headers):
    try:
        claims = verify(headers, TRUSTED_PEER_ID)
    except VerifyError as e:
        if e.kind == "TokenMissing":
            return 401, "no identity token"
        if e.kind == "Expired":
            return 401, "identity token expired"
        if e.kind == "BadSignature":
            return 401, "identity token forged"
        if e.kind == "AlgorithmRejected":
            return 401, "identity token wrong alg"
        return 401, "identity token invalid"
    # claims["sub"], claims["email"], claims["name"], claims["auth_method"], ...
    return 200, render_for_user(claims)
```

## API

```python
def verify(
    headers: Mapping,
    trusted_peer_id: str,
    now: datetime | None = None,
) -> dict[str, Any]: ...
```

`headers` accepts any mapping with case-insensitive `.get(name)` —
WSGI environ shims, Starlette/FastAPI headers, plain dicts. Returns
the verified claims dict (open-ended so new claim fields don't break
existing call sites).

Raises `VerifyError` with structured `.kind` values:

| `.kind` | meaning |
|---|---|
| `TokenMissing` | The `X-P2claw-Identity-Token` header is absent. |
| `Malformed` | The token isn't a parseable JWS. |
| `AlgorithmRejected` | The token's alg isn't `EdDSA` (e.g. `none`, `HS256`, `RS256`). |
| `BadSignature` | The signature doesn't verify against the trusted peer_id. |
| `Expired` | Past `exp + 15s` leeway. |
| `NotYetValid` | Before `nbf − 15s` leeway. |
| `IssuerMismatch` | The token's `iss` claim doesn't match the trusted peer_id. |

A malformed `trusted_peer_id` (operator config bug, not a token issue)
raises `ValueError` instead of `VerifyError`.

## What this does NOT do

- **No `extract_claims_unverified`.** Verify-then-extract is the only
  path the library exposes. If you want to debug raw payloads, parse
  the JWS yourself.
- **No authorization.** Verification answers _who_. Authorization
  (which user can do what) is your app's call.

## License

MIT. See [`LICENSE`](LICENSE).
