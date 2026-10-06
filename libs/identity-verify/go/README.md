# p2claw identity-verify (Go)

Verify the `X-P2claw-Identity-Token` (EdDSA JWT) that a p2claw agent
attaches to forwarded requests. Cryptographically pins the request to
the issuing box's identity — your app stops having to trust the plain
`X-P2claw-*` headers.

Thin wrapper
over [`golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt); the
crypto is theirs, the package's value is the API shape and the
cross-language test-vector fidelity that matches the Rust, TypeScript,
and Python reference libs.

## Install

```sh
go get github.com/phact/p2claw-agent/libs/identity-verify/go
```

(Module path subject to change at first publish — confirm with the
go.mod once the canonical repo path is settled.)

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

```go
import (
    "errors"
    "net/http"

    iv "github.com/phact/p2claw-agent/libs/identity-verify/go"
)

func handler(w http.ResponseWriter, r *http.Request) {
    claims, err := iv.VerifyHTTP(r, TrustedPeerID, nil)
    if err != nil {
        var ve *iv.VerifyError
        if errors.As(err, &ve) {
            switch ve.Kind {
            case iv.ErrTokenMissing:      http.Error(w, "no identity token", 401)
            case iv.ErrExpired:           http.Error(w, "identity token expired", 401)
            case iv.ErrBadSignature:      http.Error(w, "identity token forged", 401)
            case iv.ErrAlgorithmRejected: http.Error(w, "identity token wrong alg", 401)
            default:                      http.Error(w, "identity token invalid", 401)
            }
            return
        }
        http.Error(w, err.Error(), 500)
        return
    }
    // claims.Sub, claims.Email, claims.Name, claims.AuthMethod, claims.Extra
    render(w, claims)
}
```

## API

```go
func Verify(headers HeaderGetter, trustedPeerID string, opts *Options) (*Claims, error)
func VerifyHTTP(r *http.Request, trustedPeerID string, opts *Options) (*Claims, error)
```

Returns `*Claims` on success. Returns `*VerifyError` (matchable via
`errors.As`) on verification failure — the `.Kind` field is one of:

| `.Kind` | meaning |
|---|---|
| `TokenMissing` | The `X-P2claw-Identity-Token` header is absent. |
| `Malformed` | The token isn't a parseable JWS. |
| `AlgorithmRejected` | The token's alg isn't `EdDSA` (e.g. `none`, `HS256`, `RS256`). |
| `BadSignature` | The signature doesn't verify against the trusted peer_id. |
| `Expired` | Past `exp + 15s` leeway. |
| `NotYetValid` | Before `nbf − 15s` leeway. |
| `IssuerMismatch` | The token's `iss` claim doesn't match the trusted peer_id. |

A malformed `trustedPeerID` (operator config bug, not a token issue)
returns a plain `error` value — `errors.As` to `*VerifyError` returns
false. Distinguish operator config errors from token-verification
errors that way.

## What this does NOT do

- **No `ExtractClaimsUnverified` helper.** Verify-then-extract is the
  only path the library exposes. If you want to debug raw payloads,
  parse the JWS yourself.
- **No authorization.** Verification answers _who_. Authorization
  (which user can do what) is your app's call.

## License

MIT. See [`LICENSE`](LICENSE).
