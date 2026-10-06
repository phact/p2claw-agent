# @p2claw/identity-verify

Verify the `X-P2claw-Identity-Token` (EdDSA JWT) that a p2claw agent
attaches to forwarded requests. Cryptographically pins the request to
the issuing box's identity — your app stops having to trust the plain
`X-P2claw-*` headers.

Thin wrapper
over [`jose`](https://github.com/panva/jose); the crypto is `jose`'s,
the package's value is the API shape + the cross-language test-vector
fidelity that matches the Rust, Python, and Go reference libs.

## Install

```sh
npm install @p2claw/identity-verify
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

```ts
import { verify, VerifyError } from "@p2claw/identity-verify";

// In your request handler:
try {
  const claims = await verify(req.headers, TRUSTED_PEER_ID);
  // claims.sub, claims.email, claims.name, claims.auth_method, ...
  req.user = { email: claims.email, name: claims.name };
} catch (err) {
  if (err instanceof VerifyError) {
    switch (err.kind) {
      case "TokenMissing":       return res.status(401).send("no identity token");
      case "Expired":            return res.status(401).send("identity token expired");
      case "BadSignature":       return res.status(401).send("identity token forged");
      case "AlgorithmRejected":  return res.status(401).send("identity token wrong alg");
      default:                   return res.status(401).send("identity token invalid");
    }
  }
  throw err;
}
```

## What this does NOT do

- **No `extractClaimsUnverified`.** Verify-then-extract is the only
  path the library exposes. If you want to debug raw payloads, parse
  the JWS yourself.
- **No authorization.** Verification answers _who_ — the box-asserted
  identity. Authorization (which user can do what) is your app's call.
- **No clock-skew handling beyond ±15s.** Tokens have a 60-second exp
  window; we apply a 15-second leeway each side. Anything past that
  is an `expired` error.

## API

```ts
async function verify(
  headers: HeadersLike,
  trustedPeerId: string,
  options?: { now?: Date },
): Promise<Claims>;
```

`headers` accepts a real Fetch `Headers`, a Node `IncomingHttpHeaders`
record, or any plain key-value object. `trustedPeerId` is the 52-char
z-base-32 peer_id from the operator's app config. `options.now`
overrides the reference time (useful in tests).

Returns `Claims` on success:

```ts
interface Claims {
  sub: string;
  iss: string;     // == trustedPeerId on success
  iat: number;
  exp: number;
  email?: string;
  name?: string;
  auth_method?: string;
  [key: string]: unknown;
}
```

Throws `VerifyError` with one of these `.kind` values on failure:

| kind | meaning |
|---|---|
| `TokenMissing` | The `X-P2claw-Identity-Token` header is absent. |
| `Malformed` | The token isn't a parseable JWS. |
| `AlgorithmRejected` | The token's alg isn't `EdDSA` (e.g. `none`, `HS256`, `RS256`). |
| `BadSignature` | The signature doesn't verify against the trusted peer_id. |
| `Expired` | Past `exp + 15s` leeway. |
| `NotYetValid` | Before `nbf − 15s` leeway. |
| `IssuerMismatch` | The token's `iss` claim doesn't match the trusted peer_id. |

A malformed `trustedPeerId` (operator config bug, not a token issue)
throws a plain `TypeError` instead of `VerifyError`.

## License

MIT. See [`LICENSE`](LICENSE).
