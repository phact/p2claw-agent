// Generate a placeholder shared test-vectors JSON for development.
//
// Mints the cases the canonical schema calls for, pinned to fixed
// `verify_at` timestamps so the fixture never wall-clock expires.
// Output path: ../../test-vectors.json (the cross-language fixture
// location every reference lib loads from).
//
// Run via `npm run gen:vectors`. The canonical fixture is produced by
// the Rust `gen-identity-vectors` binary; this is a local fallback.

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { SignJWT, exportJWK, generateKeyPair } from "jose";

import { encodePeerId } from "../src/peer-id.js";

const HERE = fileURLToPath(new URL(".", import.meta.url));
// Writes to a gitignored dev-only path. The canonical
// `libs/identity-verify/test-vectors.json` is OWNED by native-dev's
// Rust `gen-vectors` binary — nothing else writes there.
const OUT_PATH = resolve(HERE, "../.placeholder-vectors.json");

const IAT = 1735200000;
const EXP = IAT + 60;
const VERIFY_AT = IAT + 30;
const VERIFY_AT_EXPIRED = EXP + 130;

interface VectorCase {
  name: string;
  token: string;
  verify_at: number;
  expect: string; // "ok" | "err:<Variant>"
  expected_claims?: Record<string, unknown>;
}

interface VectorFile {
  spec_version: string;
  generated_by: string;
  note: string;
  trusted_peer_id: string;
  cases: VectorCase[];
}

async function jwkToRawPubkey(jwk: { x?: string }): Promise<Uint8Array> {
  if (!jwk.x) throw new Error("EdDSA jwk missing x");
  return Buffer.from(jwk.x, "base64url");
}

const baseClaims = {
  sub: "alice@example.com",
  email: "alice@example.com",
  name: "Alice Q.",
  auth_method: "oauth",
};

async function main(): Promise<void> {
  // Trusted box keypair — pubkey becomes `trusted_peer_id`. All
  // positive + most negative cases sign with this.
  const box = await generateKeyPair("EdDSA", { extractable: true });
  const boxJwk = await exportJWK(box.publicKey);
  const boxPubkey = await jwkToRawPubkey(boxJwk);
  const trustedPeerId = encodePeerId(boxPubkey);

  // Wrong key — for the `wrong_key` negative.
  const evil = await generateKeyPair("EdDSA", { extractable: true });

  const claimsForToken = {
    ...baseClaims,
    iss: trustedPeerId,
  };

  // Positive.
  const positiveToken = await new SignJWT(claimsForToken)
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuedAt(IAT)
    .setExpirationTime(EXP)
    .sign(box.privateKey);
  const expectedClaims = {
    iss: trustedPeerId,
    sub: baseClaims.sub,
    iat: IAT,
    exp: EXP,
    email: baseClaims.email,
    name: baseClaims.name,
    auth_method: baseClaims.auth_method,
  };

  // Negative: expired. Same token, verify after exp+leeway.
  const expiredToken = positiveToken;

  // Negative: alg_none. Unsigned JWS with `{"alg":"none"}` header.
  const noneHeader = base64Url(JSON.stringify({ alg: "none", typ: "JWT" }));
  const nonePayload = base64Url(JSON.stringify(claimsForToken));
  const algNoneToken = `${noneHeader}.${nonePayload}.`;

  // Negative: alg_hs256. HMAC-signed; jose rejects the alg before
  // checking the MAC.
  const hsKey = new Uint8Array(32).fill(7);
  const hs256Token = await new SignJWT(claimsForToken)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(IAT)
    .setExpirationTime(EXP)
    .sign(hsKey);

  // Negative: wrong_key. EdDSA-signed but by the wrong private key.
  const wrongKeyToken = await new SignJWT(claimsForToken)
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuedAt(IAT)
    .setExpirationTime(EXP)
    .sign(evil.privateKey);

  // Negative: tampered. Flip one payload byte; signature breaks.
  const tamperedToken = tamperPayloadByte(positiveToken);

  // Negative: malformed. Doesn't parse as a JWS.
  const malformedToken = "this.is.not-a-jwt";

  // Negative: not_yet_valid. `nbf` (not-before) is set well past the
  // leeway window — jose validates nbf against `now`, treats iat as
  // informational, so we set both to keep the token internally
  // consistent and let the nbf check fire.
  const futureNbf = IAT + 1000;
  const notYetValidToken = await new SignJWT({
    ...claimsForToken,
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuedAt(futureNbf)
    .setNotBefore(futureNbf)
    .setExpirationTime(futureNbf + 60)
    .sign(box.privateKey);

  // Negative: issuer_mismatch. Properly signed by box but iss claim
  // names a different peer_id — defence-in-depth check fires.
  const other = await generateKeyPair("EdDSA", { extractable: true });
  const otherJwk = await exportJWK(other.publicKey);
  const otherPubkey = await jwkToRawPubkey(otherJwk);
  const issuerMismatchToken = await new SignJWT({
    ...baseClaims,
    iss: encodePeerId(otherPubkey),
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuedAt(IAT)
    .setExpirationTime(EXP)
    .sign(box.privateKey);

  const out: VectorFile = {
    spec_version: "0.1",
    generated_by: "@p2claw/identity-verify: gen-placeholder-vectors.ts",
    note:
      "Placeholder fixture authored from the TS lib. Pinned IAT=1735200000, EXP=IAT+60. Tokens are random per regeneration (Ed25519 seed is not deterministic in this generator). The canonical fixture is produced by the Rust gen-identity-vectors binary.",
    trusted_peer_id: trustedPeerId,
    cases: [
      {
        name: "positive_oauth_identity",
        token: positiveToken,
        verify_at: VERIFY_AT,
        expect: "ok",
        expected_claims: expectedClaims,
      },
      { name: "negative_expired",        token: expiredToken,        verify_at: VERIFY_AT_EXPIRED, expect: "err:Expired" },
      { name: "negative_alg_none",       token: algNoneToken,        verify_at: VERIFY_AT,         expect: "err:AlgorithmRejected" },
      { name: "negative_alg_hs256",      token: hs256Token,          verify_at: VERIFY_AT,         expect: "err:AlgorithmRejected" },
      { name: "negative_wrong_key",      token: wrongKeyToken,       verify_at: VERIFY_AT,         expect: "err:BadSignature" },
      { name: "negative_tampered",       token: tamperedToken,       verify_at: VERIFY_AT,         expect: "err:BadSignature" },
      { name: "negative_malformed",      token: malformedToken,      verify_at: VERIFY_AT,         expect: "err:Malformed" },
      { name: "negative_not_yet_valid",  token: notYetValidToken,    verify_at: VERIFY_AT,         expect: "err:NotYetValid" },
      { name: "negative_issuer_mismatch", token: issuerMismatchToken, verify_at: VERIFY_AT,         expect: "err:IssuerMismatch" },
    ],
  };

  writeFileSync(OUT_PATH, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${OUT_PATH}`);
  console.log(`trusted_peer_id = ${trustedPeerId}`);
}

function base64Url(s: string): string {
  return Buffer.from(s).toString("base64url");
}

function tamperPayloadByte(token: string): string {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("token is not a compact JWS");
  const payload = Buffer.from(parts[1]!, "base64url");
  payload[0] = payload[0]! ^ 0x01;
  parts[1] = payload.toString("base64url");
  return parts.join(".");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
