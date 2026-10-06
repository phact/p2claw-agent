import { errors as joseErrors, importJWK, jwtVerify, type JWK } from "jose";

import { VerifyError } from "./errors.js";
import { decodePeerId } from "./peer-id.js";
import type { Claims, HeadersLike } from "./types.js";

/** Canonical header the daemon mints into. */
export const TOKEN_HEADER = "x-p2claw-identity-token";

/** Clock-skew tolerance applied to `exp`/`iat`. Attestations live
 *  60s; 15s leeway in either direction. */
const LEEWAY_SECONDS = 15;

/** Options the caller can pass to override default behavior. */
export interface VerifyOptions {
  /** Reference time (mostly for tests). Defaults to `new Date()`. */
  now?: Date;
}

/**
 * Verify the `X-P2claw-Identity-Token` carried on `headers` against
 * the operator-supplied `trustedPeerId` (z-base-32 box pubkey).
 *
 * Returns the verified claims on success. Throws `VerifyError` (with
 * a structured `.kind`) on any verification failure. Throws a plain
 * `TypeError` if `trustedPeerId` isn't a valid z-base-32 string —
 * that's a configuration mistake, not a verification outcome.
 *
 * No "extract claims without verifying" path is offered by design;
 * verify-then-extract is the only API.
 */
export async function verify(
  headers: HeadersLike,
  trustedPeerId: string,
  options: VerifyOptions = {},
): Promise<Claims> {
  let pubkey: Uint8Array;
  try {
    pubkey = decodePeerId(trustedPeerId);
  } catch (err) {
    throw new TypeError(
      `invalid trustedPeerId: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const token = readHeader(headers, TOKEN_HEADER);
  if (!token) {
    throw new VerifyError("TokenMissing", `no ${TOKEN_HEADER} header`);
  }

  // Peek the JOSE header's `alg` before handing the token to the JWT
  // lib. The underlying library will also reject non-EdDSA via
  // `algorithms:[...]` — but some libraries (notably golang-jwt v5)
  // wrap the alg-rejection inside a generic signature-invalid error
  // class that's hard to discriminate. Peeking pins
  // `AlgorithmRejected` as the right discriminant unconditionally
  // and matches the Rust reference lib's defence-in-depth pattern.
  const peekedAlg = peekJoseAlg(token);
  if (peekedAlg !== null && peekedAlg !== "EdDSA") {
    throw new VerifyError("AlgorithmRejected", `alg=${peekedAlg} is not EdDSA`);
  }

  // jose's importJWK is the cross-runtime path that doesn't require
  // Node's `crypto.createPublicKey`. The `x` field is the 32-byte
  // Ed25519 pubkey base64url-encoded; jose handles the rest.
  const jwk: JWK = {
    kty: "OKP",
    crv: "Ed25519",
    x: base64UrlEncode(pubkey),
    alg: "EdDSA",
  };
  const key = await importJWK(jwk, "EdDSA");

  const now = options.now ?? new Date();

  let payload: Record<string, unknown>;
  try {
    const result = await jwtVerify(token, key, {
      algorithms: ["EdDSA"],
      clockTolerance: LEEWAY_SECONDS,
      currentDate: now,
    });
    payload = result.payload as Record<string, unknown>;
  } catch (err) {
    throw mapJoseError(err);
  }

  // Defence-in-depth: even if signature verifies, the `iss` claim
  // must match the trusted peer_id. A correctly-keyed but spoofed-iss
  // token shouldn't slip through.
  if (payload["iss"] !== trustedPeerId) {
    throw new VerifyError(
      "IssuerMismatch",
      `iss=${String(payload["iss"])} does not match trusted peer_id`,
    );
  }

  // iat-future: jose only enforces nbf, not iat. The spec treats
  // iat in the future as "not yet valid" too — apply leeway.
  const iat = payload["iat"];
  if (typeof iat === "number") {
    const nowSec = Math.floor(now.getTime() / 1000);
    if (iat > nowSec + LEEWAY_SECONDS) {
      throw new VerifyError(
        "NotYetValid",
        `iat=${iat} > now=${nowSec} (leeway ${LEEWAY_SECONDS}s)`,
      );
    }
  }

  return payload as Claims;
}

/** Map jose's error inventory onto the canonical PascalCase vocabulary. */
function mapJoseError(err: unknown): VerifyError {
  if (err instanceof joseErrors.JWTExpired) {
    return new VerifyError("Expired", err.message);
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    const claim = (err as { claim?: string }).claim;
    if (claim === "nbf" || claim === "iat") {
      return new VerifyError("NotYetValid", err.message);
    }
    return new VerifyError("Malformed", err.message);
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
    return new VerifyError("BadSignature", err.message);
  }
  if (err instanceof joseErrors.JOSEAlgNotAllowed) {
    return new VerifyError("AlgorithmRejected", err.message);
  }
  // `JWSInvalid` and `JWTInvalid` both indicate that the input
  // didn't parse as a valid JWS / JWT structure — that's a malformed
  // token, not a signature failure.
  if (
    err instanceof joseErrors.JWSInvalid ||
    err instanceof joseErrors.JWTInvalid
  ) {
    return new VerifyError("Malformed", err.message);
  }
  return new VerifyError(
    "Malformed",
    err instanceof Error ? err.message : String(err),
  );
}

function readHeader(headers: HeadersLike, name: string): string | undefined {
  const lower = name.toLowerCase();
  if ("get" in headers && typeof headers.get === "function") {
    const v = headers.get(name) ?? headers.get(lower);
    return v ?? undefined;
  }
  const rec = headers as Record<string, string | string[] | undefined>;
  for (const k of Object.keys(rec)) {
    if (k.toLowerCase() === lower) {
      const v = rec[k];
      if (Array.isArray(v)) return v[0];
      return v;
    }
  }
  return undefined;
}

/**
 * Decode the JOSE header's `alg` field by hand, without delegating
 * to the JWT library. Returns the alg string on success, or `null` if
 * the token doesn't even parse as a JWS header (e.g. wrong segment
 * count, undecodable base64, non-JSON header) — those cases are left
 * for the library's full decode to classify as `Malformed`.
 */
function peekJoseAlg(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let header: unknown;
  try {
    const bytes = base64UrlDecode(parts[0]!);
    header = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  if (header && typeof header === "object") {
    const alg = (header as { alg?: unknown }).alg;
    if (typeof alg === "string") return alg;
  }
  return null;
}

function base64UrlDecode(s: string): Uint8Array {
  // Pad to a multiple of 4, restore standard chars, then decode.
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const std = padded.replace(/-/g, "+").replace(/_/g, "/");
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(std, "base64"));
  }
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base64UrlEncode(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64url");
  }
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
