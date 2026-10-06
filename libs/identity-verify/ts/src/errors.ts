/**
 * Verification error variants. PascalCase strings match the canonical
 * cross-language test-vector vocabulary used by the Rust / Python /
 * Go reference libs — `expect: "err:<Variant>"` in the shared fixture
 * keys directly off these strings.
 */
export type VerifyErrorKind =
  | "TokenMissing"
  | "Malformed"
  | "AlgorithmRejected"
  | "BadSignature"
  | "Expired"
  | "NotYetValid"
  | "IssuerMismatch";

/**
 * One-and-only error class the public verify API throws when a token
 * is presented but fails verification. `kind` is the structured
 * discriminant; `message` is human-readable detail.
 *
 * Configuration errors (e.g. a malformed `trustedPeerId`) throw a
 * plain `TypeError` instead — they're a programmer / operator issue,
 * not a verification outcome.
 */
export class VerifyError extends Error {
  readonly kind: VerifyErrorKind;

  constructor(kind: VerifyErrorKind, message: string) {
    super(message);
    this.name = "VerifyError";
    this.kind = kind;
  }
}
