/**
 * Verified identity claims from a `X-P2claw-Identity-Token`. New
 * claim fields the box mints in the future appear here additively
 * — existing fields don't change. Apps reading `claims.email` today
 * keep compiling tomorrow.
 */
export interface Claims {
  /** Subject the upstream app should treat as the principal. */
  sub: string;
  /** Issuer — the box's peer_id (z-base-32 Ed25519 pubkey). */
  iss: string;
  /** Issued-at, Unix seconds. */
  iat: number;
  /** Expiry, Unix seconds. */
  exp: number;
  /** Verified email, if the upstream auth method supplied one. */
  email?: string;
  /** Display name, if available. */
  name?: string;
  /**
   * How the principal authenticated (e.g. `"oauth"`, `"basic"`).
   * Surfaces for app-side audit logs / per-method gating.
   */
  auth_method?: string;
  /** Any additional claims the box has added. Forward-compatible. */
  [key: string]: unknown;
}

/** Subset of `Headers` the verify function consumes. Accepts a real
 *  Fetch `Headers`, a Node `IncomingHttpHeaders`-shaped record, or
 *  any plain key-value object. */
export type HeadersLike =
  | { get(name: string): string | null }
  | Record<string, string | string[] | undefined>;
