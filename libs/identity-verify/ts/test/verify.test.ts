// Vector-driven test suite for the verify lib.
//
// Loads the shared cross-language fixture at
// `libs/identity-verify/test-vectors.json` and asserts:
//
//   - `expect: "ok"` cases  → verify() resolves to expected_claims
//   - `expect: "err:<Variant>"` cases → verify() throws VerifyError
//     with `.kind === "<Variant>"`
//
// The same JSON drives the Rust / Python / Go reference libs, so any
// divergence (e.g. one lib accepting `alg=none`) shows up as a single
// failed case here.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { TOKEN_HEADER, VerifyError, verify } from "../src/index.js";

interface VectorCase {
  name: string;
  token: string;
  verify_at: number;
  expect: string; // "ok" | "err:<Variant>"
  expected_claims?: Record<string, unknown>;
}

interface VectorFile {
  spec_version?: string;
  trusted_peer_id: string;
  cases: VectorCase[];
}

const HERE = fileURLToPath(new URL(".", import.meta.url));
// Canonical fixture is owned by native-dev's Rust gen-vectors binary.
// Falls back to a local dev placeholder so the suite stays runnable
// before that's been generated on this checkout.
const CANONICAL = resolve(HERE, "../../test-vectors.json");
const PLACEHOLDER = resolve(HERE, "../.placeholder-vectors.json");
const FIXTURE_PATH = existsSync(CANONICAL) ? CANONICAL : PLACEHOLDER;

const fixture: VectorFile = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));

describe("verify against shared test vectors", () => {
  for (const c of fixture.cases) {
    it(`case: ${c.name}`, async () => {
      const headers = new Headers();
      headers.set(TOKEN_HEADER, c.token);
      const now = new Date(c.verify_at * 1000);
      if (c.expect === "ok") {
        const claims = await verify(headers, fixture.trusted_peer_id, { now });
        expect(claims).toMatchObject(c.expected_claims ?? {});
      } else {
        const variant = parseErrVariant(c.expect);
        await expect(
          verify(headers, fixture.trusted_peer_id, { now }),
        ).rejects.toMatchObject({
          name: "VerifyError",
          kind: variant,
        });
      }
    });
  }
});

describe("verify cohorts not driven by the shared fixture", () => {
  it("rejects when the token header is missing", async () => {
    const headers = new Headers();
    await expect(
      verify(headers, fixture.trusted_peer_id),
    ).rejects.toMatchObject({
      name: "VerifyError",
      kind: "TokenMissing",
    });
  });

  it("throws TypeError (not VerifyError) when the trusted peer_id can't be decoded", async () => {
    const headers = new Headers();
    headers.set(TOKEN_HEADER, "not-relevant");
    await expect(
      verify(headers, "not-a-z-base-32-string"),
    ).rejects.toBeInstanceOf(TypeError);
  });

  it("accepts a plain key-value record as headers", async () => {
    const validCase = fixture.cases.find((c) => c.expect === "ok");
    if (!validCase) throw new Error("fixture has no positive case");
    const headers = { "X-P2claw-Identity-Token": validCase.token };
    const now = new Date(validCase.verify_at * 1000);
    const claims = await verify(headers, fixture.trusted_peer_id, { now });
    expect(claims.iss).toBe(fixture.trusted_peer_id);
  });

  it("error class instance check", () => {
    expect(new VerifyError("TokenMissing", "x")).toBeInstanceOf(VerifyError);
    expect(new VerifyError("TokenMissing", "x")).toBeInstanceOf(Error);
  });
});

function parseErrVariant(expect: string): string {
  if (!expect.startsWith("err:")) {
    throw new Error(`expected "err:<Variant>", got "${expect}"`);
  }
  return expect.slice(4);
}
