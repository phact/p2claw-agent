import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocketServer } from "ws";

import { AgentClient, AgentError, AgentNotRunning, defaultSocketPath } from "../src/index.js";

interface Recorded {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

/** Unix-socket HTTP server that records requests and replays canned
 *  responses keyed by `METHOD path`. */
class FakeAgent {
  readonly socketPath: string;
  readonly requests: Recorded[] = [];
  readonly responses = new Map<string, [number, unknown]>();
  readonly server: http.Server;

  constructor() {
    this.socketPath = path.join(mkdtempSync(path.join(os.tmpdir(), "agent-client-")), "agent.sock");
    this.server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        this.requests.push({
          method: req.method ?? "",
          url: req.url ?? "",
          headers: req.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
        const key = `${req.method} ${(req.url ?? "").split("?")[0]}`;
        const [status, payload] = this.responses.get(key) ?? [404, { error: "not_found" }];
        res.writeHead(status, { "content-type": "application/json" });
        res.end(typeof payload === "string" ? payload : JSON.stringify(payload));
      });
    });
  }

  listen(): Promise<void> {
    return new Promise((r) => this.server.listen(this.socketPath, r));
  }

  close(): Promise<void> {
    return new Promise((r) => this.server.close(() => r()));
  }
}

let agent: FakeAgent;
let client: AgentClient;

beforeEach(async () => {
  agent = new FakeAgent();
  await agent.listen();
  client = new AgentClient({ socketPath: agent.socketPath });
});

afterEach(async () => {
  await agent.close();
});

describe("AgentClient", () => {
  it("reads identity and status", async () => {
    agent.responses.set("GET /v1/identity", [200, { peer_id: "p", alias: "a-b-1", registered: true }]);
    agent.responses.set("GET /v1/status", [200, { version: "0.10.19", route_count: 2 }]);
    expect((await client.identity()).alias).toBe("a-b-1");
    expect((await client.status()).route_count).toBe(2);
  });

  it("surfaces the agent's error code", async () => {
    agent.responses.set("POST /v1/routes", [400, { error: "bad_name", detail: "too long" }]);
    const err = await client.expose("x".repeat(40), { port: 1 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AgentError);
    expect(err).toMatchObject({ status: 400, error: "bad_name", detail: "too long" });
  });

  it("returns null for an unknown app", async () => {
    expect(await client.app("nope")).toBeNull();
  });

  it("builds expose bodies", async () => {
    agent.responses.set("POST /v1/routes", [200, { name: "x", url: null }]);
    await client.expose("web", { port: 5173 });
    await client.expose("svc", { socketPath: "/run/svc.sock" });
    await client.expose("gated", { port: 8000, authOauth: ["github"] });
    await client.expose("flip", { port: 8000, private: false });
    const bodies = agent.requests.map((r) => JSON.parse(r.body));
    expect(bodies[0]).toEqual({ name: "web", upstream: "http://127.0.0.1:5173" });
    expect(bodies[1]).toEqual({ name: "svc", upstream: "unix:/run/svc.sock", visibility: "private" });
    expect(bodies[2].auth).toEqual([{ kind: "oauth", providers: ["github"] }]);
    expect(bodies[3].visibility).toBe("public");
  });

  it("rejects bad expose combinations without calling the agent", () => {
    expect(() => client.expose("x", {})).toThrow(TypeError);
    expect(() => client.expose("x", { port: 1, socketPath: "/s" })).toThrow(TypeError);
    expect(() => client.expose("x", { socketPath: "/s", private: false })).toThrow(TypeError);
    expect(() => client.expose("x", { port: 1, private: true, authOauth: true })).toThrow(TypeError);
    expect(() => client.expose("x", { socketPath: "/tmp/has space.sock" })).toThrow(TypeError);
    expect(agent.requests).toHaveLength(0);
  });

  it("merges shares and removes them", async () => {
    agent.responses.set("GET /v1/shares", [
      200,
      { shares: [{ app: "svc", peers: ["p1"] }, { app: "other", peers: ["p9"] }] },
    ]);
    agent.responses.set("PUT /v1/shares", [
      200,
      { shares: [{ app: "svc", peers: ["p1", "p2"] }, { app: "other", peers: ["p9"] }] },
    ]);
    expect(await client.share("svc", ["p1", "p2"])).toEqual(["p1", "p2"]);
    expect(JSON.parse(agent.requests.at(-1)!.body)).toEqual({
      shares: [{ app: "svc", peers: ["p1", "p2"] }, { app: "other", peers: ["p9"] }],
    });
    await client.unshare("svc", "p1");
    expect(JSON.parse(agent.requests.at(-1)!.body).shares[0]).toEqual({ app: "svc", peers: [] });
    await client.unshare("svc");
    expect(JSON.parse(agent.requests.at(-1)!.body)).toEqual({ shares: [{ app: "other", peers: ["p9"] }] });
  });

  it("manages email settings and the allowlist", async () => {
    const summary = {
      enabled: false,
      addresses: [],
      allowlist: ["you@gmail.com"],
      unread: 0,
      rejections: null,
      rejections_available: false,
    };
    agent.responses.set("GET /v1/email", [200, summary]);
    agent.responses.set("PUT /v1/email", [200, { ...summary, enabled: true }]);
    agent.responses.set("PUT /v1/email/allowlist", [200, { allowlist: ["you@gmail.com", "b@x.org"] }]);

    expect((await client.email()).rejections).toBeNull();
    expect((await client.emailEnable()).enabled).toBe(true);
    expect(JSON.parse(agent.requests.at(-1)!.body)).toEqual({ enabled: true });
    await client.emailDisable();
    expect(JSON.parse(agent.requests.at(-1)!.body)).toEqual({ enabled: false });

    expect(await client.emailAllow(["You+tag@Gmail.com", "B@x.org"])).toEqual(["you@gmail.com", "b@x.org"]);
    expect(JSON.parse(agent.requests.at(-1)!.body)).toEqual({ allowlist: ["you@gmail.com", "b@x.org"] });
    await client.emailDisallow("you+other@gmail.com");
    expect(JSON.parse(agent.requests.at(-1)!.body)).toEqual({ allowlist: [] });
    await expect(client.emailAllow(["nope"])).rejects.toBeInstanceOf(TypeError);
  });

  it("reads, acks and deletes mail", async () => {
    const light = { id: "m_1", kind: "message", subject: "hi", acked: false };
    agent.responses.set("GET /v1/email/messages", [200, { messages: [light] }]);
    agent.responses.set("GET /v1/email/messages/m_1", [200, { ...light, text: "body" }]);
    agent.responses.set("GET /v1/email/messages/m_1/attachments/a_1", [200, "%PDF-1.4"]);
    agent.responses.set("POST /v1/email/messages/m_1/ack", [200, { ...light, acked: true }]);
    agent.responses.set("DELETE /v1/email/messages/m_1", [204, ""]);
    agent.responses.set("GET /v1/email/rejected", [
      200,
      { totals: { not_allowed: 2 }, recent: [], admitted_today: 1, daily_limit: 1000 },
    ]);

    expect(await client.emailMessages()).toEqual([light]);
    expect(await client.emailMessages({ unread: true })).toEqual([light]);
    expect(agent.requests.at(-1)!.url).toBe("/v1/email/messages?unread=1");
    expect((await client.emailMessage("m_1")).text).toBe("body");
    // The fake answers the raw form with the same JSON; it must come back as bytes untouched.
    const raw = await client.emailMessage("m_1", { raw: true });
    expect(raw.toString("utf8")).toBe(JSON.stringify({ ...light, text: "body" }));
    expect(agent.requests.at(-1)!.url).toBe("/v1/email/messages/m_1?format=raw");
    expect((await client.emailAttachment("m_1", "a_1")).toString("utf8")).toBe("%PDF-1.4");
    expect((await client.emailAck("m_1")).acked).toBe(true);
    await client.emailDelete("m_1");
    expect(agent.requests.at(-1)!.method).toBe("DELETE");
    expect((await client.emailRejected()).totals).toEqual({ not_allowed: 2 });
    const err = await client.emailAttachment("m_1", "a_9").catch((e: unknown) => e);
    expect(err).toMatchObject({ status: 404, error: "not_found" });
  });

  it("watches for new message ids", async () => {
    agent.responses.set("GET /v1/email/messages", [200, '{"id":"m_1"}\n{"lagged":3}\n{"id":"m_2"}\n']);
    const ids: string[] = [];
    for await (const id of client.emailWatch()) ids.push(id);
    expect(ids).toEqual(["m_1", "m_2"]);
    expect(agent.requests.at(-1)!.url).toBe("/v1/email/messages?watch=1");
  });

  it("fetch targets the proxy and returns app errors as responses", async () => {
    agent.responses.set("POST /v1/proxy/blue-otter-7392/svc/items", [201, { ok: true }]);
    const r = await client.fetch("blue-otter-7392", "svc", "items?x=1", { method: "POST", json: { a: 1 } });
    expect(r.status).toBe(201);
    expect(r.json()).toEqual({ ok: true });
    const sent = agent.requests.at(-1)!;
    expect(sent.url).toBe("/v1/proxy/blue-otter-7392/svc/items?x=1");
    expect(JSON.parse(sent.body)).toEqual({ a: 1 });
    expect(sent.headers["content-type"]).toBe("application/json");
    expect((await client.fetch("blue-otter-7392", "svc", "/missing")).status).toBe(404);
  });

  it("opens a WebSocket through the proxy path", async () => {
    await agent.close();
    const server = http.createServer();
    const wss = new WebSocketServer({ server });
    let seenPath = "";
    wss.on("connection", (ws, req) => {
      seenPath = req.url ?? "";
      ws.on("message", (m) => ws.send(m.toString()));
    });
    await new Promise<void>((r) => server.listen(agent.socketPath, r));
    try {
      const ws = await client.websocket("blue-otter-7392", "svc", "/ws");
      const echo = new Promise<string>((r) => ws.once("message", (m) => r(m.toString())));
      ws.send("hi");
      expect(await echo).toBe("hi");
      expect(seenPath).toBe("/v1/proxy/blue-otter-7392/svc/ws");
      ws.close();
    } finally {
      wss.close();
      await new Promise<void>((r) => server.close(() => r()));
      agent = new FakeAgent();
      await agent.listen();
    }
  });

  it("reports a missing agent as AgentNotRunning", async () => {
    const c = new AgentClient({ socketPath: path.join(os.tmpdir(), "no-such-agent.sock") });
    await expect(c.status()).rejects.toBeInstanceOf(AgentNotRunning);
  });

  it("resolves the socket path the way the agent does", () => {
    expect(defaultSocketPath({ P2CLAW_AGENT_RUNTIME_DIR: "/srv/p2claw" })).toBe("/srv/p2claw/agent.sock");
    if (process.platform === "linux") {
      expect(defaultSocketPath({ XDG_RUNTIME_DIR: "/run/user/1000" })).toBe("/run/user/1000/p2claw/agent.sock");
    }
  });
});

function b64urlSha256(data: string): string {
  return createHash("sha256").update(data).digest("base64url");
}

function stateFor(nonceHash: string): string {
  const claims = JSON.stringify({ peer_id: "p", flow_id: "f_1", nonce_hash: nonceHash });
  return `s1.${Buffer.from(claims).toString("base64url")}.sig`;
}

describe("AgentClient oauth grants", () => {
  it("calls every oauth-grants endpoint", async () => {
    agent.responses.set("GET /v1/oauth-grants/providers", [
      200,
      { providers: [{ name: "google", scopes: ["calendar.app.created"], revoke_url: "r" }] },
    ]);
    agent.responses.set("POST /v1/oauth-grants/flows", [
      200,
      { flow_id: "f_1", authorize_url: "https://accounts.google.com/x" },
    ]);
    agent.responses.set("GET /v1/oauth-grants/flows/f_1", [
      200,
      { flow_id: "f_1", status: "ready", code: "c0de", state: "s1.x.y" },
    ]);
    agent.responses.set("POST /v1/oauth-grants/flows/f_1/exchange", [
      200,
      { access_token: "at", expires_in: 3600, provider: "google", grant: "g1.k.z" },
    ]);
    agent.responses.set("POST /v1/oauth-grants/refresh", [200, { access_token: "at2", expires_in: 3600 }]);
    agent.responses.set("GET /v1/oauth-grants", [
      200,
      { grants: [{ id: "gr_1", provider: "google", scopes: [], created_at: 1 }] },
    ]);
    agent.responses.set("GET /v1/oauth-grants/gr_1/token", [200, { access_token: "at3", expires_in: 100 }]);
    agent.responses.set("DELETE /v1/oauth-grants/gr_1", [
      200,
      { id: "gr_1", provider: "google", provider_revoked: true },
    ]);

    expect((await client.oauthGrantsProviders())[0]!.name).toBe("google");
    const started = await client.oauthGrantsStart("google", ["calendar.app.created"], "chal", "nh");
    expect(started.flow_id).toBe("f_1");
    expect(JSON.parse(agent.requests.at(-1)!.body)).toEqual({
      provider: "google",
      scopes: ["calendar.app.created"],
      code_challenge: "chal",
      nonce_hash: "nh",
    });
    expect((await client.oauthGrantsWait("f_1")).code).toBe("c0de");
    expect(agent.requests.at(-1)!.url).toBe("/v1/oauth-grants/flows/f_1?wait=1");
    expect((await client.oauthGrantsExchange("f_1", "verifier")).grant).toBe("g1.k.z");
    expect(JSON.parse(agent.requests.at(-1)!.body)).toEqual({ code_verifier: "verifier", store: false });
    await client.oauthGrantsExchange("f_1", "verifier", { store: true });
    expect(JSON.parse(agent.requests.at(-1)!.body).store).toBe(true);
    expect((await client.oauthGrantsRefresh("g1.k.z", "google")).access_token).toBe("at2");
    expect(JSON.parse(agent.requests.at(-1)!.body)).toEqual({ provider: "google", grant: "g1.k.z" });
    expect((await client.oauthGrants())[0]!.id).toBe("gr_1");
    expect((await client.oauthGrantsToken("gr_1")).access_token).toBe("at3");
    expect((await client.oauthGrantsRevoke("gr_1")).provider_revoked).toBe(true);
    expect(agent.requests.at(-1)!.method).toBe("DELETE");

    agent.responses.set("GET /v1/oauth-grants/gr_1/token", [410, { error: "invalid_grant" }]);
    const err = await client.oauthGrantsToken("gr_1").catch((e: unknown) => e);
    expect(err).toMatchObject({ status: 410, error: "invalid_grant" });
  });

  it("wait honours its timeout", async () => {
    agent.responses.set("GET /v1/oauth-grants/flows/f_1", [200, { flow_id: "f_1", status: "pending" }]);
    const view = await client.oauthGrantsWait("f_1", { timeoutMs: 200 });
    expect(view.status).toBe("pending");
    expect(agent.requests[0]!.url).toContain("wait=1&timeout=1");
  });

  it("connect runs the app side of a flow", async () => {
    agent.responses.set("POST /v1/oauth-grants/flows", [
      200,
      { flow_id: "f_1", authorize_url: "https://accounts.google.com/x" },
    ]);
    agent.responses.set("POST /v1/oauth-grants/flows/f_1/exchange", [
      200,
      { access_token: "at", expires_in: 3600, provider: "google", grant_id: "gr_1" },
    ]);
    const flow = await client.oauthGrantsConnect("google", ["calendar.app.created"], { store: true });
    expect([flow.flowId, flow.authorizeUrl]).toEqual(["f_1", "https://accounts.google.com/x"]);
    const start = JSON.parse(agent.requests.at(-1)!.body);
    expect(start.code_challenge).toHaveLength(43);
    expect(start.nonce_hash).toHaveLength(43);

    agent.responses.set("GET /v1/oauth-grants/flows/f_1", [
      200,
      { flow_id: "f_1", status: "ready", code: "c0de", state: stateFor(start.nonce_hash) },
    ]);
    const result = await flow.wait();
    expect(result.grant_id).toBe("gr_1");
    const exchange = JSON.parse(agent.requests.at(-1)!.body);
    expect(exchange.store).toBe(true);
    expect(b64urlSha256(exchange.code_verifier)).toBe(start.code_challenge);
  });

  it("connect rejects foreign callbacks and failed flows", async () => {
    agent.responses.set("POST /v1/oauth-grants/flows", [200, { flow_id: "f_1", authorize_url: "u" }]);
    const flow = await client.oauthGrantsConnect("google", ["s"]);
    agent.responses.set("GET /v1/oauth-grants/flows/f_1", [
      200,
      { flow_id: "f_1", status: "ready", code: "c0de", state: stateFor("other") },
    ]);
    await expect(flow.wait()).rejects.toMatchObject({ error: "state_mismatch" });
    expect(agent.requests.some((r) => r.url.includes("exchange"))).toBe(false);

    agent.responses.set("GET /v1/oauth-grants/flows/f_1", [
      200,
      { flow_id: "f_1", status: "error", error: "access_denied" },
    ]);
    await expect(flow.wait()).rejects.toMatchObject({ error: "flow_error", detail: "access_denied" });

    agent.responses.set("GET /v1/oauth-grants/flows/f_1", [200, { flow_id: "f_1", status: "pending" }]);
    await expect(flow.wait({ timeoutMs: 100 })).rejects.toMatchObject({ error: "flow_pending" });
  });
});
