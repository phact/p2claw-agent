// Client for the p2claw agent's local API (HTTP over a Unix socket).

import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import type { IncomingMessage } from "node:http";
import type WebSocket from "ws";

export interface Identity {
  peer_id: string;
  alias: string | null;
  registered: boolean;
}

export interface Status {
  version: string;
  uptime_secs: number;
  peer_id: string;
  alias: string | null;
  route_count: number;
  coord: { state: string; since_secs: number; last_ack_age_secs: number | null };
}

export interface Session {
  id: string;
  kind: "browser" | "iroh";
  transport: "direct" | "relay" | "unknown";
  age_secs: number;
}

export interface AuthMethod {
  kind: "oauth";
  providers?: string[];
}

export interface App {
  name: string;
  upstream: string;
  registered_at: number;
  auth: AuthMethod[];
  visibility: "public" | "private";
  /** Public apps only, once the machine is registered. */
  url?: string;
}

export interface ExposeResult {
  name: string;
  url: string | null;
  pending_announce?: boolean;
}

export interface Share {
  app: string;
  peers: string[];
}

export interface ExposeOptions {
  port?: number;
  socketPath?: string;
  upstream?: string;
  /** `true` private, `false` public, omitted keeps an existing app's visibility. */
  private?: boolean;
  /** `true` allows any provider the broker knows; a list restricts to those. */
  authOauth?: boolean | string[];
}

export interface EmailRejectionTotals {
  totals: Record<string, number>;
  admitted_today: number;
  daily_limit: number;
}

export interface EmailSummary {
  enabled: boolean;
  addresses: string[];
  allowlist: string[];
  unread: number;
  total: number;
  forwarding_requests: number;
  config_error?: string;
  /** `null` when coordination was unreachable. */
  rejections: EmailRejectionTotals | null;
  rejections_available: boolean;
  /** Set when the change was saved locally but coordination has not confirmed it yet. */
  pending_sync?: boolean;
}

export interface EmailAttachment {
  id: string;
  name: string | null;
  type: string;
  size: number;
}

export interface EmailAuth {
  dkim: string;
  dkim_domain?: string;
  arc: string;
}

export interface EmailMessage {
  id: string;
  /** `expired` entries are summaries of mail that was never fetched; they have no body. */
  kind: "message" | "expired";
  /** RFC 3339. */
  received_at: string;
  to?: string;
  from: string;
  forwarded_by: string | null;
  subject: string;
  /** Present on a single message, never in a listing. */
  text?: string;
  html?: string;
  attachments?: EmailAttachment[];
  attachment_count: number;
  auth: EmailAuth | null;
  acked: boolean;
  size: number;
}

export interface EmailRejectedSender {
  from: string;
  reason: string;
  count: number;
  last_seen: number;
}

export interface EmailRejections extends EmailRejectionTotals {
  recent: EmailRejectedSender[];
}

export interface OauthProvider {
  name: string;
  scopes: string[];
  revoke_url: string;
}

export interface OauthFlowStarted {
  flow_id: string;
  authorize_url: string;
}

export interface OauthFlowView {
  flow_id: string;
  provider: string;
  status: "pending" | "ready" | "error" | "expired" | "consumed";
  code?: string;
  state?: string;
  error?: string;
}

export interface OauthTokenResponse {
  access_token: string;
  expires_in: number;
  scope?: string;
  /** A replacement grant when the provider rotated the refresh token. */
  grant?: string;
}

export interface OauthExchangeResult extends OauthTokenResponse {
  provider: string;
  /** Agent-managed exchanges (`store: true`) return the stored grant's id instead of the grant. */
  grant_id?: string;
}

export interface OauthGrantSummary {
  id: string;
  provider: string;
  scopes: string[];
  /** Unix seconds. */
  created_at: number;
}

export interface OauthAccessToken {
  access_token: string;
  expires_in: number;
  scope?: string;
}

export interface OauthRevokeResult {
  id: string;
  provider: string;
  /** `false` when the grant was dropped locally but the provider did not confirm. */
  provider_revoked: boolean;
  provider_error?: string;
}

export interface FetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
  /** Serialized as JSON with `content-type: application/json`. */
  json?: unknown;
  timeoutMs?: number;
}

export class AgentError extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    readonly detail?: string,
    readonly body?: unknown,
  ) {
    super(`${status} ${error}${detail ? `: ${detail}` : ""}`);
    this.name = "AgentError";
  }
}

export class AgentNotRunning extends AgentError {
  constructor(readonly socketPath: string, cause: Error) {
    super(0, "agent_not_running", `${socketPath}: ${cause.message}`);
    this.name = "AgentNotRunning";
  }
}

/** A fully read response from an app on another machine. */
export class FetchResponse {
  constructor(
    readonly status: number,
    readonly headers: http.IncomingHttpHeaders,
    readonly body: Buffer,
  ) {}

  get ok(): boolean {
    return this.status >= 200 && this.status < 300;
  }

  text(): string {
    return this.body.toString("utf8");
  }

  json<T = unknown>(): T {
    return JSON.parse(this.text()) as T;
  }
}

// Characters a URL would percent-encode; the agent reads a `unix:`
// upstream path back verbatim, so they can't appear in a socket path.
const UNSAFE_SOCKET_CHARS = /[\s%?#"<>`{}^|\\]/;

/** The socket the agent listens on, resolved the way the agent does. */
export function defaultSocketPath(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.P2CLAW_AGENT_RUNTIME_DIR;
  if (override) return path.join(override, "agent.sock");
  const uid = os.userInfo().uid;
  if (process.platform === "linux") {
    if (env.XDG_RUNTIME_DIR) return path.join(env.XDG_RUNTIME_DIR, "p2claw", "agent.sock");
    if (uid === 0 && existsSync("/run/p2claw")) return "/run/p2claw/agent.sock";
  }
  return `/tmp/p2claw-${uid}/agent.sock`;
}

export interface AgentClientOptions {
  socketPath?: string;
  timeoutMs?: number;
}

/**
 * Talks to the p2claw agent on this machine. Management calls reject with
 * {@link AgentError}; {@link AgentClient.fetch} resolves with whatever
 * the app on the other machine answered, including error statuses.
 */
export class AgentClient {
  readonly socketPath: string;
  readonly timeoutMs: number;

  constructor(opts: AgentClientOptions = {}) {
    this.socketPath = opts.socketPath ?? defaultSocketPath();
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  // -- transport --------------------------------------------------------

  /** Low-level request; the caller consumes the streamed response. */
  request(
    method: string,
    target: string,
    opts: { headers?: Record<string, string>; body?: string | Uint8Array; timeoutMs?: number } = {},
  ): Promise<IncomingMessage> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string | number> = { host: "localhost", ...opts.headers };
      if (opts.body !== undefined) headers["content-length"] = Buffer.byteLength(opts.body);
      const req = http.request(
        { socketPath: this.socketPath, method, path: target, headers },
        resolve,
      );
      req.setTimeout(opts.timeoutMs ?? this.timeoutMs, () =>
        req.destroy(new Error(`timed out after ${opts.timeoutMs ?? this.timeoutMs}ms`)),
      );
      req.on("error", (e: NodeJS.ErrnoException) => {
        if (e.code === "ENOENT" || e.code === "ECONNREFUSED") {
          reject(new AgentNotRunning(this.socketPath, e));
        } else {
          reject(e);
        }
      });
      if (opts.body !== undefined) req.write(opts.body);
      req.end();
    });
  }

  private async call<T>(
    method: string,
    target: string,
    payload?: unknown,
    timeoutMs?: number,
  ): Promise<T> {
    const body = payload === undefined ? undefined : JSON.stringify(payload);
    const res = await this.request(method, target, {
      body,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      timeoutMs,
    });
    const raw = await readAll(res);
    let parsed: unknown = undefined;
    if (raw.length > 0) {
      try {
        parsed = JSON.parse(raw.toString("utf8"));
      } catch {
        parsed = raw.toString("utf8");
      }
    }
    const status = res.statusCode ?? 0;
    if (status >= 400) {
      if (parsed && typeof parsed === "object") {
        const p = parsed as { error?: string; detail?: string };
        throw new AgentError(status, p.error ?? "error", p.detail, parsed);
      }
      throw new AgentError(status, "error", parsed ? String(parsed) : undefined, parsed);
    }
    return parsed as T;
  }

  // -- this box ---------------------------------------------------------

  identity(): Promise<Identity> {
    return this.call("GET", "/v1/identity");
  }

  status(): Promise<Status> {
    return this.call("GET", "/v1/status");
  }

  async sessions(): Promise<Session[]> {
    return (await this.call<{ sessions: Session[] }>("GET", "/v1/sessions")).sessions;
  }

  // -- apps -------------------------------------------------------------

  async apps(): Promise<App[]> {
    return (await this.call<{ routes: App[] }>("GET", "/v1/routes")).routes;
  }

  /** One app, or `null` if there is no app by that name. */
  async app(name: string): Promise<App | null> {
    try {
      return await this.call<App>("GET", `/v1/routes/${encodeURIComponent(name)}`);
    } catch (e) {
      if (e instanceof AgentError && e.status === 404) return null;
      throw e;
    }
  }

  /**
   * Register or replace an app. Give exactly one of `port`,
   * `socketPath` or `upstream`. A `socketPath` upstream implies
   * private; private apps can't use OAuth (access comes from shares).
   */
  expose(name: string, opts: ExposeOptions): Promise<ExposeResult> {
    const given = [opts.port, opts.socketPath, opts.upstream].filter((x) => x !== undefined);
    if (given.length !== 1) throw new TypeError("give exactly one of port, socketPath, upstream");
    let upstream = opts.upstream;
    let isPrivate = opts.private;
    if (opts.port !== undefined) upstream = `http://127.0.0.1:${opts.port}`;
    if (opts.socketPath !== undefined) {
      if (isPrivate === false) {
        throw new TypeError("a socketPath upstream is only allowed for private apps");
      }
      upstream = socketUpstream(opts.socketPath);
      isPrivate = true;
    }
    if (isPrivate && opts.authOauth) {
      throw new TypeError("private apps can't use OAuth; access comes from shares");
    }
    const body: Record<string, unknown> = { name, upstream };
    if (opts.authOauth) {
      const method: AuthMethod = { kind: "oauth" };
      if (Array.isArray(opts.authOauth)) {
        if (opts.authOauth.length === 0) {
          throw new TypeError("authOauth list must name at least one provider");
        }
        method.providers = opts.authOauth;
      }
      body.auth = [method];
    }
    if (isPrivate !== undefined) body.visibility = isPrivate ? "private" : "public";
    return this.call("POST", "/v1/routes", body);
  }

  /** Change an existing public app's OAuth gate (`false` removes it). */
  async setAuth(name: string, authOauth: boolean | string[]): Promise<ExposeResult> {
    const current = await this.app(name);
    if (!current) throw new AgentError(404, "not_found", `no app named ${name}`);
    return this.expose(name, {
      upstream: current.upstream,
      private: current.visibility === "private",
      authOauth,
    });
  }

  async unexpose(name: string): Promise<void> {
    await this.call("DELETE", `/v1/routes/${encodeURIComponent(name)}`);
  }

  // -- shares -----------------------------------------------------------

  async shares(): Promise<Share[]> {
    return (await this.call<{ shares: Share[] }>("GET", "/v1/shares")).shares;
  }

  /** Let `peers` (z-base-32 peer ids) call private app `app`. Resolves to
   *  the app's full peer list. */
  async share(app: string, peers: string[]): Promise<string[]> {
    const table = await this.shares();
    let row = table.find((r) => r.app === app);
    if (!row) {
      row = { app, peers: [] };
      table.push(row);
    }
    for (const p of peers) if (!row.peers.includes(p)) row.peers.push(p);
    const saved = (await this.call<{ shares: Share[] }>("PUT", "/v1/shares", { shares: table }))
      .shares;
    return saved.find((r) => r.app === app)?.peers ?? [];
  }

  /** Revoke one peer, or every peer when `peer` is omitted. Takes effect
   *  on the next request; open connections run until they close. */
  async unshare(app: string, peer?: string): Promise<void> {
    let table = await this.shares();
    if (peer === undefined) {
      table = table.filter((r) => r.app !== app);
    } else {
      for (const r of table) if (r.app === app) r.peers = r.peers.filter((p) => p !== peer);
    }
    await this.call("PUT", "/v1/shares", { shares: table });
  }

  // -- email ------------------------------------------------------------

  /** Addresses, enabled flag, allowlist, unread count and rejection totals. */
  email(): Promise<EmailSummary> {
    return this.call("GET", "/v1/email");
  }

  /** Turn email on; coordination assigns `<alias>@<parent>`. */
  emailEnable(): Promise<EmailSummary> {
    return this.call("PUT", "/v1/email", { enabled: true });
  }

  /** Turn email off. The inbox is kept. */
  emailDisable(): Promise<EmailSummary> {
    return this.call("PUT", "/v1/email", { enabled: false });
  }

  /** Add senders to the allowlist. Resolves to the stored list. */
  async emailAllow(addrs: string[]): Promise<string[]> {
    const table = [...(await this.email()).allowlist];
    for (const a of addrs) {
      const n = normalizeAddress(a);
      if (!table.includes(n)) table.push(n);
    }
    return this.putAllowlist(table);
  }

  /** Remove a sender from the allowlist. Resolves to the stored list. */
  async emailDisallow(addr: string): Promise<string[]> {
    const target = normalizeAddress(addr);
    const table = (await this.email()).allowlist.filter((a) => a !== target);
    return this.putAllowlist(table);
  }

  private async putAllowlist(allowlist: string[]): Promise<string[]> {
    return (await this.call<{ allowlist: string[] }>("PUT", "/v1/email/allowlist", { allowlist }))
      .allowlist;
  }

  /** Inbox listing, newest first, without bodies. */
  async emailMessages(opts: { unread?: boolean } = {}): Promise<EmailMessage[]> {
    const target = `/v1/email/messages${opts.unread ? "?unread=1" : ""}`;
    return (await this.call<{ messages: EmailMessage[] }>("GET", target)).messages;
  }

  /** One message with its bodies and attachment table, or the original
   *  RFC 5322 bytes with `{ raw: true }`. */
  emailMessage(id: string): Promise<EmailMessage>;
  emailMessage(id: string, opts: { raw: true }): Promise<Buffer>;
  emailMessage(id: string, opts: { raw?: boolean } = {}): Promise<EmailMessage | Buffer> {
    const base = `/v1/email/messages/${encodeURIComponent(id)}`;
    if (opts.raw) return this.callBytes("GET", `${base}?format=raw`);
    return this.call<EmailMessage>("GET", base);
  }

  /** The bytes of attachment `aid` (from the message's `attachments`). */
  emailAttachment(id: string, aid: string): Promise<Buffer> {
    return this.callBytes(
      "GET",
      `/v1/email/messages/${encodeURIComponent(id)}/attachments/${encodeURIComponent(aid)}`,
    );
  }

  /** Mark a message handled. It stays until deleted. */
  emailAck(id: string): Promise<EmailMessage> {
    return this.call("POST", `/v1/email/messages/${encodeURIComponent(id)}/ack`);
  }

  async emailDelete(id: string): Promise<void> {
    await this.call("DELETE", `/v1/email/messages/${encodeURIComponent(id)}`);
  }

  /**
   * Yield the id of each message as it arrives. Catch up with
   * `emailMessages({ unread: true })` on start: earlier messages are not
   * replayed.
   */
  async *emailWatch(): AsyncGenerator<string, void, undefined> {
    const res = await this.request("GET", "/v1/email/messages?watch=1", { timeoutMs: 0 });
    const status = res.statusCode ?? 0;
    if (status >= 400) {
      const raw = (await readAll(res)).toString("utf8");
      let parsed: { error?: string; detail?: string } | undefined;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = undefined;
      }
      throw new AgentError(status, parsed?.error ?? "error", parsed?.detail ?? raw);
    }
    let pending = "";
    for await (const chunk of res) {
      pending += (chunk as Buffer).toString("utf8");
      let nl = pending.indexOf("\n");
      while (nl >= 0) {
        const line = pending.slice(0, nl);
        pending = pending.slice(nl + 1);
        nl = pending.indexOf("\n");
        if (!line.trim()) continue;
        let event: { id?: unknown };
        try {
          event = JSON.parse(line);
        } catch {
          continue;
        }
        if (typeof event.id === "string") yield event.id;
      }
    }
  }

  /** Senders coordination turned away: totals per reason and recent senders. */
  emailRejected(): Promise<EmailRejections> {
    return this.call("GET", "/v1/email/rejected");
  }

  // -- oauth grants -----------------------------------------------------

  /** Providers and scopes available through p2claw Connect. */
  async oauthGrantsProviders(): Promise<OauthProvider[]> {
    return (await this.call<{ providers: OauthProvider[] }>("GET", "/v1/oauth-grants/providers"))
      .providers;
  }

  /**
   * Start a consent flow. `codeChallenge` is the PKCE S256 challenge,
   * `nonceHash` the base64url SHA-256 of a one-time nonce. Show the
   * returned `authorize_url` to the user. {@link AgentClient.oauthGrantsConnect}
   * does all of this for you.
   */
  oauthGrantsStart(
    provider: string,
    scopes: string[],
    codeChallenge: string,
    nonceHash: string,
  ): Promise<OauthFlowStarted> {
    return this.call("POST", "/v1/oauth-grants/flows", {
      provider,
      scopes,
      code_challenge: codeChallenge,
      nonce_hash: nonceHash,
    });
  }

  /**
   * Wait for the user to finish consenting. Resolves with the flow once
   * its status is no longer `pending`, or with the pending view when
   * `timeoutMs` passes first.
   */
  async oauthGrantsWait(flowId: string, opts: { timeoutMs?: number } = {}): Promise<OauthFlowView> {
    const base = `/v1/oauth-grants/flows/${encodeURIComponent(flowId)}`;
    const deadline = opts.timeoutMs === undefined ? undefined : Date.now() + opts.timeoutMs;
    for (;;) {
      let pollSecs = WAIT_POLL_SECONDS;
      let target = `${base}?wait=1`;
      if (deadline !== undefined) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) return this.call("GET", base);
        pollSecs = Math.min(pollSecs, Math.max(1, Math.floor(remaining / 1000)));
        target += `&timeout=${pollSecs}`;
      }
      const view = await this.call<OauthFlowView>("GET", target, undefined, (pollSecs + 15) * 1000);
      if (view.status !== "pending") return view;
    }
  }

  /**
   * Exchange a finished flow for an access token. App-managed (default):
   * the result carries `grant`; keep it with `provider` for
   * {@link AgentClient.oauthGrantsRefresh}. Agent-managed (`store: true`):
   * the agent keeps the grant and returns `grant_id` for
   * {@link AgentClient.oauthGrantsToken}.
   */
  oauthGrantsExchange(
    flowId: string,
    codeVerifier: string,
    opts: { store?: boolean } = {},
  ): Promise<OauthExchangeResult> {
    return this.call("POST", `/v1/oauth-grants/flows/${encodeURIComponent(flowId)}/exchange`, {
      code_verifier: codeVerifier,
      store: opts.store ?? false,
    });
  }

  /**
   * New access token for an app-managed grant. A returned `grant` replaces
   * the stored one. Rejects with `AgentError` 410 `invalid_grant` when the
   * provider no longer honours it.
   */
  oauthGrantsRefresh(grant: string, provider: string): Promise<OauthTokenResponse> {
    return this.call("POST", "/v1/oauth-grants/refresh", { provider, grant });
  }

  /** Grants the agent keeps. */
  async oauthGrants(): Promise<OauthGrantSummary[]> {
    return (await this.call<{ grants: OauthGrantSummary[] }>("GET", "/v1/oauth-grants")).grants;
  }

  /**
   * Current access token for a stored grant, refreshed as needed. Rejects
   * with `AgentError` 410 `invalid_grant` (and drops the grant) when the
   * provider rejects it.
   */
  oauthGrantsToken(grantId: string): Promise<OauthAccessToken> {
    return this.call("GET", `/v1/oauth-grants/${encodeURIComponent(grantId)}/token`);
  }

  /** Revoke a stored grant at the provider and forget it. */
  oauthGrantsRevoke(grantId: string): Promise<OauthRevokeResult> {
    return this.call("DELETE", `/v1/oauth-grants/${encodeURIComponent(grantId)}`);
  }

  /**
   * Start a consent flow with a fresh PKCE verifier and nonce. Show
   * `flow.authorizeUrl` to the user, then `await flow.wait()` for the
   * exchange result once they approve.
   */
  async oauthGrantsConnect(
    provider: string,
    scopes: string[],
    opts: { store?: boolean } = {},
  ): Promise<OauthGrantFlow> {
    const codeVerifier = randomBytes(48).toString("base64url");
    const nonce = randomBytes(24).toString("base64url");
    const started = await this.oauthGrantsStart(
      provider,
      scopes,
      b64urlSha256(codeVerifier),
      b64urlSha256(nonce),
    );
    return new OauthGrantFlow(this, started, provider, scopes, opts.store ?? false, codeVerifier, nonce);
  }

  private async callBytes(method: string, target: string): Promise<Buffer> {
    const res = await this.request(method, target);
    const raw = await readAll(res);
    const status = res.statusCode ?? 0;
    if (status >= 400) {
      let parsed: { error?: string; detail?: string } | undefined;
      try {
        parsed = JSON.parse(raw.toString("utf8"));
      } catch {
        parsed = undefined;
      }
      throw new AgentError(status, parsed?.error ?? "error", parsed?.detail, parsed);
    }
    return raw;
  }

  // -- other boxes ------------------------------------------------------

  /** Path on the agent socket for private app `app` on machine `peer`. */
  proxyPath(peer: string, app: string, appPath = "/"): string {
    return `/v1/proxy/${peer}/${app}${appPath.startsWith("/") ? appPath : `/${appPath}`}`;
  }

  /**
   * Send an HTTP request to private app `app` on machine `peer` (alias
   * or peer id), which must have shared it with this machine. Resolves
   * with the app's response as-is. Use {@link AgentClient.request} with
   * {@link AgentClient.proxyPath} to stream a large body.
   */
  async fetch(
    peer: string,
    app: string,
    appPath = "/",
    opts: FetchOptions = {},
  ): Promise<FetchResponse> {
    const headers = { ...opts.headers };
    let body = opts.body;
    if (opts.json !== undefined) {
      body = JSON.stringify(opts.json);
      headers["content-type"] ??= "application/json";
    }
    const res = await this.request(opts.method ?? "GET", this.proxyPath(peer, app, appPath), {
      headers,
      body,
      timeoutMs: opts.timeoutMs,
    });
    return new FetchResponse(res.statusCode ?? 0, res.headers, await readAll(res));
  }

  /**
   * Open a WebSocket to private app `app` on machine `peer`. Needs the `ws`
   * package. Resolves once the connection is open.
   */
  async websocket(
    peer: string,
    app: string,
    appPath = "/",
    opts: { headers?: Record<string, string> } = {},
  ): Promise<WebSocket> {
    let WS: typeof WebSocket;
    try {
      WS = (await import("ws")).default;
    } catch {
      throw new Error("websocket() needs the 'ws' package: npm install ws");
    }
    const url = `ws+unix://${this.socketPath}:${this.proxyPath(peer, app, appPath)}`;
    const ws = new WS(url, { headers: opts.headers });
    await new Promise<void>((resolve, reject) => {
      ws.once("open", () => resolve());
      ws.once("unexpected-response", (_req, res) =>
        reject(new AgentError(res.statusCode ?? 0, "websocket_rejected")),
      );
      ws.once("error", reject);
    });
    return ws;
  }
}

/** Longest the agent holds a `?wait=1` poll before answering `pending`. */
const WAIT_POLL_SECONDS = 55;

/**
 * A consent flow started by {@link AgentClient.oauthGrantsConnect}. Holds
 * the PKCE verifier and nonce so {@link OauthGrantFlow.wait} can finish it.
 */
export class OauthGrantFlow {
  readonly flowId: string;
  readonly authorizeUrl: string;
  private readonly nonceHash: string;

  constructor(
    private readonly client: AgentClient,
    started: OauthFlowStarted,
    readonly provider: string,
    readonly scopes: string[],
    readonly store: boolean,
    private readonly codeVerifier: string,
    nonce: string,
  ) {
    this.flowId = started.flow_id;
    this.authorizeUrl = started.authorize_url;
    this.nonceHash = b64urlSha256(nonce);
  }

  /**
   * Wait until the user approves, check the callback carries this flow's
   * nonce, and exchange. Rejects with `AgentError` `flow_pending` after
   * `timeoutMs`, or `flow_error` / `flow_expired` / `state_mismatch` when
   * the flow can't be finished.
   */
  async wait(opts: { timeoutMs?: number } = {}): Promise<OauthExchangeResult> {
    const view = await this.client.oauthGrantsWait(this.flowId, opts);
    if (view.status === "pending") {
      throw new AgentError(0, "flow_pending", `flow ${this.flowId} is still waiting for the user`, view);
    }
    if (view.status !== "ready") {
      throw new AgentError(0, `flow_${view.status}`, view.error, view);
    }
    if (stateNonceHash(view.state ?? "") !== this.nonceHash) {
      throw new AgentError(0, "state_mismatch", "the callback is not for this flow", view);
    }
    return this.client.oauthGrantsExchange(this.flowId, this.codeVerifier, { store: this.store });
  }
}

function b64urlSha256(data: string): string {
  return createHash("sha256").update(data).digest("base64url");
}

/**
 * The `nonce_hash` inside a broker-signed `state` (`s1.<json>.<sig>`). The
 * signature is the broker's to check; the app only confirms the callback
 * belongs to the flow it started.
 */
function stateNonceHash(state: string): string | undefined {
  const parts = state.split(".");
  if (parts.length !== 3 || parts[0] !== "s1") return undefined;
  try {
    const claims: unknown = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
    if (claims && typeof claims === "object") {
      const nh = (claims as { nonce_hash?: unknown }).nonce_hash;
      if (typeof nh === "string") return nh;
    }
  } catch {
    // not a state we understand
  }
  return undefined;
}

/** The agent's canonical form: lower-case, plus-tag dropped. */
function normalizeAddress(addr: string): string {
  const s = addr.trim().toLowerCase();
  const at = s.lastIndexOf("@");
  const local = at > 0 ? s.slice(0, at) : "";
  const domain = at >= 0 ? s.slice(at + 1) : "";
  if (!local || !domain) throw new TypeError(`${JSON.stringify(addr)} is not an email address`);
  return `${local.split("+")[0]}@${domain}`;
}

function socketUpstream(socketPath: string): string {
  const abs = path.resolve(socketPath);
  const bad = abs.match(UNSAFE_SOCKET_CHARS);
  if (bad) throw new TypeError(`socket path ${JSON.stringify(abs)} contains ${JSON.stringify(bad[0])}`);
  return `unix:${abs}`;
}

function readAll(res: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    res.on("data", (c: Buffer) => chunks.push(c));
    res.on("end", () => resolve(Buffer.concat(chunks)));
    res.on("error", reject);
  });
}
