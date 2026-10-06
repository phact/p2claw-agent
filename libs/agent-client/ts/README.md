# @p2claw/agent-client (Node)

Client for the p2claw agent's local API. The agent (`p2claw run`) is the
daemon that publishes apps from this machine; it serves a small
HTTP API on a Unix socket that only this machine's user can reach. This
package wraps that API: manage your apps and who they're shared with,
and call private apps that other machines have shared with you.

Node 20+, no runtime dependencies. `websocket()` needs the `ws` package.

```sh
npm install @p2claw/agent-client
npm install ws   # only for websocket()
```

## Use

```ts
import { AgentClient } from "@p2claw/agent-client";

const agent = new AgentClient(); // finds the agent's socket the way the agent does
console.log((await agent.status()).alias);

// Publish a local app, or make it private and share it with one peer.
await agent.expose("web", { port: 5173 });
await agent.expose("db-api", { socketPath: "/run/db-api.sock" }); // socket upstreams are private
await agent.share("db-api", ["<their peer id>"]);

// Call a private app another machine shared with you.
const r = await agent.fetch("blue-otter-7392", "db-api", "/rows?limit=10");
console.log(r.status, r.json());

// Stream a large response.
const res = await agent.request("GET", agent.proxyPath("blue-otter-7392", "files", "/big.tar"));
res.pipe(process.stdout);

const ws = await agent.websocket("blue-otter-7392", "chat", "/ws");
ws.on("message", (m) => console.log(m.toString()));
ws.send("hi");
```

`peer` is the other machine's alias or peer id. `fetch` resolves with the
app's response as-is, including error statuses; an app that isn't shared
with you answers 404, the same as one that doesn't exist.

## API

| Method | Does |
|---|---|
| `identity()`, `status()`, `sessions()` | This machine: peer id and alias, version and coordination link, live visitor sessions. |
| `apps()`, `app(name)` | List apps, or one app (`null` if missing). |
| `expose(name, { port \| socketPath \| upstream, private, authOauth })` | Register or replace an app. Omitting `private` keeps an existing app's visibility. |
| `setAuth(name, authOauth)`, `unexpose(name)` | Change a public app's OAuth gate; remove an app. |
| `shares()`, `share(app, peers)`, `unshare(app, peer?)` | Who may call your private apps. Revocation applies to new requests. |
| `email()`, `emailEnable()`, `emailDisable()` | This machine's inbound email: addresses, allowlist, unread count, rejection totals; turn it on or off. |
| `emailAllow(addrs)`, `emailDisallow(addr)` | Senders whose mail is accepted. Exact addresses; plus-tags are ignored. |
| `emailMessages({ unread })`, `emailMessage(id, { raw })`, `emailAttachment(id, aid)` | Read the inbox: listing without bodies, one message with bodies and attachments (or the raw RFC 5322 bytes), one attachment. |
| `emailAck(id)`, `emailDelete(id)`, `emailWatch()` | Mark a message handled (it stays), remove it, or iterate (`for await`) over new message ids as they arrive. |
| `emailRejected()` | Senders coordination turned away, with reasons. |
| `fetch(peer, app, path, { method, headers, body \| json })` | HTTP to a private app on another machine. |
| `request(method, target, opts)`, `proxyPath(peer, app, path)` | Streaming access to any local-API path. |
| `websocket(peer, app, path, { headers })` | WebSocket to a private app on another machine. |

Management calls reject with `AgentError` (`status`, `error`, `detail`);
`AgentNotRunning` when nothing listens on the socket. Pass
`{ socketPath }` to target a specific agent.

License: MIT.
