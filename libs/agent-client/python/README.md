# p2claw-agent-client (Python)

Client for the p2claw agent's local API. The agent (`p2claw run`) is the
daemon that publishes apps from this machine; it serves a small
HTTP API on a Unix socket that only this machine's user can reach. This
package wraps that API: manage your apps and who they're shared with,
and call private apps that other machines have shared with you.

Standard library only. WebSockets need the optional `websockets` package.

```sh
pip install p2claw-agent-client               # HTTP only
pip install 'p2claw-agent-client[websocket]'  # plus websocket()
```

## Use

```python
from p2claw_agent_client import AgentClient

agent = AgentClient()  # finds the agent's socket the way the agent does
print(agent.status()["alias"])

# Publish a local app, or make it private and share it with one peer.
agent.expose("web", port=5173)
agent.expose("db-api", socket_path="/run/db-api.sock")  # socket upstreams are private
agent.share("db-api", ["<their peer id>"])

# Call a private app another machine shared with you.
r = agent.fetch("blue-otter-7392", "db-api", "/rows?limit=10")
print(r.status, r.json())

with agent.fetch("blue-otter-7392", "files", "/big.tar", stream=True) as r:
    for chunk in r.iter_chunks():
        ...

with agent.websocket("blue-otter-7392", "chat", "/ws") as ws:
    ws.send("hi")
    print(ws.recv())
```

`peer` is the other machine's alias or peer id. `fetch` returns the app's
response as-is, including error statuses; an app that isn't shared with
you answers 404, the same as one that doesn't exist.

## API

| Method | Does |
|---|---|
| `identity()`, `status()`, `sessions()` | This machine: peer id and alias, version and coordination link, live visitor sessions. |
| `apps()`, `app(name)` | List apps, or one app (`None` if missing). |
| `expose(name, port= / socket_path= / upstream=, private=, auth_oauth=)` | Register or replace an app. `private=None` keeps an existing app's visibility. |
| `set_auth(name, auth_oauth)`, `unexpose(name)` | Change a public app's OAuth gate; remove an app. |
| `shares()`, `share(app, peers)`, `unshare(app, peer=None)` | Who may call your private apps. Revocation applies to new requests. |
| `email()`, `email_enable()`, `email_disable()` | This machine's inbound email: addresses, allowlist, unread count, rejection totals; turn it on or off. |
| `email_allow(addrs)`, `email_disallow(addr)` | Senders whose mail is accepted. Exact addresses; plus-tags are ignored. |
| `email_messages(unread=False)`, `email_message(id, raw=False)`, `email_attachment(id, aid)` | Read the inbox: listing without bodies, one message with bodies and attachments (or the raw RFC 5322 bytes), one attachment. |
| `email_ack(id)`, `email_delete(id)`, `email_watch()` | Mark a message handled (it stays), remove it, or iterate over new message ids as they arrive. |
| `email_rejected()` | Senders coordination turned away, with reasons. |
| `fetch(peer, app, path, method=, headers=, body= / json_body=, stream=)` | HTTP to a private app on another machine. |
| `websocket(peer, app, path, headers=)` | WebSocket to a private app on another machine. |

Management calls raise `AgentError` (`.status`, `.error`, `.detail`);
`AgentNotRunning` when nothing listens on the socket. Pass
`socket_path=` to target a specific agent.

License: MIT.
