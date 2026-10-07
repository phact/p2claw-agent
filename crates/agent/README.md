# p2claw agent

`p2claw` is the daemon that runs on your machine and gives apps listening on
`127.0.0.1` a public URL served peer-to-peer. It generates an Ed25519
identity, registers with a p2claw **coordination server** (the service that
assigns names and brokers connection setup, but never carries app traffic),
and reverse-proxies inbound connections from visitors to your local apps.

Each registered machine gets an **alias** such as `quiet-river-3847`,
permanent for the lifetime of its identity key. An app exposed under the name
`myapp` becomes reachable at `https://myapp-quiet-river-3847.p2claw.com/`.

How a visitor reaches the app:

- **Browsers** open a WebRTC data channel straight to your machine. The page
  is bootstrapped from the p2claw domain; the data path is end-to-end encrypted
  and the coordination server sees only signaling metadata.
- **Other machines** running the agent dial over QUIC (via [iroh]) directly.
- **Everything else** (`curl`, webhooks, file uploads) arrives through the
  p2claw **edge**, an HTTPS front door that tunnels the request to your
  machine.

Standard HTTP/1.1, streaming bodies, SSE, and WebSockets work without changes
to the app. The agent does not build, start, or supervise your apps; you keep
them listening on a loopback port.

The coordination server and edge are not part of this release. The agent talks
to a p2claw coordination server; the public one is at `coord.p2claw.com`.

[iroh]: https://github.com/n0-computer/iroh

## Install

```sh
curl -fsSL https://p2claw.com/install | sh
```

The script downloads the release tarball for your platform (macOS arm64 /
x86_64, Linux x86_64 / arm64), verifies its SHA-256 against the published
`SHA256SUMS`, and installs to `~/.local/bin/p2claw` without sudo. Pass
`--prefix <dir>` or set `P2CLAW_INSTALL_DIR` to install elsewhere. Windows runs
under WSL.

## Build from source

```sh
cargo build --release -p p2claw-agent
# binary at target/release/p2claw
```

Requires a stable Rust toolchain. Before running a self-built binary, read the
[Auto-upgrade](#auto-upgrade) section: by default the agent replaces itself
with the official release within an hour.

## Usage

```sh
p2claw run                           # foreground; registers on first start
p2claw identity                      # print peer_id and alias (offline)
p2claw apps expose myapp --port 5173 # publish 127.0.0.1:5173 as myapp-<alias>
p2claw apps list
p2claw service install               # keep it running across logout / reboot
```

`p2claw run` prints the alias on first registration. The identity key and
registration state live in the data directory (see
[Configuration](#configuration)); keeping that directory across reinstalls
keeps your alias.

### CLI surface

| Command | What it does |
|---|---|
| `run` | Run the agent in the foreground (the default when no command is given). Registers on first start, holds the control connection to the coordination server, serves the local API. |
| `identity` | Print the current `peer_id` and, if registered, the alias. Does not touch the network. |
| `status` | Live status of the running agent: version, uptime, control-connection state, route count. |
| `sessions` | List active visitor sessions with their transport path and age. |
| `register` | Force re-registration against the coordination server; overwrites `agent.state` on success. |
| `apps expose <name> --port <port>` | Register or replace an app. `--auth-oauth [providers]` gates it behind p2claw OAuth; `--private` makes it reachable only by peers you share it with; `--json`, `--no-qr`. |
| `apps expose <name> --socket <path>` | Same, for an app listening on a Unix socket instead of a port. Implies `--private`. |
| `apps unexpose <name>` | Remove an app. |
| `apps list [--json] [--qr]` | List registered apps. |
| `apps show <name> [--json]` | Print one app's state, including its auth method list. |
| `apps set-auth <name> [--auth-oauth ...]` | Replace an app's auth method list. |
| `apps clear-auth <name>` | Make an app public again. |
| `apps share` / `unshare` / `shares` | Share a private app with specific peers, revoke, and list shares. |
| `apps connect <peer>/<app> [--listen addr]` | Use a private app another machine shared with you: serves it on a local port (HTTP and WebSockets), forwarding through the agent on this machine. |
| `email …` | Inbound email for this machine: `enable` / `disable`, `allow` / `disallow` senders, `forwarding` (Gmail), `list` / `show` / `attachment` / `ack` / `rm` / `watch`, `rejected`. With no subcommand, prints a summary. See [Email](#email). |
| `oauth-grants …` | OAuth grants for apps on this machine through p2claw Connect: `providers`, `start` / `wait` / `exchange [--store]`, `refresh`, `list` / `token` / `revoke`. See [OAuth grants](#oauth-grants). |
| `service install` / `uninstall` / `status` / `config-check` | Manage the agent as a user-scope OS service (launchd on macOS, `systemd --user` on Linux). `install --system` installs a machine-scope service with the MagicDNS pieces (SNI listener on 443, local resolver, local CA) and needs sudo. |
| `upgrade --check` / `--apply` / `--pin <ver>` / `--unpin` / `--disable` / `--enable` / `--status` | Drive or control auto-upgrade by hand. |

Every subcommand accepts `--help`. All `apps`, `email`, `oauth-grants`,
`status`, and `sessions` commands talk to the running agent over a
Unix-domain socket, so `p2claw run` (or the installed service) must be up.

### Authenticated apps

`apps expose <name> --port <port> --auth-oauth` requires visitors to sign in
through the p2claw OAuth broker before the request reaches your app. On
authenticated requests the app receives `X-P2claw-User`, `X-P2claw-Email`,
`X-P2claw-Provider`, and, when the provider supplies them, `X-P2claw-Name` and
`X-P2claw-Picture`. Incoming `X-P2claw-*` headers are always stripped before
forwarding, whether or not auth is on. Unauthenticated requests get `401` with
`P2claw-Auth-Required: true`.

## Private apps between machines

A private app has no public URL. Only machines you share it with can call
it, identified by their peer id (`p2claw identity` prints it):

```sh
# On the machine that runs the app
p2claw apps expose db-api --socket /run/db-api.sock   # or --port 8080 --private
p2claw apps share db-api --with <their peer id>

# On the machine that uses it
p2claw apps connect <owner alias>/db-api --listen 127.0.0.1:8080
curl http://127.0.0.1:8080/rows
```

The app sees the caller's peer id in `X-P2claw-Peer`. Unshared or
unknown apps both answer 404, so names can't be probed.

Programs can skip `connect` and call the agent's local API directly.
It is HTTP on the agent's Unix socket (`$XDG_RUNTIME_DIR/p2claw/agent.sock`
on Linux, `/tmp/p2claw-$UID/agent.sock` on macOS), and
`/v1/proxy/<peer>/<app>/<path>` forwards HTTP and WebSockets to a shared
app:

```sh
curl --unix-socket "$XDG_RUNTIME_DIR/p2claw/agent.sock" \
  http://localhost/v1/proxy/<owner alias>/db-api/rows
```

Client libraries for the same API: [Python](../../libs/agent-client/python)
and [Node](../../libs/agent-client/ts).

## Email

Every machine with email enabled can receive mail at `<alias>@p2claw.com`,
plus one address per vanity alias; all of them reach the same inbox. Only
senders you allow get in, and only when their mail carries a DKIM signature
that passes for the sender's domain. Everything else bounces and never reaches
your machine.

```sh
p2claw email enable                      # ask for the address
p2claw email allow you@example.com       # repeat for several senders
p2claw email                             # addresses, allowlist, unread count, rejections
p2claw email list --unread
p2claw email show <id>                   # headers, attachments, text body (--raw for RFC 5322)
p2claw email attachment <id> <aid> -o file.pdf
p2claw email ack <id>                    # mark handled; it stays in the inbox
p2claw email rm <id>
p2claw email watch                       # one JSON line per message as it arrives
p2claw email rejected                    # who was turned away, and why
```

Gmail can forward mail here. Add the address as a forwarding address in
Gmail; Gmail then sends a confirmation request. `p2claw email forwarding`
shows the pending request with its confirmation link. Open the link, then run
`p2claw email forwarding approve <gmail account>` so mail that account
forwards is admitted (`revoke` undoes it).

After the email service checks a message, it encrypts it to your machine's
key and holds it for up to 7 days if the machine is offline. Once fetched,
mail stays on your machine until you delete it; `ack` only marks it handled.

The same operations are available on the local API under `/v1/email`, and
the Python and Node client libraries expose them as `email_*` /
`email*` methods, so apps on the machine can read the inbox directly.

## OAuth grants

An app on this machine can get a user's permission to call a provider API
(Google Calendar first) through **p2claw Connect**, without registering an
OAuth client of its own. The app asks the agent to start a flow and shows
the user a consent link; the user approves "p2claw Connect" at the
provider; the callback reaches the agent through the coordination server,
and the agent turns it into an access token. The p2claw OAuth broker holds
the provider client secret and does the code exchange and refreshes, but
keeps nothing: the grant it returns is sealed to this machine's identity
key and lives only here. A copy taken off the machine is useless.

The app picks who keeps the grant:

- **App-managed:** the exchange returns the grant to the app, which stores
  it and asks the agent to refresh it when the access token expires.
- **Agent-managed:** the agent keeps the grant in `oauth-grants.json` in its
  data directory and hands out access tokens on request, refreshing behind
  the call. `list` and `revoke` work on these grants.

```sh
p2claw oauth-grants providers                      # providers and scopes on offer
p2claw oauth-grants start google --scope calendar.app.created \
    --challenge <pkce challenge> --nonce-hash <hash>   # prints the flow id and consent URL
p2claw oauth-grants wait <flow id>                 # blocks until the user approves
p2claw oauth-grants exchange <flow id> --verifier <pkce verifier> --store
p2claw oauth-grants list
p2claw oauth-grants token <grant id>               # a current access token
p2claw oauth-grants revoke <grant id>              # revoke at the provider and forget
p2claw oauth-grants refresh google < grant.txt     # app-managed grants
```

The same operations are available on the local API under
`/v1/oauth-grants`, and the Python and Node client libraries expose them as
`oauth_grants_*` / `oauthGrants*` methods, including a helper that runs the
whole app side of a flow (PKCE, nonce, wait, exchange) in one call. Anything
that can reach the agent's socket can get tokens from stored grants, the
same trust boundary as the rest of the local API.

## Configuration

The agent is configured through environment variables (and, for the first
two, matching CLI flags).

| Variable | Default | Effect |
|---|---|---|
| `P2CLAW_COORD_DOMAIN` (`--coord-domain`) | `coord.p2claw.com` | Coordination server FQDN. Bound into the registration signature, so it must match what the server verifies against. Used by `run` and `register`. |
| `P2CLAW_COORD_URL` (`--coord-url`) | `https://<coord_domain>` | Scheme + host for the coordination HTTP endpoint. Override for local servers such as `http://127.0.0.1:8081`. |
| `P2CLAW_AGENT_OAUTH_BROKER_URL` | `https://oauth.p2claw.com` | OAuth broker whose JWKS the agent trusts for `--auth-oauth` apps, and which brokers `oauth-grants` flows. |
| `P2CLAW_AGENT_STUN_URL` | `stun:stun.cloudflare.com:3478` | STUN server used to gather server-reflexive ICE candidates for browser visitors. Set to an empty string to disable STUN. |
| `P2CLAW_AGENT_DATA_DIR` | `$XDG_DATA_HOME/p2claw` on Linux, `~/Library/Application Support/p2claw` on macOS | Holds `identity.key`, `agent.state`, the route table, and auto-upgrade policy files. |
| `P2CLAW_AGENT_RUNTIME_DIR` | `$XDG_RUNTIME_DIR/p2claw`, else `/run/p2claw` as root | Holds `agent.sock`, the local-API Unix socket. |
| `P2CLAW_AGENT_DISABLE_MAGICDNS` | unset | `true` skips the MagicDNS pipeline (local CA, 443 SNI listener, local DNS resolver, privilege drop). User-scope service installs set this; inbound traffic still works. |
| `P2CLAW_DNS_PORT` | `5354` | Port for the local MagicDNS resolver when the pipeline is enabled. |
| `P2CLAW_RELEASE_REPO` | `phact/p2claw-agent` | GitHub `<owner>/<repo>` auto-upgrade pulls releases from. See below. |

The **parent domain** (`p2claw.com` for the public service) is the suffix
under which app URLs are formed. It is assigned by the coordination server at
registration and stored in `agent.state`; `service install --system` also
accepts `--parent-domain` to name the resolver file before first registration.
The compiled-in fallback is set at build time:

```sh
P2CLAW_DEFAULT_PARENT_DOMAIN=claw.example.com cargo build --release -p p2claw-agent
```

Self-hosters running their own coordination server set this together with
`P2CLAW_COORD_DOMAIN`.

## Auto-upgrade

Auto-upgrade is **on by default**. Once an hour the running agent resolves the
latest release of the GitHub repository named by `P2CLAW_RELEASE_REPO`
(default `phact/p2claw-agent`), downloads the tarball for its platform,
verifies the SHA-256 against the release's `SHA256SUMS` file, swaps the binary
into place, and asks its service supervisor to restart it. The previous binary
is kept as `<path>.previous` and restored if the new one fails its post-upgrade
health check.

**If you build the agent yourself or run a fork, a stock binary will replace
itself with the official release from `phact/p2claw-agent` within an hour.**
To prevent that, do one of the following:

- Point it at your own releases: set `P2CLAW_RELEASE_REPO=<owner>/<repo>` in
  the environment the agent runs under. `service install` (and
  `service install --system`) copies the value from the installing shell into
  the unit or plist it writes, so `P2CLAW_RELEASE_REPO=acme/p2claw p2claw
  service install` is enough.
- Disable it: `p2claw upgrade --disable` (re-enable with `--enable`). This
  writes a sentinel file to the data directory that both the hourly task and
  `upgrade --apply` honor.
- Pin it: `p2claw upgrade --pin <version>` refuses releases past that version
  (`--unpin` clears it).

`p2claw upgrade --status` shows the current pin / disabled state and
`upgrade --check` prints what the next cycle would do without changing
anything.

## Crate layout

| Crate | Purpose |
|---|---|
| `crates/agent` | The `p2claw` binary: daemon, local API, CLI, service install, auto-upgrade. |
| `crates/wire` | Frame codec for the visitor ↔ agent wire protocol. |
| `crates/translator` | Bridges the wire protocol to HTTP requests/responses and WebSocket sessions, on either side of a connection. |
| `crates/identity` | Ed25519 keys, `peer_id` derivation (z-base-32), and the signed proofs used at registration and in browser bootstrap. |
| `crates/control-proto` | Message types and framing for the agent ↔ coordination control connection. |
| `crates/p2claw-iroh-client` | Client library that opens a QUIC connection to another machine's agent over iroh and speaks the wire protocol; used for machine-to-machine dials. |

`libs/identity-verify` is a separate small library (Rust, TypeScript, Python,
Go) for verifying the identity attestation tokens the agent mints for
authenticated apps.

## License

MIT. See [`LICENSE`](../../LICENSE).
