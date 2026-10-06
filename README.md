# p2claw-agent

[p2claw](https://p2claw.com) gives apps running on your machine a public URL,
served peer-to-peer. This repository holds the **p2claw agent** (the `p2claw`
binary that runs on your machine) and the libraries and SDKs that talk to it.

```sh
curl -fsSL https://p2claw.com/install | sh
p2claw run
p2claw apps expose myapp --port 5173   # https://myapp-<your alias>.p2claw.com/
```

Browsers reach your app over a WebRTC data channel straight to your machine;
other machines running the agent dial it over QUIC; plain HTTP clients go
through an HTTPS edge that tunnels to your machine. The data path is end-to-end
encrypted. See [`crates/agent`](crates/agent/README.md) for the full guide:
CLI, private apps between machines, inbound email, configuration, running as a
service and auto-upgrade.

## What's here

| Path | What it is |
|---|---|
| [`crates/agent`](crates/agent) | The agent: daemon and CLI, published as the `p2claw` binary. |
| [`crates/wire`](crates/wire), [`crates/translator`](crates/translator) | The peer wire protocol: frame codec, and the bridge between it and HTTP / WebSocket. |
| [`crates/identity`](crates/identity) | Ed25519 identities, peer ids, alias labels and the signatures built on them. |
| [`crates/control-proto`](crates/control-proto) | Messages between the agent and the coordination server. |
| [`crates/email-proto`](crates/email-proto) | The sealed format inbound email is delivered in. |
| [`crates/p2claw-iroh-client`](crates/p2claw-iroh-client) | Client for calling apps on other machines over QUIC. |
| [`crates/p2claw-mobile`](crates/p2claw-mobile), [`mobile/`](mobile) | Android and iOS SDKs for reaching p2claw apps from native apps. |
| [`libs/agent-client`](libs/agent-client) | Python and TypeScript clients for the agent's local API. |
| [`libs/identity-verify`](libs/identity-verify) | Verifiers for p2claw identity attestations (Rust, Go, Python, TypeScript). |

Not in this repository: the coordination server, the edge, the OAuth broker
and the browser bootstrap. The agent uses the hosted service at `p2claw.com`.

## Build

```sh
cargo build --release -p p2claw-agent   # target/release/p2claw
cargo test --workspace
```

A self-built agent replaces itself with the official release unless
auto-upgrade is turned off; see
[Auto-upgrade](crates/agent/README.md#auto-upgrade).

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Please report security issues privately through
[GitHub security advisories](../../security/advisories/new).

## License

MIT. See [LICENSE](LICENSE).
