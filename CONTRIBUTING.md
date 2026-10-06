# Contributing

Issues and pull requests are welcome.

## How changes land

This repository is published from the project's main repository. An accepted
pull request is applied there and comes back here with the next sync, under
your authorship. The pull request is closed with a link to that commit.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For the SDKs, run the checks in `libs/agent-client/python` and
`libs/agent-client/ts` as CI does (`.github/workflows/ci.yml`).

## Terms used in the code

- **box**: a machine running the agent. User-facing text says "machine"; code,
  the coordination protocol and the `P2CLAW_AGENT_*` settings say `box`.
- **coord**: the coordination server. It registers boxes, assigns aliases and
  relays connection setup. It never carries app traffic.
- **edge**: the HTTPS front door that tunnels plain HTTP clients to a box.
- **alias**: a box's public name, such as `quiet-river-3847`; apps are served at
  `<app>-<alias>.p2claw.com`.
- **peer id**: a box's Ed25519 public key in z-base-32. Aliases resolve to it.

## Code comments

Explain why, not what, and keep comments about the code in front of them. No
issue numbers, design-document references or change history in comments; those
belong in commit messages and pull requests.

## Security

Report vulnerabilities privately through
[GitHub security advisories](../../security/advisories/new), not in a public
issue.
