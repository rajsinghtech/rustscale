# rustscale

A Rust implementation of Tailscale's client stack — the equivalent of Go's `tsnet` package —
supporting direct (UDP hole-punched) connections, DERP relay, and peer relay, with the long-term
goal of a full TUN-mode client.

## Development model: ALL implementation work goes through opencode agents

Claude Code acts as the **orchestrator only**. All code in this repo is written by opencode
agents running `vercel-ent/zai/glm-5.2`. Do not write implementation code directly with
Edit/Write except for docs, specs, and this file.

### How to call opencode

The binary is at `~/.opencode/bin/opencode` (on PATH). Model id as opencode knows it:
`ai/vercel-ent/zai/glm-5.2` (verify with `opencode models | grep vercel`).

One-shot task (preferred, run in background for long builds):

```bash
opencode run -m ai/vercel-ent/zai/glm-5.2 \
  --dir /Users/rajsingh/Documents/GitHub/rustscale \
  --auto \
  --title "phase-1-scaffold" \
  "<detailed task prompt>"
```

Key flags learned:
- `--auto` — auto-approve tool permissions (required for unattended runs; agents can't be interactive here).
- `--dir` — working directory for the agent. Always point at this repo.
- `-c` / `-s <sessionID>` — continue the last / a specific session to iterate with context intact.
- `--title` — name the session so it's findable later via `opencode session list`.
- `--format json` — raw event stream if output needs parsing.
- `--variant high` — bump reasoning effort for hard protocol work.
- `-f <file>` — attach files (e.g., a spec) to the message.

Session management:
```bash
opencode session list            # find previous sessions
opencode run -s <id> "fix ..."   # continue a session with its context
opencode export <id>             # dump full session JSON
```

### Orchestration workflow

1. Write/refine the phase spec in `docs/` (Claude does this).
2. Launch opencode with a **self-contained prompt**: goal, file layout, references to the Go
   sources under `/Users/rajsingh/Documents/GitHub/tailscale` (agent can read them —
   mention exact paths), acceptance criteria (`cargo build`, `cargo test`, `cargo clippy`).
3. Run long builds with Bash `run_in_background: true` and poll the output file.
4. After each phase: verify with `cargo build && cargo test && cargo clippy` yourself,
   review the diff, then either continue the session (`-c`) with fixes or start the next phase.
5. Commit as the local user only (no Claude branding — see global CLAUDE.md rules).

### Prompting lessons for glm-5.2

- Give exact file paths in the Go repo to port from; it will read them.
- One phase per run; keep phases to a few thousand lines of output max.
- Always state acceptance criteria explicitly and tell it to run `cargo build`/`cargo test` itself.
- If a run stalls or produces broken code, continue the session with the compiler errors pasted in.

### Recurring toolsmith pass (token efficiency)

Regularly (after every 1–2 phases) launch a separate opencode agent whose ONLY job is to
review past session logs and improve tooling to save tokens:

```bash
opencode run -m ai/vercel-ent/zai/glm-5.2 --auto \
  --dir /Users/rajsingh/Documents/GitHub/rustscale \
  --title "toolsmith-$(date +%Y%m%d)" \
  "Read docs/toolsmith.md and follow it."
```

The standing instructions live in `docs/toolsmith.md`. Inputs it inspects:
- `opencode session list` + `opencode export <id>` for recent build sessions
- `opencode stats` for token/cost per session
Outputs it may produce:
- Helper scripts in `tools/` (e.g., a `tools/check.sh` that runs build+test+clippy and prints
  only failures — so build agents don't re-derive commands or dump full logs into context)
- Prompt-template improvements appended to `docs/prompt-notes.md` (patterns that caused
  retries, over-long outputs, redundant file reads)
- `.opencode/` config tweaks (custom commands/agents) if they'd cut repeated boilerplate
Review its diff before committing, like any other agent's work.

## Ephemeral tailnets for e2e tests

See `docs/tailnet-testing.md` (verified live). Local: source `.secrets/tailscale.env`
(gitignored OAuth creds) + `tools/tailnet/*.sh`. CI: GitHub OIDC/WIF, no secret —
same WIF client as tailgate. **The org client has only the `tailnets` scope, so you
must save the child `oauthClient` creds from every create response — they are the only
way to delete that tailnet.** Always clean up tailnets in test teardown.

## Roadmap (agreed with user, in order)

1–6. Core stack through TUN mode (phases 1–5 done through tsnet; TUN next).
7. **Packet filter** — enforce MapResponse filter rules (correctness gate; port wgengine/filter).
8. **FFI / libtailscale** — C ABI over tsnet + Python/Node/Swift/Kotlin bindings. The strategic
   differentiator vs Go (no runtime to embed). **Constraint that applies NOW: keep the tsnet
   public API C-representable** — no generics/lifetimes/async in the public surface that can't
   map to a C handle model; prefer opaque handles + plain data structs at the boundary.
9. **Mobile/constrained targets** — iOS NetworkExtension (<50MB), Android, OpenWrt/musl static;
   size profiling and feature-gated deps.
10. **Perf data plane** — UDP GSO/GRO, io_uring TUN+socket path, batched magicsock IO;
    iperf3 benchmark harness vs tailscaled in CI.
11. **Serve/Funnel + certs + MagicDNS** — ListenTLS/ListenFunnel, LE certs via control,
    in-netstack DNS resolver.
12. **SSH server, exit node/subnet routes, Taildrop.**
13. **DERP + peer relay server** in Rust (reuse frame codec).

## Reference sources (read-only)

- `/Users/rajsingh/Documents/GitHub/tailscale` — the Go implementation. Key dirs:
  - `tsnet/` — the embedding API we're replicating
  - `tailcfg/` — control protocol types (netmap, node, DERPMap)
  - `control/controlclient/`, `control/controlhttp/` — control plane client (Noise/ts2021)
  - `derp/`, `derp/derphttp/` — DERP relay protocol
  - `disco/` — NAT traversal discovery protocol
  - `wgengine/magicsock/` — the path selection engine (direct/DERP/peer-relay)
  - `net/udprelay/`, `wgengine/magicsock/relaymanager.go` — peer relay
  - `net/netcheck/` — STUN-based net probing
  - `ipn/ipnlocal/` — LocalBackend state machine
- `/Users/rajsingh/Documents/GitHub/tailscale-client-go-v2` — API client (for tailnet mgmt)

## Architecture (target)

Cargo workspace, crates mirroring the Go layout:

- `crates/tailcfg` — wire types (Node, NetMap, DERPMap, ts2021 messages), serde
- `crates/key` — node/machine/disco keys (curve25519/ed25519)
- `crates/disco` — disco message encode/decode + box crypto
- `crates/derp` — DERP client protocol over HTTP/TLS (frame codec, derphttp client)
- `crates/netcheck` — STUN probing, DERP latency, portmap detection
- `crates/controlclient` — ts2021 Noise control channel, map polling, register
- `crates/magicsock` — UDP socket mgmt, endpoint discovery, path selection (direct/DERP/peer relay)
- `crates/relayclient` — peer relay (UDP relay) client
- `crates/wg` — WireGuard data plane (use `boringtun` crate as the tunnel engine)
- `crates/netstack` — userspace TCP/IP (use `smoltcp`) for tsnet-style dialing/listening
- `crates/tsnet` — the public embedding API (Server::up, listen, dial)
- `crates/tun` (later) — real TUN device support for full client mode

## Build/verify

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```
