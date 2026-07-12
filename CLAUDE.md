# rustscale

A Rust implementation of Tailscale's client stack — the equivalent of Go's `tsnet` package —
supporting direct (UDP hole-punched) connections, DERP relay, and peer relay, with the long-term
goal of a full TUN-mode client.

## Development model: ALL implementation work goes through opencode agents

Claude Code acts as the **orchestrator only**. All code in this repo is written by opencode
agents running `vercel-ent/zai/glm-5.2`. Do not write implementation code directly with
Edit/Write except for docs, specs, and this file.

### How to call opencode

**Use the server harness — NOT `opencode run`.** `opencode run` is synchronous with no
timeout; when the model stalls it blocks forever and leaves zombie processes. The harness
at `tools/agent/opencode-task.sh` drives the persistent server HTTP API instead:
async prompt admission, allow-all permission ruleset (unattended), hard watchdog
deadline with abort, result harvesting.

```bash
tools/agent/opencode-task.sh "phase-N-title" "<detailed task prompt>" [deadline_secs=2400]
tools/agent/opencode-task.sh --continue <sessionID> "fix ..." [deadline_secs]
```

- Run it with Bash `run_in_background: true`; the final assistant message lands on stdout.
- Exit 3 = watchdog aborted at the deadline (prints the sessionID — inspect partial work
  on disk, then `--continue` that session).
- The server is auto-started on 127.0.0.1:4096 if not running (`/tmp/opencode-serve.log`).
- Model default: `vercel-ent/zai/glm-5.2` (override with OPENCODE_PROVIDER/OPENCODE_MODEL).
- Under the hood: `POST /session?directory=...` (with `permission:[{permission:"*",pattern:"*",action:"allow"}]`),
  `POST /session/:id/prompt_async` (204, non-blocking), poll `/session/status` +
  `/session/:id/message`, `POST /session/:id/abort` on deadline.

Session management (inspection/debugging):
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
opencode run -m vercel-ent/zai/glm-5.2 --auto \
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

1–8 done: core stack, tsnet, TUN, packet filter, FFI, perf (beats tailscaled:
p50 ~170us vs 257us, throughput 465–838 vs 384 Mbps, localhost direct).

Feature-port order (user-specified 2026-07-09):
1. **MagicDNS resolver + LE certs via control** — unlocks real listen_tls; required for Funnel/Serve.
2. **WhoIs (peer identity)** — netmap lookup by IP; critical for auth-aware services.
3. **Network monitor (netmon)** — re-STUN/endpoint refresh/DERP reconnect on network transitions.
4. **Port mapping (NAT-PMP/PCP/UPnP)** — done: `crates/portmapper` with Client facade (probe, create/renew, cache), PMP/PCP byte-exact packet codec, UPnP SSDP+SOAP, fake IGD tests; magicsock publishes portmap endpoint best-effort alongside local/STUN endpoints.
5. **Exit node support** — route all traffic via exit node.
6. **Funnel + ServeConfig** — public exposure (443/8443/10000).
7. **Health tracking** — production monitoring UX.
8. **SOCKS5 proxy** — Docker/k8s sidecar pattern.
9. **LocalAPI** — CLI tooling integration.
10. **Tailscale SSH** — large.
Then: mobile/constrained targets, Linux perf (GSO/GRO, io_uring via CI), Taildrop,
DERP+peer relay server. Standing constraint: tsnet public API stays C-representable.

**Full tiered gap inventory: `docs/parity.md`** (Tier 1 core compat → Tier 5 server-side).
Update its status column as phases land; agents should consult it for Go source paths.
Items the execution order above doesn't cover yet (split DNS, Tailscale Services/
ListenService, multi-profile, netmap disk cache, peer MTU, DNS cache/fallback,
CapturePcap, captive portal wiring, etc.) get scheduled from that file after port-10.

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
- `crates/portmapper` — NAT-PMP/PCP/UPnP port mapping client (gateway discovery, probe, create/renew, cache)
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
