# RustScale agent guide

RustScale aims for Tailscale/tsnet compatibility while preserving or improving direct-path performance. AI assistance is optional project tooling; generated changes follow the same review, testing, licensing, and security requirements as every other contribution.

## Working rules

- Keep each change focused. Preserve unrelated edits and never delete or overwrite a dirty worktree as cleanup.
- Read the relevant crate and tests before editing. Use `docs/parity.md` for current compatibility status instead of relying on historical phase notes.
- Give implementation tasks a self-contained goal, relevant files and upstream references, constraints, and an explicit acceptance gate. Prefer one coherent task per run.
- Continue the same saved session when addressing review or compiler feedback instead of restarting broad exploration.
- Do not claim compatibility or performance improvements without reproducible test or benchmark evidence.
- Never place credentials, private repository locations, machine-specific paths, or generated session logs in tracked files.

## Validation gates

Use the narrowest gate that fully covers the change:

- `tools/check.sh` for product code and workspace-wide changes.
- `tools/check.sh <package>` when a change is isolated to one Rust package.
- `tools/bench/check.sh` for benchmark-harness-only changes.
- `tools/agent/check.sh` for agent harness or contributor-policy changes.

Run `git diff --check` as part of review. Cross-platform, packaging, coverage, fuzz, Pages, and interop behavior remains authoritative in GitHub Actions.

## Worktrees and agent runs

The optional harness under `tools/agent/` creates isolated `agent/<title>` worktrees and records resumable run metadata under the ignored `.agent-runs/` directory. Inspect `tools/worktree-status.sh` before starting or cleaning up work. Entries marked `DIRTY_UNCOMMITTED` or `AHEAD_UNMERGED` require manual review.

The normal lifecycle is:

1. Start one focused implementation run with `tools/agent/codex-task.sh`.
2. Use `--continue` for follow-up fixes in the same worktree and saved session.
3. Review with `tools/agent/agent-review.sh <title>`.
4. Commit reviewed changes in the worktree, then merge with `tools/agent/worktree-merge.sh <title>`.
5. If validation fails, preserve the worktree and report the next action rather than deleting it.

Use `tools/agent/pi-research.sh` for read-only Pi research. It exposes only Pi's read/search tools, enforces a deadline, refuses an initially dirty checkout, and rejects a result if the repository changes during the run. See `docs/agent-harness.md` for commands and configuration.

## Upstream reference

The canonical Go implementation is `github.com/tailscale/tailscale`, published as the `tailscale.com` module. `tools/go-find.sh` searches the pinned module version by default; set `TAILSCALE_GO_REPO` only when intentionally comparing a full local clone.

Useful upstream areas:

- `tsnet/` for the embedding API.
- `tailcfg/` for control protocol and netmap types.
- `control/controlclient/` and `control/controlhttp/` for the control-plane client.
- `derp/` and `derp/derphttp/` for relay framing and transport.
- `disco/`, `net/netcheck/`, and `wgengine/magicsock/` for discovery, probing, and path selection.
- `wgengine/router/`, `wgengine/tstun/`, and `net/tstun/` for routed and TUN operation.
- `ipn/ipnlocal/` and `ipn/localapi/` for backend state and the local API.

## Workspace map

The Cargo workspace mirrors upstream responsibilities. Core areas include `tailcfg`, `key`, `disco`, `derp`, `netcheck`, `controlclient`, `magicsock`, `wg`, `netstack`, `tsnet`, `tun`, `router`, `ipn`, `localclient`, `ssh`, and the `rustscaled` daemon. Keep wire behavior byte-compatible where required and keep public `tsnet`/FFI surfaces stable unless the task explicitly changes them.
