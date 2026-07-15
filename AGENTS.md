# RustScale agent guide

RustScale aims for Tailscale/tsnet compatibility while preserving or improving direct-path performance.

Keep changes scoped and preserve unrelated work, especially dirty worktrees. Use `tools/check.sh` for product changes, `tools/bench/check.sh` for benchmark-only changes, and `tools/agent/check.sh` for the agent harness. Do not claim compatibility or performance improvements without reproducible test or benchmark evidence.

The optional agent harness under `tools/agent/` creates isolated worktrees and records run metadata. Its provider and model names are intentionally visible and configurable through the documented environment variables. See `docs/agent-harness.md`.
