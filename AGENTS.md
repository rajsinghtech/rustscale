# RustScale agent rules

RustScale exists to reach Tailscale/tsnet product parity while preserving or improving direct-path performance. Coding work uses `gpt-5.6-terra`; OpenCode DeepSeek is research-only.

Worktrees belong to their assigned task. Preserve unrelated dirty changes, never delete or overwrite another task's worktree, and inspect dirty trees before acting. Coding agents do not commit. Use the task-specific quiet gate (`tools/check.sh`, or `tools/bench/check.sh` for benchmark-only work), not ad-hoc Cargo acceptance commands.

Direct-path benchmarks must keep identical CLI semantics, including `ping --until-direct`. Never claim performance without verified benchmark evidence.
