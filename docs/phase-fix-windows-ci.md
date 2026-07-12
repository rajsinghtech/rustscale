# Fix phase: make Windows CI genuinely green (then blocking)

The Windows-port phase landed and `cargo check --target x86_64-pc-windows-msvc`
now passes, but the CI "Check (windows)" job fails for two avoidable reasons —
NOT a code portability problem:

1. **Workflow bug**: the `Test (windows-meaningful crates)` step in
   `.github/workflows/ci.yml` is written with bash `\` line-continuations, but
   the Windows runner uses PowerShell, which parses the continued
   `-p rustscale-key ...` line as a separate command → "The term '-p' is not
   recognized". The tests themselves all PASS (0 failed) before this parse
   error. Fix: make the step shell-portable — either put the whole
   `cargo test -p ... -p ...` on ONE line, or add `shell: bash` to that step
   (bash is available on GitHub windows runners). Prefer `shell: bash` for
   readability; apply the same to the plain `Check (windows)` step if it has
   the same latent issue.

2. **tsnet unix-only warnings**: `crates/tsnet/src/lib.rs` emits 8 warnings on
   Windows (unix-only fns never used + unused vars) that will break the leg
   once it enforces `-D warnings`:
   - `apply_tun_routes` (line ~3902), `apply_accepted_subnet_routes` (~3941),
     `apply_exit_node_routes` (~3982), `run_cmd` (~4039) — "never used" on
     Windows (they're unix route helpers)
   - unused vars `monitor` (~1150), `tun` (~1167) on the non-unix path
   - an `unreachable_code` warning (~1191)
   cfg-gate these unix-only helpers/branches with `#[cfg(unix)]` (or the
   appropriate target_os set they already use elsewhere) so Windows neither
   compiles them nor warns. Match the repo's existing cfg-gating pattern
   (see crates/netmon, crates/netns after the recent sweeps). Do NOT delete
   them or change unix behavior.

3. Once 1+2 are done and the Windows job passes cleanly: make the Windows test
   step run under warnings-as-errors too (so it stays honest), and REMOVE the
   `continue-on-error` from the Windows legs (Check (windows) matrix leg and the
   x86_64-pc-windows-msvc cross-check) so they become blocking and count in
   alls-green. If any residual warning/error remains that you cannot fix
   cleanly in this phase, STOP: leave continue-on-error in place, document the
   exact remaining item in docs/parity.md, and say so — do not force it green
   by suppressing real problems.

## Verification (you cannot run the Windows runner locally)
- `cargo check --workspace --target x86_64-pc-windows-msvc` — must pass (add the
  target via rustup; `cargo check` type-checks without linking from macOS).
- `cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings`
  — must be clean (this reproduces the warnings-as-errors the CI leg will enforce).
- No regressions: `cargo build/test/clippy --workspace` native + `cargo clippy
  --workspace --all-targets --target x86_64-unknown-linux-musl -- -D warnings`.
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`.
- Update docs/parity.md "Windows port" section to reflect green/blocking status.
