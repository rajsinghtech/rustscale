# macOS Parity + Build Pipeline Implementation Plan

> **For agentic workers:** Execution model is repo-specific: Claude Code orchestrates; every
> task is executed by a Codex agent via `tools/agent/codex-task.sh` (see CLAUDE.md).
> OpenCode is reserved for DeepSeek research, review, docs, and toolsmith passes. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the macOS-specific parity gaps (P1/P2 from the 2026-07-11 gap inventory) and add
a Tailscale-style release/build pipeline.

**Architecture:** Each phase is one Codex agent run in an isolated worktree
(`tools/agent/codex-task.sh "phase-NN-title" "<prompt>"`), verified with
`cargo build && cargo test && cargo clippy` + diff review, then merged via
`tools/agent/worktree-merge.sh`. Go sources under `/Users/rajsingh/Documents/GitHub/tailscale`
are the porting references.

**Tech Stack:** Rust workspace, libc for darwin syscalls, existing crates (dns, netmon, tsnet, ffi).

## Global Constraints

- All implementation code written by Codex agents, never directly by the orchestrator.
- tsnet/ffi public API stays C-representable.
- Acceptance per phase: `cargo build --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`.
- Commits by local user only, no AI branding.
- Update `docs/parity.md` status column as each phase lands.

---

### Phase 32: macOS DNS OS configurator

**Port:** `net/dns/manager_darwin.go` (198 lines) — the tailscaled-on-macOS configurator that
writes `/etc/resolver/$SUFFIX` files pointing MagicDNS suffixes at 100.100.100.100.

**Files:** extend `crates/dns` with `os_darwin.rs` (darwinConfigurator: SetDNS/Close/
SupportsSplitDNS, resolver-file header marker for safe cleanup, /etc/resolv.conf comparison to
avoid clobbering); an `OsConfigurator` trait in `crates/dns` with a no-op fallback for other
platforms; wire into tsnet TUN mode behind an opt-in builder flag (writing /etc/resolver
requires root).

**Tests:** resolver-file content generation, cleanup-only-our-files (header marker), no-op on
non-darwin — all against a temp dir override of `resolverDir` (the Go code has this seam).

### Phase 33: safesocket crate

**Port:** `safesocket/safesocket_darwin.go` (361 lines) + the generic unix-socket path from
`safesocket/`. New `crates/safesocket`: unix socket listener/dialer with darwin sameuserproof
fallback (localhost TCP port + token file in shared dir, `initSameUserProofToken` semantics,
port+token parse from filename `sameuserproof-$PORT-$TOKEN` macsys variant and file-content
macos variant). Needed for the CLI↔daemon split in Phase 36.

### Phase 34: routetable crate

**Port:** `net/routetable/routetable_bsd.go` (293 lines) + `routetable_darwin.go` +
`routetable_bsdconst.go`. New `crates/routetable`: fetch RIB via
`sysctl(CTL_NET, AF_ROUTE, 0, 0, NET_RT_DUMP2/NET_RT_DUMP, 0)`, parse rt_msghdr + sockaddrs into
RouteEntry {family, type, dst prefix, gateway, iface, flags}. Route *manipulation* for exit-node
split routing stays in `crates/tun` (already does /1 splits); this crate is read/enumerate, used
by diagnostics and Phase 37.

### Phase 35: tcpinfo + breaktcp (darwin) — small, deepseek tier

**Port:** `net/tcpinfo/tcpinfo_darwin.go` (33 lines: RTT via getsockopt
`TCP_CONNECTION_INFO`) and `ipn/ipnlocal/breaktcp_darwin.go` (30 lines: scan fds 0..1000,
getsockopt TCP_CONNECTION_INFO success ⇒ close fd). Small crate `crates/tcpinfo` +
`break_tcp_conns()` helper in tsnet routing (called on exit-node switch).

### Phase 36: rustscaled daemon + launchd install

**Port:** `cmd/tailscaled/install_darwin.go` (199 lines). New `crates/rustscaled` binary:
runs tsnet in TUN mode, LocalAPI over the Phase 33 safesocket; subcommands
`install-system-daemon` / `uninstall-system-daemon` writing
`/Library/LaunchDaemons/com.rustscale.rustscaled.plist`, copying the binary to
`/usr/local/bin/rustscaled`, `launchctl load/start` (and stop/unload/remove on uninstall,
tolerating partial state exactly as the Go code does). Blocked by Phase 33.

### Phase 37: netmon darwin parity

**Port:** `net/netmon/defaultroute_darwin.go` (122 lines: default route interface index via
AF_ROUTE RTM_GET round-trip, excluding utun/tailscale interface) and
`net/netmon/interfaces_darwin.go` (111 lines). Extend `crates/netmon/src/os_darwin.rs` +
`interfaces.rs`: DefaultRouteInterfaceIndex, utun detection, ignore-list parity.

### Phase 38: release/build pipeline

**Input:** `docs/build-pipeline-research.md` (research agent output). Add what's missing vs
existing ci.yml/e2e.yml/bench.yml:
- `.github/workflows/release.yml`: on tag `v*` — build macOS aarch64+x86_64 → `lipo` universal
  binary; Linux x86_64/aarch64 gnu + musl (static) via cross; FFI cdylib+staticlib + generated
  header (`tools/gen-header.sh`); SHA256SUMS; upload to GitHub Release.
- `.github/workflows/audit.yml`: cargo-audit + cargo-deny (schedule + on Cargo.lock change).
- Version stamping: workspace `build.rs` pattern embedding `git describe --long` into
  binaries/FFI (`ts_version()` already exists in ffi — wire real value).

### Deferred (P3)

hostinfo darwin extras, quarantine xattr (post-Taildrop), peermtu (no-op in Go too),
sockstats. Schedule from `docs/parity.md` later.

## Execution tracking

- [ ] Phase 32 agent run + verify + merge
- [ ] Phase 33 agent run + verify + merge
- [ ] Phase 34 agent run + verify + merge
- [ ] Phase 35 agent run + verify + merge
- [ ] Phase 36 agent run + verify + merge (after 33)
- [ ] Phase 37 agent run + verify + merge
- [ ] Phase 38 agent run + verify + merge (after research doc)
- [ ] parity.md updated per phase; final commit
