# Phase: magicsock connectivity (disco heartbeat + UDP lifetime probing + PMTUD)

Closes verified-audit P0 gaps #5, #6, #7 (ranks 7, 8, 9).

## Goal

Port three missing magicsock connectivity mechanisms from Go's
`wgengine/magicsock/endpoint.go`:

1. **Disco heartbeat** — a per-peer 3s timer that sends disco Ping messages
   to the currently-trusted best UDP address, keeping NAT pinholes open and
   confirming path viability. Demand-driven: armed by outbound TX activity,
   self-rescheduling, stops after 45s of session idle.
2. **UDP lifetime probing** — cliff-interval probing at 10s/30s/60s of
   inactivity to detect NAT pinhole closure. On probe timeout, demote the
   direct path (clear bestAddr) forcing DERP fallback.
3. **PMTUD (peer MTU discovery)** — send MTU-probe disco pings at multiple
   sizes to discover the path MTU. Disabled by default (gated by control
   flag / envknob), same as Go.

## Go source reference

All in `/Users/rajsingh/Documents/GitHub/tailscale/wgengine/magicsock/`:

### Disco heartbeat
- `endpoint.go:829-895` — `heartbeat()` timer callback
- `endpoint.go:974-979` — `noteTxActivityExtTriggerLocked()` arms timer
- `endpoint.go:1308-1372` — `startDiscoPingLocked()` with `pingHeartbeat`
- `magicsock.go:4032` — `heartbeatInterval = 3 * time.Second`
- `magicsock.go:4016` — `sessionActiveTimeout = 45 * time.Second`
- `magicsock.go:4036` — `trustUDPAddrDuration = 6500ms`
- `magicsock.go:4052` — `pingTimeoutDuration = 5 * time.Second`
- `endpoint.go:898-902` — `setHeartbeatDisabled()` (silent disco control)

### UDP lifetime probing
- `endpoint.go:178-204` — `probeUDPLifetime` struct
- `endpoint.go:250-260` — `ProbeUDPLifetimeConfig` struct
- `endpoint.go:269-276` — `defaultProbeUDPLifetimeConfig` (cliffs [10s,30s,60s], cycle 24h)
- `endpoint.go:706-742` — `maybeProbeUDPLifetimeLocked()` (gating)
- `endpoint.go:778-824` — `heartbeatForLifetime()` (cliff probe sender)
- `endpoint.go:1166-1194` — `probeUDPLifetimeCliffDoneLocked()` (pong/timeout)
- `endpoint.go:1196-1211` — `discoPingTimeout()` (demotes bestAddr)
- `endpoint.go:164` — `udpLifetimeProbeCliffSlack = 2s`

### PMTUD
- `peermtu.go:38-57` — `ShouldPMTUD()` (defaults false)
- `peermtu.go:86-118` — `UpdatePMTUD()` (sets DF socket option)
- `endpoint.go:40-52` — `mtuProbePingSizesV4/V6` from `WireMTUsToProbe`
- `endpoint.go:1308-1372` — `startDiscoPingLocked` PMTUD burst
- `endpoint.go:1729-1822` — `handlePongConnLocked` records wireMTU
- `endpoint.go:1691-1704` — `pingSizeToPktLen()`
- `net/tstun/mtu.go:85-92` — `WireMTUsToProbe = [1280,1320,1400,1500,8000,9000]`

### Disco ping purpose enum
- `pingDiscovery = 0`, `pingHeartbeat = 1`, `pingCLI = 2`, `pingHeartbeatForUDPLifetime = 3`

## Current Rust state

- `crates/magicsock/src/endpoint.rs` (333 lines) — has `Endpoint` struct with
  `best_addr: Option<(SocketAddr, Instant)>`, `pending_pings`, `candidates`,
  `call_me_maybe_sent`. No heartbeat timer, no UDP lifetime, no PMTUD.
- `crates/magicsock/src/lib.rs` (1678 lines) — `Inner` has `endpoints:
  HashMap<NodePublic, Arc<Mutex<Endpoint>>>`, disco ping send in
  `send_disco_ping`. Pings fire on `set_netmap` and CallMeMaybe only.
- `crates/magicsock/src/disco_io.rs` (89 lines) — disco message
  encode/decode + ping/pong handling.
- No `tokio::time::interval` for disco pings anywhere.

## Implementation plan

### 1. Disco heartbeat
- Add `heart_beat_handle: Option<tokio::time::Sleep>` or
  `Option<JoinHandle>` to `Endpoint` (or a separate heartbeat task per peer).
- Add `last_send_ext: Option<Instant>` to track outbound TX activity.
- Add `heartbeat_disabled: bool` field (control flag, default false).
- On any outbound WG data packet to a peer, call
  `note_tx_activity()` which arms the heartbeat timer if not already running.
- Heartbeat timer fires every 3s: sends a `disco::Ping` with purpose
  `pingHeartbeat` to the best_addr. If `last_send_ext` is older than 45s,
  stop the timer (session idle).
- Pong timeout (5s) on heartbeat ping to untrusted bestAddr → clear bestAddr.
- On `set_netmap`, update `heartbeat_disabled` from node flags.

### 2. UDP lifetime probing
- Add `ProbeUDPLifetime` state to `Endpoint`: `cliffs: [Duration; 3]`,
  `current_cliff: usize`, `cycle_active: bool`, `cycle_started_at:
  Option<Instant>`, `probe_timer: Option<JoinHandle>`.
- After heartbeat ends (session idle 45s), call
  `maybe_probe_udp_lifetime()` which starts a cycle if:
  - `best_addr` is valid and trusted
  - peer has disco key
  - lower disco key probes (lexicographic comparison to avoid duplicate work)
  - no cycle in last 24h
- Schedule first cliff probe at `10s - 2s = 8s` of inactivity.
- On pong: advance to next cliff (30s - 2s, then 60s - 2s).
- On timeout: clear bestAddr (demote direct path), reset cycle.
- Add `pingHeartbeatForUDPLifetime` to the disco ping purpose enum.

### 3. PMTUD (structure only, disabled by default)
- Add `peer_mtu_enabled: Arc<AtomicBool>` to `Magicsock`/`Inner`.
- Add `wire_mtu` field to the best-addr tracking (the discovered path MTU).
- When PMTUD is enabled and a discovery ping is sent, replace single ping
  with a burst of pings at sizes from `WireMTUsToProbe`.
- On pong, record the largest succeeding size as `wireMTU`.
- In `betterAddr` comparison, prefer larger `wireMTU` on ties.
- **Keep it disabled by default** (matching Go). The control flag wiring
  can be a simple `Arc<AtomicBool>` settable via a method.
- Socket-level DF bit setting is platform-specific and can be stubbed
  (return Ok) on non-unix — the probe mechanism itself works without DF
  by just checking which sizes get pongs.

## Acceptance criteria

- `tools/check.sh` passes (build + test + clippy -D warnings + fmt).
- New unit tests for:
  - Heartbeat timer arming on TX activity
  - Heartbeat self-cancellation after 45s idle
  - UDP lifetime cliff scheduling (10s, 30s, 60s)
  - UDP lifetime probe timeout → bestAddr demotion
  - PMTUD enabled flag → multi-size ping burst
  - PMTUD disabled by default
- Existing magicsock tests still pass.

## Constraints

- Do NOT fetch docs.rs or explore `~/.cargo/registry/`.
- Before reading Go sources, check `docs/porting-notes.md` for distilled facts.
- Use `tools/check.sh --check rustscale-magicsock` during iteration (fast
  type-check). Use `tools/check.sh rustscale-magicsock` for full build.
  Use `tools/check.sh` (workspace) only at the end.
- Add `#![allow(non_snake_case)]` if mirroring Go field names.
- In your OWN files, NEVER re-read the whole file — use `grep -n` or
  `tools/where.sh` to find line numbers, read narrow windows.
