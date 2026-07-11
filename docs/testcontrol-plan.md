# testcontrol Plan — In-Memory Control Server + Integration Harness

## 1. The Go Feedback Loop

Go's integration testing has three layers that compose to catch interop bugs before deployment:

### Layer 1: `testcontrol.Server` (in-memory fake control plane)

A single-tailnet control server that implements Go's `http.Handler`. It serves:
- **`/key`** — Noise public key exchange (GET, returns machine key for legacy or JSON for v2).
- **`/ts2021`** — Noise IK handshake upgrade (POST → `101 Switching Protocols` via `controlhttpserver.AcceptHTTP`, then h2c over the Noise transport).
- **`/machine/register`** — Node registration with auth path simulation (RequireAuth, RequireAuthKey, RequireMachineAuth, per-node key expiry, key rotation with OldNodeKey, rate limiting).
- **`/machine/map`** — Streaming long-poll map response: 4-byte LE length-prefixed JSON frames, keepalive, PeersChanged/PeersRemoved delta support, suppressable auto responses + explicit AddRawMapResponse injection.
- **`/machine/set-dns`** — ACME DNS-01 challenge response validation.
- **`/c2n/`** — Node C2N (call-to-node) response routing via PingRequest payloads.
- **`/machine/tka/`** — Tailnet Lock init/finish/bootstrap/sync/sign.

The test API surface (methods on `Server` for orchestrators) includes: `AddFakeNode`, `SetNodeCapMap`, `SetExpireAllNodes`, `AddPingRequest`, `SendC2N`, `AddRawMapResponse`, `SetJailed`, `SetMasqueradeAddresses`, `SetSubnetRoutes`, `AddDNSRecords`, `SetGlobalAppCaps`, `CompleteAuth`, `CompleteDeviceApproval`, `AwaitNodeInMapRequest`, `InServeMap`, `AllNodes`, `Node`, `NumNodes`.

Key design properties:
- **In-process** — No network, no ports (uses `httptest.NewServer`), tests run at full speed.
- **No auth wall** — Tests control the auth flow. `CompleteAuth` unblocks `serveRegister` immediately.
- **Deterministic churn** — `SetExpireAllNodes`, `AddRawMapResponse` let tests force netmap events that would take hours to happen naturally (key expiry) or are hard to trigger (incremental PeersRemoved).
- **Constraint simulation** — `SetMasqueradeAddresses` simulates NAT by rewriting peer addresses in netmap; `SetJailed` tests client-side jailing.

### Layer 2: `integration.go` (binary harness)

`NewTestEnv` orchestrates everything in-process:
1. Starts a local **DERP server** + **STUN server** (via `derpserver.New` + `stuntest.ServeWithPacketListener`).
2. Wraps them into a `tailcfg.DERPMap` with `InsecureForTests: true`.
3. Starts a **LogCatcher** (fake logtail server) to capture log uploads.
4. Starts a **TrafficTrap** (HTTP proxy) to verify no traffic leaves localhost.
5. Builds `tailscaled` + `tailscale` binaries once, copies via hardlink/FD for each test.
6. `TestNode.StartDaemon()` execs `tailscaled` with env vars pointing everything at the local servers (`TS_LOG_TARGET`, `HTTP_PROXY`, `TS_DEBUG_PERMIT_HTTP_C2N`, `TS_PANIC_IF_HIT_MAIN_CONTROL`).
7. Tests orchestrate up/down/login/logout/ping/status via the `tailscale` CLI and `local.Client` API.

**Scenarios covered** (from `integration_test.go`): login flow (4 auth paths), auth key, force-reauth, interrupted auth, device approval, key expiry (node transitions through NeedsLogin on expiry and back to Running on re-enable), two-node setup with peer discovery, incremental `PeersRemoved` map delta, incremental `PeersChanged` AllowedIPs delta (VIP route test), C2N ping request, logout-removes-all-peers, no-control-conn-when-down, IP persistence across restart, NAT masquerade pings, client-side jailing.

### Layer 3: natlab + vnet (network simulation)

- **natlab** (`tstest/natlab`): Pure in-memory UDP packet simulation. `Network` models a subnet, `Machine` has interfaces + routing table, `PacketHandler` interface for firewall/NAT behaviors (HandleIn, HandleOut, HandleForward). Used for magicsock traversal logic testing without real sockets.
- **vnet** (`tstest/natlab/vnet`): Full L3 network simulator using gVisor netstack, supporting real tailscaled in QEMU VMs. NAT types: EasyNAT (endpoint-independent mapping, address/port-dependent filtering), EasyAFNAT (address-dependent filtering), HardNAT (address/port-dependent mapping+filtering), One2OneNAT, with optional NAT-PMP/PCP.
- **nat_test.go**: 8x8 grid of NAT-type pairs; boots VMs behind each NAT, pings across them, classifies result as derp/local/direct. Caches results in `.cache` files.

**Why this catches bugs pre-deploy**: The same code paths (control client, magicsock, DERP client, netstack) run in these tests as in production — but against a fake control server that can force any state transition. Bugs that only surface with specific netmap churn (key expiry recovery, incremental peer removal) are caught before they hit real tailnets.

---

## 2. Gap Analysis: Which GCP Interop Bugs Would a Fake Control Server Have Caught

From `docs/gcp-interop-bugs.md`:

| Bug | Would testcontrol catch? | Why |
|-----|------------------------|-----|
| **Bug 1: HomeDERP not in netmap** | **YES** | testcontrol+derpserver combined test verifies DERP connect → server registers → HomeDERP appears in netmap → peer sees Relay. The exact data path is exercised locally. |
| **Bug 2: fetch_map false error** | **YES** | `fetch_map` with `OmitPeers=true` → testcontrol responds with empty body → client should not report error. A unit test with the fake control server would have caught this immediately. |
| **Bug 3: MagicDNS bind failure** | **PARTIAL** | Would catch the crash/panic but not the platform-specific `EADDRNOTAVAIL` (depends on OS config). A mock-interface test would be needed. |
| **Bug 4: No periodic endpoint updates** | **YES** | Integration test with 2-node setup and `AwaitNodeInMapRequest` + checking that endpoint updates are received periodically. Control server can log received MapRequests and verify expected cadence. |
| **Bug 5: HomeDERP not communicated** | **YES** | Same as Bug 1. The DERP→control→peer relay chain is fully exercisable in a 2-node test with local DERP. |
| **Bug 6: DERP keepalive missing** | **YES** | Run node for 70s, check that DERP PING/PONG frames are exchanged (visible via control's InServeMap staying alive). |
| **Bug 7: NetInfo missing from Hostinfo** | **YES** | Control server logs incoming MapRequest.Hostinfo.NetInfo. Test verifies it's populated and contains PreferredDERP. |
| **Bug 8: Streaming map doesn't reconnect** | **YES** | Stop the control server, restart it, verify the streaming poll re-establishes (AwaitNodeInMapRequest succeeds afterward). |
| **Bug 9: No STUN endpoints** | **PARTIAL** | DERP+STUN server combo (as in RunDERPAndSTUN) tests the full STUN→netcheck pipeline. Would catch missing STUN endpoints in advertised list. |
| **Bug 10: 127.0.0.1 in endpoints** | **YES** | After map poll, inspect `Node.Endpoints` on the testcontrol. Assert no loopback addresses. |

**Conclusion**: 8/10 bugs would have been caught locally before GCP. The two partial misses (MagicDNS bind failure, STUN endpoint completeness in certain environments) still depend on real networking or OS config, but the core protocol/connectivity bugs are all testable.

---

## 3. Phased Plan for rustscale

### Phase A: `crates/testcontrol` — Minimal Fake Control Server

**Goal**: Implement an in-process `testcontrol::Server` that rustscale tsnet nodes can register against, get a netmap, and receive streaming map updates. Must speak the ts2021 Noise protocol on the server side.

#### Option 1: Pure Rust implementation (RECOMMENDED)

**Implementation sketch**:
- `crates/testcontrol/` with `Server` struct hosting an HTTP + Noise-upgrade listener.
- Reuse `crates/controlclient/src/controlbase.rs` in **server mode**: implement `controlbase::server_handshake(conn, private_key, initiation_bytes)` — the Noise IK server side. This is the mirror of the existing client handshake. The Noise math (curve25519, ChaChaPoly, BLAKE2s) is already implemented; we need the server-side state machine (receive initiation, compute shared secret, send response).
- `controlhttp::serve_noise_upgrade()`: accept HTTP upgrade request, extract base64 init header, do server handshake, then upgrade to h2c (using the `h2` crate's server API).
- Serve routes: `/key` (GET), `/ts2021` (upgrade), over h2c: `/machine/register`, `/machine/map`.
- Map response framing: 4-byte LE length-prefixed JSON (same as Go).
- Streaming long-poll with per-node update channels (like Go's `updates map[NodeID]chan updateType`).
- Test surface API: `AddNode`, `SetCapMap`, `SetExpireAllNodes`, `AddPingRequest`, `SetDNS`, `AddRawMapResponse`, `AwaitNodeInMapRequest`.

**Alternatives considered**: Serving `/key` as plain HTTP (no Noise) for the key-fetch part; the Noise upgrade path should match production so both client and server paths are exercised.

**Tradeoffs vs Option 2 below**:
- (+) Rust end-to-end: no foreign binary, no build dependency on Go, no cross-compile pain.
- (+) Full control: can add test-only hooks anywhere (inspect server state, force netmap deltas, log every MapRequest).
- (+) Works on any platform rustscale supports (macOS CI, no Go toolchain needed).
- (-) Must implement Noise server-side handshake (mirror of existing client handshake — ~250 lines of new crypto code).
- (-) Must implement h2c server lift (we already have the `h2` crate as a dependency).
  - Estimated: the `h2` crate's server API handles h2c upgrade, but we need to wrap the Noise `Conn` (which implements `AsyncRead+AsyncWrite`) as a `h2` transport.

#### Option 2: Embed the Go testcontrol binary

**Implementation sketch**:
- Precompile Go `testcontrol` into a standalone HTTP server binary (it's already a `http.Handler`, so wrap with a `main()` that listens on a random port).
- Rust test code spawns this binary as a child process, reads the port number from stdout.
- Point rustscale's `Server::up` at `http://127.0.0.1:<port>` via the control URL.

**Tradeoffs**:
- (+) Zero Rust implementation work — the Go testcontrol is battle-tested.
- (+) Full Go testcontrol capability surface available immediately, including DERP map injection, TKA, C2N responses.
- (-) **Massive build-time dependency**: requires Go toolchain to compile the test binary. Cross-compilation for CI runners (macOS ARM, Linux x86_64) means `go build` must work or we ship prebuilt binaries.
- (-) **Foreign process management**: test code must spawn, wait for port, monitor process health, handle cleanup (zombie processes if test panics). This is fragile.
- (-) **No introspection from Rust**: the Go process is an opaque HTTP server. You can't add Rust-native test hooks (e.g., `SetExpireAllNodes` becomes HTTP API calls, which is fine, but you can't inspect Go-internal state from the Rust test harness).
- (-) **No Rust wire path testing**: The Rust Noise implementation (controlbase) would not be exercised — the Go testcontrol speaks Go's Noise handshake, not Rust's. This defeats the purpose of testing the Rust protocol implementation.
- (+) Could work as a **transitional** approach: embed Go binary for early testing while Rust testcontrol is built.

**Recommendation**: Start with Option 1 (Pure Rust). The Rust controlbase already has the client handshake; the server handshake is the mirror. The `h2` server API is already a workspace dependency. If timeline pressure demands it, Option 2 is a fallback (compile the Go binary once and check it in to a test fixtures directory, or build it in CI).

**Acceptance criteria**:
- `cargo test -p rustscale-testcontrol` passes.
- A single tsnet `Server` can register against the testcontrol, receive a netmap, and reach `Running` state.
- Test verifies: register request/response, map poll with streaming keepalive.
- No external network access needed.

**Estimated size**: ~1500 lines of Rust. 1 opencode phase.

---

### Phase B: Integration Test Crate

**Goal**: Write integration tests that boot two tsnet::Server instances against the testcontrol, verifying end-to-end flows.

**Implementation**:
- `crates/testcontrol/tests/integration.rs` (or a separate `crates/integration-test/`).
- `TestEnv` struct: owns `testcontrol::Server`, DERP server instance, two tsnet `Server`s.
- DERP server: use a local `derper` binary or an in-process DERP stand-in.
- Scenarios:

1. **Basic login**: One node starts, registers, gets IP, reaches Running. Assert `status().BackendState == "Running"`.
2. **Two nodes discover each other**: N1 registers, N2 registers. N1 sees N2 as a peer via netmap. Ping via DERP succeeds.
3. **Key expiry**: Force `SetExpireAllNodes(true)`. Node transitions to NeedsLogin. `SetExpireAllNodes(false)`. Node recovers to Running.
4. **Incremental PeersRemoved**: N1 sees N2. Inject `AddRawMapResponse` with `PeersRemoved: [N2.ID]`. N1's peer list drops to 0.
5. **Capability change**: Set `SetNodeCapMap` to add/remove a capability. Node's `debug control-knobs` or equivalent shows the change.
6. **DNS config push**: Set `DNSConfig` on control. Node's DNS responder observes the update.
7. **DERP-only path**: Force DERP (disable direct paths via `MagicsockConfig::disable_direct_paths`). Ping between two nodes succeeds via relay.
8. **Ping request from control**: `AddPingRequest` sends a URL. Node fetches it.

**Test infrastructure**:
- `RunDERPAndSTUN` helper (in-process DERP server + STUN listener on random ports; wraps into `DERPMap` with `InsecureForTests`).
- `LogCatcher` (logtail HTTP server to capture node logs).
- Node process management: spawn tsnet Server in a background tokio task, wait for Running via poll.

**Acceptance criteria**:
- All 8 scenarios pass with `cargo test -p rustscale-testcontrol -- --test integration`.
- Each runs in <30s.
- Tests can be repeated (no state leakage).

**Estimated size**: ~2000 lines of Rust. 1 opencode phase.

---

### Phase C: Local DERP Server

**Goal**: Run a real DERP server in-process so integration tests exercise actual DERP relay.

**Approach**: Two options, implement both:

1. **Rust-native DERP server** (`crates/derp/src/server.rs`): Port the Go `derp/derpserver` in-process API. A `DerpServer` that accepts TCP/TLS connections and speaks the DERP protocol (ClientInfo/ServerInfo, packets relay, PING/PONG keepalive, rate-limiting). This is needed longer-term anyway for the peer relay server (roadmap item).
2. **Pinned `derper` binary**: For early testing, download a prebuilt Go `derper` binary and spawn it as a child process on a random port. This is a quick path to getting a real DERP server.

**Acceptance criteria**:
- DERP server boots on localhost, accepts clients, relays packets between them.
- `tailcfg.DERPMap` points at local DERP and clients connect to it.
- Two nodes can exchange packets through the local DERP relay.

**Estimated size**: ~800 lines for Rust-native server (protocol framing is already defined in `crates/derp/src/protocol.rs`). 1 opencode phase.

---

### Phase D: UDP Impairment Shim for NAT/Traversal Tests

**Goal**: Simulate NAT behaviors, packet loss, latency, and reordering around magicsock's UDP socket without real networks (natlab-style).

**Approach**:
- A `UdpImpairer` wrapping a UDP socket that applies:
  - **Drop**: configurable drop rate for inbound/outbound packets.
  - **Latency**: fixed or jittered delay per packet (via a delay queue).
  - **NAT**: rewrite source IP:port for outbound, filter inbound (full-cone vs symmetric).
  - **Reorder**: optional random reordering within a window (to test disco race handling).
- Implemented as a `tokio::io::AsyncRead/Write` wrapper around `tokio::net::UdpSocket` with a configurable `ImpairmentConfig`.
- Integration with `MagicsockConfig::udp_socket` — inject the impaired socket instead of a real one.

**Why not full natlab?** The natlab packet-switched simulator is powerful but duplicates what the Go codebase does for testing magicsock traversal. For rustscale, shimming at the UDP socket level is simpler, exercises the real magicsock code, and gets 80% of the value. A full natlab in Rust could be a follow-up.

**Acceptance criteria**:
- Tests can configure 10% packet drop, verify retransmission works.
- Tests can configure symmetric NAT, verify DERP fallback.
- Tests run without network interfaces or root.

**Estimated size**: ~400 lines for the shim. 1/2 opencode phase (can be inlined into Phase B or Phase D).

---

## Summary: Phase Plan

| Phase | Crate | Description | Lines | Depends On |
|-------|-------|-------------|-------|------------|
| A | `crates/testcontrol` | Fake control server (Noise server handshake, h2c, register, map poll) | ~1500 | None (reuses existing controlbase) |
| B | `crates/testcontrol/tests/` | Integration tests (8 scenarios) | ~2000 | Phase A + Phase C |
| C | `crates/derp` (add server) | In-process DERP relay | ~800 | None (protocol.rs already exists) |
| D | `crates/magicsock` (add shim) | UDP impairment wrapper for traversal tests | ~400 | Phase B |

**Total new code**: ~4700 lines across 4 phases.
