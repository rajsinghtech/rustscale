# Peer Relay — Server & Client Completeness

Port both sides of Tailscale peer relay:
- **Server**: `net/udprelay/` — UDP relay server that allocates VNIs, runs the 3-way disco bind handshake, and forwards Geneve-encapsulated data between two clients.
- **Client**: `wgengine/magicsock/relaymanager.go` — relay server discovery, endpoint allocation (via DERP), bind handshake, ping/pong probing for latency, and path scoring.

rustscale already has a **partial client** (`crates/magicsock/src/relay.rs` + disco message types). The server is absent.

## 1. Protocol Description

### 1.1 Overview

Peer relay lets two tailnet nodes communicate through a third node acting as a UDP relay (no DERP server involvement post-allocation). The relay server opens a single UDP socket, allocates a VNI (24-bit Virtual Network Identifier from the Geneve header) per client pair, runs a 3-way disco handshake to verify clients know the shared secret, then forwards Geneve-encapsulated WireGuard (or disco) packets between the two bound endpoints.

### 1.2 Allocation via DERP (not peerAPI)

A client discovers relay-capable peers from the netmap: nodes with `PeerCapabilityRelayTarget` set on them by the ACL and `Hostinfo.PeerRelay: true` in their Hostinfo. These become `candidatePeerRelay` entries in magicsock's `relayManager`.

The allocation request is a `disco.AllocateUDPRelayEndpointRequest` message (type 0x08), sent **over DERP** to the relay server node's home DERP region. The relay server node's magicsock receives it, authenticates the disco sender, and routes it over an eventbus to the local `relayserver` extension (Go: `feature/relayserver/relayserver.go`), which calls `AllocateEndpoint()` on the `udprelay.Server`.

The response (`AllocateUDPRelayEndpointResponse`, type 0x09) flows back over DERP to the requesting client, carrying the `ServerEndpoint` (ServerDisco, ClientDisco, LamportID, VNI, AddrPorts, bind lifetimes).

**Key fact: the allocation request does NOT use peerAPI (`/v0/relay/endpoint`).** There is no such handler in Go's peerAPI. The allocation goes over the existing DERP disco message path. The Go codebase does have a `localapi "debug-peer-relay-sessions"` handler for status inspection, but that's a debug-only endpoint.

### 1.3 3-Way Bind Handshake

After receiving the `ServerEndpoint`, the requesting client initiates the bind handshake directly over UDP to one of the server's advertised `AddrPorts`.

```
Client A                    Relay Server                  Client B
   |                            |                            |
   |--- BindUDPRelayEndpoint -->|                            |
   |     (VNI, gen, RemoteKey)  |                            |
   |                            |                            |
   |<-- BindUDPRelayEndpointChal|                            |
   |    (VNI, gen, RemoteKey,   |                            |
   |     Challenge = BLAKE2s    |                            |
   |     MAC(src, common))     |                            |
   |                            |                            |
   |--- BindUDPRelayEndpointAns |                            |
   |    (echo Challenge)       |                            |
   |                            |                            |
```

1. **Client A → Server** (`BindUDPRelayEndpoint`, type 0x04): sent as a Geneve control packet (`GeneveHeader{Control: true, Protocol: GeneveProtocolDisco}`). The disco payload is encrypted (NaCl box) with `shared_secret = server_disco.shared(clientA_disco)`. Contains VNI, handshake generation (nonzero), and the remote peer's disco key (Client B's disco key). Challenge field is padding (all zeros).

2. **Server → Client A** (`BindUDPRelayEndpointChallenge`, type 0x05): server validates VNI + RemoteKey match the allocation, records the sender's source IP:port as `inProgressGeneration[senderIndex] = generation`. Computes a BLAKE2s MAC over `(VNI, generation, RemoteKey, src_addr_port)` using a rotating MAC secret. Replies with the same Geneve-encapsulated disco, sealed with `server_disco.shared(clientA_disco)`.

3. **Client A → Server** (`BindUDPRelayEndpointAnswer`, type 0x06): client echoes the received Challenge field back. Server validates the MAC against both active MAC secrets, and if matched, marks the binding as complete: `boundAddrPorts[senderIndex] = from`.

The other client (B) may also handshake from its side (different source IP:port). After both sides are bound, the endpoint transitions to `endpointOpen` and server forwards data packets.

### 1.4 Geneve Encapsulation

All packets to/from the relay server carry an 8-byte Geneve header:

```
Byte 0: 0x00 (version=0, flags=0)
Byte 1: 0x00 (flags)
Bytes 2-3: protocol type (big-endian)
          0x0002 = WireGuard data (Control=false)
          0x0000 = Disco control (Control=true)
Bytes 4-6: VNI (24-bit, big-endian)
Byte 7: 0x00 (reserved)
```

- **Data packets**: protocol=0x0800 (Ethernet/IP, or WireGuard with `GeneveProtocolWireGuard`), Control=false. The payload is the raw WireGuard datagram. Server forwards it to the other bound client.
- **Control (disco) packets**: protocol=`GeneveProtocolDisco`, Control=true. The payload is a disco envelope (Magic + senderDiscoPub + NaCl box). Server decrypts, processes the handshake message, and may forward or reply.

### 1.5 VNI Lifecycle

- **Allocation**: `AllocateEndpoint()` picks the next available VNI from a 24-bit space (1 to 2^24-1, minVNI=1, maxVNI=0xFFFFFF) using a simple sequential scan ("BSD port selection").
- **BindLifetime** (default 30s): if both clients haven't completed the handshake within this window since allocation, the endpoint is garbage-collected.
- **SteadyStateLifetime** (default 5min): after both sides are bound, if no data is received from a client for this duration, the endpoint is expired.
- **Re-binding**: a client can update its binding by doing a new handshake from a different source IP:port (e.g. after a network transition). The old binding for that sender index is overwritten.
- **LamportID**: monotonically increasing allocation counter. Lets clients detect and resolve races: if two clients both allocate on the same server, the higher LamportID wins.

### 1.6 Client-Side Score

In the Go endpoint scoring (Go `endpoint.go`): relay paths rank below direct UDP but above DERP. After the bind handshake completes, the client sends a disco Ping over the relay path; when the Pong comes back (from the peer, forwarded by the relay server), latency is measured and `udpRelayEndpointReady()` is called with the relay address + VNI + latency. The path is considered trusted until direct discovery produces a better path.

## 2. Gap Table: Go vs rustscale

### 2.1 Server Side

| Feature | Go source | rustscale status | Rust ref |
|---------|-----------|-----------------|----------|
| UDP relay `Server` struct (socket bind, packet read loop, Geneve decode/dispatch) | `net/udprelay/server.go:67-456` | **missing** — entire crate absent | — |
| VNI allocation (`getNextVNILocked`, 24-bit space, sequential scan) | `net/udprelay/server.go:982-996` | **missing** | — |
| `AllocateEndpoint(discoA, discoB)` — endpoint creation, shared secret derivation, return `ServerEndpoint` | `net/udprelay/server.go:1013-1081` | **missing** | — |
| 3-way bind handshake server side (`handleSealedDiscoControlMsg` → `handleDiscoControlMsg`: Bind → Challenge → Answer with BLAKE2s MAC verification) | `net/udprelay/server.go:157-288` | **missing** | — |
| Data packet forwarding (`handleDataPacket` — lookup bound addr, forward raw payload) | `net/udprelay/server.go:290-316` | **missing** | — |
| Packet read loop (`packetReadLoop`, batch read → handlePacket → batch write per dest) | `net/udprelay/server.go:865-963` | **missing** | — |
| Endpoint GC loop (BindLifetime expiry, SteadyStateLifetime expiry) | `net/udprelay/server.go:764-790` | **missing** | — |
| BLAKE2s MAC secret rotation (`maybeRotateMACSecretLocked`, ~2min interval) | `net/udprelay/server.go:845-863` | **missing** | — |
| Server address discovery (STUN, local interfaces, cloud metadata) | `net/udprelay/server.go:458-560` | **missing** | — |
| Metrics (forwarded packets/bytes per AF pair, endpoint state gauge) | `net/udprelay/metrics.go` | **missing** | — |
| `ServerEndpoint` shared type | `net/udprelay/endpoint/endpoint.go` | **missing** | — |
| Relayserver extension (eventbus subscriber on alloc requests, calls `AllocateEndpoint`, publishes response) | `feature/relayserver/relayserver.go:133-174` | **missing** | — |
| Status/debug endpoint (`GetSessions`) | `net/udprelay/server.go:1102-1118` | **missing** | — |

### 2.2 Client Side

| Feature | Go source | rustscale status | Rust ref |
|---------|-----------|-----------------|----------|
| Geneve header encode/decode (8-byte header, VNI/protocol/control fields) | `magicsock/relaymanager.go` (uses `net/packet.GeneveHeader`) | **done** | `crates/magicsock/src/relay.rs:29-49` |
| Disco message types for relay handshake (Bind/Challenge/Answer) | `disco/disco.go:394-456` | **done** | `crates/disco/src/message.rs:300-345` |
| `CallMeMaybeVia` message type | `disco/disco.go:635-653` | **done** | `crates/disco/src/message.rs:462-499` |
| `AllocateUDPRelayEndpointRequest` / `Response` message types | `disco/disco.go:458-532` | **done** | `crates/disco/src/message.rs:501-593` |
| `UdpRelayEndpoint` wire type (shared by CMMV and alloc response) | `disco/disco.go:534-618` | **done** | `crates/disco/src/message.rs:351-460` |
| `RelayHandshake` client state machine (start_bind, handle_challenge, establish, reset) | `magicsock/relaymanager.go:873-1021` (embedded in handshakeServerEndpoint) | **done** (basic state only) | `crates/magicsock/src/relay.rs:61-147` |
| `RelayPhase` enum (None/Binding/Established) | — | **done** | `crates/magicsock/src/relay.rs:52-58` |
| Endpoint scoring: `PathClass::Relay` ranked below Direct, above Derp | `magicsock/endpoint.go` | **done** | `crates/magicsock/src/endpoint.rs:26-28` |
| `BestPath::Relay { addr, vni }` variant | `magicsock/endpoint.go` | **done** | `crates/magicsock/src/endpoint.rs:44-45` |
| `Endpoint::set_relay` / `clear_relay` | `magicsock/endpoint.go:udpRelayEndpointReady` | **done** (unused) | `crates/magicsock/src/endpoint.rs:182-189` |
| Send path for relay (Geneve-encapsulate WG data, send to relay addr) | `magicsock/magicsock.go:sendDiscoMessage` | **done** | `crates/magicsock/src/lib.rs:791-800` |
| **relayManager event loop** (work tracking, allocation/handshake state, per-server/disco maps) | `relaymanager.go:35-80, 198-264` | **missing** | — |
| **Relay server discovery** from netmap (`updateRelayServersSet`, `relayCandidateLocked`, `candidatePeerRelay`) | `magicsock/magicsock.go:2941-3025` | **missing** | — |
| **`candidatePeerRelay` type** (nodeKey, discoKey, derpHomeRegionID) | `magicsock/magicsock.go:3015-3025` | **missing** | — |
| **Allocation request flow** (`allocateServerEndpoint` — sends `AllocateUDPRelayEndpointRequest` via DERP, waits for response with retry) | `relaymanager.go:1025-1090` | **missing** | — |
| **Allocation response handling** (`handleRxDiscoMsgRunLoop` routes `AllocateUDPRelayEndpointResponse` to pending alloc work) | `relaymanager.go:584-676` | **missing** | — |
| **Handshake goroutine** (`handshakeServerEndpoint` — sends `BindUDPRelayEndpoint` to all server addr ports, waits for Challenge, sends Answer+Ping, waits for Pong, measures latency) | `relaymanager.go:873-1021` | **missing** (RelayHandshake has basic state but no actual I/O or timer-driven loop) | — |
| **CallMeMaybeVia sending** (after successful allocation, tell the remote peer via DERP about the relay endpoint) | `relaymanager.go:851-871` | **missing** | — |
| **CallMeMaybeVia handling** (receive CMMV, create relay endpoint from it, start handshake) | `relaymanager.go:448-466` | **missing** | — |
| **Ping/pong via relay** (after bind handshake, send disco Ping through relay, measure round-trip latency) | `relaymanager.go:931-949` | **missing** | — |
| **Disco message routing for relay** (handle `BindUDPRelayEndpointChallenge`, `AllocateUDPRelayEndpointResponse`, relayed `Ping`/`Pong`) | `magicsock/magicsock.go:sendDiscoMessage` + `relaymanager.go:584-676` | **missing** (no relay-specific handling in `handle_disco_udp` / `handle_disco_derp`) | `crates/magicsock/src/lib.rs:1072-1232` |
| **Relay server tracking in netmap** (`PeerCapabilityRelayTarget` ACL check, `Hostinfo.PeerRelay` flag) | `magicsock/magicsock.go:2941-3013` | **missing** (Hostinfo.PeerRelay field exists but unused) | `crates/tailcfg/src/node.rs:268` |
| **Relay server upsert/remove** per peer (O(1) variants for incremental netmap) | `relaymanager.go:493-503` | **missing** | — |
| **In-process allocation shortcut** (when relay server is self, bypass DERP via eventbus) | `magicsock/magicsock.go:1950-1963` | **missing** | — |

### 2.3 Tailcfg / Control Plane

| Feature | Go source | rustscale status | Rust ref |
|---------|-----------|-----------------|----------|
| `Hostinfo.PeerRelay` bool | `tailcfg.go:908` | **done** | `crates/tailcfg/src/node.rs:268` |
| `PeerCapabilityRelay` / `PeerCapabilityRelayTarget` capability constants | `tailcfg.go:1578-1583` | **missing** | — |
| `NodeAttrDisableRelayServer` / `NodeAttrDisableRelayClient` | `tailcfg.go:2715-2727` | **missing** | — |
| `capVerIsRelayCapable` (capability version >= 120 for relay) | `tailcfg.go:169-170` | **missing** | — |
| `NodeCapMap` (exists, but relay-specific cap parsing absent) | `tailcfg.go` | **done** (generic) | `crates/tailcfg/src/lib.rs:131` |

## 3. Phased Implementation Plan

### Phase 1: `crates/udprelay` — Server Crate

**Go sources**: `net/udprelay/server.go`, `net/udprelay/endpoint/endpoint.go`, `net/udprelay/metrics.go`

**What to build**:
- `crates/udprelay/src/` with:
  - `endpoint` module containing `ServerEndpoint` struct (ServerDisco, ClientDisco [2], LamportID, VNI, AddrPorts, BindLifetime, SteadyStateLifetime) and `ServerRetryAfter` constant
  - `server` module with `Server` struct binding UDP4 (+ UDP6) sockets, packet read loop (batch read from platform socket or single-packet fallback)
  - `AllocateEndpoint(disco_a, disco_b) -> Result<ServerEndpoint>` — VNI allocation (24-bit sequential scan via `getNextVniLocked`), shared secret derivation (`disco.Shared(peer)`)
  - 3-way handshake server: `handleSealedDiscoControlMsg` → decrypt → `handleDiscoControlMsg` → validate VNI + RemoteKey → compute BLAKE2s MAC → reply Challenge → later verify Answer MAC → mark bound
  - `handleDataPacket`: lookup VNI → forward payload to other bound client
  - Endpoint GC: periodic scan, expire based on BindLifetime (30s) / SteadyStateLifetime (5min)
  - MAC secret rotation (~2min interval), two-active-secrets window
  - `GeneveHeader` struct encode/decode (8-byte, VNI/protocol/control)
  - Multiple socket binding per address family (SO_REUSEPORT, GOMAXPROCS-based)
- Geneve types can live in a shared `crates/tailcfg` or `crates/net` module (currently in `crates/magicsock/src/relay.rs` — move to shared)

**Acceptance criteria**:
- `cargo build --workspace` passes
- `cargo test -p rustscale-udprelay` passes with unit tests:
  - Geneve header roundtrip
  - Full 3-way handshake between two test clients and server (in-process UDP sockets, loopback)
  - Data packet forward after handshake
  - Re-binding from new source address
  - VNI allocation wraps around and pools exhaust
  - Endpoint expiry (bind lifetime + steady state)
  - BLAKE2s MAC computation + verification
  - MAC secret rotation
- `cargo clippy --workspace --all-targets` passes

**Estimated size**: ~1200 lines. 1 opencode phase.

---

### Phase 2: Relay Server Extension for tsnet

**Go sources**: `feature/relayserver/relayserver.go`, `magicsock/magicsock.go:543-571` (UDPRelayAllocReq/Resp)

**What to build**:
- In `crates/tsnet/src/` (or new `crates/relayserver/src/`), an `Extension` that:
  - Owns a `udprelay::Server` instance
  - Listens for allocation requests: either a channel-based event or wired into magicsock's disco receive path
  - On `AllocateUDPRelayEndpointRequest` (received via DERP by magicsock), calls `server.allocate_endpoint(client_disco[0], client_disco[1])`
  - Sends `AllocateUDPRelayEndpointResponse` back via DERP to the requesting node
- Integration point: magicsock must route received `AllocateUDPRelayEndpointRequest` disco messages (type 0x08) to this extension instead of dropping them.
- The in-process shortcut (allocation to self) should directly call the local extension without a DERP round-trip.

**Acceptance criteria**:
- Node configured as relay server receives an alloc request over DERP, successfully allocates an endpoint, returns the ServerEndpoint to the requester
- Self-allocation shortcut works (no DERP round-trip for local relay server)
- `cargo build && cargo test && cargo clippy` pass

**Estimated size**: ~400 lines. 1 opencode phase.

---

### Phase 3: `relayManager` Client — Discovery, Allocation, Handshake, Probing

**Go sources**: `relaymanager.go` (entire file), `magicsock/magicsock.go:543-571, 1946-1963, 2941-3025`

**What to build**:
- `RelayManager` struct in `crates/magicsock/src/relay_manager.rs`:
  - `candidatePeerRelay` type: `{ node_key, disco_key, derp_home_region }`
  - Server tracking: `HashMap<NodePublic, CandidatePeerRelay>` updated from netmap
  - Server discovery: iterate peers from netmap, check `CapMap` for `PeerCapabilityRelayTarget` and `Hostinfo.PeerRelay`
  - `AllocWork` per (endpoint, relay server) tuple — sends `AllocateUDPRelayEndpointRequest` disco message via DERP to the relay server's home region
  - Retry timer (10s timeout, 3s retry on `ErrServerNotReady`)
  - `HandshakeWork` per (server disco, VNI) — the client-side 3-way handshake goroutine:
    1. Send `BindUDPRelayEndpoint` to all server AddrPorts (one IP per address family)
    2. Wait for `BindUDPRelayEndpointChallenge` (with timer `min(BindLifetime, 30s)`)
    3. Send `BindUDPRelayEndpointAnswer` + disco `Ping` together
    4. Wait for disco `Pong` over the relay path, measure latency
    5. Call `Endpoint::set_relay(addr, vni)` with the pong source address and VNI
  - `CallMeMaybeVia` sending: after allocation, send `CallMeMaybeVia` via DERP to the remote peer
  - `CallMeMaybeVia` handling: receive `CallMeMaybeVia` disco message → create `ServerEndpoint` from it → start handshake work (same as above)
  - LamportID dedup: compare LamportID when seeing duplicate endpoint info, discard stale
  - Proper cancellation of in-flight work when endpoint is removed
  - Wired into magicsock's disco receive path: route relay-type messages (BindChallenge, AllocResponse, relayed Ping/Pong, CallMeMaybeVia) to the manager
  - Wire into `Magicsock::set_netmap` for server discovery

**Acceptance criteria**:
- `cargo build && cargo test && cargo clippy` pass
- Unit tests for: allocation state machine, handshake state machine, CallMeMaybeVia send/receive, server set update, LamportID dedup
- Integration test (Phase 5) shows two nodes can send/receive data through a third relay server node

**Estimated size**: ~1500 lines. 1-2 opencode phases (can split into "discovery+allocation" and "handshake+probing" if needed).

---

### Phase 4: Tailcfg Capabilities for Relay

**Go sources**: `tailcfg/tailcfg.go:1578-1583, 2715-2727, 169-170`

**What to build**:
- Add constants to `crates/tailcfg/src/lib.rs` (or a new `caps.rs`):
  - `PeerCapabilityRelay: &str = "tailscale.com/cap/relay"`
  - `PeerCapabilityRelayTarget: &str = "tailscale.com/cap/relay-target"`
  - `NodeAttrDisableRelayServer: &str = "disable-relay-server"`
  - `NodeAttrDisableRelayClient: &str = "disable-relay-client"`
- Relay capability version check constant (`CAP_VERSION_RELAY = 120`)
- Helper on `NodeCapMap`: `has_capability(cap: &str) -> bool` for checking if a node has a given capability
- Wire into `updateRelayServersSet` check in Phase 3

**Acceptance criteria**: `cargo build && cargo test -p rustscale-tailcfg` pass. New constants and helpers work.

**Estimated size**: ~100 lines. Can be inlined into Phase 3.

---

### Phase 5: Integration Test — Two Clients + One Relay Server

**Go sources**: `net/udprelay/server_test.go` (test pattern), `feature/relayserver/relayserver_test.go`

**Prerequisites**: Phases 1-3, plus the testcontrol harness (see `docs/testcontrol-plan.md` Phase A+B).

**What to build**:
- In the integration test crate (`crates/testcontrol/tests/` or a new test module):
  - Helper: start an in-process `udprelay::Server` on loopback
  - Start 3 `tsnet::Server` instances against testcontrol: two clients (A, B) and one relay server (R)
  - Configure R's netmap with `PeerCapabilityRelayTarget` for A and B, `Hostinfo.PeerRelay: true`
  - Test scenarios:
    1. **Allocation flow**: A discovers R as relay server, sends alloc request via DERP, receives `ServerEndpoint`, starts bind handshake
    2. **Bidirectional data**: A and B both bind to the same endpoint on R, exchange WireGuard data frames through the relay
    3. **CallMeMaybeVia**: After A allocates, R sends `CallMeMaybeVia` to B via DERP; B starts its own handshake with R
    4. **Rebinding**: A switches to a new source port, re-handshakes, continues sending/receiving
    5. **Expiry**: Stop sending data, wait past `SteadyStateLifetime`, verify GC removes the endpoint

**Acceptance criteria**: All 5 scenarios pass with `cargo test`. No external network access needed.

**Estimated size**: ~600 lines. 1 opencode phase.

---

## 4. Architecture Summary

```
┌──────────────────────────────┐
│       Node A (client)         │
│  ┌──────────────────────┐    │
│  │ relayManager         │    │
│  │  • server discovery  │    │
│  │  • alloc work        │◄───│ AllocateUDPRelayEndpointRequest (via DERP)
│  │  • handshake work    │◄───│ AllocateUDPRelayEndpointResponse (via DERP)
│  │  • CallMeMaybeVia    │───►│ CallMeMaybeVia (via DERP)
│  │  • ping/pong probing │    │
│  └──────────────────────┘    │
│         │     ▲              │
│         ▼     │              │
│  ┌────────────────┐          │
│  │ Endpoint       │          │ BestPath::Relay { addr, vni }
│  │ set_relay()    │          │
│  └────────────────┘          │
└──────────────────────────────┘
         │ bind handshake & data (UDP/Geneve)
         ▼
┌──────────────────────────────┐
│   Node R (relay server)      │
│  ┌──────────────────────┐    │
│  │ udprelay::Server     │    │
│  │  • socket bind       │    │
│  │  • VNI allocation    │    │
│  │  • 3-way handshake   │    │
│  │  • data forward      │    │
│  │  • GC + MAC rotation │    │
│  └──────────────────────┘    │
│  ┌──────────────────────┐    │
│  │ relayserver::Ext     │    │
│  │  • on_alloc_req      │◄───│ AllocateUDPRelayEndpointRequest (from DERP)
│  │  → AllocateEndpoint  │───►│ AllocateUDPRelayEndpointResponse (to DERP)
│  └──────────────────────┘    │
└──────────────────────────────┘
```

Key design points:
- The relay server node runs both `udprelay::Server` (UDP data plane) and `relayserver::Extension` (control plane: receives alloc requests via DERP, calls into Server, returns responses)
- The allocation request is sent as a disco message over DERP to the relay server node's home DERP — NOT via peerAPI HTTP
- The 3-way bind handshake and all data flow over UDP directly to the relay server's address:port, using Geneve encapsulation with VNI
- After binding, both clients can send WG datagrams (or disco pings/pongs) through the relay. The server's forwarding loop is simple: on receive, look up VNI, forward to other client's bound address
- Client-side relayManager tracks all in-flight work per endpoint+server and handles concurrency (multiple servers, duplicate allocations, LamportID ordering)
