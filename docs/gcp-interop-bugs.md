# GCP Interop Bug Report — 2026-07-10

## Environment
- **GCP VM**: `rs-gcp-interop` (us-east1-b, 34.24.127.181, n1-standard-4, Ubuntu 22.04)
- **rustscale**: built from working tree HEAD, `cargo build --release --example hello`
  - Hostname: `rs-gcp`, IP: 100.90.62.9, CAPABILITY_VERSION=141
- **Go tailscale**: 1.98.8 on same GCP VM, mode: userspace (--tun=userspace-networking)
  - Hostname: `go-gcp`, IP: 100.84.28.94
- **MacBook**: tailscale 1.98.8 (client) / 1.101.162 (server), IP: 100.72.184.20
- **Tailnet**: rajsinghtech@ (152 peers)

## Comparison summary

| Test                          | go-gcp (Go) | rs-gcp (rustscale) |
|-------------------------------|-------------|---------------------|
| Node appears in tailscale status | YES         | YES                 |
| Online                        | YES         | YES                 |
| tailscale ping                | 45ms direct  | TIMEOUT             |
| curl http://node:8080         | N/A         | TIMEOUT             |
| DERP relay known to peers     | mia         | (empty)             |
| CurAddr                       | 34.24.127.181:46891 | (empty)     |
| Addrs (netmap endpoints)      | null        | null                |

## Bug 1: Peer connectivity completely broken (CRITICAL)

**Symptom**: MacBook `tailscale ping 100.90.62.9` times out. `curl http://100.90.62.9:8080/`
times out. The MacBook sees `rs-gcp` as `Online: true` but cannot reach it by
direct UDP, DERP relay, or peer relay.

**Root cause investigation**: The MacBook's tailscale peer entry for `rs-gcp`
shows:
```json
{
  "HostName": "rs-gcp",
  "Online": true,
  "Addrs": null,
  "CurAddr": "",
  "Relay": "",
  "DERP": null
}
```

Compare with `go-gcp` on the same VM:
```json
{
  "HostName": "go-gcp",
  "Online": true,
  "Addrs": null,
  "CurAddr": "34.24.127.181:46891",
  "Relay": "mia",
  "DERP": null
}
```

Key differences:
1. `go-gcp` has `Relay: "mia"` — MacBook knows which DERP region go-gcp is
   connected to and can initiate DERP-relayed communication.
2. `rs-gcp` has `Relay: ""` — MacBook does NOT know rs-gcp's DERP home region.
   Without a known DERP home, the MacBook's tailscale cannot initiate DERP relay
   communication with rs-gcp.

The control server sets `HomeDERP` on the Node entry in the netmap. If
`HomeDERP=0`, peers have no DERP fallback. This is determined by the DERP
server notifying the control server when a client connects. The rustscale DERP
client log says "DERP connected to region 16" but the control server is
apparently not being notified.

**Investigation needed**:
- Verify the DERP client `send_client_key` is sending a correctly-formatted
  `ClientInfo` frame that the DERP server accepts and registers.
- Verify the DERP connection type (HTTP/2 upgrade vs direct TCP) matches what
  the DERP server expects for client registration.
- Verify the DERP connection is maintained (keep-alive) — if the connection
  drops after handshake, the DERP server may deregister the client.
- Check if the machine key used for DERP matches the one registered with control.

**Files**:
- `crates/derp/src/client.rs` — DerpClient::from_stream, send_client_key
- `crates/derp/src/protocol.rs` — ClientInfo serialization
- `crates/tsnet/src/lib.rs` — DERP connection setup (~line 800+)
- Go reference: `derp/derphttp/derphttpclient.go`

## Bug 2: Endpoint update "fails" with "no map response" (MODERATE)

**Symptom**: rustscale prints:
```
tsnet: endpoint update failed (non-fatal): io: no map response
```

**Root cause**: `ControlClient::fetch_map()` (crates/controlclient/src/client.rs:287)
sends a `MapRequest` with `Stream=false, OmitPeers=true` and then waits for a
`MapResponse` via `rx.recv()`. When the control server responds with 200 and
an empty body (normal for OmitPeers=true), `stream_map` returns `Ok(())`
without sending anything on the channel. `fetch_map` then gets `None` from
`rx.recv()` and returns `StreamMapError::Io("no map response")`.

The MapRequest IS sent and the server likely DID process the endpoints, but
the code reports a false-positive error.

**Fix**: Add a method to `ControlClient` that sends a MapRequest without
expecting a response (or treats empty body as success for OmitPeers=true).
Then update the two callers in `crates/tsnet/src/lib.rs` (lines 839, 2100).

**Files**:
- `crates/controlclient/src/client.rs:287-293` — fetch_map
- `crates/tsnet/src/lib.rs:839, 2100` — callers

## Bug 3: MagicDNS responder bind failure (LOW)

**Symptom**:
```
tsnet: MagicDNS responder not started (Cannot assign requested address (os error 99))
```

**Root cause**: `DnsResponder::new()` binds to `MAGICDNS_VIP:53`
(`100.100.100.100:53`). On the GCP VM, this IP is not assigned to any network
interface (no TUN device in tsnet mode), so `EADDRNOTAVAIL` (error 99).

**Fix**: Fall back to binding `127.0.0.1:0` (random port) or `0.0.0.0:53`
(if root) or `127.0.0.1:53` when `100.100.100.100:53` fails. The DNS responder
is primarily used for in-process resolution via `dial()` — the actual OS-level
DNS integration is secondary for tsnet mode.

**Files**:
- `crates/tsnet/src/lib.rs:527-543` — responder spawn
- `crates/dns/src/lib.rs:265+` — DnsResponder implementation

## Bug 4: No periodic endpoint updates (MODERATE)

**Symptom**: Go tailscale regularly sends endpoint updates via the control
plane map request, enabling peers to learn about new STUN endpoints and
path changes. rustscale only sends endpoints once at startup (Bug 2, which
"fails") and on link-change (netmon trigger). There is no periodic endpoint
report timer.

**Impact**: Even if Bug 2 is fixed, STUN-discovered endpoints, port-mapping
results, and network transitions won't be communicated to the control server
until a netmon link-change event fires.

**Fix**: Add a periodic timer task (e.g., every 5 minutes) that sends an
endpoint update MapRequest with `OmitPeers=true` containing current magicsock
local/STUN endpoints. Also trigger on netcheck completion (when new STUN
endpoints are discovered).

**Files**:
- `crates/tsnet/src/lib.rs:810-842` — initial endpoint update
- `crates/tsnet/src/lib.rs:2080-2110` — link-change endpoint update
- Go reference: `controlclient/auto.go` — `setEndpoints` flow

## Bug 5 (suspected): DERP home region not communicated to control (CRITICAL)

**Symptom**: See Bug 1. The DERP server is not notifying the control server
that rs-gcp is connected to DERP region 16. This may be because:

1. The DERP client connects but doesn't complete the HTTP/2 upgrade (the Go
   DERP server expects an HTTP upgrade, and the rustscale client may use a
   different connection type).
2. The `ClientInfo` box isn't being verified by the DERP server (wrong machine
   key, wrong protocol format).
3. The DERP connection drops immediately after handshake.

**Investigation needed**:
- Check if `connect_with_upgrade` or `connect` (direct) is being used.
  The Go DERP server (`derpServer.ServeHTTP`) expects an HTTP upgrade
  request, not a direct TCP connection.
- Verify the `ClientInfo` box format matches Go's (`derp/derp_server.go`).
- Check the DERP client's keep-alive/heartbeat mechanism.

**Files**:
- `crates/derp/src/client.rs:101-129` — connect methods
- `crates/derp/src/protocol.rs` — ClientInfo, ServerInfo
- `crates/tsnet/src/lib.rs` — DERP bootstrapping
- Go reference: `derp/derphttp/derphttpclient.go`, `derp/derp_server.go`

## Additional observations (not bugs, but notable)

- rustscale startup log: `local UDP endpoints: ["10.142.15.201:44819", "127.0.0.1:44819"]`
  - Contains `127.0.0.1` — the control server may filter this (useless for
    remote peers). Go tailscale sends the external IP discovered via STUN.
  - No STUN results visible in the log — STUN netcheck results are important
    for direct + relay endpoint discovery.

- `go-gcp` achieves: DERP(mia) in 186ms → peer-relay in 74ms → direct in 45ms
  - This shows the full path negotiation working: DERP first, then peer-relay
    (via aperture), then direct UDP.
  - rustscale has none of these paths working.

- The GCP VM also has Go tailscale (1.98.8) installed for direct comparison.
  The Go tailscale starts with `--tun=userspace-networking` mode.
