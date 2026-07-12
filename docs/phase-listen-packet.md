# Phase: ListenPacket (UDP on tailnet)

Closes verified-audit P0 gap #52 (rank 10): no UDP listen on netstack.
TCP-only; no `ListenPacket` (UDP on tailnet).

## Goal

Add UDP listening support to the netstack so applications can listen for
UDP packets on their tailnet IP address. This enables DNS servers, custom
UDP protocols, and any service that needs to receive UDP via tsnet.

## Go source reference

All in `/Users/rajsingh/Documents/GitHub/tailscale/`:

### tsnet ListenPacket
- `tsnet/tsnet.go:1294-1344` — `Server.ListenPacket(network, addr) (net.PacketConn, error)`
- `tsnet/tsnet.go:1346-1355` — `udpPacketConn` wrapper (unregisters on Close)
- `tsnet/tsnet.go:1247-1253` — `getUDPHandlerForFlow` (lookup in listeners map)

### netstack UDP
- `wgengine/netstack/netstack.go:1818-1860` — `Impl.ListenPacket`: creates gVisor UDP endpoint, binds, returns gonet.UDPConn
- `wgengine/netstack/netstack.go:645-648` — UDP forwarder for unmatched packets
- `wgengine/netstack/netstack.go:174-185` — `GetUDPHandlerForFlow` callback field

### Data flow
1. WireGuard decrypts → injectInbound → gVisor/smoltcp demuxer
2. Bound UDP socket matched by (localAddr, localPort) with wildcard remote
3. Application ReadFrom returns payload + source address
4. Outbound: WriteTo → smoltcp emits → WireGuard encrypts → peer

### Port allocation
- `tsnet/tsnet.go:2013-2014` — ephemeral port range 10002-19999

## Current Rust state

- `crates/netstack/src/lib.rs` — TCP-only. `Command` enum has `Listen`, `ListenOn`, `AddAddr`, `Dial` (all TCP). No UDP commands.
- smoltcp workspace dep: `features = ["medium-ip", "proto-ipv4", "socket-tcp", "alloc"]` — **missing `socket-udp`**.
- `crates/netstack/src/lib.rs:423` — `new_tcp_socket()` helper; no `new_udp_socket()`.
- `crates/tsnet/src/lib.rs` — has `listen()` and `listen_on()` for TCP; no `listen_packet()`.

## Implementation plan

### 1. Enable smoltcp UDP
In the root `Cargo.toml`, add `"socket-udp"` to smoltcp features:
```toml
smoltcp = { version = "0.13", default-features = false, features = ["medium-ip", "proto-ipv4", "socket-tcp", "socket-udp", "alloc"] }
```

### 2. Add UDP socket support to netstack
In `crates/netstack/src/lib.rs`:

- Add a `Command::ListenPacket { addr: IpAddr, port: u16, reply: oneshot::Sender<Result<UdpListener, NetstackError>> }` variant.
- Add a `UdpListener` struct that wraps an `mpsc::Receiver<UdpPacket>` and provides:
  - `async recv_from(&mut self) -> Result<(Bytes, SocketAddr), NetstackError>` — receive a packet + source
  - `async send_to(&self, data: &[u8], dst: SocketAddr) -> Result<(), NetstackError>` — send a packet
  - `local_addr(&self) -> SocketAddr` — the bound address
  - `Drop` implementation that sends a `Command::CloseUdp` to unregister
- Add `UdpPacket { data: Bytes, src: SocketAddr }` struct.
- In the poll loop: create a `smoltcp::socket::udp::Socket`, bind it to the requested addr:port, and on each poll iteration call `socket.recv_from()` to dequeue incoming packets, forwarding them to the `mpsc::Sender` of the listener. For outbound, call `socket.send_to()`.
- Add a UDP socket tracking map (similar to the TCP conn map): `udp_sockets: HashMap<(IpAddr, u16), UdpSocketState>` where `UdpSocketState` holds the smoltcp socket handle + the mpsc::Sender.
- In the inbound packet path (where IP packets are dispatched): if the packet is UDP and matches a bound socket, feed it to smoltcp. Smoltcp's socket set polling handles the demuxing.

### 3. Add listen_packet to tsnet
In `crates/tsnet/src/lib.rs`:
- Add `pub async fn listen_packet(&self, addr: &str) -> Result<UdpListener, TsnetError>` method on `Server`.
- Parse the address (resolve hostname to tailnet IP, or use the node's tailnet IP if `:port` form).
- Send `Command::ListenPacket` to the netstack.
- Return the `UdpListener`.

### 4. Port allocation
- If port 0 is requested, allocate from ephemeral range 10002-19999.
- Track allocated ports to avoid collisions.

### 5. Register in listeners map
- Register the UDP listener in the existing `listeners` map (or a new `udp_listeners` map) so incoming packets can be routed.

## Acceptance criteria

- `tools/check.sh` passes (build + test + clippy -D warnings + fmt).
- `Server::listen_packet(":<port>")` returns a `UdpListener` that can `recv_from()` and `send_to()`.
- A peer sending UDP to the node's tailnet IP:port is received by `recv_from()`.
- `send_to()` sends packets through WireGuard to the peer.
- Ephemeral port allocation (port 0) works.
- Unit test: bind a UDP socket, send a packet to it from the netstack, verify recv_from returns it.
- Integration test (if feasible with testcontrol): two nodes, one listens, the other sends, packet is received.

## Constraints

- Do NOT fetch docs.rs or explore `~/.cargo/registry/`.
- Before reading Go sources, check `docs/porting-notes.md` for distilled facts (smoltcp API may be documented there).
- Use `tools/check.sh --check rustscale-netstack` during iteration.
- Use `tools/check.sh rustscale-netstack` for full single-crate build.
- Use `tools/check.sh` (workspace) ONLY at the end.
- NEVER run raw cargo build/test/clippy/fmt — use `tools/check.sh`.
- In your OWN files, NEVER re-read the whole file — use `grep -n` or `tools/where.sh`.
- The `netstack` crate sets `#![allow(unsafe_code)]` if needed (check existing).
- smoltcp's `udp::Socket` API: `recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, IpEndpoint)>` and `send_to(&mut self, data: &[u8], dst: IpEndpoint) -> Result<()>`. Check the exact API in the smoltcp source if needed via `grep -rn "pub fn recv_from\|pub fn send_to" ~/.cargo/registry/src/*/smoltcp-*/src/socket/udp.rs`.
