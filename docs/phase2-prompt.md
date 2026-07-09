# Phase 2: crates/disco + crates/derp

You are a senior Rust systems engineer on "rustscale", a Rust port of Tailscale's
client stack. The Go reference is at /Users/rajsingh/Documents/GitHub/tailscale
(READ ONLY — never modify it). Phase 1 already built `crates/key` and
`crates/tailcfg`. READ their `src/lib.rs` (and submodules) to learn the existing
APIs and REUSE them — do not reinvent crypto or key types.

## Workspace setup

The workspace Cargo.toml is at the repo root. `members = ["crates/*"]` means any
new dir under `crates/` is auto-included. Add any new shared deps to
`[workspace.dependencies]` in the root `Cargo.toml`. Each crate gets
`[lints] workspace = true` and `version.workspace = true` etc. — copy the
pattern from `crates/key/Cargo.toml`.

Existing `[workspace.dependencies]` already has: serde, serde_json, thiserror,
curve25519-dalek, ed25519-dalek, crypto_box, rand, rand_core, hex, base64,
data-encoding, chrono, tokio. You will likely need to ADD: `bytes`, `tokio-rustls`,
`rustls` (or `rustls-pemfile`), `webpki-roots`, `http`, `httparse`. Pin reasonable
versions. Workspace lint config forbids `unsafe_code` and uses pedantic clippy
with several style lints allowed — keep it clean.

## Existing key crate API you MUST reuse

Read `/Users/rajsingh/Documents/GitHub/rustscale/crates/key/src/lib.rs`,
`node.rs`, `disco.rs`, `machine.rs`, `boxcrypto.rs`. Key types:

- `rustscale_key::NodePublic` — 32-byte node public key. `.raw32() -> [u8;32]`,
  `.from_raw32([u8;32])`, `.is_zero()`, `.short_string()`, `.marshal_text()`.
  Implements `Display` as `nodekey:<hex>`, `FromStr`, serde as that typed string.
- `rustscale_key::NodePrivate` — node private key. `.generate()`,
  `.public() -> NodePublic`, `.seal_to(peer: &NodePublic, cleartext: &[u8])
  -> Result<Vec<u8>, KeyError>` returns `nonce(24) || ct`, `.open_from(peer:
  &NodePublic, ciphertext: &[u8]) -> Option<Vec<u8>>`.
- `rustscale_key::DiscoPublic` — 32-byte disco public key. `.raw32()`,
  `.from_raw32(..)`, `.is_zero()`, `.short_string()` (`d:<16hex>`),
  `.marshal_text()` (`discokey:<hex>`), `FromStr`, serde.
- `rustscale_key::DiscoPrivate` — `.generate()`, `.public() -> DiscoPublic`,
  `.shared(peer: &DiscoPublic) -> DiscoShared`.
- `rustscale_key::DiscoShared` — precomputed NaCl box shared key. `.seal(&[u8])
  -> Result<Vec<u8>, KeyError>` returns `nonce(24) || ct`. `.open(&[u8]) ->
  Option<Vec<u8>>`. `.zero()`, `.is_zero()`.
- `rustscale_key::KEY_LEN = 32`, `rustscale_key::NONCE_LEN = 24`.

For IP addresses in disco messages, use the `std::net::IpAddr`/`Ipv4Addr`/
`Ipv6Addr` types (no extra crate needed). Encode IPs as 16-byte v4-mapped-v6
(`Addr().As16()` in Go) — for an IPv4 `a.b.c.d` the 16 bytes are
`00 00 00 00 00 00 00 00 00 00 ff ff a b c d`. Decode reverses with
`.unmap()` (IPv4-mapped -> IPv4). Use `std::net::SocketAddr` / a small
`AddrPort` helper (you can define a thin newtype or just use `SocketAddr`).
Port is big-endian u16.

---

## CRATE 1: crates/disco

Port the disco NAT-traversal message codec from
`/Users/rajsingh/Documents/GitHub/tailscale/disco/disco.go` (READ IT CAREFULLY —
wire formats must match byte-for-byte). Also read `disco_test.go` for golden
test vectors you MUST replicate exactly.

### Wire envelope (the crypto wrapper, NOT the payload)

From disco.go lines 6-19:
```
magic          [6]byte  // "TS💬" = bytes 0x54 53 f0 9f 92 ac
senderDiscoPub [32]byte // disco public key of sender
nonce          [24]byte // nacl box nonce
<box>          ...      // nacl box ciphertext (sealed with DiscoShared)
```
- `MAGIC = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac]` (6 bytes — the UTF-8 of "TS💬").
- `KEY_LEN = 32`, `NONCE_LEN = 24`.
- `LooksLikeDiscoWrapper(p)`: `p.len() >= 6+32+24 && p[..6] == MAGIC`.
- `Source(p) -> (&[u8;32], bool)`: returns the sender disco pub key slice if it
  looks like a disco wrapper (bytes 6..38).
- Provide `seal_packet(sender_priv: &DiscoPrivate, peer: &DiscoPublic, payload:
  &[u8]) -> Vec<u8>` that builds `magic || sender_pub(32) || <DiscoShared::seal
  output>` — i.e. `MAGIC ++ sender_priv.public().raw32() ++ shared.seal(payload)`.
  The seal output is already `nonce(24) || ct`. So the full packet is
  `6 + 32 + 24 + len(payload) + 16` bytes.
- Provide `open_packet(receiver_priv: &DiscoPrivate, packet: &[u8]) ->
  Option<(DiscoPublic, Vec<u8>)>` that checks MAGIC, extracts sender pub key,
  precomputes `receiver_priv.shared(&sender_pub)`, calls `.open()` on
  `packet[6+32..]`, returns `(sender_pub, plaintext)`. None on bad magic/auth.

### Inner payload format (after box decryption)

From disco.go:
```
messageType     byte
messageVersion  byte   (0 for now; ignore trailing bytes)
message-payload [...]byte
```
`Message::parse(payload: &[u8]) -> Result<Message, DiscoError>`: payload must be
>= 2 bytes. First byte = type, second = version, rest = body. `Message::marshal
(&self) -> Vec<u8>` returns the payload only (type+ver+body), WITHOUT the crypto
envelope. `MessageHeaderLen = 2`.

Message enum — port EVERY type in disco.go with the same type/version bytes and
field encodings:

1. **Ping** (TypePing=0x01, ver=0): `[12]byte TxID`, optional `NodeKey:
   NodePublic` (omitted when zero — old clients), `Padding: usize` (count of
   trailing zero bytes; used for path MTU). Marshal: `dataLen = 12 + (32 if
   NodeKey non-zero else 0) + Padding`; header; copy TxID; if NodeKey non-zero
   append its raw32; then `Padding` zero bytes. Parse: body must be >= 12; copy
   TxID; `Padding = len(body) - 12`; if remaining >= 32, read NodeKey raw32 and
   `Padding -= 32`. (Lax on longer messages for fwd compat — match Go's
   `len(p) >= key.NodePublicRawLen` check, not exact equality.) `PingLen = 44`
   (12 + 32, without header or padding).

2. **Pong** (TypePong=0x02, ver=0): `[12]byte TxID`, `Src: AddrPort` (18 bytes
   on wire: 16-byte v4-mapped-v6 IP + 2-byte BE port). `pongLen = 30`. Marshal:
   header(30); TxID; IP as16; BE port. Parse: body >= 30; TxID; IP from 16 bytes
   (v4-mapped -> Ipv4 via unmap); BE port.

3. **CallMeMaybe** (TypeCallMeMaybe=0x03, ver=0): `MyNumber: Vec<AddrPort>`.
   `epLength = 18` (16 IP + 2 port). Marshal: header(18 * len); for each, write
   as16 + BE port. Parse: if `len(body) % 18 != 0 || ver != 0 || len == 0`
   return empty (match Go — it returns an empty struct, NOT an error). Otherwise
   loop 18-byte chunks.

4. **BindUDPRelayEndpoint** (Type=0x04), **BindUDPRelayEndpointChallenge**
   (Type=0x05), **BindUDPRelayEndpointAnswer** (Type=0x06) — all carry
   `BindUDPRelayEndpointCommon` (ver=0). `bindUDPRelayEndpointCommonLen = 72`:
   `VNI: u32` (BE), `Generation: u32` (BE), `RemoteKey: DiscoPublic` (32 raw
   bytes), `Challenge: [32;u8]`. Marshal each: header(72); encode common.
   Parse: decode common (body >= 72). `BindUDPRelayChallengeLen = 32`.

5. **CallMeMaybeVia** (Type=0x07, ver=0): wraps `UDPRelayEndpoint` (see below).
   Marshal: header(`udpRelayEndpointLenMinusAddrPorts + 18*len(AddrPorts)`); encode
   UDPRelayEndpoint. Parse: if ver != 0 return empty; else decode UDPRelayEndpoint.

6. **AllocateUDPRelayEndpointRequest** (Type=0x08, ver=0):
   `ClientDisco: [DiscoPublic; 2]`, `Generation: u32`.
   `allocateUDPRelayEndpointRequestLen = 32*2 + 4 = 68`. Marshal: header(68);
   two disco pubkeys (32 each); BE u32 generation. Parse: if ver != 0 return
   default; if body < 68 return errShort; read two disco keys + generation.

7. **AllocateUDPRelayEndpointResponse** (Type=0x09, ver=0): `Generation: u32` +
   `UDPRelayEndpoint`. Marshal: header(4 + udpRelayEndpointLenMinusAddrPorts +
   18*len(AddrPorts)); BE u32 generation; encode UDPRelayEndpoint. Parse: if ver
   != 0 return default; if body < 4 errShort; read generation; decode
   UDPRelayEndpoint from body[4..].

### UDPRelayEndpoint (shared by CallMeMaybeVia and AllocateUDPRelayEndpointResponse)

`udpRelayEndpointLenMinusAddrPorts = 32 + 64 + 8 + 4 + 8 + 8 = 124`:
- `ServerDisco: DiscoPublic` (32)
- `ClientDisco: [DiscoPublic; 2]` (64)
- `LamportID: u64` (8, BE)
- `VNI: u32` (4, BE)
- `BindLifetime: Duration` (8, BE u64 nanoseconds — Go's `time.Duration` is int64 ns; encode `as u64`)
- `SteadyStateLifetime: Duration` (8, BE u64 ns)
- `AddrPorts: Vec<AddrPort>` (18 each)

Use `std::time::Duration`. Encode as `u64` via `as_nanos() as u64` (Go casts
`time.Duration` (int64) directly to uint64 — sign is always positive here).
`encode`: write all fields + the AddrPorts (as16 + BE port each). `decode`:
require `len >= 124 + 18` AND `(len - 124) % 18 == 0` else errShort; read
fields; loop remaining 18-byte chunks into AddrPorts. NOTE the Go decode check
is `len(b) < udpRelayEndpointLenMinusAddrPorts+epLength` — i.e. requires at
least ONE addrport. Replicate exactly.

### Errors & API shape

- `#[derive(Debug, thiserror::Error)] pub enum DiscoError { #[error("short
  message")] Short, #[error("unknown message type 0x{0:02x}")] UnknownType(u8),
  ... }`
- `pub enum Message { Ping(Ping), Pong(Pong), CallMeMaybe(CallMeMaybe),
  BindUDPRelayEndpoint(BindUDPRelayEndpoint),
  BindUDPRelayEndpointChallenge(BindUDPRelayEndpointChallenge),
  BindUDPRelayEndpointAnswer(BindUDPRelayEndpointAnswer),
  CallMeMaybeVia(CallMeMaybeVia),
  AllocateUDPRelayEndpointRequest(AllocateUDPRelayEndpointRequest),
  AllocateUDPRelayEndpointResponse(AllocateUDPRelayEndpointResponse) }`
- Each message struct holds the fields above. Give them `Debug`, `Clone`,
  `PartialEq`, `Eq` where sane (AddrPort/Duration are Eq-able).
- `Message::marshal(&self) -> Vec<u8>` (payload only).
- `Message::parse(payload: &[u8]) -> Result<Message, DiscoError>`.
- `Message::summary(&self) -> String` (port `MessageSummary`).
- `pub const MAGIC: [u8; 6]`, `pub const KEY_LEN: usize = 32`,
  `pub const NONCE_LEN: usize = 24`, `pub const MESSAGE_HEADER_LEN: usize = 2`,
  plus the message type byte consts and the length consts (pub where useful).
- `pub fn looks_like_disco_wrapper(p: &[u8]) -> bool`,
  `pub fn source(p: &[u8]) -> Option<[u8; 32]>` (returns the 32 sender bytes).
- `pub fn seal_packet(sender: &DiscoPrivate, peer: &DiscoPublic, payload:
  &[u8]) -> Result<Vec<u8>, KeyError>`,
  `pub fn open_packet(receiver: &DiscoPrivate, packet: &[u8]) ->
  Option<(DiscoPublic, Vec<u8>)>`.

Define a small `AddrPort` type (or reuse `std::net::SocketAddr`): it needs
`As16` (16-byte v4-mapped-v6) encode/decode and BE port. If you define your own,
give it `From<SocketAddr>`, `to SocketAddr`, `Display` as `ip:port`, `Eq`,
`Debug`. Put it in a `wire` submodule. The Go `netip.AddrPort` v4 renders the
16 bytes as the v4-mapped form and `.Unmap()` turns it back into a v4 Addr.

### Tests (crates/disco)

1. **Golden byte vectors** — replicate disco_test.go `TestMarshalAndParse`
   EXACTLY. The `want` strings are space-separated hex of the marshaled payload
   (type+ver+body, NO envelope). Build each message with the same field values
   (note the Go `{1: 1, 2: 2, 30: 30, 31: 31}` slice literal means a 32-byte
   array with those indices set — construct `[u8;32]` with index 1=1,2=2,30=30,
   31=31). Assert `hex::encode(marshal())` matches the golden (strip spaces).
   Then parse back and assert equality. Cases: `ping`, `ping_with_nodekey_src`,
   `ping_with_padding`, `ping_with_padding_and_nodekey_src`, `pong`, `pongv6`,
   `call_me_maybe`, `call_me_maybe_endpoints`, `bind_udp_relay_endpoint`,
   `bind_udp_relay_endpoint_challenge`, `bind_udp_relay_endpoint_answer`,
   `call_me_maybe_via`, `allocate_udp_relay_endpoint_request`,
   `allocate_udp_relay_endpoint_response`.
   The Go test appends to `"foo"` first then strips it — you can skip that and
   just marshal to a fresh Vec.
2. **Roundtrip** for each message type (marshal -> parse -> eq).
3. **Full seal/open packet test**: generate two DiscoPrivate, seal a Ping
   payload from A to B, open with B, assert the parsed message matches. Also
   assert open fails with wrong key and that `looks_like_disco_wrapper`/`source`
   behave correctly.
4. **Error cases**: parse of <2 bytes -> Short; unknown type byte -> UnknownType.

### disco Cargo.toml

```toml
[package]
name = "rustscale-disco"
description = "Tailscale disco NAT-traversal message codec for rustscale"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true

[dependencies]
rustscale-key = { path = "../key", version = "0.1.0" }
thiserror.workspace = true
hex.workspace = true

[dev-dependencies]
serde_json.workspace = true
```
(Add `bytes` if you use it; you may not need it — `Vec<u8>` is fine.)

---

## CRATE 2: crates/derp

Port the DERP client protocol from the Go reference:
- `/Users/rajsingh/Documents/GitHub/tailscale/derp/derp.go` — frame types/constants, frame codec.
- `/Users/rajsingh/Documents/GitHub/tailscale/derp/derp_client.go` — client handshake + Recv/Send.
- `/Users/rajsingh/Documents/GitHub/tailscale/derp/derphttp/derphttp_client.go` — HTTP upgrade flow.

### Frame codec (sync, no network — testable standalone)

From derp.go:
- `FrameHeaderLen = 5` (1 byte type + 4 byte BE u32 length). Length is the body
  length NOT including the 5-byte header.
- `MaxPacketSize = 64 << 10 = 65536`. `MaxInfoLen = 1 << 20`. `KeyLen = 32`.
  `NonceLen = 24`. `ProtocolVersion = 2`.
- `MAGIC = "DERP🔑"` = bytes `[0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91]`
  (8 bytes — UTF-8 of "DERP🔑"). Sent in the FrameServerKey frame.
- Frame types (copy the exact byte values): `FrameServerKey=0x01`,
  `FrameClientInfo=0x02`, `FrameServerInfo=0x03`, `FrameSendPacket=0x04`,
  `FrameRecvPacket=0x05`, `FrameKeepAlive=0x06`, `FrameNotePreferred=0x07`,
  `FramePeerGone=0x08`, `FramePeerPresent=0x09`, `FrameForwardPacket=0x0a`,
  `FrameWatchConns=0x10`, `FrameClosePeer=0x11`, `FramePing=0x12`,
  `FramePong=0x13`, `FrameHealth=0x14`, `FrameRestarting=0x15`.
- `PeerGoneReason`: `Disconnected=0x00`, `NotHere=0x01`, `MeshConnBroke=0xf0`.
- `PeerPresentFlags` bits: `IsRegular=1<<0`, `IsMeshPeer=1<<1`, `IsProber=1<<2`,
  `NotIdeal=1<<3`.
- HTTP headers: `IdealNodeHeader = "Ideal-Node"`, `FastStartHeader =
  "Derp-Fast-Start"`.

Provide a pure-sync frame codec module (`frame.rs`) operating on `&mut [u8]` /
`Vec<u8>` / `std::io::Read`/`Write` (or `bytes::Buf`/`BufMut`). Recommend:
- `pub fn write_frame_header<W: Write>(w: &mut W, t: FrameType, len: u32) ->
  io::Result<()>` — writes 1 byte type + 4 BE bytes.
- `pub fn write_frame<W: Write>(w: &mut W, t: FrameType, body: &[u8]) ->
  io::Result<()>` — header + body + flush (flush only if W is BufWriter; for
  generics, just write — caller flushes). Actually simplest: `write_frame_header`
  then write body; provide a `FrameWriter` wrapping a `BufWriter<W>` with
  `write_frame` that flushes.
- `pub fn read_frame_header<R: Read>(r: &mut R) -> io::Result<(FrameType, u32)>`
  — reads 5 bytes, returns (type, BE length).
- `pub fn read_frame<R: Read>(r: &mut R, max_size: u32, buf: &mut Vec<u8>) ->
  io::Result<(FrameType, u32)>` — read header, check len <= max_size, read body
  into buf. (Port `readFrame`; handle the short-buffer semantics — for our use
  just read exactly `len` bytes into `buf` and return (type, len).)

Keep the codec sync and independently unit-testable. Use `bytes` crate if
convenient, but `std::io` is fine too.

### Client handshake (sync core + async wrapper)

Port derp_client.go `recvServerKey` / `sendClientKey` / `Recv`:

**recvServerKey**: read a FrameServerKey frame; body must be >= 40 bytes
(8 magic + 32 pubkey) and start with the 8-byte DERP magic; extract the 32-byte
server NodePublic. (Allow longer frames for fwd compat — if len > 40 that's ok
as long as first 40 are valid; match Go's `io.ErrShortBuffer` tolerance.)

**sendClientKey**: marshal `ClientInfo` as JSON `{Version, MeshKey, CanAckPings,
IsProber}` (use serde; field names match Go json tags: `meshKey,omitempty,
omitzero`, `version,omitempty`, `CanAckPings` (no tag => "CanAckPings"),
`IsProber` with `",omitempty"`). Actually CHECK the Go json tags in
derp_client.go lines 165-182:
  - `MeshKey` `json:"meshKey,omitempty,omitzero"`
  - `Version` `json:"version,omitempty"`
  - `CanAckPings` (no tag => field name "CanAckPings")
  - `IsProber` `json:",omitempty"` => field name "IsProber", omitempty
So the Rust struct needs `#[serde(rename = "meshKey", default,
skip_serializing_if = "...zero...")]` etc. MeshKey is `[16;u8]` (DERPMesh is
16 bytes) — represent as a `MeshKey([u8;16])` newtype with serde as a hex string
or base64? CHECK: Go `key.DERPMesh` marshals as... it's `[16]byte` with a
`MarshalText`/`UnmarshalText` that outputs hex. Look at
`/Users/rajsingh/Documents/GitHub/tailscale/types/key/derpmesh.go` if unsure.
For our client, MeshKey is usually empty/zero, so default-skip is fine. Represent
it as `Option<[u8;16]>` or a newtype that serializes as hex and skips when zero.
Then `seal_to(server_key, json_bytes)` -> `nonce(24)||ct`. Build the
FrameClientInfo body: `public_key(32) ++ msgbox`. Write the frame.
`Version = ProtocolVersion = 2`.

**recv loop / ReceivedMessage enum**: port the `Recv` switch. Define:
```
pub enum Received {
    ServerInfo(ServerInfo),
    ReceivedPacket { source: NodePublic, data: Vec<u8> },
    KeepAlive,
    PeerGone { peer: NodePublic, reason: PeerGoneReason },
    PeerPresent { key: NodePublic, ip_port: Option<SocketAddr>, flags: PeerPresentFlags },
    Ping([u8;8]),
    Pong([u8;8]),
    Health { problem: String },
    Restarting { reconnect_in: Duration, try_for: Duration },
}
```
For FrameRecvPacket (v2): body = 32-byte src pubkey + data. For FramePeerGone:
32-byte peer + optional 1-byte reason (default Disconnected if absent). For
FramePeerPresent: 32 key + optional 16+2 ip:port + optional 1 flags byte (use
cutLeadingN semantics — return what's present). For FramePing/Pong: 8 bytes.
For FrameHealth: body as UTF-8 string. For FrameRestarting: 4 BE u32 reconnect_ms
+ 4 BE u32 try_for_ms -> Durations. For FrameKeepAlive: empty. For
FrameServerInfo: `nonce(24)||box` sealed from serverKey to... actually it's
`privateKey.OpenFrom(serverKey, b)` — open with our private key from server key.
Parse JSON `{version, TokenBucketBytesPerSecond, TokenBucketBytesBurst}`.

**send methods**: `send_packet(dst: NodePublic, pkt: &[u8])` (FrameSendPacket:
32 dst + pkt, reject > MaxPacketSize), `forward_packet(src, dst, pkt)`
(FrameForwardPacket: 32 src + 32 dst + pkt), `note_preferred(bool)`
(FrameNotePreferred 1 byte 0x00/0x01), `send_ping([u8;8])`, `send_pong([u8;8])`,
`watch_conns()`, `close_peer(NodePublic)`.

### Async derphttp client (tokio + rustls)

Port derphttp_client.go's connect flow, but async. API:
```
pub struct DerpClient { /* tokio frame reader/writer over the stream, server key, our keys */ }
impl DerpClient {
    pub async fn connect(host: &str, port: u16, use_tls: bool, private_key: NodePrivate) -> Result<DerpClient, DerpError>;
    pub async fn send_packet(&mut self, dst: NodePublic, pkt: &[u8]) -> Result<(), DerpError>;
    pub async fn recv(&mut self) -> Result<Received, DerpError>;
    pub async fn note_preferred(&mut self, preferred: bool) -> Result<(), DerpError>;
    pub async fn send_ping(&mut self, data: [u8;8]) -> Result<(), DerpError>;
    pub async fn send_pong(&mut self, data: [u8;8]) -> Result<(), DerpError>;
    pub fn server_public_key(&self) -> NodePublic;
}
```
Connect flow:
1. TCP connect to `host:port` (tokio::net::TcpStream). If `use_tls`, wrap with
   `tokio_rustls::TlsConnector` + `webpki_roots::TLS_SERVER_ROOTS`. Use SNI =
   host.
2. Send HTTP upgrade request: `GET /derp HTTP/1.1\r\nHost: {host}\r\nUpgrade:
   DERP\r\nConnection: Upgrade\r\n\r\n` (also send `Derp-Fast-Start: 1` to
   suppress the HTTP response, matching the fast-start path — this lets us
   start the DERP protocol immediately without reading a 101). Actually: to keep
   it simple and match the fast-start path, send the request WITH
   `Derp-Fast-Start: 1` and do NOT read the HTTP response (the server hijacks
   and starts speaking DERP). If not using fast-start, read the HTTP 101
   response. Support both via a flag; default to fast-start=true for the client.
   Read derphttp_client.go lines 505-555 for the exact request shape.
3. After the upgrade, run the DERP handshake: read FrameServerKey (8 magic + 32
   server key), send FrameClientInfo (32 pub + sealed ClientInfo JSON), then
   optionally read FrameServerInfo.
4. Return the DerpClient holding the framed stream.

Use `tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter}` and the
sync frame codec via a thin async adapter (read 5 bytes, read body; write
header+body+flush). You can implement `read_frame_async`/`write_frame_async`
helpers operating on `tokio::io::AsyncRead`/`AsyncWrite`. Keep the pure frame
codec sync and call it from async glue where convenient, OR duplicate the logic
in async helpers — either is fine, but the SYNC codec MUST be independently
testable (unit tests with `std::io::Cursor`).

### Errors

`#[derive(Debug, thiserror::Error)] pub enum DerpError { Io(#[from] io::Error),
Tls(#[from] tokio_rustls::rustls::Error ...), BadFrame(String), BadMagic,
ShortFrame, BadServerInfo(String), Json(#[from] serde_json::Error),
Key(#[from] rustscale_key::KeyError), ... }` Use `#[from]` where the dep allows.

### Tests (crates/derp)

1. **Frame codec roundtrips** (sync, `std::io::Cursor`): for every frame type,
   write_frame then read_frame and assert type + body match. Use the golden
   header bytes from derp_test.go `TestWriteFrameHeader` / `TestReadFrameHeader`
   (e.g. `{0x04, 0x00, 0x00, 0x04, 0x00}` for SendPacket len 1024;
   `{0x06,0,0,0,0}` KeepAlive; `{0x05,0xff,0xff,0xff,0xff}` RecvPacket max).
2. **Handshake over a tokio duplex stream**: implement a minimal fake DERP
   server in the test that speaks the REAL byte protocol:
   - Generate a server NodePrivate; on connect send FrameServerKey (8 magic +
     32 server pub).
   - Read the client's FrameClientInfo (32 pub + nonce24+box); open with
     server's NodePrivate from the client's public key; parse ClientInfo JSON;
     assert version == 2.
   - Send a FrameServerInfo (sealed) — or skip if fast-start.
   - Echo: when the client sends a FrameSendPacket (32 dst + pkt), the server
     sends back a FrameRecvPacket (32 src=client_pub + same pkt).
   - Client asserts it received `Received::ReceivedPacket{source, data}` with
     the right values.
   - Also test: server sends FramePeerGone (32 peer + 1 reason) -> client gets
     PeerGone; server sends FramePing(8 bytes) -> client gets Ping; server sends
     FrameHealth("dup") -> client gets Health{problem:"dup"}.
   Use `tokio::io::duplex(8192)` — NO real network. The fake server task reads
   frames using the same codec. Verify the handshake keys actually authenticate
   (the server opens the client's box with the real NodePrivate — proving
   wire-compat with the Go protocol).
3. **Send packet rejects oversize**: `send_packet` with > MaxPacketSize bytes
   returns an error.

### derp Cargo.toml

```toml
[package]
name = "rustscale-derp"
description = "DERP relay client protocol for rustscale"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true

[dependencies]
rustscale-key = { path = "../key", version = "0.1.0" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio.workspace = true
tokio-rustls = "0.26"
webpki-roots = "0.26"
bytes = "1"

[dev-dependencies]
tokio.workspace = true
```
(Adjust versions as needed to resolve cleanly. `tokio-rustls` 0.26 + `rustls`
0.23 + `webpki-roots` 0.26 is a known-good combo. If you need `rustls` directly,
add it. `http`/`httparse` only if you implement HTTP response parsing — with
fast-start you may not need them, so only add if used.)

---

## Acceptance criteria — RUN THESE YOURSELF and fix everything until clean

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```
ALL must pass with zero warnings (the workspace forbids unsafe_code and uses
pedantic clippy). Idiomatic Rust, `thiserror` errors, NO `.unwrap()`/`.expect()`
OUTSIDE tests (use `?` and proper error handling). Inside tests `.unwrap()` is
fine. Do not leave `TODO`/`unimplemented!`/`panic!` in non-test code. Match the
existing crate style (module docs `//!`, `#![forbid(unsafe_code)]`, pub re-exports
in lib.rs). Reproduce the Go wire formats BYTE-FOR-BYTE — the golden disco test
vectors are your proof. For DERP, the fake-server handshake test proves wire
compat.

## Key reminders

- READ the Go files yourself (paths above) — they are the source of truth. Read
  `crates/key/src/*.rs` to reuse the existing key/box APIs.
- Do NOT modify the Go reference repo or any crate outside `crates/disco` and
  `crates/derp` (and the root `Cargo.toml` for new deps).
- `crates/disco` depends on `rustscale-key` only. `crates/derp` depends on
  `rustscale-key`, serde, serde_json, tokio, tokio-rustls, webpki-roots, bytes,
  thiserror.
- After writing, run `cargo build --workspace && cargo test --workspace &&
  cargo clippy --workspace --all-targets` yourself and iterate until all clean.
  Paste any compile errors back into your own reasoning and fix them.
