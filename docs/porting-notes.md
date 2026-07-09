# Porting notes — condensed reference facts

Distilled from porting the Go Tailscale sources to Rust so future build agents
don't re-read large Go files for facts already established. Source paths are
under `/Users/rajsingh/Documents/GitHub/tailscale`.

## Key text format (`types/key/*.go`)

All keys are 32-byte X25519 (node/machine) or X25519 (disco). Serialized text
form is `<prefix>:<64 hex lowercase>`. 32 raw bytes = 64 hex chars.

| Go type            | private prefix | public prefix  | binary prefix | raw len |
|--------------------|----------------|----------------|---------------|---------|
| `NodePrivate/Public`   | `privkey:`     | `nodekey:`     | `np`          | 32      |
| `MachinePrivate/Public`| `privkey:`     | `mkey:`        | —             | 32      |
| `DiscoPrivate/Public`  | —              | `discokey:`    | —             | 32      |

Quirk: node and machine **private** keys share the `privkey:` prefix (only
the public prefixes disambiguate). `nodePrivateHexPrefix`/`machinePrivateHexPrefix`
are both literally `"privkey:"`.

Go helpers: `appendHexKey(b, prefix, k[:])` writes `prefix:hex`, `parseHex(dst, b, prefix)`
validates the prefix + decodes 64 hex into the 32-byte dest. The "bad old"
expired-node prefix is `badOldPrefix = [109,167,116,213,215,116]` (base64 → `bad01`).

## crypto_box API (Rust crate `crypto_box` 0.9)

The Go reference uses `golang.org/x/crypto/nacl/box` (XSalsa20-Poly1305 over
X25519). The Rust equivalent is the `crypto_box` crate with `SalsaBox`.

**Gotcha that cost a fix cycle**: `SecretKey::from_bytes` and
`PublicKey::from_bytes` take `[u8; 32]` **by value** (they `Copy`), not by
reference. Call as `SecretKey::from_bytes(*sk)` / `PublicKey::from_bytes(*pk)`.

Working pattern (see `crates/key/src/boxcrypto.rs`):
```rust
use crypto_box::{aead::{generic_array::GenericArray, Aead}, PublicKey, SecretKey, SalsaBox};
fn salsa(my_sk: &[u8;32], peer_pk: &[u8;32]) -> SalsaBox {
    let sk = SecretKey::from_bytes(*my_sk);       // by value
    let pk = PublicKey::from_bytes(*peer_pk);      // by value
    SalsaBox::new(&pk, &sk)
}
// seal: fresh 24-byte nonce, encrypt, output = nonce(24) || ciphertext
// open: split nonce = ct[..24], payload = ct[24..]; decrypt -> Option<Vec<u8>>
```
Wire format on the box itself: `nonce(24) || ciphertext` (nonce prepended).
`NONCE_LEN = 24`. Derive public from private: `PublicKey::from(&secret).to_bytes()`.

## disco wire format (`disco/disco.go`)

A discovery message on the wire:
```
magic          [6]byte   // "TS💬" = 0x54 53 f0 9f 92 ac
senderDiscoPub [32]byte  // sender's disco public key
nonce          [24]byte  // nacl box nonce
<box ciphertext ...>     // nacl-box-encrypted payload
```
`NonceLen = 24`, `keyLen = 32`. After decrypting the box, the inner payload is:
```
messageType    byte   // one of the Type* constants
messageVersion byte   // 0 for now; ignore trailing bytes
message-payload [...]byte
```
MessageType constants:
| name                              | value |
|-----------------------------------|-------|
| TypePing                          | 0x01  |
| TypePong                          | 0x02  |
| TypeCallMeMaybe                   | 0x03  |
| TypeBindUDPRelayEndpoint          | 0x04  |
| TypeBindUDPRelayEndpointChallenge | 0x05  |
| TypeBindUDPRelayEndpointAnswer    | 0x06  |
| TypeCallMeMaybeVia                | 0x07  |
| TypeAllocateUDPRelayEndpointRequest  | 0x08  |
| TypeAllocateUDPRelayEndpointResponse | 0x09  |

## tailcfg.go type → line map (`tailcfg/tailcfg.go`, 3631 lines)

The file is large. Use these line ranges instead of walking it blindly.

| Type / group        | starts ~line | Notes |
|---------------------|--------------|-------|
| `CapabilityVersion` | 47           | `int` alias; bumped each client change |
| `ID`, `UserID`, `LoginID`, `NodeID` | 203–236 | all `int64` aliases; `IsZero()` helpers |
| `StableNodeID`      | 250          | string alias |
| `User` / `Login` / `UserProfile` | 267–321 | |
| `RawMessage`        | 322          | string holding raw JSON; custom Marshal/UnmarshalJSON |
| **`Node`**          | **351**      | the big one; ~190 fields through line ~540 |
| `MachineStatus`     | 654          | enum; MarshalText/UnmarshalText |
| `Service` / `Location` | 783–845    | |
| **`Hostinfo`**      | **848**      | ~80 fields through ~930 |
| `TPMInfo`           | 931          | |
| `VIPService`        | 1010         | |
| **`NetInfo`**       | **1036**     | network probe results; ~68 fields |
| `SignatureType`     | 1180         | enum with text marshaling |
| `RegisterResponseAuth` | 1247      | |
| **`RegisterRequest`**  | **1261**   | ~54 fields through ~1314 |
| **`RegisterResponse`** | **1315**   | ~17 fields through ~1331 |
| `EndpointType` / **`Endpoint`** | 1332–1378 | |
| **`MapRequest`**    | **1379**     | ~115 fields through ~1493 |
| `PortRange` / `NetPortRange` | 1494–1523 | |
| `CapGrant` / `PeerCapability` | 1524–1595 | |
| `NodeCapMap`        | 1596         | `map[NodeCapability][]RawMessage` |
| `FilterRule`        | 1684         | ACL rule |
| **`DNSConfig`** / `DNSRecord` | 1753–1863 | |
| `PingRequest` / `PingResponse` | 1864–1970 | |
| **`MapResponse`**   | **1971**     | ~210 fields through ~2184 — second biggest struct |
| `ClientVersion`     | 2268         | |
| `ControlDialPlan`   | 2300         | |
| `Debug`             | 2336         | |
| `SetDNSRequest`/`Response` | 2880–2913 | |
| `SSHPolicy`/`SSHRule`/`SSHPrincipal`/`SSHAction` | 2958–3101 | |
| **`PeerChange`**    | **3311**     | incremental peer update |
| `EarlyNoise`        | 3367         | noise handshake setup |

## opt.Bool (`types/opt/bool.go`)

Tri-state boolean for "unset / true / false". Marshals to JSON as `"true"` /
`"false"`, and **omits entirely when unset** (custom MarshalJSON returns null +
omits via `*bool`-style). In Rust, model as `Option<bool>` with
`#[serde(skip_serializing_if = "Option::is_none")]`; for fields that must
default, `#[serde(default)]`. The `is_unset()` helper returns true when None.

## Lint policy (already in workspace `Cargo.toml`)

`unsafe_code = "forbid"`, clippy `pedantic = warn` with the noisier lints
allowed workspace-wide (`doc_markdown`, `module_name_repetitions`,
`must_use_candidate`, `cast_*`, `needless_pass_by_value`, etc.).

**Crate-specific**: `crates/tailcfg` sets `#![allow(non_snake_case)]` because
its structs mirror Go's PascalCase JSON wire field names verbatim. Any crate
that mirrors Go wire types should do the same up front to avoid a lint storm.

## Noise IK crypto crates (controlbase, ts2021)

The control protocol uses `Noise_IK_25519_ChaChaPoly_BLAKE2s`. Three Rust
crates cover it; versions are pinned in the workspace `Cargo.toml`.

### `curve25519-dalek` 4.x — X25519 DH

```rust
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint};
// X25519(priv, pub):  MontgomeryPoint(pub).mul_clamped(*priv) -> [u8;32]
fn x25519(priv: &[u8;32], pub_: &[u8;32]) -> [u8;32] {
    MontgomeryPoint(*pub_).mul_clamped(*priv).0      // .0 extracts [u8;32]
}
// basepoint mult (derive public from private):
X25519_BASEPOINT.mul_clamped(*priv).0
```
`mul_clamped` takes `[u8;32]` **by value** (Copy). No `from_bytes` needed.

### `chacha20poly1305` 0.10 — AEAD

```rust
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
// Go uses standard ChaCha20Poly1305 with a 12-byte all-zero nonce — NOT XChaCha20.
let cipher = ChaCha20Poly1305::new(key.into());       // key: &[u8;32] via GenericArray
let nonce = Nonce::from_slice(&[0u8; 12]);            // 12-byte, not 24
let ct = cipher.encrypt(nonce, Payload{ msg: plaintext, aad: &h })?;
let pt = cipher.decrypt(nonce, Payload{ msg: ct, aad: &h })?;
```
**Gotcha that cost fix cycles**: use `Aead` trait (not `AeadInPlace`) for
encrypt/decrypt. Use `ChaCha20Poly1305` (12-byte nonce), not
`XChaCha20Poly1305` (24-byte nonce). The `Nonce` type is `GenericArray<u8,
U12>`; `Nonce::from_slice(&[0u8;12])` works.

### `blake2` 0.10 — BLAKE2s-256 hash + HMAC + HKDF

```rust
use blake2::{Blake2s256, Digest};         // Blake2s256 = 32-byte output
let h = Blake2s256::new();
blake2::digest::Update::update(&mut hasher, data);  // or `hasher.update(data)` if Digest is in scope
let out: [u8;32] = hasher.finalize().into();
```
**Critical gotcha**: the `hkdf` crate (0.12) does NOT work with `blake2` 0.10
(BufferKind mismatch). HMAC-BLAKE2s + HKDF must be hand-rolled:
- `hmac_blake2s(key, data)`: RFC 2104 with 64-byte block, 32-byte output.
- `hkdf_blake2s(salt, ikm, info, out)`: RFC 5869 extract+expand.
See `crates/controlclient/src/controlbase.rs:110-180` for the working
implementation. **Do not add `hkdf` or `digest` to Cargo.toml** — just `blake2`.

### Noise IK wire format (from Go `controlbase/messages.go`)

Initiation (client→server, 101 bytes):
```
u16 BE  protocol version
u8      message type (1)
u16 BE  payload length (96)
[32]    client ephemeral public key (cleartext)
[48]    client machine public key (ChaCha20Poly1305 encrypted + 16-byte tag)
[16]    tag (empty-payload auth)
```
Response (server→client, 51 bytes):
```
u8      message type (2)
u16 BE  payload length (48)
[32]    server ephemeral public key (cleartext)
[16]    tag
```
Post-handshake records:
```
u8      message type (4)
u16 BE  ciphertext length
[N]     ChaCha20Poly1305 ciphertext, 12-byte BE nonce incrementing per record
```
Limits: `MAX_MESSAGE_SIZE = 4096`, `MAX_PLAINTEXT = 4096 - 3 - 16 = 4077`.

## boringtun API (`crates/wg`, WireGuard data plane)

The `boringtun` crate (0.7) provides `noise::Tunn` — a per-peer WireGuard
state machine. We wrap it; the caller (magicsock) moves UDP/DERP datagrams.

**Do NOT fetch docs.rs** — the API is small. Here it is:

```rust
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

// Constructor: Tunn::new(own_static_secret, peer_public_key, None, None, index, None)
//   - StaticSecret::from([u8;32])   — via From<[u8;32]>
//   - PublicKey::from([u8;32])      — via From<[u8;32]>
//   - index: u32 (caller-chosen unique per-peer index for rate limiter)
let tunn = Tunn::new(StaticSecret::from(*priv_bytes),
                     PublicKey::from(*pub_bytes), None, None, 0, None);

// Encapsulate: plaintext IP packet → WG ciphertext datagrams
let mut dst = vec![0u8; src.len() + 32];  // min 148 bytes
match tunn.encapsulate(plaintext, &mut dst) {
    TunnResult::WriteToNetwork(buf) => { /* send buf over transport */ }
    TunnResult::Done => { /* nothing to send */ }
    TunnResult::Err(e) => { /* non-fatal protocol error */ }
    TunnResult::WriteToTunnelV4(_,_) | TunnResult::WriteToTunnelV6(_,_) => { /* shouldn't happen on encap */ }
}

// Decapsulate: incoming WG datagram → plaintext IP packet + replies
// After WriteToNetwork, MUST re-call decapsulate with empty &[] until Done.
match tunn.decapsulate(None, datagram, &mut dst) {
    TunnResult::WriteToNetwork(buf) => { /* reply to send; re-call with &[] */ }
    TunnResult::WriteToTunnelV4(buf,_) | TunnResult::WriteToTunnelV6(buf,_) => { /* plaintext IP packet */ }
    TunnResult::Done => { /* stop loop */ }
    TunnResult::Err(_) => { /* non-fatal, stop */ }
}

// Timer tick (~250ms): produces keepalives / retransmissions
while let TunnResult::WriteToNetwork(buf) = tunn.update_timers(&mut dst) { /* send buf */ }

// Force handshake initiation
tunn.format_handshake_initiation(&mut dst, false);  // false = not force-amplification

// Helpers
tunn.is_expired() -> bool;
tunn.time_since_last_handshake() -> Option<Duration>;
Tunn::dst_address(ip_packet) -> Option<IpAddr>;     // associated fn, parses dst IP
```

Key conversion from our types: `NodePrivate::raw32()` / `NodePublic::raw32()`
→ `[u8;32]` → `StaticSecret::from(...)` / `PublicKey::from(...)`.

## Go source file maps (for targeted reads)

### `net/netcheck/netcheck.go` (1759 lines)

| Type / function        | starts ~line | Notes |
|------------------------|--------------|-------|
| `var`/`const` blocks   | 52           | max probes, timeouts |
| **`Report`**           | **90**       | network probe results struct (~80 fields) |
| `Report` methods       | 136–191      | GetGlobalAddrs, AnyPortMapping, Clone |
| **`Client`**           | **193**      | the netcheck client struct |
| `enoughRegions`/`logf` | 248–282      | internal helpers |
| `probeProto` enum      | 336          | probeProtocolICMP/HTTPS/STUN |
| `probe` struct         | 356          | single probe descriptor |
| `probePlan`            | 386          | map of region→probes |
| `makeProbePlan`        | 435          | builds the probe schedule |
| `reportState`          | 593          | in-flight report accumulator |
| **`GetReport`**        | **800**      | main entry point (~220 lines) |
| `finishAndStoreReport` | 1024         | |
| `runHTTPOnlyChecks`    | 1037         | fallback when UDP blocked |
| `measureHTTPSLatency`  | 1107         | HTTPS DERP probe |
| `measureICMPLatency`   | 1188/1233    | ICMP probe |
| `addReportHistory`     | 1384         | preferred-DERP selection |
| `runProbe`             | 1546         | per-probe execution |

### `control/controlbase/` (3 files, ~990 lines total)

| File           | Lines | Key types/functions |
|----------------|-------|---------------------|
| `handshake.go` | 494   | `ClientDeferred` (68), `Client` (109), `Server` (201), `symmetricState` (328), `Initialize`/`MixHash`/`MixKey`/`EncryptAndHash`/`DecryptAndHash`/`Split` (342+) |
| `conn.go`      | 409   | `Conn` (41), `Read` (242), `Write` (270), `Close` (324), nonce incrementing (133/162) |
| `messages.go`  | 87    | `initiationMessage` [101]byte (39), `responseMessage` [51]byte (71), header/payload accessors |

### `control/controlhttp/client.go` (581 lines)

| Function            | ~line | Notes |
|---------------------|-------|-------|
| `Dialer.Dial`       | 67    | top-level entry |
| `Dialer.dial`       | 98    | tries HTTP then HTTPS |
| `Dialer.dialHost`   | 227   | per-host dial |
| `tryURLUpgrade`     | 405   | the /ts2021 HTTP upgrade dance (POST, Upgrade header, base64 init in X-Tailscale-Handshake, parse 101) |

### `control/controlclient/direct.go` (2005 lines)

| Type / function        | ~line | Notes |
|------------------------|-------|-------|
| `Direct` struct        | 73    | the control client state |
| `Options`              | 138   | constructor config |
| `NewDirect`            | 301   | constructor |
| `TryLogin`/`doLogin`   | 559/663 | registration flow |
| `SetEndpoints`         | 954   | endpoint update |

### `control/ts2021/client.go` (317 lines)

| Type / function  | ~line | Notes |
|------------------|-------|-------|
| `Client`         | 38    | wraps a Noise `Conn` |
| `ClientOpts`     | 57    | |
| `NewClient`      | 107   | |
| `dial`           | 200   | Noise dial + upgrade |
| `Post`/`DoWithBody` | 294/298 | HTTP-over-Noise requests |

### `wgengine/magicsock/` (17K lines across files)

| File              | Lines | Key contents |
|-------------------|-------|---------------|
| **`magicsock.go`** | 4594  | `Conn` (157), `Options` (449), `NewConn` (639), `updateEndpoints` (888), `determineEndpoints` (1285) |
| **`endpoint.go`** | 2119  | per-peer endpoint state, disco ping/pong, path tracking |
| `relaymanager.go` | 1139  | peer relay (UDP relay) allocation + management |
| `derp.go`         | 1076  | DERP relay path send/recv |
| `endpoint_tracker.go` | 248 | endpoint change tracking |
| `peermap.go`      | 232   | node-key → endpoint map |
| `rebinding_conn.go` | 200 | UDP socket rebinding on network change |

**Phase-4 note**: the magicsock agent did NOT read these Go files — it used
boringtun docs + existing Rust crate APIs. For deeper magicsock porting
(disco pings, path selection, relay), read the specific line ranges above.

## Control-plane wire protocol (ts2021) — established live in phase 5

Every fact below was verified against the real `controlplane.tailscale.com`
during phase-5 e2e debugging. Re-read the Go sources only if you need a field
this summary omits. Source: `control/controlhttp/`, `control/controlbase/`,
`control/controlclient/direct.go`, `control/ts2021/`.

### Connection setup, in order

1. **Fetch the server's Noise public key over plain TLS** — `GET https://<control>/key?v=<capability_version>`.
   Response JSON: `{"publicKey":"mkey:...","legacyPublicKey":"mkey:..."}`. Use
   `publicKey` as the Noise `ControlKey` (the server's *machine* public key).
   Go: `loadServerPubKeys` in `direct.go:1533`. **This is NOT optional** — if you
   pass your own machine key as the control key, the server can't decrypt the
   initiation and closes the connection (EOF).

2. **HTTP/1.1 upgrade to `/ts2021`** — `POST https://<control>/ts2021` with
   headers `Upgrade: tailscale-control-protocol`, `Connection: upgrade`, and
   **`X-Tailscale-Handshake: <base64(initiation)>`**. The 101-byte Noise
   initiation message goes **base64-encoded in the `X-Tailscale-Handshake`
   request header**, NOT in the POST body and NOT after the 101. Header constant
   `HandshakeHeaderName = "X-Tailscale-Handshake"` (`controlhttpcommon`). Server
   replies `101 Switching Protocols` (parse the numeric code from the full
   status line — `"HTTP/1.1 101 ..."` does not `starts_with("101")`).

3. **Noise handshake response arrives on the upgraded stream** — the 51-byte
   server response is the first bytes after the `101` headers on the upgraded
   connection. If your byte-by-byte header reader over-reads past `\r\n\r\n`,
   prepend those trailing bytes to the Noise response read (Tailscale's Go
   client drains them from `resp.Body`; we capture them explicitly).

4. **Optional early payload before HTTP/2** — after the Noise handshake, the
   server MAY send 9 bytes before HTTP/2 begins. If the first 5 bytes are
   `\xff\xff\xffTS` (`EarlyPayloadMagic`), it's a JSON `EarlyNoise` message with
   a **4-byte BE** length prefix. Otherwise those 9 bytes are the server's first
   HTTP/2 frame (SETTINGS) and MUST be prepended back to the stream before h2.

5. **HTTP/2 runs inside the Noise tunnel** — the connection is NOT raw JSON
   frames. Go's `ts2021.Client` uses `http.Transport` with
   `SetUnencryptedHTTP2(true)` + a custom `DialTLSContext` returning the Noise
   `Conn`. In Rust: add the `h2` crate, wrap the Noise record stream in an
   `AsyncRead+AsyncWrite` adapter (`NoiseIo` in `controlbase.rs` — spawns two
   pump tasks bridging the duplex ↔ Noise record encrypt/decrypt), then
   `h2::client::handshake()`. The client sends the standard HTTP/2 preface
   (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + SETTINGS).

### Post-handshake record framing (controlbase)

Each Noise record on the wire: `u8 type (4=record) + u16 BE ciphertext-length +
ChaCha20Poly1305 ciphertext`. `MAX_MESSAGE_SIZE=4096`, `MAX_PLAINTEXT=4077`. The
12-byte AEAD nonce is BE, incrementing per record. The `NoiseIo` adapter hides
this from h2 by presenting a raw byte stream.

**tx/rx cipher direction (cost a real-server failure)**: after the IK `Split`,
Go **client** uses `tx=c1, rx=c2`; Go **server** uses `tx=c2, rx=c1`. If you
swap both sides consistently your own client/server unit tests pass but the real
server fails. Match Go's direction exactly.

**Protocol/Capability version = 141** (current as of phase 5). The version is
mixed into the Noise prologue as `"Tailscale Control Protocol v<version>"`.
`RegisterRequest.Version` is set to `CurrentCapabilityVersion` (141) right before
sending (Go sets `1` initially then overrides). The server accepts any version
in the initiation, but use current to avoid negotiation surprises.

### HTTP/2 requests inside the Noise tunnel

- **Register**: `POST /machine/register` with JSON `RegisterRequest` body →
  standard HTTP/2 request/response. Response body is JSON `RegisterResponse`.
  The authkey goes in `Auth: Option<RegisterResponseAuth>{ AuthKey }` — **not**
  a top-level field. Go: `request.Auth = &tailcfg.RegisterResponseAuth{AuthKey:
  authKey}` when `authKey != ""` (`direct.go:809`). Also set `NodeKey`,
  `OldNodeKey` (zero for first register), `Hostinfo`, `Version`, `Timestamp`.
  `ts2021.AddLBHeader` adds `X-Node-Key`/`X-Old-Node-Key` LB-routing headers.

- **Map poll**: `POST /machine/map` with JSON `MapRequest` body → HTTP/2 `200
  OK`, then the response body is a stream of **4-byte LE (little-endian)
  size-prefixed** JSON `MapResponse` messages. This is *application-level*
  framing within the HTTP/2 response body, not HTTP/2 frame framing. Read loop:
  `u32 LE length`, then `length` bytes of JSON, repeat until EOF/long-poll close.
  Utilities: `decode_map_frames` / `encode_map_frame` (`client.rs`).

### MapResponse semantics learned the hard way

- **`PeersChanged` carries the initial peer list, not `Peers`.** The control
  server sends peers via `PeersChanged` (the delta field) even in the FIRST
  `MapResponse`; `Peers` (the full list) is often empty. When bootstrapping from
  the first response you must check `PeersChanged` (fall back to it when `Peers`
  is empty). Subsequent responses stream deltas via `PeersChanged` + removals via
  `PeersRemoved`; merge by node key.

- **`KeepAlive` responses must be skipped** (`if resp.KeepAlive { continue; }`)
  — they carry no peer data and must not be processed as peer updates.

- **Go nil slices/maps marshal as JSON `null`**. Multiple `Vec` and `BTreeMap`
  fields in `MapResponse`/`Node`/`DERPMap` receive explicit `null` from the
  server. Rust `Vec<T>`/`BTreeMap` with `#[serde(default)]` only default when the
  field is *missing*, not on explicit `null` — deserialization fails with
  `"invalid type: null, expected a sequence"`. Fix: a `deserialize_null_to_default`
  helper (`Option<T>::deserialize(d)?.unwrap_or_default()`), applied to all
  server-received Vec/map fields. For `DERPMap.Regions` (int-keyed map) use a
  combined `deserialize_int_key_null`. `NodeCapMap` values can be `null` too →
  custom `deserialize_capmap`. And `RawMessage` must accept ANY JSON type
  (bool/num/null, not just strings) — use `serde_json::Value`, not
  `#[serde(transparent)]` over `String`.

- **DiscoKey + Endpoints must be pushed to the server BEFORE the streaming
  MapResponse.** The control server processes the MapRequest body
  asynchronously and generates the first streaming `MapResponse` from
  registration data (which lacks `DiscoKey` and `Endpoints`). Peers
  therefore see `DiscoKey=zero` and `Endpoints=[]` and can never initiate
  disco probing for a direct path. Fix: send a lightweight non-streaming
  `MapRequest` (`Stream=false, OmitPeers=true`) with `DiscoKey` +
  `Endpoints` BEFORE starting the streaming long-poll. The server processes
  this request, stores the DiscoKey/Endpoints, and the subsequent streaming
  `MapResponse` includes peers with non-zero `DiscoKey` and populated
  `Endpoints`. Without this, two nodes on the same machine stay on DERP
  forever (13 Mbps, 69ms p50) instead of going direct (782 Mbps, 10ms p50).
  Go avoids this because `updateControl` restarts the map poll when
  endpoints change, effectively re-sending the MapRequest with updated
  DiscoKey/Endpoints. The `MapRequest.Endpoints` field comment says
  "Ignored when Stream and Version>=68" — the server still processes
  DiscoKey from the MapRequest, but only when it's a fresh request, not
  when it's bundled into the initial streaming response generation.

- **Local interface endpoint gathering.** Go's `determineEndpoints`
  (`magicsock.go:1285`) enumerates local interfaces via `netmon.LocalAddresses`
  and pairs each up IPv4 address with the bound UDP port. Rustscale uses
  the `if-addrs` crate (`get_if_addrs()`) in `gather_local_endpoints()`
  (`magicsock/src/lib.rs`). Include LAN, tailnet, and loopback IPs —
  loopback is essential for same-machine direct paths.

### DERP relay connection

- **TLS SNI must use the DERP node `HostName`, not its IP.** Connecting TCP to
  the IP is fine, but the TLS `ServerName` must be the hostname (e.g.
  `derp1.tailscale.com`) — passing an IP gives `received fatal alert:
  InternalError`. So `connect_with_upgrade` takes separate TCP-dial-host and
  TLS-SNI-host params.

## rustls crypto provider (aws-lc-rs vs ring)

`rustls` and `tokio-rustls` default features include `aws_lc_rs`. If you add
`ring`, both providers compile in and rustls panics at runtime:
`"Could not automatically determine the process-level CryptoProvider"`. Fix at
the source:
```toml
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12", "logging"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring", "tls12", "logging"] }
```
Belt-and-suspenders: install the ring provider once via
`rustls::crypto::ring::default_provider().install_default()` guarded by
`std::sync::Once`, ignoring the `AlreadyInstalled` error. Called in
`tsnet::Server::up()`, `controlclient/src/controlhttp.rs`, `derp/src/client.rs`.

## TUN device platform API (`crates/tun`)

Established in phase 6. All needed constants are in the `libc` crate; no
`unsafe` is needed in our own source *except* the raw syscalls for utun, so the
`tun` crate sets `#![allow(unsafe_code)]` at the module level (workspace is
`forbid`).

### macOS — utun

1. `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL=2)` → fd.
2. `CTLIOCGINFO` ioctl with `"com.apple.net.utun_control"` → fills `ctl_info`
   (gives the 4-byte `ctl_id`).
3. `connect` with `sockaddr_ctl { sc_id: ctl_id, sc_len, sc_family: AF_SYSTEM,
   ss_sysaddr: AF_SYS_CONTROL, sc_unit: ifIndex+1, ... }`.
4. `getsockopt(fd, SYSPROTO_CONTROL=2, UTUN_OPT_IFNAME=2)` → interface name.
5. Set nonblocking; wrap fd in `tokio::io::AsyncFd`.
6. **4-byte AF header framing**: reads include it at the front — `buf[3]` is
   `AF_INET`(2) / `AF_INET6`(30); the actual packet starts at offset 4. Writes
   must prepend it: `buf[0..3] = 0`, `buf[3] = AF_INET|AF_INET6` chosen from
   `buf[4] >> 4` (the IP-version nibble of the first packet byte). Callers see
   plain IP packets — the crate strips/prepends the header internally.

### Linux — `/dev/net/tun`

`open("/dev/net/tun")` + `TUNSETIFF` ioctl with `IFF_TUN | IFF_NO_PI` → plain
packets, **no AF header**. `ifreq` struct via `libc::ifreq` (union access needs
`unsafe`). cfg-gated `#[cfg(target_os = "linux")]`; compiles on macOS but is
untestable there. Use `tokio::io::AsyncFd` for async IO.

### Routing into TUN mode

`Server::up_tun(TunModeConfig)` shares a `bootstrap()` with `up()`, then runs a
pump racing `tun.read_packet()` (→ longest-prefix route lookup over peer
`AllowedIPs`/`Addresses` via `RouteTable` → WG encapsulate → magicsock send)
against `magicsock.poll_recv()` (→ WG decapsulate → TUN write) and a 250ms WG
timer tick. `RouteTable` is longest-prefix-match; when `AllowedIPs` is empty
(Go sends `null` → empty after deserialize), fall back to `Addresses`.

## Packet filter (`crates/filter`) — phase 7

Go semantics replicated (see `crates/filter/src/lib.rs`): TCP non-SYN packets
always pass (only SYN is matched); UDP uses a 512-entry size-based LRU flow
cache keyed on the *reversed* 5-tuple (outbound records, inbound checks);
`localNets` prefilter drops packets whose dst IP isn't ours; `PacketFilters`
deltas keyed by name with a `"base"` default key (`"*"` with None clears all);
ICMP echo-reply/error always accepted, echo-requests match IPs only; `pre()`
handles multicast/link-local/fragment/unknown-proto before proto-specific logic.
For the rule/parse types see `crates/tailcfg/src/filter.rs`
(`FilterRule`, `NetPortRange`, `CapGrant`).

## Subnet routing + Serve (phase 10a)

### Subnet route advertisement

- `Hostinfo.RoutableIPs: Vec<String>` (CIDRs like `"192.0.2.0/24"`) is sent in
  both the `RegisterRequest` and `MapRequest` Hostinfo. Control must approve
  the routes (via `POST /api/v2/device/{id}/routes` with `{"routes":[...]}`)
  before peers see them in this node's `AllowedIPs`.
- `Node.PrimaryRoutes: Vec<String>` is the approved subset returned by control.
- Builder: `.advertise_routes(vec!["192.0.2.0/24".into()])` sets
  `Hostinfo.RoutableIPs`; `.accept_routes(true)` installs peer subnet routes.

### Route table accept_routes filtering

`RouteTable::from_peers_with_opts(peers, accept_routes)`:
- `accept_routes=false` (default): only prefixes within tailnet ranges
  (100.64.0.0/10 v4, fd7a:115c:a1e0::/48 v6) are installed.
- `accept_routes=true`: all `AllowedIPs`/`Addresses` prefixes installed,
  including peer-advertised subnet CIDRs.
- The tailnet range check is `is_tailnet_prefix(net, prefix)` in routing.rs.
- `rebuild_with_opts` / `rebuild` (preserves the previous accept_routes flag).

### Filter + subnet routes

`Filter::add_local_cidrs(&[cidr_strings])` extends the localNets prefilter
with advertised subnet routes so the filter admits packets destined to those
subnets (normally the prefilter drops packets whose dst isn't a local tailnet
IP). Called in `bootstrap()` and `rebuild_filter()` when advertise_routes is
non-empty. See `crates/filter/src/lib.rs`.

### TLS (listen_tls) — self-signed per node

- `CertProvider` trait (object-safe, `Send + Sync`): `cert_chain()` →
  `Vec<CertificateDer<'static>>`, `private_key()` → `PrivateKeyDer<'static>`.
  Future LE-via-control impl drops in behind the same trait.
- `SelfSignedCertProvider` uses `rcgen` (0.13, ring backend) to generate a
  self-signed cert in-process. **Self-signed at this stage** — clients must
  skip verification.
- `TlsListener` wraps a netstack `Listener` with `tokio_rustls::TlsAcceptor`.
- `TlsStream` is a concrete newtype over `tokio_rustls::server::TlsStream<NetstackStream>`.
- **C-representable**: both are concrete structs (no generics), usable behind
  opaque FFI handles.

### rcgen 0.13 API (ring backend)

```toml
rcgen = { version = "0.13", default-features = false, features = ["ring", "pem"] }
```
```rust
use rcgen::{generate_simple_self_signed, CertifiedKey};
let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec!["localhost".into()])?;
let cert_chain = vec![cert.der().clone()]; // CertificateDer<'static>
let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
```
`cert.der()` returns `&CertificateDer<'static>` (rustls pki_types).
`key_pair.serialize_der()` returns `Vec<u8>` (PKCS#8 private key DER).

### Dangerous TLS client verifier (test only)

For tests connecting to a self-signed `listen_tls` server, use
`rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(...)`
with a `ServerCertVerifier` that returns `Ok(ServerCertVerified::assertion())`
from `verify_server_cert` and `Ok(HandshakeSignatureValid::assertion())` from
`verify_tls12/13_signature`. The `verify_server_cert` signature in rustls 0.23
takes 6 params: `(end_entity, intermediates, server_name, ocsp_response, now)`.
See `dangerous_client_config()` in `crates/tsnet/src/tests.rs`.

### API route approval (e2e helper)

`POST /api/v2/device/{deviceId}/routes` with `{"routes":["192.0.2.0/24"]}`
approves advertised routes. The device ID comes from
`GET /api/v2/tailnet/{tailnet}/devices` (match by hostname). Uses
`TS_E2E_API_TOKEN` (the child tailnet token from e2e.sh).

### Serve example

`crates/tsnet/examples/rustscale-serve.rs` — serves HTTP (plain + `--tls`)
with `/bench` endpoint streaming N MB (`--bytes`). Flags: `--authkey`,
`--hostname`, `--port`, `--bytes`, `--tls`.
