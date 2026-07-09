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
