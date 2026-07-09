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
