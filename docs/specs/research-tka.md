# TKA (Tailnet Lock) Client-Side Verification — Research Digest

**Goal:** Pre-digest Go sources so a future coding agent can port a minimal TKA
client (verify-only, no signing/mutation) into `crates/tka`.

---

## Go Source Inventory (`tailscale/tka/`)

| File | Build Tag | Lines | Purpose |
|------|-----------|-------|---------|
| `aum.go` | `!ts_omit_tailnetlock` | 361 | AUM type (CBOR, BLAKE2s hash, sig hash, weight, serialize/deserialize, static validation) |
| `builder.go` | `!ts_omit_tailnetlock` | ~200 | `UpdateBuilder` + `Signer` interface for constructing signed AUMs (NOT needed for verify-only) |
| `deeplink.go` | `!ts_omit_tailnetlock` | 223 | `tailscale://sign-device` HMAC deeplinks (NOT needed for verify-only) |
| `disabled_stub.go` | `ts_omit_tailnetlock` | ~50 | Stub types when TKA compiled out |
| `key.go` | *(none)* | 134 | `Key` (Kind, Votes, Public, Meta), KeyID == ed25519 public bytes, 32 bytes |
| `limits.go` | *(none)* | 35 | Constants: max 32 disablement values, 512 keys, 512 meta bytes, 2000 scan/sync iter, 400 head-intersection iter |
| `sig.go` | `!ts_omit_tailnetlock` | 498 | `NodeKeySignature` — the **critical** file: `SigKind` (Direct/Rotation/Credential), CBOR, `SigHash()`, `verifySignature()`, `ResignNKS`, `SignByCredential`, `DecodeWrappedAuthkey` |
| `state.go` | `!ts_omit_tailnetlock` | 331 | `State` (LastAUMHash, DisablementValues, Keys, StateID1/2), `applyVerifiedAUM()`, `checkDisablement()`, `GetKey()` |
| `sync.go` | `!ts_omit_tailnetlock` | 276 | `SyncOffer`, `ComputeMissingAUMS`, `ToSyncOffer`/`FromSyncOffer` — peer-to-peer state convergence |
| `tailchonk.go` | `!ts_omit_tailnetlock` | 977 | `Chonk` interface (AUM storage), `Mem` + `FS` implementations, compaction |
| `tka.go` | `!ts_omit_tailnetlock` | 860 | **Central** `Authority` type: `Open`, `Bootstrap`, `Create`, `Inform`, `InformIdempotent`, `NodeKeyAuthorized`, `NodeKeyAuthorizedWithDetails`, `ValidDisablement`, fork resolution (`pickNextAUM`), chain computation |
| `verify.go` | `!ts_omit_tailnetlock` | 36 | `signatureVerify()` — wraps ed25519consensus over AUM BLAKE2s digest |
| `tka_clone.go` | *(none)* | ~80 | Generated deep-copy helper for NodeKeySignature |

---

## AUM CBOR Wire Format (field table)

From `aum.go:132-156`:

```go
type AUM struct {
    MessageKind AUMKind              `cbor:"1,keyasint"`  // uint8 (0=Invalid, 1=AddKey, 2=RemoveKey, 3=NoOp, 4=UpdateKey, 5=Checkpoint)
    PrevAUMHash PrevAUMHash          `cbor:"2,keyasint"`  // []byte, nil for genesis
    Key         *Key                 `cbor:"3,keyasint,omitempty"`  // for AddKey
    KeyID       tkatype.KeyID        `cbor:"4,keyasint,omitempty"`  // for RemoveKey/UpdateKey
    State       *State               `cbor:"5,keyasint,omitempty"`  // for Checkpoint
    Votes       *uint                `cbor:"6,keyasint,omitempty"`  // for UpdateKey
    Meta        map[string]string    `cbor:"7,keyasint,omitempty"`  // for UpdateKey
    Signatures  []tkatype.Signature  `cbor:"23,keyasint,omitempty"`
}
```

`tkatype.Signature` (from `/types/tkatype/tkatype.go`):
```go
type Signature struct {
    KeyID     KeyID  `cbor:"1,keyasint"`  // 32 bytes (ed25519 public key)
    Signature []byte `cbor:"2,keyasint"`  // ed25519 sig (64 bytes)
}
```

Key CBOR encoding rules (from `tka.go:23-32`):
- CTAP2 canonical CBOR (deterministic, no indefinite length, no tags, max 16 nesting levels)
- Duplicate map keys forbidden

### AUM Hashing

```go
func (a *AUM) Hash() AUMHash {
    return blake2s.Sum256(a.Serialize())               // ALL fields incl signatures
}

func (a AUM) SigHash() tkatype.AUMSigHash {
    dupe := a
    dupe.Signatures = nil
    return blake2s.Sum256(dupe.Serialize())             // exclude signatures (avoids circular dep)
}
```

`AUMHash` = `[blake2s.Size]byte` (= 32 bytes). Serialized as base32-no-pad for filenames/text.

### NodeKeySignature CBOR Wire Format

From `sig.go:74-104`:

```go
type NodeKeySignature struct {
    SigKind       SigKind              `cbor:"1,keyasint"`   // 0=Invalid, 1=SigDirect, 2=SigRotation, 3=SigCredential
    Pubkey        []byte               `cbor:"2,keyasint,omitempty"`  // node key public (32 bytes wireguard)
    KeyID         []byte               `cbor:"3,keyasint,omitempty"`  // 32 bytes ed25519 public (for Direct/Credential)
    Signature     []byte               `cbor:"4,keyasint,omitempty"`  // ed25519 (R,S) packed
    Nested        *NodeKeySignature    `cbor:"5,keyasint,omitempty"`  // for SigRotation
    WrappingPubkey []byte              `cbor:"6,keyasint,omitempty"`  // ed25519 public that must sign the embedding sig
}
```

### NodeKeySignature SigHash

```go
func (s NodeKeySignature) SigHash() [blake2s.Size]byte {
    dupe := s
    dupe.Signature = nil
    return blake2s.Sum256(dupe.Serialize())   // CBOR CTAP2 of all fields except Signature
}
```

---

## Signature Chain Verification Algorithm (step-by-step)

`Authority.NodeKeyAuthorizedWithDetails` (`tka.go:688-711`) is the **entry point**:

```
INPUT:  nodeKey (key.NodePublic), nodeKeySignature (tkatype.MarshaledSignature = []byte CBOR)

1. Unserialize CBOR bytes → NodeKeySignature
2. If SigKind == SigCredential → reject (credentials can't authorize nodes alone)
3. Resolve authorizingKeyID() — walks through nested SigRotation to find the leaf's KeyID
4. Look up KeyID in Authority.state.Keys → get trusted VerificationKey (ed25519 public + votes)
5. Call decoded.verifySignature(nodeKey, verificationKey)
```

`verifySignature()` (`sig.go:247-312`) — recursive chain verification:

```
verifySignature(nodeKey, verificationKey):
  a. If SigKind != SigCredential:
     - Assert nodeKey.MarshalBinary() == Pubkey field
  b. Compute sigHash = SigHash() (BLAKE2s of CBOR serialization with Signature=nil)

  c. SWITCH on SigKind:

     SigDirect:
       - Assert Nested == nil
       - ed25519consensus.Verify(verificationKey.Public, sigHash, s.Signature)
       - Return nil on success

     SigRotation:
       - Assert Nested != nil
       - Get wrappingPublic() from Nested (recursive: Nested.WrappingPubkey if set, else recurse down)
       - ed25519.Verify(wrappingPubkey, sigHash, s.Signature)  // NOTE: uses std ed25519 here, not ed25519consensus
       - Recurse: Nested.verifySignature(nestedPub, verificationKey)

     SigCredential:
       - Assert Nested == nil
       - ed25519consensus.Verify(verificationKey.Public, sigHash, s.Signature)
       - NOTE: no nodeKey check (credentials certify an indirection key, not a node key)

  d. Return RotationDetails if SigRotation (walk nested chain, collect PrevNodeKeys)
```

### Key Chain Resolution Rules (SigRotation → SigDirect)

Typical tailnet-locked node has:
```
SigRotation(nodeKey=new)
  └── Signature: signed by WrappingPubkey (node's TL private key)
  └── Nested: SigRotation(nodeKey=old)
        └── Signature: signed by WrappingPubkey (inherited from deeper)
        └── Nested: SigDirect(nodeKey=original)
              └── Signature: signed by trusted TKA key
              └── KeyID: 32-byte ed25519 public key in Authority.state.Keys
```

Fork resolution: `RotationDetails.PrevNodeKeys` lists old node keys; `rotationTracker`
drops peers whose current node key is in this list (they've rotated to a new key).

---

## Control Endpoints (`/machine/tka/*`)

All sent over Noise HTTP transport (same as `/machine/map`). All use `POST` with
`application/json`.

| Endpoint | Request Type | Response Type | Purpose |
|----------|-------------|---------------|---------|
| `/machine/tka/init/begin` | `TKAInitBeginRequest` | `TKAInitBeginResponse` | Submit genesis AUM, get nodes needing sigs |
| `/machine/tka/init/finish` | `TKAInitFinishRequest` | `TKAInitFinishResponse` | Submit node-key sigs for all existing nodes |
| `/machine/tka/bootstrap` | `TKABootstrapRequest` | `TKABootstrapResponse` | Fetch genesis AUM or disablement secret |
| `/machine/tka/sync/offer` | `TKASyncOfferRequest` | `TKASyncOfferResponse` | Exchange sync offers, get missing AUMs |
| `/machine/tka/sync/send` | `TKASyncSendRequest` | `TKASyncSendResponse` | Upload missing AUMs to control |
| `/machine/tka/disable` | `TKADisableRequest` | `TKADisableResponse` | Disable TKA with disablement secret |
| `/machine/tka/sign` | `TKASubmitSignatureRequest` | `TKASubmitSignatureResponse` | Submit a node-key signature |
| `/machine/tka/affected-sigs` | `TKASignaturesUsingKeyRequest` | `TKASignaturesUsingKeyResponse` | List signatures signed by a KeyID |

### JSON Wire Shapes

`TKAInfo` (in `MapResponse`):
```go
type TKAInfo struct {
    Head     string `json:",omitempty"`  // base32 AUMHash
    Disabled bool   `json:",omitempty"`  // control wants TKA disabled
}
```

`TKABootstrapRequest`/`TKABootstrapResponse` — used for enable/disable:
```go
type TKABootstrapRequest struct {
    Version CapabilityVersion
    NodeKey key.NodePublic
    Head    string  // base32 AUMHash, empty if not enabled
}

type TKABootstrapResponse struct {
    GenesisAUM       MarshaledAUM `json:",omitempty"`   // CBOR AUM bytes (base64 on wire)
    DisablementSecret []byte       `json:",omitempty"`   // secret for disablement
}
```

`TKASyncOfferRequest`/`TKASyncOfferResponse` — bidir sync:
```go
type TKASyncOfferRequest struct {
    Version   CapabilityVersion
    NodeKey   key.NodePublic
    Head      string     // base32 AUMHash (local head)
    Ancestors []string   // base32 AUMHash (sampled ancestors)
}

type TKASyncOfferResponse struct {
    Head        string          // base32 (control head)
    Ancestors   []string        // base32 (control ancestors)
    MissingAUMs []MarshaledAUM  // CBOR AUMs control thinks node is missing
}
```

`TKASyncSendRequest`:
```go
type TKASyncSendRequest struct {
    Version     CapabilityVersion
    NodeKey     key.NodePublic
    Head        string           // base32 (node head after applying received AUMs)
    MissingAUMs []MarshaledAUM   // CBOR AUMs node thinks control is missing
    Interactive bool
}
```

---

## Integration Flow (`ipn/ipnlocal/tailnet-lock.go`)

The `tkaSyncIfNeeded` function (`local.go:2034`), called on every `MapResponse`, handles 4 scenarios:

1. **Enablement** (`b.tka==nil` but netmap wants TKA):
   - POST `/machine/tka/bootstrap` → get `GenesisAUM` (CBOR checkpoint AUM)
   - `tka.Bootstrap(storage, genesisAUM)` → creates Authority from checkpoint
   - Then runs sync flow to converge state

2. **Disablement** (netmap says disabled but local TKA exists):
   - POST `/machine/tka/bootstrap` → get `DisablementSecret`
   - `authority.ValidDisablement(secret)` → if true, clear local TKA state

3. **Sync needed** (local head != netmap TKAInfo.Head):
   - `authority.SyncOffer(storage)` → build offer (head + sampled ancestors)
   - POST `/machine/tka/sync/offer` → get control's offer + MissingAUMs
   - `tka.ToSyncOffer(...)` → decode control offer
   - `localAuthority.MissingAUMs(storage, controlOffer)` → AUMs node needs to send
   - `localAuthority.Inform(storage, missingAUMsFromControl)` → apply control's AUMs
   - POST `/machine/tka/sync/send` → send AUMs control is missing

4. **Up to date** — no action

### Netmap Peer Filtering (`tkaFilterNetmapLocked`, `local.go:2054`)

Called after sync for every MapResponse:

```
for each peer in nm.Peers:
  if peer.UnsignedPeerAPIOnly(): skip (not subject to TL)
  if peer.KeySignature is empty: DROP peer
  else:
      authority.NodeKeyAuthorizedWithDetails(peer.Key(), sig)
      if error: DROP peer
      if rotation details: track obsolete keys
```

Peers are filtered **before** `setNetMapLocked()`. Dropped peers are recorded in
`b.tka.filtered` for `tailscale status` display.

Self-check: `authority.NodeKeyAuthorized(selfNode.Key(), selfSig)` — sets health warning
if we are locked out.

---

## Minimal Client Scope (verify-only)

A verify-only TKA client needs only:

### Required (implement):
- **AUM deserialization** (CBOR → `AUM` struct)
- **NodeKeySignature deserialization** (CBOR → `NodeKeySignature` enum)
- **State** type (LastAUMHash, Keys list, DisablementValues, StateID1/2)
- **Key** type (Kind=Key25519, Votes, Public)
- **Authority** (only: head, oldestAncestor, state)
  - `Open(storage)` — load from persisted chonk (`computeActiveChain`)
  - `Bootstrap(storage, genesisAUM)` — init from checkpoint
  - `Inform(storage, updates)` — apply incoming AUMs
  - `NodeKeyAuthorized(nodeKey, sig)` / `NodeKeyAuthorizedWithDetails`
  - `ValidDisablement(secret)`
  - `SyncOffer(storage)` / `MissingAUMs(storage, remoteOffer)`
- **Chonk storage** (`Mem` is sufficient for initial port; `FS` for persistence)
- **Signature verification** (`verifySignature` + `signatureVerify`)
- **BLAKE2s hashing** for AUMHash, SigHash, AUMSigHash
- **Control RPCs**: `/machine/tka/bootstrap`, `/machine/tka/sync/offer`, `/machine/tka/sync/send`

### NOT required (can skip for verify-only):
- `UpdateBuilder` and `Signer` interface (no signing)
- `Create()` / genesis generation
- `ResignNKS()`, `SignByCredential()` (no key rotation from client)
- `MakeRetroactiveRevocation()` (admin operations run from `tailscale lock` CLI)
- `Compact()` (nice-to-have, not needed for correctness)
- Deeplink generation/validation
- `DisablementKDF` for *generation* (only need `checkDisablement`)

### Failure mode for unsigned peers:
- Peer without `KeySignature` → dropped from netmap → no packets routed
- Peer with invalid `KeySignature` → dropped, logged
- Peer with rotated key → dropped (handled by `rotationTracker` dedup)
- Self without valid sig → health warning ("locked out"), local node still functions
  but other nodes drop us

---

## Rust Crate Design Sketch (`crates/tka`)

### Dependencies (new):
- `ciborium` or `minicbor` — CBOR decode/encode (CTAP2 mode; need deterministic encoding for SigHash)
- `blake2` — BLAKE2s-256
- `ed25519-dalek` — ed25519 signature verification
- `serde` optional (CBOR is native; JSON needed only for control wire)

### Core types:

```rust
// aum.rs
pub struct AumHash(pub [u8; 32]);      // BLAKE2s digest
pub type PrevAumHash = Option<[u8; 32]>;

pub enum AumKind { AddKey, RemoveKey, NoOp, UpdateKey, Checkpoint }

pub struct Aum {
    pub message_kind: AumKind,
    pub prev_aum_hash: PrevAumHash,    // None = genesis
    pub key: Option<Key>,
    pub key_id: Option<Vec<u8>>,
    pub state: Option<State>,          // for Checkpoint
    pub votes: Option<u32>,
    pub meta: Option<HashMap<String, String>>,
    pub signatures: Vec<Signature>,
}

pub struct Signature {
    pub key_id: Vec<u8>,               // 32 bytes
    pub signature: Vec<u8>,            // 64 bytes
}

// sig.rs
pub enum SigKind { Direct, Rotation, Credential }

pub struct NodeKeySignature {
    pub sig_kind: SigKind,
    pub pubkey: Option<Vec<u8>>,       // node key public
    pub key_id: Option<Vec<u8>>,       // TKA key reference
    pub signature: Option<Vec<u8>>,    // ed25519
    pub nested: Option<Box<NodeKeySignature>>,
    pub wrapping_pubkey: Option<Vec<u8>>,
}

// key.rs
pub enum KeyKind { Key25519 }

pub struct Key {
    pub kind: KeyKind,
    pub votes: u32,
    pub public: Vec<u8>,               // ed25519 public (32 bytes)
    pub meta: HashMap<String, String>,
}

// state.rs
pub struct State {
    pub last_aum_hash: Option<AumHash>,
    pub disablement_values: Vec<Vec<u8>>,
    pub keys: Vec<Key>,
    pub state_id1: u64,
    pub state_id2: u64,
}

// authority.rs
pub struct Authority {
    head: Aum,
    oldest_ancestor: Aum,
    state: State,
}

impl Authority {
    pub fn open(storage: &dyn Chonk) -> Result<Self>;
    pub fn bootstrap(storage: &dyn Chonk, bootstrap: &Aum) -> Result<Self>;
    pub fn inform(&mut self, storage: &dyn Chonk, updates: &[Aum]) -> Result;
    pub fn node_key_authorized(&self, node_key: &[u8], nks_bytes: &[u8]) -> Result;
    pub fn valid_disablement(&self, secret: &[u8]) -> bool;
    pub fn sync_offer(&self, storage: &dyn Chonk) -> Result<SyncOffer>;
    pub fn missing_aums(&self, storage: &dyn Chonk, remote: &SyncOffer) -> Result<Vec<Aum>>;
}
```

### `source.into()` conversion to Rust types:

┌─────────────────────┬──────────────────────┬────────────────────┐
│ Go Type              │ Go Serde             │ Rust Equivalent    │
├─────────────────────┼──────────────────────┼────────────────────┤
│ tkatype.MarshaledAUM  │ CBOR bytes (base64   │ Vec<u8> → deser   │
│                       │ on wire)             │ → Aum             │
│ tkatype.MarshaledSignature  │ CBOR bytes     │ Vec<u8> → deser   │
│                       │                      │ → NodeKeySignature│
│ tka.AUMHash           │ base32 string        │ AumHash           │
│ tka.SyncOffer         │ JSON struct {}       │ SyncOffer         │
│ tailcfg.TKAInfo       │ JSON in MapResponse  │ TKAInfo           │
└─────────────────────┴──────────────────────┴────────────────────┘

### Mutex-ordering pattern from Go:

```
tkaSyncLock BEFORE b.mu
  (tkaSyncLock is the outer, coarse lock; b.mu is the inner, fine-grained lock)
```

For Rustscale: a single `tokio::sync::Mutex<Option<TkaState>>` in tsnet `Server`.

### Where to hook in existing code:

1. `crates/tsnet/src/map_update.rs` — in the peer merge loop, after receiving `resp.Peers`,
   call `tka.node_key_authorized()` per peer. This is the **filter hook**. Already has `UnsignedPeerAPIOnly`
   field on `Node`. `Node.KeySignature` is `Option<Vec<u8>>` — exactly what we need.

2. `crates/controlclient/src/client.rs` — add `/machine/tka/bootstrap` and
   `/machine/tka/sync/*` POST paths alongside the existing `/machine/register` and
   `/machine/map`. The Noise HTTP/2 transport is already established via `noise_io`.

3. `crates/tailcfg/src/map.rs` — `MapResponse` needs `TKAInfo` and `TKAEnabled` fields
   added (only `TKAHead` exists as a bare string currently, no `TKAInfo` struct).

### Netmap `TKAEnabled` / `TKAHead` gap:

In the Go `netmap.NetworkMap`, these fields exist:
```go
type NetworkMap struct {
    TKAEnabled bool
    TKAHead    string
    // ...
}
```

Current Rustscale `MapResponse` in `crates/tailcfg/src/map.rs` has `TKAHead` as a bare `String` field
but no `TKAEnabled` boolean. Both are needed.

---

## Key Implementation Notes

1. **ed25519consensus vs std ed25519**: Go uses `ed25519consensus` (non-contributory verification)
   for `SigDirect`/`SigCredential` but plain `ed25519.Verify` for `SigRotation`. Rust should use
   `ed25519-dalek`'s `verify_strict()` for the consensus path and plain `verify()` for the rotation
   path. (Strict verification rejects signatures with non-canonical `s` values; plain verification
   accepts them.)

2. **CBOR nesting limit**: Go caps at 16 levels (`MaxNestedLevels`). The rotation chain trim
   (`maybeTrimRotationSignatureChain`) limits to 15 prev keys to stay under this. Must replicate
   the decode limit in Rust.

3. **AUM fork resolution**: `pickNextAUM` weights signatures by `key.votes`. AUM with higher
   total weight wins. If equal, `RemoveKey` wins. If still equal, lowest AUMHash wins. This
   must match exactly for cross-implementation consensus.

4. **Disablement**: Argon2id(time=4, mem=16KiB, threads=4) keyed with fixed salt
   `"tailscale network-lock disablement salt"`. `checkDisablement` re-derives the KDF output
   and constant-time compares against stored values. The `argon2` crate handles this.

5. **Chonk storage**: `Mem` = in-memory `HashMap<AUMHash, AUM>` + `HashMap<AUMHash, Vec<AUMHash>>`
   parent index. `FS` = CBOR-serialized per-AUM files at `base/XX/XXXX...` (first 2 base32 chars
   as subdirectory). The `last_active_ancestor` file is raw bytes of the AUMHash.
