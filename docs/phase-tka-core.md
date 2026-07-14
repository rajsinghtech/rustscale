# Phase: TKA core (`crates/tka`, part 1 of 2 — wire types + verification)

First half of the Tailnet Lock port: the cryptographic core with no control
or netmap wiring. Full pre-digested research:
**`docs/specs/research-tka.md`** — read it first; it contains the CBOR field
tables, hashing rules, the verification algorithm step-by-step, and the crate
design sketch this spec follows. Part 2 (Authority sync, control RPCs, netmap
peer filtering) is a separate later phase — do NOT start it.

## Scope: new crate `crates/tka`

1. **Wire types with CBOR** (research §AUM CBOR Wire Format): `Aum` (integer
   map keys 1,2,3,4,5,6,7,23 — `keyasint`), `Signature` (keys 1,2),
   `NodeKeySignature` (keys 1..6), `Key` (research shows Go key.go — read
   `/Users/rajsingh/Documents/GitHub/tailscale/tka/key.go` for its exact CBOR
   keys), `State` (read `/Users/rajsingh/Documents/GitHub/tailscale/tka/state.go`
   for exact keys). Encoding MUST be CTAP2 canonical CBOR (deterministic map
   ordering, definite lengths, no tags) and decoding must enforce a max
   nesting depth of 16 and reject duplicate map keys. Choose `ciborium` or
   `minicbor` (new workspace dep — pick whichever cleanly supports
   integer-keyed structs + canonical encoding; justify in a comment).
   omitempty semantics: absent optional fields are omitted from the map
   entirely, exactly as Go's `omitempty` — round-trips with Go bytes must be
   byte-identical (serialize(deserialize(x)) == x).
2. **Hashing** (blake2 workspace dep, BLAKE2s-256):
   `Aum::hash()` = blake2s(serialize(all fields)),
   `Aum::sig_hash()` = blake2s(serialize with Signatures=empty/omitted),
   `NodeKeySignature::sig_hash()` = blake2s(serialize with Signature omitted).
   `AumHash([u8;32])` with base32-no-pad Display/FromStr (Go serializes AUM
   hashes as unpadded base32 for text).
3. **Signature verification** (research §Signature Chain Verification —
   follow it exactly):
   - `SigKind` enum (0 Invalid, 1 Direct, 2 Rotation, 3 Credential).
   - `NodeKeySignature::verify_signature(node_key_bytes, verification_key)`:
     Direct/Credential use `ed25519_dalek::VerifyingKey::verify_strict`
     (ed25519consensus equivalent); Rotation's outer check uses plain
     `verify`; recursion into `nested`; `wrapping_pubkey()` resolution
     (research §c SWITCH table and Go sig.go:247-312 — read the Go file for
     edge cases: pubkey match assertion, nested-must/must-not rules).
   - `authorizing_key_id()` — walk nested chain to the leaf KeyID.
   - Rotation chain depth limit (15) per research Key Implementation Note 2.
4. **Disablement check**: `check_disablement(secret, disablement_values)` —
   Argon2id time=4, mem=16KiB, threads=4, fixed salt
   `"tailscale network-lock disablement salt"` (verify exact params against
   Go `/Users/rajsingh/Documents/GitHub/tailscale/tka/state.go` — grep
   DisablementKDF), constant-time compare. New `argon2` dep.
5. **Storage trait**: `Chonk` trait (get AUM by hash, children-of, set-last-
   active-ancestor etc — mirror the Go interface surface that part 2 will
   need; read tailchonk.go's interface definition) + `MemChonk` impl.
   `FsChonk` is part 2 — skip.
6. **Limits** (tka/limits.go): constants module.

## Tests

- Port every hardcoded test vector you can find in the Go tests
  (`/Users/rajsingh/Documents/GitHub/tailscale/tka/aum_test.go`,
  `sig_test.go`, `state_test.go`) — especially any fixed hash/serialization
  expectations; byte-exact CBOR golden tests are the acceptance backbone.
- Self-consistency: round-trip encode/decode; sig_hash excludes signatures;
  hash changes when any field changes.
- Verification: construct a Direct sig with a locally generated ed25519 key
  and verify; build a Rotation→Direct chain and verify; tamper each field →
  fails; Credential-alone rejection; depth-limit rejection.
- Disablement KDF: derive + check roundtrip, wrong secret fails.

## Acceptance criteria (run yourself)

- `cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all`
- New deps added at workspace level, minimal features.
- Update `docs/parity.md` `Tailnet Lock / TKA` row to 🔶 with a precise
  summary of what part 1 covers and what part 2 will add.
- Do NOT modify `crates/magicsock`, `crates/tsnet`, `crates/controlclient`,
  or `crates/tailcfg` — part 1 is the standalone crate only.
- Do not commit; do not spawn other agents.
