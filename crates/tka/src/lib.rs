#![forbid(unsafe_code)]
//! Tailnet Key Authority (TKA) — CBOR wire types, hashing, and verification.
//!
//! CTAP2-canonical CBOR encoding/decoding for the Tailnet Lock wire types:
//! AUMs, NodeKeySignature, Key, and State. AUM hashing (BLAKE2s-256),
//! signature verification (ed25519), disablement (Argon2id), durable storage,
//! authority state transitions, update building, and peer AUM synchronization.
//! Control-plane synchronization and LocalAPI/CLI integration are outside this
//! crate.

pub mod aum;
pub mod authority;
pub mod builder;
pub mod chonk;
pub mod disablement;
pub mod key;
pub mod sig;
pub mod state;
pub mod sync;

pub use aum::{Aum, AumHash, AumKind, Signature};
pub use authority::{AumSigner, Authority, AuthorityError};
pub use builder::UpdateBuilder;
pub use chonk::{Chonk, ChonkError, FsChonk, MemChonk};
pub use disablement::{check_disablement, disablement_kdf};
pub use key::{Key, KeyKind};
pub use sig::{
    decode_wrapped_auth_key, sign_by_credential, NodeKeySignature, RotationDetails, SigKind,
    VerifyError, WrappedAuthKeyError,
};
pub use state::State;
pub use sync::{SyncError, SyncOffer};
