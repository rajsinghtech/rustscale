#![forbid(unsafe_code)]
//! Tailnet Key Authority (TKA) — CBOR wire types, hashing, and verification.
//!
//! CTAP2-canonical CBOR encoding/decoding for the Tailnet Lock wire types:
//! AUMs, NodeKeySignature, Key, and State. AUM hashing (BLAKE2s-256),
//! signature verification (ed25519), disablement (Argon2id), and in-memory
//! storage are included. FS storage and the Authority state machine come
//! in later phases.

pub mod aum;
pub mod chonk;
pub mod disablement;
pub mod key;
pub mod sig;
pub mod state;

pub use aum::{Aum, AumHash, AumKind, Signature};
pub use chonk::{Chonk, MemChonk};
pub use disablement::{check_disablement, disablement_kdf};
pub use key::{Key, KeyKind};
pub use sig::{NodeKeySignature, RotationDetails, SigKind, VerifyError};
pub use state::State;
