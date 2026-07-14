//! Chonk — AUM storage interface and in-memory implementation.
//!
//! Mirrors the Go `Chonk` interface: stores AUMs indexed by hash, maintains
//! a parent→children index, and tracks the last active ancestor.

use std::collections::HashMap;

use crate::aum::{Aum, AumHash};

/// Storage backend for AUMs.
pub trait Chonk {
    /// Retrieve an AUM by its hash.
    fn aum(&self, hash: &AumHash) -> Option<Aum>;

    /// Get the child AUM hashes of a given parent hash.
    fn children(&self, hash: &AumHash) -> Vec<AumHash>;

    /// Get the last active ancestor hash.
    fn last_active_ancestor(&self) -> Option<AumHash>;

    /// Set the last active ancestor hash.
    fn set_last_active_ancestor(&mut self, hash: AumHash);

    /// Store AUMs, updating the index. Returns the number of new AUMs stored.
    fn store_aums(&mut self, aums: &[Aum]) -> usize;
}

/// In-memory `Chonk` implementation using `HashMap`.
#[derive(Default)]
pub struct MemChonk {
    aums: HashMap<AumHash, Aum>,
    children: HashMap<AumHash, Vec<AumHash>>,
    last_active: Option<AumHash>,
}

impl MemChonk {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Chonk for MemChonk {
    fn aum(&self, hash: &AumHash) -> Option<Aum> {
        self.aums.get(hash).cloned()
    }

    fn children(&self, hash: &AumHash) -> Vec<AumHash> {
        self.children.get(hash).cloned().unwrap_or_default()
    }

    fn last_active_ancestor(&self) -> Option<AumHash> {
        self.last_active
    }

    fn set_last_active_ancestor(&mut self, hash: AumHash) {
        self.last_active = Some(hash);
    }

    fn store_aums(&mut self, aums: &[Aum]) -> usize {
        let mut new_count = 0;
        for aum in aums {
            let hash = aum.hash();
            if !self.aums.contains_key(&hash) {
                new_count += 1;
            }
            // Update parent→children index.
            if let Some(prev) = &aum.prev_aum_hash {
                if prev.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(prev);
                    let parent = AumHash(arr);
                    self.children.entry(parent).or_default().push(hash);
                }
            }
            self.aums.insert(hash, aum.clone());
        }
        new_count
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aum::AumKind;

    fn make_aum(kind: AumKind, prev: Option<Vec<u8>>) -> Aum {
        Aum {
            message_kind: kind,
            prev_aum_hash: prev,
            key: None,
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        }
    }

    #[test]
    fn store_and_retrieve() {
        let mut chonk = MemChonk::new();
        let aum = make_aum(AumKind::NoOp, None);
        let hash = aum.hash();

        let n = chonk.store_aums(&[aum.clone()]);
        assert_eq!(n, 1);

        let retrieved = chonk.aum(&hash).unwrap();
        assert_eq!(retrieved, aum);
    }

    #[test]
    fn store_duplicate_is_idempotent() {
        let mut chonk = MemChonk::new();
        let aum = make_aum(AumKind::NoOp, None);

        chonk.store_aums(&[aum.clone()]);
        let n = chonk.store_aums(&[aum]);
        assert_eq!(n, 0);
    }

    #[test]
    fn children_index() {
        let mut chonk = MemChonk::new();

        let parent = make_aum(AumKind::NoOp, None);
        let parent_hash = parent.hash();

        let child1 = make_aum(AumKind::NoOp, Some(parent_hash.0.to_vec()));
        let child1_hash = child1.hash();

        let child2 = make_aum(AumKind::AddKey, Some(parent_hash.0.to_vec()));
        let child2_hash = child2.hash();

        chonk.store_aums(&[parent, child1, child2]);

        let mut kids = chonk.children(&parent_hash);
        kids.sort();
        let mut expected = vec![child1_hash, child2_hash];
        expected.sort();
        assert_eq!(kids, expected);
    }

    #[test]
    fn last_active_ancestor() {
        let mut chonk = MemChonk::new();
        assert_eq!(chonk.last_active_ancestor(), None);

        let aum = make_aum(AumKind::NoOp, None);
        let hash = aum.hash();
        chonk.set_last_active_ancestor(hash);
        assert_eq!(chonk.last_active_ancestor(), Some(hash));
    }

    #[test]
    fn children_of_unknown_hash_is_empty() {
        let chonk = MemChonk::new();
        let unknown = AumHash([0xFF; 32]);
        assert!(chonk.children(&unknown).is_empty());
    }
}
