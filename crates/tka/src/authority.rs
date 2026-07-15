//! Tailnet Key Authority state machine.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signer as _, VerifyingKey};

use crate::aum::{Aum, AumHash, AumKind, Signature};
use crate::chonk::{Chonk, ChonkError};
use crate::disablement::check_disablement;
use crate::key::{Key, KeyKind};
use crate::sig::{NodeKeySignature, RotationDetails, SigKind};
use crate::state::State;

pub(crate) const MAX_SCAN_ITERATIONS: usize = 2000;

/// A source of signatures for authority updates.
pub trait AumSigner {
    fn sign_aum(&self, hash: &[u8; 32]) -> Result<Vec<Signature>, String>;
}

impl AumSigner for ed25519_dalek::SigningKey {
    fn sign_aum(&self, hash: &[u8; 32]) -> Result<Vec<Signature>, String> {
        Ok(vec![Signature {
            key_id: self.verifying_key().to_bytes().to_vec(),
            signature: self.sign(hash).to_bytes().to_vec(),
        }])
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error(transparent)]
    Storage(#[from] ChonkError),
    #[error("invalid AUM: {0}")]
    InvalidAum(String),
    #[error("invalid authority state: {0}")]
    InvalidState(String),
    #[error("signature verification failed: {0}")]
    Signature(String),
    #[error("AUM chain has no candidates")]
    Empty,
    #[error("multiple distinct AUM chains have no active-ancestor intersection")]
    DistinctChains,
    #[error("AUM traversal exceeded {0} updates")]
    TraversalLimit(usize),
    #[error("AUM chain is missing parent {0}")]
    MissingParent(AumHash),
    #[error("inform requires at least one update")]
    EmptyInform,
    #[error("signing AUM failed: {0}")]
    Signing(String),
    #[error("node signature is not authorized: {0}")]
    NodeAuthorization(String),
}

/// Runtime state derived from a verified AUM chain.
#[derive(Debug, Clone)]
pub struct Authority {
    pub(crate) head: Aum,
    pub(crate) oldest_ancestor: Aum,
    pub(crate) state: State,
}

impl Authority {
    /// Open and fully recompute an authority from durable storage.
    pub fn open(storage: &dyn Chonk) -> Result<Self, AuthorityError> {
        let heads = storage.heads()?;
        if heads.is_empty() {
            return Err(AuthorityError::Empty);
        }
        let hint = storage.last_active_ancestor()?;

        let mut roots: HashMap<AumHash, (Aum, bool)> = HashMap::new();
        for head in &heads {
            let path = path_to_root(storage, head.clone())?;
            let root = path.last().expect("path always contains head").clone();
            let intersects_hint =
                hint.is_some_and(|hint| path.iter().any(|aum| aum.hash() == hint));
            roots
                .entry(root.hash())
                .and_modify(|entry| entry.1 |= intersects_hint)
                .or_insert((root, intersects_hint));
        }

        let oldest_ancestor = if roots.len() == 1 {
            roots.into_values().next().expect("one root").0
        } else {
            let mut hinted = roots.into_values().filter(|(_, intersects)| *intersects);
            let selected = hinted.next().ok_or(AuthorityError::DistinctChains)?;
            if hinted.next().is_some() {
                return Err(AuthorityError::DistinctChains);
            }
            selected.0
        };

        let (head, state) = fast_forward(storage, oldest_ancestor.clone())?;
        Ok(Self {
            head,
            oldest_ancestor,
            state,
        })
    }

    /// Create a new authority using a signed checkpoint genesis AUM.
    pub fn create(
        storage: &dyn Chonk,
        state: State,
        signer: &dyn AumSigner,
    ) -> Result<(Self, Aum), AuthorityError> {
        let mut genesis = Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: None,
            key: None,
            key_id: None,
            state: Some(state),
            votes: None,
            meta: None,
            signatures: Vec::new(),
        };
        genesis.validate().map_err(AuthorityError::InvalidState)?;
        genesis.signatures = signer
            .sign_aum(&genesis.sig_hash())
            .map_err(AuthorityError::Signing)?;
        let authority = Self::bootstrap(storage, genesis.clone())?;
        Ok((authority, genesis))
    }

    /// Bootstrap empty storage from a signed checkpoint.
    pub fn bootstrap(storage: &dyn Chonk, bootstrap: Aum) -> Result<Self, AuthorityError> {
        if !storage.heads()?.is_empty() {
            return Err(AuthorityError::InvalidState("Chonk is not empty".into()));
        }
        if bootstrap.message_kind != AumKind::Checkpoint {
            return Err(AuthorityError::InvalidAum(
                "bootstrap AUM must be a checkpoint".into(),
            ));
        }
        let genesis_state = bootstrap.state.as_ref().ok_or_else(|| {
            AuthorityError::InvalidAum("bootstrap checkpoint has no state".into())
        })?;
        verify_aum(&bootstrap, genesis_state, true)?;
        storage.store_verified_aums(std::slice::from_ref(&bootstrap))?;
        storage.set_last_active_ancestor(bootstrap.hash())?;
        Self::open(storage)
    }

    pub fn head(&self) -> AumHash {
        self.head.hash()
    }

    pub fn keys(&self) -> Vec<Key> {
        self.state.keys.clone()
    }

    pub fn key_trusted(&self, key_id: &[u8]) -> bool {
        self.state.key(key_id).is_some()
    }

    pub fn state_ids(&self) -> (u64, u64) {
        (self.state.state_id1, self.state.state_id2)
    }

    pub fn valid_disablement(&self, secret: &[u8]) -> bool {
        check_disablement(secret, &self.state.disablement_values)
    }

    /// Verify a marshaled node-key signature against the current trusted keys.
    pub fn node_key_authorized(
        &self,
        node_key: &[u8],
        marshaled_signature: &[u8],
    ) -> Result<Option<RotationDetails>, AuthorityError> {
        let signature = NodeKeySignature::decode(marshaled_signature)
            .map_err(|error| AuthorityError::NodeAuthorization(error.to_string()))?;
        if signature.sig_kind == SigKind::Credential {
            return Err(AuthorityError::NodeAuthorization(
                "credential signatures cannot authorize nodes directly".into(),
            ));
        }
        let key_id = signature.authorizing_key_id().ok_or_else(|| {
            AuthorityError::NodeAuthorization("signature has no authorizing key ID".into())
        })?;
        let key = self.state.key(key_id).ok_or_else(|| {
            AuthorityError::NodeAuthorization("authorizing key is not trusted".into())
        })?;
        signature
            .verify_signature(node_key, &key.public)
            .map_err(|error| AuthorityError::NodeAuthorization(error.to_string()))
    }

    /// Validate all updates before storing any of them, then recompute the
    /// active chain. Updates must be ordered parent before child.
    pub fn inform(&mut self, storage: &dyn Chonk, updates: &[Aum]) -> Result<(), AuthorityError> {
        if updates.is_empty() {
            return Err(AuthorityError::EmptyInform);
        }

        let mut states = HashMap::new();
        states.insert(self.head(), self.state.clone());
        let mut staged = Vec::new();
        for (index, update) in updates.iter().enumerate() {
            let hash = update.hash();
            match storage.aum(&hash) {
                Ok(_) => continue,
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(error.into()),
            }
            let parent = update.parent().ok_or_else(|| {
                AuthorityError::InvalidAum(format!("update {index} has no valid parent"))
            })?;
            let parent_state = if let Some(state) = states.get(&parent) {
                state.clone()
            } else {
                state_at(storage, parent)?
            };
            verify_aum(update, &parent_state, false)
                .map_err(|error| AuthorityError::InvalidAum(format!("update {index}: {error}")))?;
            let next = parent_state.apply_verified(update).map_err(|error| {
                AuthorityError::InvalidState(format!("update {index}: {error}"))
            })?;
            states.insert(hash, next);
            staged.push(update.clone());
        }

        storage.store_verified_aums(&staged)?;
        let replacement = Self::open(storage)?;
        *self = replacement;
        Ok(())
    }

    pub fn new_updater<'a>(
        &'a self,
        signer: Option<&'a dyn AumSigner>,
    ) -> crate::builder::UpdateBuilder<'a> {
        crate::builder::UpdateBuilder::new(self, signer)
    }
}

fn path_to_root(storage: &dyn Chonk, head: Aum) -> Result<Vec<Aum>, AuthorityError> {
    let mut path = Vec::new();
    let mut current = head;
    let mut seen = HashSet::new();
    for _ in 0..MAX_SCAN_ITERATIONS {
        let hash = current.hash();
        if !seen.insert(hash) {
            return Err(AuthorityError::InvalidState("cycle in AUM chain".into()));
        }
        let parent = current.parent();
        let is_checkpoint = current.message_kind == AumKind::Checkpoint;
        path.push(current);
        let Some(parent) = parent else {
            return Ok(path);
        };
        current = match storage.aum(&parent) {
            Ok(aum) => aum,
            Err(error) if error.is_not_found() && is_checkpoint => {
                // Compaction may retain a checkpoint while purging its parent.
                return Ok(path);
            }
            Err(error) if error.is_not_found() => {
                return Err(AuthorityError::MissingParent(parent));
            }
            Err(error) => return Err(error.into()),
        };
    }
    Err(AuthorityError::TraversalLimit(MAX_SCAN_ITERATIONS))
}

pub(crate) fn state_at(storage: &dyn Chonk, wanted: AumHash) -> Result<State, AuthorityError> {
    let top = storage.aum(&wanted)?;
    let mut path = path_to_root(storage, top)?;
    path.reverse();
    let genesis = path
        .first()
        .ok_or_else(|| AuthorityError::InvalidState("empty AUM path".into()))?;
    if genesis.message_kind != AumKind::Checkpoint {
        return Err(AuthorityError::InvalidState(
            "oldest retained AUM must be a checkpoint".into(),
        ));
    }
    let mut state = genesis
        .state
        .as_ref()
        .ok_or_else(|| AuthorityError::InvalidState("retained checkpoint has no state".into()))?
        .clone();
    if genesis.parent().is_some() {
        // A compacted anchor was verified before its ancestry was purged. Its
        // signatures cannot be rechecked because they are authorized by the
        // pre-checkpoint state, which may differ from the checkpoint state.
        genesis.validate().map_err(AuthorityError::InvalidAum)?;
        if genesis.signatures.is_empty() {
            return Err(AuthorityError::InvalidAum(
                "unsigned retained checkpoint".into(),
            ));
        }
    } else {
        verify_aum(genesis, &state, true)?;
    }
    state = state.with_last_aum(genesis);

    for update in path.iter().skip(1) {
        verify_aum(update, &state, false)?;
        state = state
            .apply_verified(update)
            .map_err(AuthorityError::InvalidState)?;
    }
    Ok(state)
}

fn fast_forward(storage: &dyn Chonk, oldest: Aum) -> Result<(Aum, State), AuthorityError> {
    let mut current = oldest;
    let mut state = state_at(storage, current.hash())?;
    for _ in 0..MAX_SCAN_ITERATIONS {
        let children = storage.child_aums(&current.hash())?;
        if children.is_empty() {
            return Ok((current, state));
        }
        for child in &children {
            verify_aum(child, &state, false)?;
        }
        let next = pick_next(&state, children);
        state = state
            .apply_verified(&next)
            .map_err(AuthorityError::InvalidState)?;
        current = next;
    }
    Err(AuthorityError::TraversalLimit(MAX_SCAN_ITERATIONS))
}

fn pick_next(state: &State, mut candidates: Vec<Aum>) -> Aum {
    candidates.sort_by(|left, right| compare_candidates(state, left, right));
    candidates.remove(0)
}

fn compare_candidates(state: &State, left: &Aum, right: &Aum) -> Ordering {
    let left_weight = signature_weight(state, left);
    let right_weight = signature_weight(state, right);
    right_weight
        .cmp(&left_weight)
        .then_with(|| {
            match (
                left.message_kind == AumKind::RemoveKey,
                right.message_kind == AumKind::RemoveKey,
            ) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => Ordering::Equal,
            }
        })
        .then_with(|| left.hash().cmp(&right.hash()))
}

fn signature_weight(state: &State, aum: &Aum) -> u64 {
    let mut seen = HashSet::<Vec<u8>>::new();
    aum.signatures
        .iter()
        .filter_map(|signature| {
            if !seen.insert(signature.key_id.clone()) {
                return None;
            }
            state.key(&signature.key_id).map(|key| key.votes)
        })
        .sum()
}

fn verify_aum(aum: &Aum, state: &State, genesis: bool) -> Result<(), AuthorityError> {
    aum.validate().map_err(AuthorityError::InvalidAum)?;
    if !genesis {
        let expected = state
            .last_aum_hash
            .as_deref()
            .and_then(AumHash::from_slice)
            .ok_or_else(|| AuthorityError::InvalidState("state has no valid head".into()))?;
        if aum.parent() != Some(expected) {
            return Err(AuthorityError::InvalidAum(format!(
                "parent does not match state head {expected}"
            )));
        }
    }
    if aum.signatures.is_empty() {
        return Err(AuthorityError::InvalidAum("unsigned AUM".into()));
    }
    let digest = aum.sig_hash();
    for (index, signature) in aum.signatures.iter().enumerate() {
        let key = state.key(&signature.key_id).ok_or_else(|| {
            AuthorityError::Signature(format!("signature {index} uses an untrusted key"))
        })?;
        if key.kind != KeyKind::Key25519 {
            return Err(AuthorityError::Signature(format!(
                "signature {index} uses unsupported key kind"
            )));
        }
        let public: &[u8; 32] = key.public.as_slice().try_into().map_err(|_| {
            AuthorityError::Signature(format!("signature {index} key has invalid length"))
        })?;
        let verifying_key = VerifyingKey::from_bytes(public)
            .map_err(|_| AuthorityError::Signature(format!("signature {index} key is invalid")))?;
        let parsed = ed25519_dalek::Signature::from_slice(&signature.signature).map_err(|_| {
            AuthorityError::Signature(format!("signature {index} has invalid length"))
        })?;
        verifying_key
            .verify_strict(&digest, &parsed)
            .map_err(|_| AuthorityError::Signature(format!("signature {index} is invalid")))?;
    }
    if aum.message_kind == AumKind::RemoveKey && state.keys.len() == 1 {
        let only = state.keys[0].id().map_err(AuthorityError::InvalidState)?;
        if aum.key_id.as_deref() == Some(only) {
            return Err(AuthorityError::InvalidAum(
                "cannot remove the last trusted key".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chonk::FsChonk;
    use crate::disablement::disablement_kdf;
    use crate::sig::NodeKeySignature;

    fn signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn trusted_key(signer: &ed25519_dalek::SigningKey, votes: u64) -> Key {
        Key {
            kind: KeyKind::Key25519,
            votes,
            public: signer.verifying_key().to_bytes().to_vec(),
            meta: None,
        }
    }

    fn initial_state(keys: Vec<Key>) -> State {
        State {
            last_aum_hash: None,
            disablement_values: vec![disablement_kdf(b"authority-test-secret")],
            keys,
            state_id1: 42,
            state_id2: 84,
        }
    }

    fn sign_update(mut update: Aum, signer: &ed25519_dalek::SigningKey) -> Aum {
        update.signatures = signer.sign_aum(&update.sig_hash()).unwrap();
        update
    }

    fn noop(parent: AumHash, signer: &ed25519_dalek::SigningKey) -> Aum {
        sign_update(
            Aum {
                message_kind: AumKind::NoOp,
                prev_aum_hash: Some(parent.0.to_vec()),
                key: None,
                key_id: None,
                state: None,
                votes: None,
                meta: None,
                signatures: Vec::new(),
            },
            signer,
        )
    }

    #[test]
    fn create_bootstrap_and_filesystem_reopen() {
        let signer = signing_key(1);
        let key = trusted_key(&signer, 1);
        let dir = tempfile::tempdir().unwrap();
        let storage = FsChonk::open(dir.path()).unwrap();
        let (authority, genesis) =
            Authority::create(&storage, initial_state(vec![key.clone()]), &signer).unwrap();
        assert!(authority.key_trusted(&key.public));
        assert_eq!(authority.state_ids(), (42, 84));
        drop(storage);

        let reopened_storage = FsChonk::open(dir.path()).unwrap();
        let reopened = Authority::open(&reopened_storage).unwrap();
        assert_eq!(reopened.head(), genesis.hash());
        assert!(reopened.key_trusted(&key.public));
    }

    #[test]
    fn builder_add_remove_changes_node_authorization() {
        let root_signer = signing_key(1);
        let added_signer = signing_key(2);
        let root = trusted_key(&root_signer, 1);
        let added = trusted_key(&added_signer, 1);
        let storage = crate::chonk::MemChonk::new();
        let (mut authority, _) =
            Authority::create(&storage, initial_state(vec![root]), &root_signer).unwrap();

        let mut builder = authority.new_updater(Some(&root_signer));
        builder.add_key(added.clone()).unwrap();
        let updates = builder.finalize(&storage).unwrap();
        authority.inform(&storage, &updates).unwrap();
        assert!(authority.key_trusted(&added.public));

        let node_key = [9u8; 32];
        let mut node_signature = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(node_key.to_vec()),
            key_id: Some(added.public.clone()),
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };
        node_signature.signature = Some(
            added_signer
                .sign(&node_signature.sig_hash())
                .to_bytes()
                .to_vec(),
        );
        assert!(authority
            .node_key_authorized(&node_key, &node_signature.encode())
            .is_ok());

        let mut builder = authority.new_updater(Some(&root_signer));
        builder.remove_key(&added.public).unwrap();
        let updates = builder.finalize(&storage).unwrap();
        authority.inform(&storage, &updates).unwrap();
        assert!(!authority.key_trusted(&added.public));
        assert!(authority
            .node_key_authorized(&node_key, &node_signature.encode())
            .is_err());
    }

    #[test]
    fn builder_updates_votes_and_metadata() {
        let signer = signing_key(1);
        let root = trusted_key(&signer, 1);
        let root_id = root.public.clone();
        let dir = tempfile::tempdir().unwrap();
        let storage = FsChonk::open(dir.path()).unwrap();
        let (mut authority, _) =
            Authority::create(&storage, initial_state(vec![root]), &signer).unwrap();

        let mut builder = authority.new_updater(Some(&signer));
        builder.set_key_votes(&root_id, 7).unwrap();
        builder
            .set_key_meta(
                &root_id,
                std::collections::BTreeMap::from([
                    ("aa".into(), "longer".into()),
                    ("z".into(), "short".into()),
                ]),
            )
            .unwrap();
        let updates = builder.finalize(&storage).unwrap();
        authority.inform(&storage, &updates).unwrap();

        let expected_head = authority.head();
        let key = authority.keys().pop().unwrap();
        assert_eq!(key.votes, 7);
        assert_eq!(
            key.meta.unwrap(),
            std::collections::BTreeMap::from([
                ("aa".into(), "longer".into()),
                ("z".into(), "short".into()),
            ])
        );
        drop(storage);

        let reopened_storage = FsChonk::open(dir.path()).unwrap();
        let reopened = Authority::open(&reopened_storage).unwrap();
        assert_eq!(reopened.head(), expected_head);
        let reopened_key = reopened.keys().pop().unwrap();
        assert_eq!(reopened_key.votes, 7);
        assert_eq!(
            reopened_key.meta.unwrap(),
            std::collections::BTreeMap::from([
                ("aa".into(), "longer".into()),
                ("z".into(), "short".into()),
            ])
        );
    }

    #[test]
    fn compacted_checkpoint_anchor_reopens_without_parent() {
        let signer = signing_key(1);
        let retained_signer = signing_key(2);
        let root = trusted_key(&signer, 1);
        let retained_key = trusted_key(&retained_signer, 1);
        let full_storage = crate::chonk::MemChonk::new();
        let (mut authority, _) = Authority::create(
            &full_storage,
            initial_state(vec![root, retained_key.clone()]),
            &signer,
        )
        .unwrap();

        let parent = authority.head();
        let mut checkpoint_state = authority.state.clone();
        checkpoint_state.last_aum_hash = None;
        // A valid checkpoint may remove the key that signed it. Reopening a
        // compacted chain therefore cannot self-verify the anchor signature.
        checkpoint_state.keys = vec![retained_key];
        let checkpoint = sign_update(
            Aum {
                message_kind: AumKind::Checkpoint,
                prev_aum_hash: Some(parent.0.to_vec()),
                key: None,
                key_id: None,
                state: Some(checkpoint_state),
                votes: None,
                meta: None,
                signatures: Vec::new(),
            },
            &signer,
        );
        let child = noop(checkpoint.hash(), &retained_signer);
        authority
            .inform(&full_storage, &[checkpoint.clone(), child.clone()])
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        {
            let compacted = FsChonk::open(dir.path()).unwrap();
            compacted
                .store_verified_aums(&[checkpoint.clone(), child.clone()])
                .unwrap();
            compacted
                .set_last_active_ancestor(checkpoint.hash())
                .unwrap();
        }
        let compacted = FsChonk::open(dir.path()).unwrap();
        let reopened = Authority::open(&compacted).unwrap();
        assert_eq!(reopened.head(), child.hash());
        assert_eq!(reopened.oldest_ancestor.hash(), checkpoint.hash());
    }

    #[test]
    fn inform_rejects_bad_parent_and_invalid_signature_fork_atomically() {
        let signer = signing_key(1);
        let storage = crate::chonk::MemChonk::new();
        let (mut authority, _) = Authority::create(
            &storage,
            initial_state(vec![trusted_key(&signer, 1)]),
            &signer,
        )
        .unwrap();

        let wrong_parent = noop(AumHash([7; 32]), &signer);
        assert!(authority.inform(&storage, &[wrong_parent]).is_err());

        let first = noop(authority.head(), &signer);
        // A malformed sibling makes this an invalid fork. Neither sibling may
        // be persisted even though the first one verifies successfully.
        let mut second = noop(authority.head(), &signer);
        second.signatures[0].signature[0] ^= 1;
        assert!(authority
            .inform(&storage, &[first.clone(), second])
            .is_err());
        assert!(storage.aum(&first.hash()).unwrap_err().is_not_found());
    }

    #[test]
    fn fork_resolution_prefers_remove_key_after_signature_weight_tie() {
        let signer = signing_key(1);
        let other_signer = signing_key(2);
        let root = trusted_key(&signer, 1);
        let other = trusted_key(&other_signer, 1);
        let storage = crate::chonk::MemChonk::new();
        let (mut authority, _) =
            Authority::create(&storage, initial_state(vec![root, other.clone()]), &signer).unwrap();
        let parent = authority.head();
        let no_op = noop(parent, &signer);
        let removal = sign_update(
            Aum {
                message_kind: AumKind::RemoveKey,
                prev_aum_hash: Some(parent.0.to_vec()),
                key: None,
                key_id: Some(other.public.clone()),
                state: None,
                votes: None,
                meta: None,
                signatures: Vec::new(),
            },
            &signer,
        );
        authority
            .inform(&storage, &[no_op, removal.clone()])
            .unwrap();
        assert_eq!(authority.head(), removal.hash());
        assert!(!authority.key_trusted(&other.public));
    }

    #[test]
    fn two_authorities_exchange_missing_aums() {
        let signer = signing_key(1);
        let second_signer = signing_key(2);
        let root = trusted_key(&signer, 1);
        let second = trusted_key(&second_signer, 1);
        let left_storage = crate::chonk::MemChonk::new();
        let (mut left, genesis) =
            Authority::create(&left_storage, initial_state(vec![root]), &signer).unwrap();
        let right_storage = crate::chonk::MemChonk::new();
        let mut right = Authority::bootstrap(&right_storage, genesis).unwrap();

        let mut builder = left.new_updater(Some(&signer));
        builder.add_key(second.clone()).unwrap();
        let updates = builder.finalize(&left_storage).unwrap();
        left.inform(&left_storage, &updates).unwrap();

        let right_offer = right.sync_offer(&right_storage).unwrap();
        let missing = left.missing_aums(&left_storage, &right_offer).unwrap();
        right.inform(&right_storage, &missing).unwrap();
        assert_eq!(left.head(), right.head());
        assert!(right.key_trusted(&second.public));
    }
}
