//! Builder for signed authority updates supported by the current AUM wire types.

use std::collections::BTreeMap;

use crate::aum::{Aum, AumHash, AumKind};
use crate::authority::{AumSigner, Authority, AuthorityError};
use crate::chonk::Chonk;
use crate::key::Key;
use crate::state::State;

const MAX_KEYS: usize = 512;
const CHECKPOINT_EVERY: usize = 50;

pub struct UpdateBuilder<'a> {
    authority: &'a Authority,
    signer: Option<&'a dyn AumSigner>,
    state: State,
    parent: AumHash,
    updates: Vec<Aum>,
}

impl<'a> UpdateBuilder<'a> {
    pub(crate) fn new(authority: &'a Authority, signer: Option<&'a dyn AumSigner>) -> Self {
        Self {
            authority,
            signer,
            state: authority.state.clone(),
            parent: authority.head(),
            updates: Vec::new(),
        }
    }

    fn push(&mut self, mut update: Aum) -> Result<(), AuthorityError> {
        update.prev_aum_hash = Some(self.parent.0.to_vec());
        if let Some(signer) = self.signer {
            update.signatures = signer
                .sign_aum(&update.sig_hash())
                .map_err(AuthorityError::Signing)?;
        }
        update.validate().map_err(AuthorityError::InvalidAum)?;
        self.state = self
            .state
            .apply_verified(&update)
            .map_err(AuthorityError::InvalidState)?;
        self.parent = update.hash();
        self.updates.push(update);
        Ok(())
    }

    pub fn add_key(&mut self, key: Key) -> Result<(), AuthorityError> {
        key.validate().map_err(AuthorityError::InvalidState)?;
        if self
            .state
            .key(key.id().map_err(AuthorityError::InvalidState)?)
            .is_some()
        {
            return Err(AuthorityError::InvalidState("key already exists".into()));
        }
        if self.state.keys.len() >= MAX_KEYS {
            return Err(AuthorityError::InvalidState(
                "maximum number of trusted keys reached".into(),
            ));
        }
        self.push(Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: Vec::new(),
        })
    }

    pub fn remove_key(&mut self, key_id: &[u8]) -> Result<(), AuthorityError> {
        if self.state.key(key_id).is_none() {
            return Err(AuthorityError::InvalidState("key not found".into()));
        }
        self.push(Aum {
            message_kind: AumKind::RemoveKey,
            prev_aum_hash: None,
            key: None,
            key_id: Some(key_id.to_vec()),
            state: None,
            votes: None,
            meta: None,
            signatures: Vec::new(),
        })
    }

    pub fn set_key_votes(&mut self, key_id: &[u8], votes: u64) -> Result<(), AuthorityError> {
        if self.state.key(key_id).is_none() {
            return Err(AuthorityError::InvalidState("key not found".into()));
        }
        self.push(Aum {
            message_kind: AumKind::UpdateKey,
            prev_aum_hash: None,
            key: None,
            key_id: Some(key_id.to_vec()),
            state: None,
            votes: Some(votes),
            meta: None,
            signatures: Vec::new(),
        })
    }

    pub fn set_key_meta(
        &mut self,
        key_id: &[u8],
        meta: BTreeMap<String, String>,
    ) -> Result<(), AuthorityError> {
        if self.state.key(key_id).is_none() {
            return Err(AuthorityError::InvalidState("key not found".into()));
        }
        self.push(Aum {
            message_kind: AumKind::UpdateKey,
            prev_aum_hash: None,
            key: None,
            key_id: Some(key_id.to_vec()),
            state: None,
            votes: None,
            meta: Some(meta),
            signatures: Vec::new(),
        })
    }

    fn checkpoint(&mut self) -> Result<(), AuthorityError> {
        let mut state = self.state.clone();
        state.last_aum_hash = None;
        self.push(Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: None,
            key: None,
            key_id: None,
            state: Some(state),
            votes: None,
            meta: None,
            signatures: Vec::new(),
        })
    }

    /// Finalize updates and insert a periodic checkpoint when the active chain
    /// has gone 50 updates without one.
    pub fn finalize(mut self, storage: &dyn Chonk) -> Result<Vec<Aum>, AuthorityError> {
        let mut need_checkpoint = true;
        let mut cursor = self.authority.head();
        for _ in self.updates.len()..CHECKPOINT_EVERY {
            let aum = match storage.aum(&cursor) {
                Ok(aum) => aum,
                Err(error) if error.is_not_found() => {
                    need_checkpoint = false;
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            if aum.message_kind == AumKind::Checkpoint {
                need_checkpoint = false;
                break;
            }
            let Some(parent) = aum.parent() else {
                need_checkpoint = false;
                break;
            };
            cursor = parent;
        }
        if need_checkpoint {
            self.checkpoint()?;
        }
        if let Some(first) = self.updates.first() {
            if first.parent() != Some(self.authority.head()) {
                return Err(AuthorityError::InvalidState(
                    "updates no longer apply to authority head".into(),
                ));
            }
        }
        Ok(self.updates)
    }
}
