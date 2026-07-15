//! Bounded, untrusted-peer AUM synchronization offers.

use std::collections::HashMap;
use std::str::FromStr;

use crate::aum::{Aum, AumHash};
use crate::authority::{Authority, AuthorityError, MAX_SCAN_ITERATIONS};
use crate::chonk::Chonk;

const ANCESTORS_SKIP_START: usize = 4;
const ANCESTORS_SKIP_SHIFT: usize = 2;
const MAX_SYNC_HEAD_ITERATIONS: usize = 400;
const MAX_SYNC_ANCESTORS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOffer {
    pub head: AumHash,
    /// Newest sampled ancestor first; oldest known ancestor last.
    pub ancestors: Vec<AumHash>,
}

impl SyncOffer {
    pub fn from_strings(head: &str, ancestors: &[String]) -> Result<Self, String> {
        if ancestors.len() > MAX_SYNC_ANCESTORS {
            return Err(format!(
                "too many sync ancestors: {} > {MAX_SYNC_ANCESTORS}",
                ancestors.len()
            ));
        }
        let head = AumHash::from_str(head).map_err(|error| format!("head: {error}"))?;
        let ancestors = ancestors
            .iter()
            .enumerate()
            .map(|(index, ancestor)| {
                AumHash::from_str(ancestor).map_err(|error| format!("ancestor {index}: {error}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { head, ancestors })
    }

    pub fn to_strings(&self) -> (String, Vec<String>) {
        (
            self.head.to_string(),
            self.ancestors.iter().map(ToString::to_string).collect(),
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error("no AUM chain intersection")]
    NoIntersection,
    #[error("active AUM chain did not reach its oldest ancestor")]
    BrokenActiveChain,
    #[error("sync offer has too many ancestors: {0} > {MAX_SYNC_ANCESTORS}")]
    TooManyAncestors(usize),
}

impl Authority {
    /// Return an exponentially sampled description of the active chain.
    pub fn sync_offer(&self, storage: &dyn Chonk) -> Result<SyncOffer, SyncError> {
        let path = active_path(self, storage)?;
        let mut ancestors = Vec::new();
        let mut skip = ANCESTORS_SKIP_START;
        let head_index = path.len() - 1;
        for distance in 1..=head_index.min(MAX_SYNC_HEAD_ITERATIONS) {
            if distance % skip == 0 {
                ancestors.push(path[head_index - distance].hash());
                skip <<= ANCESTORS_SKIP_SHIFT;
            }
        }
        let oldest = self.oldest_ancestor.hash();
        if ancestors.last().copied() != Some(oldest) {
            ancestors.push(oldest);
        }
        Ok(SyncOffer {
            head: self.head(),
            ancestors,
        })
    }

    /// Return active-chain AUMs the remote side may be missing.
    pub fn missing_aums(
        &self,
        storage: &dyn Chonk,
        remote: &SyncOffer,
    ) -> Result<Vec<Aum>, SyncError> {
        if remote.ancestors.len() > MAX_SYNC_ANCESTORS {
            return Err(SyncError::TooManyAncestors(remote.ancestors.len()));
        }
        if remote.head == self.head() {
            return Ok(Vec::new());
        }
        let path = active_path(self, storage)?;
        let positions: HashMap<_, _> = path
            .iter()
            .enumerate()
            .map(|(index, aum)| (aum.hash(), index))
            .collect();
        if let Some(index) = positions.get(&remote.head).copied() {
            return Ok(path[index + 1..].to_vec());
        }
        for ancestor in &remote.ancestors {
            if let Some(index) = positions.get(ancestor).copied() {
                return Ok(path[index + 1..].to_vec());
            }
        }
        Err(SyncError::NoIntersection)
    }
}

fn active_path(authority: &Authority, storage: &dyn Chonk) -> Result<Vec<Aum>, SyncError> {
    let oldest = authority.oldest_ancestor.hash();
    let mut reverse = Vec::new();
    let mut cursor = authority.head();
    for _ in 0..MAX_SCAN_ITERATIONS {
        let aum = storage.aum(&cursor).map_err(AuthorityError::from)?;
        let parent = aum.parent();
        reverse.push(aum);
        if cursor == oldest {
            reverse.reverse();
            return Ok(reverse);
        }
        cursor = parent.ok_or(SyncError::BrokenActiveChain)?;
    }
    Err(AuthorityError::TraversalLimit(MAX_SCAN_ITERATIONS).into())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;

    use super::*;
    use crate::aum::{AumKind, Signature};
    use crate::disablement::disablement_kdf;
    use crate::key::{Key, KeyKind};
    use crate::state::State;

    #[test]
    fn sync_offer_uses_upstream_exponential_ancestor_table() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let key = Key {
            kind: KeyKind::Key25519,
            votes: 1,
            public: signer.verifying_key().to_bytes().to_vec(),
            meta: None,
        };
        let state = State {
            last_aum_hash: None,
            disablement_values: vec![disablement_kdf(b"sync-test-secret")],
            keys: vec![key],
            state_id1: 0,
            state_id2: 0,
        };
        let storage = crate::chonk::MemChonk::new();
        let (mut authority, genesis) = Authority::create(&storage, state, &signer).unwrap();
        let mut chain = vec![genesis];
        for _ in 1..25 {
            let mut update = Aum {
                message_kind: AumKind::NoOp,
                prev_aum_hash: Some(chain.last().unwrap().hash().0.to_vec()),
                key: None,
                key_id: None,
                state: None,
                votes: None,
                meta: None,
                signatures: Vec::new(),
            };
            update.signatures = vec![Signature {
                key_id: signer.verifying_key().to_bytes().to_vec(),
                signature: signer.sign(&update.sig_hash()).to_bytes().to_vec(),
            }];
            chain.push(update);
        }
        authority.inform(&storage, &chain[1..]).unwrap();

        let offer = authority.sync_offer(&storage).unwrap();
        assert_eq!(offer.head, chain[24].hash());
        assert_eq!(
            offer.ancestors,
            vec![chain[20].hash(), chain[8].hash(), chain[0].hash()]
        );

        let (head, ancestors) = offer.to_strings();
        assert_eq!(SyncOffer::from_strings(&head, &ancestors).unwrap(), offer);

        let excessive = vec![chain[0].hash().to_string(); MAX_SYNC_ANCESTORS + 1];
        assert!(SyncOffer::from_strings(&head, &excessive).is_err());
        let remote = SyncOffer {
            head: AumHash([0x99; 32]),
            ancestors: vec![chain[0].hash(); MAX_SYNC_ANCESTORS + 1],
        };
        assert!(matches!(
            authority.missing_aums(&storage, &remote),
            Err(SyncError::TooManyAncestors(length)) if length == MAX_SYNC_ANCESTORS + 1
        ));
    }
}
