//! Stable-node peer reconciliation and data-plane identity provenance.
//!
//! Control identifies a node by `Node.ID`; WireGuard authenticates its current
//! `Node.Key`.  This module keeps those concepts separate: map deltas reconcile
//! by stable ID, while every decrypted packet and accepted PeerAPI flow must
//! still match the current key owning its source address.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use rustscale_key::NodePublic;
use rustscale_packet::{Parsed, TCPFlag, TCP};
use rustscale_tailcfg::{MapResponse, Node, PeerChange};

const FLOW_TTL: Duration = Duration::from_secs(60);
const MAX_FLOWS: usize = 4096;

#[derive(Clone, Default)]
struct IdentitySnapshot {
    by_ip: HashMap<IpAddr, NodePublic>,
}

/// Shared map-application gate, current address ownership, and TUN flow
/// provenance. Data-plane readers hold `gate` while consulting tunnels/routes;
/// map updates hold its writer while replacing every peer-derived subsystem.
pub(crate) struct Runtime {
    pub(crate) gate: tokio::sync::RwLock<()>,
    identity: RwLock<Arc<IdentitySnapshot>>,
    authorization_epoch: AtomicU64,
    flows: Mutex<HashMap<Flow, FlowIdentity>>,
}

impl Runtime {
    pub(crate) fn new(peers: &[Node]) -> Result<Arc<Self>, ReconcileError> {
        let identity = IdentitySnapshot::from_peers(peers)?;
        Ok(Arc::new(Self {
            gate: tokio::sync::RwLock::new(()),
            identity: RwLock::new(Arc::new(identity)),
            authorization_epoch: AtomicU64::new(1),
            flows: Mutex::new(HashMap::new()),
        }))
    }

    pub(crate) fn install_locked(&self, peers: &[Node]) -> Result<(), ReconcileError> {
        let identity = IdentitySnapshot::from_peers(peers)?;
        *self.identity.write().expect("peer identity lock poisoned") = Arc::new(identity);
        self.advance_authorization_epoch_locked();
        Ok(())
    }

    pub(crate) fn authorization_epoch(&self) -> u64 {
        self.authorization_epoch.load(Ordering::Acquire)
    }

    /// Publish a non-identity authorization change (for example ShieldsUp)
    /// while the caller holds `gate.write()`. Final plaintext delivery rejects
    /// work staged against the preceding epoch.
    pub(crate) fn advance_authorization_epoch_locked(&self) {
        self.authorization_epoch.fetch_add(1, Ordering::AcqRel);
        self.flows.lock().expect("peer flow lock poisoned").clear();
    }

    pub(crate) fn packet_source_matches(&self, peer: &NodePublic, packet: &[u8]) -> bool {
        let parsed = Parsed::decode(packet);
        if parsed.ip_version == 0 {
            return false;
        }
        self.identity
            .read()
            .expect("peer identity lock poisoned")
            .by_ip
            .get(&parsed.src)
            .is_some_and(|owner| owner == peer)
    }

    pub(crate) fn current_owner(&self, ip: IpAddr) -> Option<NodePublic> {
        self.identity
            .read()
            .expect("peer identity lock poisoned")
            .by_ip
            .get(&ip)
            .cloned()
    }

    /// Record provenance for a newly arriving TCP flow after WireGuard and
    /// source-address ownership checks have both succeeded.
    pub(crate) fn record_packet(&self, peer: &NodePublic, packet: &[u8]) {
        let parsed = Parsed::decode(packet);
        if parsed.ip_proto != TCP || !parsed.tcp_flags.contains(TCPFlag::SYN) {
            return;
        }
        let flow = Flow {
            remote: SocketAddr::new(parsed.src, parsed.src_port),
            local: SocketAddr::new(parsed.dst, parsed.dst_port),
        };
        let now = Instant::now();
        let mut flows = self.flows.lock().expect("peer flow lock poisoned");
        flows.retain(|_, identity| now.duration_since(identity.seen) <= FLOW_TTL);
        if flows.len() >= MAX_FLOWS && !flows.contains_key(&flow) {
            if let Some(oldest) = flows
                .iter()
                .min_by_key(|(_, identity)| identity.seen)
                .map(|(flow, _)| *flow)
            {
                flows.remove(&oldest);
            }
        }
        flows.insert(
            flow,
            FlowIdentity {
                peer: peer.clone(),
                seen: now,
            },
        );
    }

    pub(crate) fn flow_owner(&self, remote: SocketAddr, local: SocketAddr) -> Option<NodePublic> {
        let flow = Flow { remote, local };
        let now = Instant::now();
        let mut flows = self.flows.lock().ok()?;
        let identity = flows.get(&flow)?;
        if now.duration_since(identity.seen) > FLOW_TTL {
            flows.remove(&flow);
            return None;
        }
        Some(identity.peer.clone())
    }
}

fn parse_node_address(address: &str) -> Option<IpAddr> {
    let (ip, prefix) = address.split_once('/')?;
    if prefix.contains('/') {
        return None;
    }
    let ip = ip.parse::<IpAddr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    let valid = match ip {
        IpAddr::V4(_) => prefix == 32,
        IpAddr::V6(_) => prefix == 128,
    };
    valid.then_some(ip)
}

impl IdentitySnapshot {
    fn from_peers(peers: &[Node]) -> Result<Self, ReconcileError> {
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        let mut by_ip = HashMap::new();
        for peer in peers {
            if peer.ID == 0 {
                return Err(ReconcileError::MissingStableId);
            }
            if !ids.insert(peer.ID) {
                return Err(ReconcileError::DuplicateStableId(peer.ID));
            }
            if peer.Key.is_zero() {
                return Err(ReconcileError::MissingNodeKey(peer.ID));
            }
            if !keys.insert(peer.Key.clone()) {
                return Err(ReconcileError::DuplicateNodeKey(peer.Key.to_string()));
            }
            for address in &peer.Addresses {
                let ip = parse_node_address(address)
                    .ok_or_else(|| ReconcileError::InvalidAddress(address.clone()))?;
                match by_ip.get(&ip) {
                    Some(owner) if owner != &peer.Key => {
                        return Err(ReconcileError::DuplicateAddress(ip));
                    }
                    _ => {
                        by_ip.insert(ip, peer.Key.clone());
                    }
                }
            }
        }
        Ok(Self { by_ip })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Flow {
    remote: SocketAddr,
    local: SocketAddr,
}

struct FlowIdentity {
    peer: NodePublic,
    seen: Instant,
}

/// Apply a map response to a peer snapshot by stable `Node.ID`. Full `Peers`
/// replaces the set; `PeersChanged` replaces the matching stable node even
/// when its key/address rotated; patches and removals also address stable IDs.
pub(crate) fn reconcile(
    current: &[Node],
    response: &MapResponse,
) -> Result<Vec<Node>, ReconcileError> {
    let mut peers = response
        .Peers
        .as_ref()
        .map_or_else(|| current.to_vec(), Clone::clone);

    let mut changed_ids = HashSet::new();
    for changed in &response.PeersChanged {
        if changed.ID == 0 {
            return Err(ReconcileError::MissingStableId);
        }
        if !changed_ids.insert(changed.ID) {
            return Err(ReconcileError::DuplicateStableId(changed.ID));
        }
        if let Some(index) = peers.iter().position(|peer| peer.ID == changed.ID) {
            peers[index] = changed.clone();
        } else {
            peers.push(changed.clone());
        }
    }

    if !response.PeersRemoved.is_empty() {
        let removed: HashSet<_> = response.PeersRemoved.iter().copied().collect();
        peers.retain(|peer| !removed.contains(&peer.ID));
    }

    if let Some(patches) = response.PeersChangedPatch.as_ref() {
        let mut patch_ids = HashSet::new();
        for patch in patches {
            if patch.NodeID == 0 {
                return Err(ReconcileError::MissingStableId);
            }
            if !patch_ids.insert(patch.NodeID) {
                return Err(ReconcileError::DuplicateStableId(patch.NodeID));
            }
            if let Some(peer) = peers.iter_mut().find(|peer| peer.ID == patch.NodeID) {
                apply_patch(peer, patch);
            }
        }
    }

    IdentitySnapshot::from_peers(&peers)?;
    Ok(peers)
}

pub(crate) fn apply_patch(node: &mut Node, patch: &PeerChange) {
    if patch.DERPRegion != 0 {
        node.HomeDERP = patch.DERPRegion;
    }
    if patch.Cap != 0 {
        node.Cap = patch.Cap;
    }
    if !patch.CapMap.is_empty() {
        node.CapMap.clone_from(&patch.CapMap);
    }
    if !patch.Endpoints.is_empty() {
        node.Endpoints.clone_from(&patch.Endpoints);
    }
    if let Some(key) = patch.Key.as_ref() {
        node.Key = key.clone();
    }
    if let Some(signature) = patch.KeySignature.as_ref() {
        node.KeySignature = Some(signature.clone());
    }
    if let Some(disco) = patch.DiscoKey.as_ref() {
        node.DiscoKey = disco.clone();
    }
    if let Some(online) = patch.Online {
        node.Online = Some(online);
    }
    if let Some(last_seen) = patch.LastSeen {
        node.LastSeen = Some(last_seen);
    }
    if let Some(key_expiry) = patch.KeyExpiry {
        node.KeyExpiry = Some(key_expiry);
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReconcileError {
    #[error("peer is missing a stable Node.ID")]
    MissingStableId,
    #[error("duplicate stable Node.ID {0}")]
    DuplicateStableId(i64),
    #[error("peer {0} is missing a WireGuard node key")]
    MissingNodeKey(i64),
    #[error("duplicate WireGuard node key {0}")]
    DuplicateNodeKey(String),
    #[error("invalid peer address {0:?}")]
    InvalidAddress(String),
    #[error("peer address {0} has multiple owners")]
    DuplicateAddress(IpAddr),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::NodePrivate;

    fn node(id: i64, key: &NodePublic, address: &str) -> Node {
        Node {
            ID: id,
            Key: key.clone(),
            Addresses: vec![format!("{address}/32")],
            AllowedIPs: vec![format!("{address}/32")],
            ..Default::default()
        }
    }

    #[test]
    fn rotation_replaces_by_stable_id_and_removes_old_address() {
        let old = NodePrivate::generate().public();
        let new = NodePrivate::generate().public();
        let current = vec![node(7, &old, "100.64.0.7")];
        let response = MapResponse {
            PeersChanged: vec![node(7, &new, "100.64.0.8")],
            ..Default::default()
        };
        let peers = reconcile(&current, &response).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].Key, new);
        assert_eq!(peers[0].Addresses, ["100.64.0.8/32"]);
    }

    #[test]
    fn absent_full_snapshot_preserves_and_present_empty_revokes() {
        let key = NodePrivate::generate().public();
        let current = vec![node(7, &key, "100.64.0.7")];
        assert_eq!(
            reconcile(&current, &MapResponse::default()).unwrap(),
            current,
            "an omitted Peers field is a delta omission"
        );
        let empty = MapResponse {
            Peers: Some(Vec::new()),
            ..Default::default()
        };
        assert!(reconcile(&current, &empty).unwrap().is_empty());
    }

    #[test]
    fn malformed_address_prefix_is_rejected() {
        let key = NodePrivate::generate().public();
        let response = MapResponse {
            Peers: Some(vec![Node {
                ID: 1,
                Key: key,
                Addresses: vec!["100.64.0.1/garbage".into()],
                ..Default::default()
            }]),
            ..Default::default()
        };
        assert!(matches!(
            reconcile(&[], &response),
            Err(ReconcileError::InvalidAddress(_))
        ));
    }

    #[test]
    fn duplicate_address_ownership_is_rejected() {
        let first = NodePrivate::generate().public();
        let second = NodePrivate::generate().public();
        let response = MapResponse {
            Peers: Some(vec![
                node(1, &first, "100.64.0.1"),
                node(2, &second, "100.64.0.1"),
            ]),
            ..Default::default()
        };
        assert!(matches!(
            reconcile(&[], &response),
            Err(ReconcileError::DuplicateAddress(_))
        ));
    }
}
