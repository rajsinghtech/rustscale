//! Traffic steering scores and rendezvous-based peer selection.
//!
//! This mirrors Tailscale's `net/traffic` package. A node's location priority
//! determines its score, and FNV-1a rendezvous hashing provides a stable,
//! per-client ordering for nodes with equal scores.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

use rustscale_tailcfg::{Node, NodeID};

/// A node's traffic score. Higher scores are preferred.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Score(pub i32);

impl From<i32> for Score {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl fmt::Display for Score {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A memoization cache for the traffic scores of the current node's peers.
#[derive(Clone, Debug, Default)]
pub struct Scores {
    self_id: NodeID,
    hasher: NodeHasher,
    cache: HashMap<NodeID, Score>,
}

impl Scores {
    /// Creates a score cache for `self_id` and scores all supplied peers.
    pub fn for_node(self_id: NodeID, peers: &[Node]) -> Self {
        let mut scores = Self {
            self_id,
            hasher: make_rendezvous_hasher(self_id),
            cache: HashMap::with_capacity(peers.len()),
        };
        scores.score_peers(peers);
        scores
    }

    /// Reports whether this cache was initialized with a non-zero node ID.
    pub fn is_valid(&self) -> bool {
        self.self_id != 0
    }

    /// Scores `node`, memoizing the first score observed for its node ID.
    pub fn score(&mut self, node: &Node) -> Score {
        if let Some(score) = self.cache.get(&node.ID) {
            return *score;
        }

        let score = Score(
            node.Hostinfo
                .as_ref()
                .and_then(|hostinfo| hostinfo.Location.as_ref())
                .map_or(0, |location| location.Priority),
        );
        self.cache.insert(node.ID, score);
        score
    }

    /// Scores each supplied peer and adds it to the cache.
    pub fn score_peers(&mut self, peers: &[Node]) {
        for peer in peers {
            self.score(peer);
        }
    }

    /// Iterates over every cached node ID and score.
    ///
    /// The iteration order is unspecified.
    pub fn all(&self) -> impl Iterator<Item = (NodeID, Score)> + '_ {
        self.cache.iter().map(|(&id, &score)| (id, score))
    }

    /// Sorts nodes from most to least preferred.
    ///
    /// Score is compared first. Equal scores are ordered by descending
    /// rendezvous hash, seeded with the current node ID.
    pub fn sort_nodes(&mut self, nodes: &mut [Node]) {
        let hasher = self.hasher;
        nodes.sort_unstable_by(|a, b| {
            let a_score = self.score(a);
            let b_score = self.score(b);
            b_score
                .cmp(&a_score)
                .then_with(|| hasher.compare(b.ID, a.ID))
        });
    }
}

/// Creates a score cache for `self_id` and scores all supplied peers.
pub fn scores_for(self_id: NodeID, peers: &[Node]) -> Scores {
    Scores::for_node(self_id, peers)
}

/// An FNV-1a rendezvous hasher seeded with the current node's ID.
#[derive(Clone, Copy, Debug, Default)]
pub struct NodeHasher {
    seed: NodeID,
}

impl NodeHasher {
    /// Hashes a node ID to a 64-bit rendezvous score.
    pub fn hash(self, node: NodeID) -> u64 {
        const OFFSET_BASIS: u64 = 14_695_981_039_346_656_037;
        const PRIME: u64 = 1_099_511_628_211;

        let mut hash = OFFSET_BASIS;
        for byte in self
            .seed
            .to_be_bytes()
            .into_iter()
            .chain(node.to_be_bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(PRIME);
        }
        hash
    }

    /// Compares two node hashes, falling back to node IDs on hash collision.
    ///
    /// The result is zero if and only if both node IDs are equal.
    pub fn compare(self, a: NodeID, b: NodeID) -> Ordering {
        self.hash(a).cmp(&self.hash(b)).then_with(|| a.cmp(&b))
    }
}

/// Returns an FNV-1a rendezvous hasher seeded with `seed`.
pub const fn make_rendezvous_hasher(seed: NodeID) -> NodeHasher {
    NodeHasher { seed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_tailcfg::{Hostinfo, Location};

    struct ScoresCase {
        name: &'static str,
        peers: Vec<Node>,
        want: Vec<(NodeID, Score)>,
    }

    fn node(id: NodeID, priority: Option<i32>) -> Node {
        Node {
            ID: id,
            Hostinfo: priority.map(|priority| Hostinfo {
                Location: Some(Location {
                    Priority: priority,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn scores_cases() -> Vec<ScoresCase> {
        vec![
            ScoresCase {
                name: "none",
                peers: vec![],
                want: vec![],
            },
            ScoresCase {
                name: "no-scores",
                peers: vec![node(37, None), node(42, None)],
                want: vec![(37, Score(0)), (42, Score(0))],
            },
            ScoresCase {
                name: "mixed-scores",
                peers: vec![node(37, None), node(42, Some(1))],
                want: vec![(37, Score(0)), (42, Score(1))],
            },
        ]
    }

    fn sorted_scores(scores: &Scores) -> Vec<(NodeID, Score)> {
        let mut got: Vec<_> = scores.all().collect();
        got.sort_unstable_by_key(|&(id, _)| id);
        got
    }

    #[test]
    fn score_one() {
        for case in scores_cases() {
            if case.peers.is_empty() {
                continue;
            }
            let mut scores = scores_for(1, &[]);
            for peer in &case.peers {
                let want = case
                    .want
                    .iter()
                    .find_map(|&(id, score)| (id == peer.ID).then_some(score))
                    .unwrap();
                assert_eq!(scores.score(peer), want, "{} initial", case.name);
                assert_eq!(scores.score(peer), want, "{} subsequent", case.name);
            }
            assert_eq!(sorted_scores(&scores), case.want, "{}", case.name);
        }
    }

    #[test]
    fn score_many() {
        for case in scores_cases() {
            let scores = scores_for(1, &case.peers);
            assert_eq!(
                sorted_scores(&scores),
                case.want,
                "{} scores_for",
                case.name
            );

            let mut scores = scores_for(1, &[]);
            scores.score_peers(&case.peers);
            assert_eq!(
                sorted_scores(&scores),
                case.want,
                "{} score_peers",
                case.name
            );
        }
    }

    #[test]
    fn score_is_memoized_by_node_id() {
        let mut scores = scores_for(1, &[]);
        assert_eq!(scores.score(&node(42, Some(1))), Score(1));
        assert_eq!(scores.score(&node(42, Some(99))), Score(1));
    }

    #[test]
    fn node_hasher_compare_properties() {
        for [self_id, a, b] in [[0, 0, 0], [1, 1, 1], [1, 10, 11], [1, 11, 10], [2, 10, 11]] {
            let hasher = make_rendezvous_hasher(self_id);
            let comparison = hasher.compare(a, b);
            assert_eq!(comparison == Ordering::Equal, a == b);
            assert_eq!(comparison, hasher.compare(a, b));
            assert_eq!(comparison, hasher.compare(b, a).reverse());
        }
    }

    #[test]
    fn fnv_hash_matches_go_vectors() {
        let cases = [
            ((0, 0), 0x8820_1fb9_60ff_6465),
            ((1, 1), 0xf4b5_cb5b_cc64_7005),
            ((1, 10), 0xf4b5_d05b_cc64_7884),
            ((-1, -1), 0xd660_7508_f5a1_e855),
        ];
        for ((seed, node), want) in cases {
            assert_eq!(make_rendezvous_hasher(seed).hash(node), want);
        }
    }

    #[test]
    fn sort_nodes_prefers_score_then_rendezvous_hash() {
        let mut peers = vec![node(37, Some(1)), node(42, Some(2)), node(10, Some(2))];
        let mut scores = scores_for(1, &peers);
        scores.sort_nodes(&mut peers);

        assert_eq!(peers.last().unwrap().ID, 37);
        assert_eq!(peers[0].ID, 10);
        assert_eq!(peers[1].ID, 42);
    }

    #[test]
    fn equal_scores_are_distributed_across_self_nodes() {
        let nodes: Vec<_> = (0_i64..40)
            .map(|i| {
                node(
                    i.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1),
                    Some(7),
                )
            })
            .collect();
        let mut best_counts = HashMap::<NodeID, usize>::new();

        for self_node in &nodes {
            let mut peers = nodes.clone();
            let mut scores = scores_for(self_node.ID, &peers);
            assert!(peers.iter().all(|peer| scores.score(peer) == Score(7)));
            scores.sort_nodes(&mut peers);
            *best_counts.entry(peers[0].ID).or_default() += 1;
        }

        assert!(best_counts.values().all(|&count| count <= nodes.len() / 2));
    }

    #[test]
    fn validity_requires_nonzero_self_id() {
        assert!(!scores_for(0, &[]).is_valid());
        assert!(scores_for(1, &[]).is_valid());
    }
}
