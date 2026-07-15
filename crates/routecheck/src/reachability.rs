//! Reachability probing for high-availability subnet routers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustscale_tailcfg::{Node as TailcfgNode, NodeID};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Default time allowed for one peer to respond.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default maximum number of probes in flight.
pub const DEFAULT_CONCURRENCY: usize = 5;
/// Absolute limit for one complete report, including gate wait and snapshots.
pub const DEFAULT_REPORT_DEADLINE: Duration = Duration::from_secs(60);

/// A canonical IP network prefix.
///
/// JSON uses the same CIDR string representation as Go's `netip.Prefix`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Prefix {
    addr: IpAddr,
    bits: u8,
}

impl Prefix {
    /// Construct and mask an IP prefix. Invalid prefix lengths return `None`.
    pub fn new(addr: IpAddr, bits: u8) -> Option<Self> {
        let addr = match addr {
            IpAddr::V4(addr) if bits <= 32 => {
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(addr) & mask))
            }
            IpAddr::V6(addr) if bits <= 128 => {
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(addr) & mask))
            }
            _ => return None,
        };
        Some(Self { addr, bits })
    }

    /// The masked network address.
    pub fn addr(self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    pub fn bits(self) -> u8 {
        self.bits
    }
}

impl FromStr for Prefix {
    type Err = PrefixParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (addr, bits) = value.split_once('/').ok_or(PrefixParseError)?;
        let addr = addr.parse().map_err(|_| PrefixParseError)?;
        let bits = bits.parse().map_err(|_| PrefixParseError)?;
        Self::new(addr, bits).ok_or(PrefixParseError)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

impl Serialize for Prefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Error parsing a CIDR prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid IP prefix")]
pub struct PrefixParseError;

/// A consistent snapshot of the local node and its peers.
#[derive(Clone, Debug)]
pub struct RouteSnapshot {
    pub self_node: TailcfgNode,
    pub peers: Vec<TailcfgNode>,
}

/// Supplies current route state without requiring platform route-table access.
#[async_trait]
pub trait RouteProvider: Send + Sync {
    async fn snapshot(&self) -> Result<RouteSnapshot, RouteProviderError>;
}

/// A route snapshot could not be produced.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RouteProviderError {
    #[error("network map is not available")]
    Unavailable,
    #[error("route provider failed: {0}")]
    Failed(String),
}

/// One successful peer reachability response.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ProbeResponse {
    pub latency: Duration,
}

/// A non-timeout probe failure. Like upstream, this makes the peer absent from
/// `Report::reachable` but does not fail the whole report.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProbeError {
    #[error("no path to peer")]
    NoPath,
    #[error("probe failed: {0}")]
    Failed(String),
}

/// Performs an unprivileged peer probe. Implementations should be
/// cancellation-safe: the client drops the future on deadline or cancellation.
#[async_trait]
pub trait ProbeProvider: Send + Sync {
    async fn probe(&self, peer: &TailcfgNode, address: IpAddr)
        -> Result<ProbeResponse, ProbeError>;
}

/// A node in a reachability report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeID,
    pub name: String,
    pub addr: IpAddr,
    pub routes: Vec<Prefix>,
}

/// Reachable nodes keyed by node ID. The report serializer emits this as a
/// sorted JSON array, matching upstream rather than as a JSON object.
pub type NodeSet = BTreeMap<NodeID, Node>;

/// Routers grouped by the prefix they can reach.
pub type RoutersByPrefix = BTreeMap<Prefix, Vec<TailcfgNode>>;
/// Reachable report nodes grouped by routed prefix.
pub type RoutablePrefixes = BTreeMap<Prefix, Vec<Node>>;

/// Result of one bounded route check.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub done: DateTime<Utc>,
    #[serde(
        serialize_with = "serialize_node_set",
        deserialize_with = "deserialize_node_set"
    )]
    pub reachable: NodeSet,
    #[serde(skip)]
    pub last_probed: BTreeMap<NodeID, DateTime<Utc>>,
}

impl Report {
    /// Group reachable routers by prefix. Router slices are sorted by node ID.
    pub fn routable_prefixes(&self) -> RoutablePrefixes {
        let mut result = RoutablePrefixes::new();
        for node in self.reachable.values() {
            for route in &node.routes {
                result.entry(*route).or_default().push(node.clone());
            }
        }
        for nodes in result.values_mut() {
            nodes.sort_unstable_by_key(|node| node.id);
        }
        result
    }
}

fn serialize_node_set<S>(nodes: &NodeSet, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    nodes.values().collect::<Vec<_>>().serialize(serializer)
}

fn deserialize_node_set<'de, D>(deserializer: D) -> Result<NodeSet, D::Error>
where
    D: Deserializer<'de>,
{
    let nodes = Vec::<Node>::deserialize(deserializer)?;
    Ok(nodes.into_iter().map(|node| (node.id, node)).collect())
}

/// Fatal route-check errors. Individual peer timeout/probe failures are not
/// fatal; they deterministically leave that peer out of the report.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("routecheck client closed")]
    Closed,
    #[error("routecheck cancelled")]
    Cancelled,
    #[error("routecheck report deadline exceeded")]
    DeadlineExceeded,
    #[error(transparent)]
    Routes(#[from] RouteProviderError),
}

/// Reachability client backed by injectable route and probe providers.
pub struct Client {
    routes: Arc<dyn RouteProvider>,
    prober: Arc<dyn ProbeProvider>,
    closed: CancellationToken,
    /// A shared client is server-wide, so this gate prevents concurrent
    /// callers from multiplying the per-report probe concurrency.
    refresh_gate: Semaphore,
    latest: RwLock<Option<Report>>,
}

impl Client {
    pub fn new(routes: Arc<dyn RouteProvider>, prober: Arc<dyn ProbeProvider>) -> Self {
        Self {
            routes,
            prober,
            closed: CancellationToken::new(),
            refresh_gate: Semaphore::new(1),
            latest: RwLock::new(None),
        }
    }

    /// Probe every router participating in at least one HA prefix.
    pub async fn refresh(&self, timeout: Duration) -> Result<Report, Error> {
        self.refresh_with_cancel(timeout, &CancellationToken::new())
            .await
    }

    /// As `refresh`, with explicit caller cancellation.
    pub async fn refresh_with_cancel(
        &self,
        timeout: Duration,
        cancelled: &CancellationToken,
    ) -> Result<Report, Error> {
        self.probe_all_ha_routers(DEFAULT_CONCURRENCY, timeout, cancelled)
            .await
    }

    /// Probe HA routers with an explicit concurrency limit. A limit of zero
    /// starts all probes concurrently, matching upstream.
    pub async fn probe_all_ha_routers(
        &self,
        limit: usize,
        timeout: Duration,
        cancelled: &CancellationToken,
    ) -> Result<Report, Error> {
        self.probe_all_ha_routers_with_deadline(limit, timeout, DEFAULT_REPORT_DEADLINE, cancelled)
            .await
    }

    /// Probe HA routers with separate per-peer and whole-report deadlines.
    /// The single shared gate is included in the report deadline.
    pub async fn probe_all_ha_routers_with_deadline(
        &self,
        limit: usize,
        timeout: Duration,
        report_deadline: Duration,
        cancelled: &CancellationToken,
    ) -> Result<Report, Error> {
        let deadline = tokio::time::Instant::now() + report_deadline;
        let _permit = tokio::select! {
            biased;
            () = self.closed.cancelled() => return Err(Error::Closed),
            () = cancelled.cancelled() => return Err(Error::Cancelled),
            () = tokio::time::sleep_until(deadline) => return Err(Error::DeadlineExceeded),
            permit = self.refresh_gate.acquire() => permit.expect("routecheck gate closed"),
        };
        let snapshot = tokio::select! {
            biased;
            () = self.closed.cancelled() => return Err(Error::Closed),
            () = cancelled.cancelled() => return Err(Error::Cancelled),
            () = tokio::time::sleep_until(deadline) => return Err(Error::DeadlineExceeded),
            snapshot = self.routes.snapshot() => snapshot?,
        };
        let candidates = ha_router_candidates(&snapshot);
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::DeadlineExceeded);
        }
        let report = self
            .probe_candidates(candidates, limit, timeout, deadline, cancelled)
            .await?;
        *self.latest.write().expect("latest report lock poisoned") = Some(report.clone());
        Ok(report)
    }

    /// Return the most recently completed report, if any.
    pub fn latest_report(&self) -> Option<Report> {
        self.latest
            .read()
            .expect("latest report lock poisoned")
            .clone()
    }

    /// Cancel active and future checks. This operation is idempotent.
    pub fn close(&self) {
        self.closed.cancel();
    }

    async fn probe_candidates(
        &self,
        candidates: Vec<Probed>,
        limit: usize,
        timeout: Duration,
        deadline: tokio::time::Instant,
        cancelled: &CancellationToken,
    ) -> Result<Report, Error> {
        let mut reachable = NodeSet::new();
        let mut last_probed = BTreeMap::new();
        let mut pending = candidates.into_iter();
        let max_in_flight = if limit == 0 { usize::MAX } else { limit };
        let mut tasks = JoinSet::new();

        loop {
            while tasks.len() < max_in_flight {
                if tokio::time::Instant::now() >= deadline {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(Error::DeadlineExceeded);
                }
                let Some(candidate) = pending.next() else {
                    break;
                };
                if candidate.peer.IsWireGuardOnly {
                    let now = Utc::now();
                    last_probed.insert(candidate.peer.ID, now);
                    reachable
                        .entry(candidate.peer.ID)
                        .or_insert_with(|| candidate.report_node());
                    continue;
                }

                let prober = self.prober.clone();
                tasks.spawn(async move {
                    let result = tokio::time::timeout(
                        timeout,
                        prober.probe(&candidate.peer, candidate.addr),
                    )
                    .await;
                    (candidate, result)
                });
            }

            if tasks.is_empty() {
                break;
            }

            let joined = tokio::select! {
                biased;
                () = self.closed.cancelled() => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(Error::Closed);
                }
                () = cancelled.cancelled() => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(Error::Cancelled);
                }
                () = tokio::time::sleep_until(deadline) => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(Error::DeadlineExceeded);
                }
                joined = tasks.join_next() => joined,
            };

            if let Some(Ok((candidate, result))) = joined {
                last_probed.insert(candidate.peer.ID, Utc::now());
                if matches!(result, Ok(Ok(_))) {
                    reachable
                        .entry(candidate.peer.ID)
                        .or_insert_with(|| candidate.report_node());
                }
            }
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(Error::DeadlineExceeded);
        }
        if self.closed.is_cancelled() {
            return Err(Error::Closed);
        }
        if cancelled.is_cancelled() {
            return Err(Error::Cancelled);
        }

        Ok(Report {
            done: Utc::now(),
            reachable,
            last_probed,
        })
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

/// Group peers by routed prefix. A peer's own interface/address prefixes are
/// excluded because routers never forward those destinations. A self entry in
/// a malformed peer snapshot is also excluded.
pub fn routers_by_prefix(snapshot: &RouteSnapshot) -> RoutersByPrefix {
    let mut routers = RoutersByPrefix::new();
    for peer in &snapshot.peers {
        if peer.ID == snapshot.self_node.ID {
            continue;
        }
        for route in routes(peer) {
            routers.entry(route).or_default().push(peer.clone());
        }
    }
    routers
}

fn routes(peer: &TailcfgNode) -> Vec<Prefix> {
    let addresses: BTreeSet<_> = peer
        .Addresses
        .iter()
        .filter_map(|prefix| prefix.parse::<Prefix>().ok())
        .collect();
    peer.AllowedIPs
        .iter()
        .filter_map(|prefix| prefix.parse::<Prefix>().ok())
        .filter(|prefix| !addresses.contains(prefix))
        .collect()
}

#[derive(Clone)]
struct Probed {
    peer: TailcfgNode,
    addr: IpAddr,
    routes: Vec<Prefix>,
}

impl Probed {
    fn report_node(&self) -> Node {
        Node {
            id: self.peer.ID,
            name: self.peer.Name.clone(),
            addr: self.addr,
            routes: self.routes.clone(),
        }
    }
}

fn ha_router_candidates(snapshot: &RouteSnapshot) -> Vec<Probed> {
    let mut by_id = BTreeMap::<NodeID, TailcfgNode>::new();
    for routers in routers_by_prefix(snapshot).values() {
        if routers.len() > 1 {
            for router in routers {
                by_id.entry(router.ID).or_insert_with(|| router.clone());
            }
        }
    }

    let (can4, can6) = supported_families(&snapshot.self_node);
    if !can4 && !can6 {
        return Vec::new();
    }

    let mut peers: Vec<_> = by_id.into_values().collect();
    rustscale_traffic::scores_for(snapshot.self_node.ID, &peers).sort_nodes(&mut peers);
    peers
        .into_iter()
        .filter_map(|peer| {
            pick_address(&peer, can4, can6).map(|addr| Probed {
                routes: routes(&peer),
                peer,
                addr,
            })
        })
        .collect()
}

fn supported_families(node: &TailcfgNode) -> (bool, bool) {
    let mut can4 = false;
    let mut can6 = false;
    for address in &node.Addresses {
        if let Ok(prefix) = address.parse::<Prefix>() {
            can4 |= prefix.addr().is_ipv4();
            can6 |= prefix.addr().is_ipv6();
        }
    }
    (can4, can6)
}

fn pick_address(node: &TailcfgNode, can4: bool, can6: bool) -> Option<IpAddr> {
    let addresses: Vec<_> = node
        .Addresses
        .iter()
        .filter_map(|prefix| prefix.parse::<Prefix>().ok().map(Prefix::addr))
        .collect();
    if can4 {
        if let Some(addr) = addresses.iter().copied().find(IpAddr::is_ipv4) {
            return Some(addr);
        }
    }
    if can6 {
        return addresses.into_iter().find(IpAddr::is_ipv6);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use rustscale_tailcfg::{Hostinfo, Location};

    use super::*;

    fn node(id: NodeID, addresses: &[&str], routes: &[&str]) -> TailcfgNode {
        TailcfgNode {
            ID: id,
            Name: format!("node{id}.example.test."),
            Addresses: addresses.iter().map(ToString::to_string).collect(),
            AllowedIPs: addresses
                .iter()
                .chain(routes.iter())
                .map(ToString::to_string)
                .collect(),
            ..Default::default()
        }
    }

    fn snapshot(peers: Vec<TailcfgNode>) -> RouteSnapshot {
        RouteSnapshot {
            self_node: node(99, &["100.64.0.99/32", "fd7a:115c:a1e0::99/128"], &[]),
            peers,
        }
    }

    struct Routes(RouteSnapshot);

    #[async_trait]
    impl RouteProvider for Routes {
        async fn snapshot(&self) -> Result<RouteSnapshot, RouteProviderError> {
            Ok(self.0.clone())
        }
    }

    struct ActiveGuard<'a>(&'a AtomicUsize);

    impl Drop for ActiveGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct Prober {
        gone: BTreeSet<NodeID>,
        calls: Mutex<Vec<(NodeID, IpAddr)>>,
        active: AtomicUsize,
        max_active: AtomicUsize,
        delay: Duration,
    }

    impl Prober {
        fn new(gone: impl IntoIterator<Item = NodeID>) -> Self {
            Self {
                gone: gone.into_iter().collect(),
                calls: Mutex::new(Vec::new()),
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                delay: Duration::ZERO,
            }
        }
    }

    #[async_trait]
    impl ProbeProvider for Prober {
        async fn probe(
            &self,
            peer: &TailcfgNode,
            address: IpAddr,
        ) -> Result<ProbeResponse, ProbeError> {
            self.calls.lock().unwrap().push((peer.ID, address));
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            let _active = ActiveGuard(&self.active);
            self.max_active.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            if self.gone.contains(&peer.ID) {
                Err(ProbeError::NoPath)
            } else {
                Ok(ProbeResponse {
                    latency: self.delay,
                })
            }
        }
    }

    #[test]
    fn prefix_is_canonical_and_string_serialized() {
        let prefix: Prefix = "192.0.2.42/24".parse().unwrap();
        assert_eq!(prefix.to_string(), "192.0.2.0/24");
        assert_eq!(serde_json::to_string(&prefix).unwrap(), r#""192.0.2.0/24""#);
        assert!("192.0.2.0/33".parse::<Prefix>().is_err());
    }

    #[test]
    fn grouping_excludes_self_and_peer_interface_routes() {
        let mut self_peer = node(99, &["100.64.0.99/32"], &["10.0.0.0/8"]);
        self_peer.AllowedIPs.push("bad-prefix".into());
        let peer = node(1, &["100.64.0.1/32"], &["10.0.0.42/24"]);
        let grouped = routers_by_prefix(&snapshot(vec![self_peer, peer]));
        assert!(!grouped.contains_key(&"100.64.0.1/32".parse().unwrap()));
        assert_eq!(grouped[&"10.0.0.0/24".parse().unwrap()][0].ID, 1);
        assert!(!grouped.values().flatten().any(|node| node.ID == 99));
    }

    #[tokio::test]
    async fn probes_only_deduplicated_ha_routers_and_reports_failures_as_absent() {
        let peers = vec![
            node(11, &["100.64.0.11/32"], &["0.0.0.0/0", "::/0"]),
            node(12, &["100.64.0.12/32"], &["0.0.0.0/0", "::/0"]),
            node(21, &["100.64.0.21/32"], &["192.0.2.0/24"]),
        ];
        let routes = Arc::new(Routes(snapshot(peers)));
        let prober = Arc::new(Prober::new([11]));
        let client = Client::new(routes, prober.clone());

        let report = client.refresh(Duration::from_secs(1)).await.unwrap();
        assert_eq!(
            report.reachable.keys().copied().collect::<Vec<_>>(),
            vec![12]
        );
        assert_eq!(report.last_probed.len(), 2);
        assert_eq!(prober.calls.lock().unwrap().len(), 2);
        assert_eq!(report.routable_prefixes().len(), 2);

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""reachable":[{"id":12"#));
        assert!(!json.contains("last_probed"));
    }

    #[tokio::test]
    async fn address_selection_prefers_v4_but_supports_v6_only_self() {
        let peers = vec![
            node(
                1,
                &["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
                &["192.0.2.0/24"],
            ),
            node(
                2,
                &["100.64.0.2/32", "fd7a:115c:a1e0::2/128"],
                &["192.0.2.0/24"],
            ),
        ];
        let mut snap = snapshot(peers);
        let prober = Arc::new(Prober::new([]));
        let client = Client::new(Arc::new(Routes(snap.clone())), prober.clone());
        client.refresh(Duration::from_secs(1)).await.unwrap();
        assert!(prober
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(_, addr)| addr.is_ipv4()));

        snap.self_node.Addresses = vec!["fd7a:115c:a1e0::99/128".into()];
        let prober = Arc::new(Prober::new([]));
        Client::new(Arc::new(Routes(snap)), prober.clone())
            .refresh(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(prober
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(_, addr)| addr.is_ipv6()));
    }

    #[tokio::test]
    async fn wireguard_only_is_assumed_reachable_without_probe() {
        let mut one = node(1, &["100.64.0.1/32"], &["192.0.2.0/24"]);
        one.IsWireGuardOnly = true;
        let peers = vec![one, node(2, &["100.64.0.2/32"], &["192.0.2.0/24"])];
        let prober = Arc::new(Prober::new([]));
        let report = Client::new(Arc::new(Routes(snapshot(peers))), prober.clone())
            .refresh(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(report.reachable.contains_key(&1));
        assert_eq!(prober.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn timeout_and_concurrency_are_bounded() {
        let peers: Vec<_> = (1..=6)
            .map(|id| node(id, &[&format!("100.64.0.{id}/32")], &["192.0.2.0/24"]))
            .collect();
        let mut inner = Prober::new([]);
        inner.delay = Duration::from_millis(100);
        let prober = Arc::new(inner);
        let client = Client::new(Arc::new(Routes(snapshot(peers))), prober.clone());

        let report = client
            .probe_all_ha_routers(2, Duration::from_millis(10), &CancellationToken::new())
            .await
            .unwrap();
        assert!(report.reachable.is_empty());
        assert_eq!(report.last_probed.len(), 6);
        assert!(prober.max_active.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test]
    async fn concurrent_refreshes_share_one_global_probe_cap() {
        let peers: Vec<_> = (1..=10)
            .map(|id| node(id, &[&format!("100.64.0.{id}/32")], &["192.0.2.0/24"]))
            .collect();
        let mut inner = Prober::new([]);
        inner.delay = Duration::from_millis(20);
        let prober = Arc::new(inner);
        let client = Arc::new(Client::new(
            Arc::new(Routes(snapshot(peers))),
            prober.clone(),
        ));

        let first = {
            let client = client.clone();
            tokio::spawn(async move { client.refresh(Duration::from_secs(1)).await })
        };
        let second = {
            let client = client.clone();
            tokio::spawn(async move { client.refresh(Duration::from_secs(1)).await })
        };
        assert!(first.await.unwrap().is_ok());
        assert!(second.await.unwrap().is_ok());
        assert!(
            prober.max_active.load(Ordering::SeqCst) <= DEFAULT_CONCURRENCY,
            "concurrent reports multiplied the global probe cap"
        );
    }

    #[tokio::test]
    async fn whole_report_deadline_cancels_large_peer_set_without_partial_report() {
        let peers: Vec<_> = (1..=100)
            .map(|id| node(id, &[&format!("100.64.1.{id}/32")], &["198.51.100.0/24"]))
            .collect();
        let mut inner = Prober::new([]);
        inner.delay = Duration::from_millis(100);
        let prober = Arc::new(inner);
        let client = Client::new(Arc::new(Routes(snapshot(peers))), prober.clone());

        let result = client
            .probe_all_ha_routers_with_deadline(
                DEFAULT_CONCURRENCY,
                Duration::from_secs(1),
                Duration::from_millis(20),
                &CancellationToken::new(),
            )
            .await;
        assert_eq!(result, Err(Error::DeadlineExceeded));
        assert!(client.latest_report().is_none());
        assert_eq!(prober.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancellation_and_close_are_fatal_and_do_not_publish_partial_report() {
        let peers = vec![
            node(1, &["100.64.0.1/32"], &["192.0.2.0/24"]),
            node(2, &["100.64.0.2/32"], &["192.0.2.0/24"]),
        ];
        let mut inner = Prober::new([]);
        inner.delay = Duration::from_secs(30);
        let client = Arc::new(Client::new(
            Arc::new(Routes(snapshot(peers))),
            Arc::new(inner),
        ));
        let cancel = CancellationToken::new();
        let cancel_task = cancel.clone();
        let client_task = client.clone();
        let task = tokio::spawn(async move {
            client_task
                .probe_all_ha_routers(1, Duration::from_secs(60), &cancel_task)
                .await
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        assert_eq!(task.await.unwrap(), Err(Error::Cancelled));
        assert!(client.latest_report().is_none());

        client.close();
        assert_eq!(
            client.refresh(Duration::from_secs(1)).await,
            Err(Error::Closed)
        );
    }

    #[test]
    fn traffic_priority_orders_candidates_before_probing() {
        let mut low = node(1, &["100.64.0.1/32"], &["192.0.2.0/24"]);
        low.Hostinfo = Some(Hostinfo {
            Location: Some(Location {
                Priority: 1,
                ..Default::default()
            }),
            ..Default::default()
        });
        let mut high = node(2, &["100.64.0.2/32"], &["192.0.2.0/24"]);
        high.Hostinfo = Some(Hostinfo {
            Location: Some(Location {
                Priority: 10,
                ..Default::default()
            }),
            ..Default::default()
        });
        let candidates = ha_router_candidates(&snapshot(vec![low, high]));
        assert_eq!(
            candidates.iter().map(|p| p.peer.ID).collect::<Vec<_>>(),
            vec![2, 1]
        );
    }
}
