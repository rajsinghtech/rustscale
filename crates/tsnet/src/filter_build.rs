#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------
// Packet filter helpers
// ---------------------------------------------------------------------------

/// Build a [`Filter`] from a [`MapResponse`]'s PacketFilter/PacketFilters
/// fields. Returns the filter and the initial named-filter map.
///
/// `peers` is used to build the peer IP → capability-set map so the filter
/// can evaluate `cap:<name>` source predicates. `shields_up` enables
/// shields-up mode (deny new inbound flows).
pub(crate) fn build_filter_from_map_response(
    resp: &MapResponse,
    local_ips: &[IpAddr],
    peers: &[Node],
    shields_up: bool,
) -> (Filter, BTreeMap<String, Vec<FilterRule>>) {
    let mut named: BTreeMap<String, Vec<FilterRule>> = BTreeMap::new();

    // PacketFilter (singular): sets the "base" key.
    if let Some(pf) = &resp.PacketFilter {
        named.insert("base".into(), pf.clone());
    }

    // PacketFilters (plural): named delta updates.
    if let Some(pfs) = &resp.PacketFilters {
        // "*" with None = clear all.
        if let Some(None) = pfs.get("*") {
            named.clear();
        }
        for (key, val) in pfs {
            if key == "*" {
                continue;
            }
            match val {
                None => {
                    named.remove(key);
                }
                Some(rules) if rules.is_empty() => {
                    named.remove(key);
                }
                Some(rules) => {
                    named.insert(key.clone(), rules.clone());
                }
            }
        }
    }

    // An absent/cleared ACL and malformed ACL are both deny-all. There is no
    // safe basis for synthesizing allow-all from an untrusted parse failure.
    let all_rules: Vec<FilterRule> = named.values().flatten().cloned().collect();

    let cap_holders = build_cap_holders(peers);
    let mut filter = Filter::new(&all_rules, local_ips, &cap_holders).unwrap_or_else(|error| {
        log::error!("tsnet: initial packet filter parse failed closed: {error}");
        Filter::allow_none()
    });
    filter.set_shields_up(shields_up);
    (filter, named)
}

/// Process PacketFilter/PacketFilters deltas from a MapResponse into the
/// named-filter map. Returns true if the map changed (and the filter should
/// be rebuilt).
pub(crate) fn process_filter_deltas(
    resp: &MapResponse,
    named: &mut BTreeMap<String, Vec<FilterRule>>,
) -> bool {
    let mut changed = false;

    if let Some(pf) = &resp.PacketFilter {
        named.insert("base".into(), pf.clone());
        changed = true;
    }

    if let Some(pfs) = &resp.PacketFilters {
        if let Some(None) = pfs.get("*") {
            named.clear();
            changed = true;
        }
        for (key, val) in pfs {
            if key == "*" {
                continue;
            }
            match val {
                None => {
                    if named.remove(key).is_some() {
                        changed = true;
                    }
                }
                Some(rules) if rules.is_empty() => {
                    if named.remove(key).is_some() {
                        changed = true;
                    }
                }
                Some(rules) => {
                    named.insert(key.clone(), rules.clone());
                    changed = true;
                }
            }
        }
    }

    changed
}

/// Rebuild the filter from the named-filter map and update the shared
/// `Arc<Mutex<Filter>>`. Advertised subnet routes are added to the filter's
/// localNets so the subnet router admits packets destined to those subnets.
/// `peers` supplies the peer capability map; `shields_up` enables
/// shields-up mode.
pub(crate) fn rebuild_filter(
    filter_arc: &Arc<std::sync::Mutex<Filter>>,
    named: &BTreeMap<String, Vec<FilterRule>>,
    local_ips: &[IpAddr],
    advertise_routes: &[String],
    peers: &[Node],
    shields_up: bool,
) {
    let all_rules: Vec<FilterRule> = named.values().flatten().cloned().collect();
    let cap_holders = build_cap_holders(peers);
    match Filter::new(&all_rules, local_ips, &cap_holders) {
        Ok(mut new_filter) => {
            if !advertise_routes.is_empty() {
                new_filter.add_local_cidrs(advertise_routes);
            }
            new_filter.set_shields_up(shields_up);
            let mut old_filter = filter_arc.lock().unwrap();
            new_filter.share_state_with(&mut old_filter);
            *old_filter = new_filter;
        }
        Err(error) => {
            // A malformed mutation is not proven monotonic, so retaining old
            // ACL, Taildrive grants, or established flow state is unsafe.
            log::error!("tsnet: packet filter update parse failed closed: {error}");
            let mut deny = Filter::allow_none();
            deny.set_shields_up(shields_up);
            *filter_arc.lock().unwrap() = deny;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn extract_tailscale_ips(map: &MapResponse) -> Vec<IpAddr> {
    map.Node.as_ref().map(extract_node_ips).unwrap_or_default()
}

pub(crate) fn extract_node_ips(node: &Node) -> Vec<IpAddr> {
    node.Addresses
        .iter()
        .filter_map(|s| s.split('/').next().and_then(|ip| ip.parse::<IpAddr>().ok()))
        .collect()
}

/// Build the peer IP → capability-set map used by the packet filter to
/// evaluate `cap:<name>` source predicates. Each peer's tailnet IPs are
/// mapped to the keys of its `Node.CapMap`. Mirrors Go's
/// `LocalBackend.srcIPHasCapForFilter` (which resolves the peer by address
/// then checks `Node.HasCap`).
fn build_cap_holders(peers: &[Node]) -> BTreeMap<IpAddr, BTreeSet<String>> {
    let mut out: BTreeMap<IpAddr, BTreeSet<String>> = BTreeMap::new();
    for peer in peers {
        if peer.CapMap.is_empty() {
            continue;
        }
        let caps: BTreeSet<String> = peer.CapMap.keys().cloned().collect();
        for ip in extract_node_ips(peer) {
            // A peer may have multiple addresses; they all share the same
            // node's CapMap. Merge in case an IP is re-used across nodes.
            out.entry(ip).or_default().extend(caps.iter().cloned());
        }
    }
    out
}

/// Pure WhoIs lookup over a peer snapshot + user profiles. Returns `None`
/// when no peer has `remote_addr` among its `Addresses`. Used by
/// [`Server::whois`] and unit tests (fake netmap).
pub(crate) fn whois_lookup(
    peers: &[Node],
    user_profiles: &BTreeMap<UserID, UserProfile>,
    remote_addr: IpAddr,
) -> Option<WhoIsInfo> {
    for peer in peers {
        let ips = extract_node_ips(peer);
        if ips.contains(&remote_addr) {
            let up = user_profiles.get(&peer.User);
            return Some(WhoIsInfo {
                found: true,
                node_name: peer.Name.clone(),
                tailscale_ips: ips,
                user_id: peer.User,
                login_name: up.map(|p| p.LoginName.clone()).unwrap_or_default(),
                display_name: up.map(|p| p.DisplayName.clone()).unwrap_or_default(),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_filter::Response;
    use rustscale_tailcfg::{NetPortRange, PortRange};

    fn rule(source: &str, destination: &str, port: u16) -> FilterRule {
        FilterRule {
            SrcIPs: vec![source.into()],
            DstPorts: vec![NetPortRange {
                IP: destination.into(),
                Bits: None,
                Ports: PortRange {
                    First: port,
                    Last: port,
                },
            }],
            ..Default::default()
        }
    }

    #[test]
    fn initial_named_filters_survive_unrelated_deltas() {
        let local: IpAddr = "100.64.0.1".parse().unwrap();
        let mut initial_named = BTreeMap::new();
        initial_named.insert(
            "initial".into(),
            Some(vec![rule("100.64.0.2", "100.64.0.1", 80)]),
        );
        let initial = MapResponse {
            PacketFilters: Some(initial_named),
            ..Default::default()
        };
        let (filter, mut named) = build_filter_from_map_response(&initial, &[local], &[], false);
        let filter = Arc::new(std::sync::Mutex::new(filter));
        assert_eq!(
            filter
                .lock()
                .unwrap()
                .check("100.64.0.2".parse().unwrap(), local, 6, 80,),
            Response::Accept
        );

        let mut delta_named = BTreeMap::new();
        delta_named.insert(
            "later".into(),
            Some(vec![rule("100.64.0.3", "100.64.0.1", 443)]),
        );
        let delta = MapResponse {
            PacketFilters: Some(delta_named),
            ..Default::default()
        };
        assert!(process_filter_deltas(&delta, &mut named));
        rebuild_filter(&filter, &named, &[local], &[], &[], false);

        let mut active = filter.lock().unwrap();
        assert_eq!(
            active.check("100.64.0.2".parse().unwrap(), local, 6, 80),
            Response::Accept,
            "the initial named ACL must not disappear on the first update"
        );
        assert_eq!(
            active.check("100.64.0.3".parse().unwrap(), local, 6, 443),
            Response::Accept
        );
    }

    #[test]
    fn malformed_initial_and_update_filters_deny_all() {
        let local: IpAddr = "100.64.0.1".parse().unwrap();
        let malformed = rule("not-an-ip", "100.64.0.1", 80);
        let initial = MapResponse {
            PacketFilter: Some(vec![malformed.clone()]),
            ..Default::default()
        };
        let (mut filter, _) = build_filter_from_map_response(&initial, &[local], &[], false);
        assert_eq!(
            filter.check("100.64.0.2".parse().unwrap(), local, 6, 80),
            Response::Drop
        );

        let valid = MapResponse {
            PacketFilter: Some(vec![rule("100.64.0.2", "100.64.0.1", 80)]),
            ..Default::default()
        };
        let (filter, mut named) = build_filter_from_map_response(&valid, &[local], &[], false);
        let filter = Arc::new(std::sync::Mutex::new(filter));
        let bad_update = MapResponse {
            PacketFilter: Some(vec![malformed]),
            ..Default::default()
        };
        assert!(process_filter_deltas(&bad_update, &mut named));
        rebuild_filter(&filter, &named, &[local], &[], &[], false);
        assert_eq!(
            filter
                .lock()
                .unwrap()
                .check("100.64.0.2".parse().unwrap(), local, 6, 80,),
            Response::Drop,
            "a malformed update must replace active and established allow state with deny-all"
        );
    }
}
