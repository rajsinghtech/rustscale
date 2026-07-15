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

    // If no rules at all, default to allow-all (matches Go behavior when
    // the control server sends no filter).
    let all_rules: Vec<FilterRule> = if named.is_empty() {
        rustscale_tailcfg::filter_allow_all()
    } else {
        named.values().flatten().cloned().collect()
    };

    let cap_holders = build_cap_holders(peers);
    let mut filter = Filter::new(&all_rules, local_ips, &cap_holders).unwrap_or_else(|error| {
        log::warn!("tsnet: rejecting malformed initial packet filter: {error}");
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
    let all_rules: Vec<FilterRule> = if named.is_empty() {
        rustscale_tailcfg::filter_allow_all()
    } else {
        named.values().flatten().cloned().collect()
    };
    let cap_holders = build_cap_holders(peers);
    let mut new_filter = match Filter::new(&all_rules, local_ips, &cap_holders) {
        Ok(filter) => filter,
        Err(error) => {
            // A malformed signed filter delta must not retain stale packet or
            // capability grants. Fail closed until control sends a valid map.
            log::warn!("tsnet: rejecting malformed packet filter update: {error}");
            Filter::allow_none()
        }
    };
    if !advertise_routes.is_empty() {
        new_filter.add_local_cidrs(advertise_routes);
    }
    new_filter.set_shields_up(shields_up);
    let mut old_filter = filter_arc.lock().unwrap();
    new_filter.share_state_with(&mut old_filter);
    *old_filter = new_filter;
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
