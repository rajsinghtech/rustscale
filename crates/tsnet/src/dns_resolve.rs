#[allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn resolve_addr(
    addr: &str,
    inner: &RunningState,
) -> Result<SocketAddr, TsnetError> {
    resolve_addr_with(addr, &inner.resolver, &inner.peers).await
}
/// Resolve `addr` (`ip:port`, `hostname:port`, or `host:port`) to a
/// [`SocketAddr`] using the shared MagicDNS resolver, the peer list, and
/// finally the system DNS resolver.
///
/// Factored out of [`resolve_addr`] so the SOCKS5 production dialer (which
/// holds clones of the shared refs, not a `&RunningState`) can reuse the exact
/// same resolution path as [`Server::dial`].
pub(crate) async fn resolve_addr_with(
    addr: &str,
    resolver: &RwLock<MagicDnsResolver>,
    peers: &RwLock<Vec<Node>>,
) -> Result<SocketAddr, TsnetError> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| TsnetError::Builder(format!("invalid address: {addr}")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| TsnetError::Builder(format!("invalid port: {addr}")))?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // Resolve via the shared MagicDNS resolver (unified with the DNS
    // responder at 100.100.100.100:53). Handles FQDNs and short hostnames
    // from the netmap.
    let r = resolver.read().await;
    if let Some(ip) = r.resolve_first(host) {
        return Ok(SocketAddr::new(ip, port));
    }
    drop(r);

    // Fallback: first-label / suffix / StableID match against the peer
    // list (used when the resolver snapshot is momentarily unavailable).
    let peers = peers.read().await;
    let host_lower = host.to_lowercase();
    let host_trimmed = host_lower.trim_end_matches('.');

    for peer in peers.iter() {
        let name = peer.Name.to_lowercase();
        let name_trimmed = name.trim_end_matches('.');
        let first_label = name_trimmed.split('.').next().unwrap_or("");
        if name_trimmed == host_trimmed
            || first_label == host_trimmed
            || name_trimmed.ends_with(&format!(".{host_trimmed}"))
            || peer.StableID.eq_ignore_ascii_case(host)
        {
            if let Some(ip) = extract_node_ips(peer).first() {
                return Ok(SocketAddr::new(*ip, port));
            }
        }
    }
    drop(peers);

    // System DNS fallback for non-tailnet hostnames (e.g. when using an
    // exit node, the SOCKS5 proxy needs to resolve internet names).
    // Without this, `dial("google.com:443")` or a SOCKS5 CONNECT to a
    // domain name fails with HostnameNotFound.
    if let Ok(mut iter) = tokio::net::lookup_host((host, port)).await {
        if let Some(sa) = iter.next() {
            return Ok(sa);
        }
    }

    Err(TsnetError::HostnameNotFound(host.to_string()))
}

/// Resolve an exit-node identifier (tailnet IP or MagicDNS hostname) to the
/// peer's node key, verifying that the peer is exit-node-capable (its
/// `AllowedIPs` contain `0.0.0.0/0`).
///
/// `ip_or_name` may be:
/// - A tailnet IP (e.g. `"100.64.0.5"`) — matched against peer `Addresses`.
/// - A MagicDNS hostname / FQDN (e.g. `"peer"` or `"peer.tailnet.ts.net"`) —
///   matched against peer `Name` (case-insensitive, trailing-dot tolerant).
///
/// Returns `Err(ExitNodeNotFound)` if no peer matches, or
/// `Err(NotExitCapable)` if the peer matches but is not exit-capable.
/// This is a pure function over a peer snapshot, so it can be unit-tested
/// with a fake netmap.
pub(crate) fn resolve_exit_node(
    peers: &[Node],
    ip_or_name: &str,
) -> Result<NodePublic, TsnetError> {
    // Try IP match first.
    if let Ok(ip) = ip_or_name.trim().parse::<IpAddr>() {
        for peer in peers {
            if peer.Key.is_zero() {
                continue;
            }
            let ips = extract_node_ips(peer);
            if ips.contains(&ip) {
                if peer_is_exit_capable(peer) {
                    return Ok(peer.Key.clone());
                }
                return Err(TsnetError::NotExitCapable(peer.Name.clone()));
            }
        }
        return Err(TsnetError::ExitNodeNotFound(ip_or_name.to_string()));
    }

    // Hostname match (case-insensitive, trailing-dot tolerant).
    // Supports full FQDN, first-label short name, and suffix match.
    let host_lower = ip_or_name.to_lowercase();
    let host_trimmed = host_lower.trim_end_matches('.');
    for peer in peers {
        if peer.Key.is_zero() {
            continue;
        }
        let name = peer.Name.to_lowercase();
        let name_trimmed = name.trim_end_matches('.');
        // First label of the FQDN (MagicDNS short name).
        let first_label = name_trimmed.split('.').next().unwrap_or("");
        if name_trimmed == host_trimmed
            || first_label == host_trimmed
            || name_trimmed.ends_with(&format!(".{host_trimmed}"))
            || peer.StableID.eq_ignore_ascii_case(ip_or_name)
        {
            if peer_is_exit_capable(peer) {
                return Ok(peer.Key.clone());
            }
            return Err(TsnetError::NotExitCapable(peer.Name.clone()));
        }
    }

    Err(TsnetError::ExitNodeNotFound(ip_or_name.to_string()))
}
