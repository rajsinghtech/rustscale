//! User dial path — user-initiated traffic (SOCKS, tsnet.Dial, DNS forwarder).
//! Route-aware, happy-eyeballs, not tracked. Mirrors Go's `tsdial.Dialer.userDial`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::sleep;

use crate::dialer::UserDialPlan;
use crate::dns_map::{split_host_port, DnsMap};

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(300);

/// Resolve `addr` (host:port) through the 3-tier DNS waterfall:
/// 1. MagicDNS (`DnsMap`) — peer name → tailnet IP
/// 2. System resolver (`tokio::net::lookup_host`)
/// 3. Exit-node DoH proxy (if configured — V1: not yet wired)
pub(crate) async fn resolve_addr(
    dns_map: &DnsMap,
    addr: &str,
    exit_dns_doh: Option<&str>,
) -> std::io::Result<Vec<SocketAddr>> {
    let (host, port) = split_host_port(addr).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("bad addr: {addr}"),
        )
    })?;

    // Tier 1: MagicDNS
    if let Some(sa) = dns_map.resolve(&host, port) {
        return Ok(vec![sa]);
    }

    // Tier 2: system resolver
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await?
        .collect();
    if !addrs.is_empty() {
        return Ok(addrs);
    }

    // Tier 3: exit-node DoH (V1: not yet wired)
    if let Some(_doh_url) = exit_dns_doh {
        // TODO: resolve via DoH proxy through the exit node
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        format!("unresolved: {host}"),
    ))
}

/// Race-dial multiple addresses with happy-eyeballs (300ms stagger). Returns
/// the first successful connection; cancels the rest.
pub(crate) async fn race_dial(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no addresses to dial",
        ));
    }
    if addrs.len() == 1 {
        return dial_one(addrs[0]).await;
    }

    // Happy-eyeballs: try the first immediately, then stagger the rest.
    let mut tasks = tokio::task::JoinSet::new();
    for (i, addr) in addrs.iter().enumerate() {
        let addr = *addr;
        if i == 0 {
            tasks.spawn(dial_one(addr));
        } else {
            tasks.spawn(async move {
                sleep(HAPPY_EYEBALLS_DELAY * i as u32 / 2).await;
                dial_one(addr).await
            });
        }
    }

    let mut last_err =
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "all dials failed");
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                tasks.abort_all();
                return Ok(stream);
            }
            Ok(Err(e)) => last_err = e,
            Err(e) => last_err = std::io::Error::other(e.to_string()),
        }
    }
    Err(last_err)
}

/// Dial a single address. The `use_netstack_for_ip` and route decisions are
/// made by the caller ([`crate::Dialer::user_dial`]); this function just
/// does a plain connect (via netns for non-tailnet addresses).
async fn dial_one(addr: SocketAddr) -> std::io::Result<TcpStream> {
    rustscale_netns::dial_tcp(&addr.ip().to_string(), addr.port()).await
}

/// Compute the [`UserDialPlan`] for a given address — resolve it and determine
/// whether it would go via Tailscale.
pub(crate) fn user_dial_plan(dns_map: &DnsMap, addr: &str) -> std::io::Result<UserDialPlan> {
    let (host, port) = split_host_port(addr).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("bad addr: {addr}"),
        )
    })?;

    // Literal IP — check if it's a tailnet IP (100.64.0.0/10 or fd7a:...).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(UserDialPlan {
            addr: SocketAddr::new(ip, port),
            via_tailscale: is_tailscale_ip(ip),
        });
    }

    // MagicDNS name → via Tailscale.
    if let Some(sa) = dns_map.resolve(&host, port) {
        return Ok(UserDialPlan {
            addr: sa,
            via_tailscale: true,
        });
    }

    // Unresolved hostname — not via Tailscale (would go through system DNS).
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        format!("unresolved: {host}"),
    ))
}

/// Check if an IP is in the Tailscale CGNAT range (100.64.0.0/10) or the
/// Tailscale IPv6 ULA range (fd7a:115c:a1e0::/48).
pub(crate) fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // 100.64.0.0/10 → 100.64.0.0 – 100.127.255.255
            let octets = v4.octets();
            octets[0] == 100 && (octets[1] & 0xc0) == 0x40
        }
        IpAddr::V6(v6) => {
            // fd7a:115c:a1e0::/48
            let segs = v6.segments();
            segs[0] == 0xfd7a && segs[1] == 0x115c && segs[2] == 0xa1e0
        }
    }
}
