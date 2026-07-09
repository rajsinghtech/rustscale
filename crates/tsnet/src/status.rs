//! Status types for tsnet.

use std::net::IpAddr;

use rustscale_key::NodePublic;
use rustscale_magicsock::PathClass;

/// Information about a single peer in the netmap.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// The peer's WireGuard node public key.
    pub node_key: NodePublic,
    /// The peer's hostname (MagicDNS name).
    pub name: String,
    /// The peer's tailscale IP addresses.
    pub ips: Vec<IpAddr>,
    /// The current magicsock path class to this peer.
    pub path_class: PathClass,
}

/// Full server status for diagnostics, returned by `Server::status()`.
#[derive(Clone, Debug)]
pub struct ServerStatus {
    /// Whether the server is up.
    pub up: bool,
    /// Our tailscale IP addresses.
    pub tailscale_ips: Vec<IpAddr>,
    /// Number of peers.
    pub peer_count: usize,
    /// Per-peer info.
    pub peers: Vec<PeerInfo>,
    /// Our hostname.
    pub hostname: String,
    /// Number of packets dropped by the packet filter.
    pub packet_drops: u64,
}

/// Identity of the peer owning a tailnet IP, returned by [`Server::whois`].
///
/// C-representable: a plain struct of primitives/`Vec`s, serializable to JSON
/// for the FFI layer's `ts_whois`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct WhoIsInfo {
    /// Whether a peer was found for the queried IP.
    pub found: bool,
    /// The peer's MagicDNS FQDN (with trailing dot).
    pub node_name: String,
    /// The peer's tailscale IP addresses.
    pub tailscale_ips: Vec<IpAddr>,
    /// The owning user's ID (`Node.User`).
    pub user_id: i64,
    /// The owning user's login name (from `UserProfile.LoginName`).
    pub login_name: String,
    /// The owning user's display name (from `UserProfile.DisplayName`).
    pub display_name: String,
}
