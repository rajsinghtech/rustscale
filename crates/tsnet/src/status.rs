//! Status types for tsnet.

use std::net::IpAddr;

use rustscale_key::NodePublic;
use rustscale_magicsock::PathClass;

/// A snapshot of the server's state after `up()` or from `status()`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Our tailscale IP addresses.
    pub tailscale_ips: Vec<IpAddr>,
    /// Number of peers in the netmap.
    pub peer_count: usize,
    /// Our home DERP region ID (0 = unknown).
    pub home_derp: i32,
    /// Whether the server is online.
    pub online: bool,
}

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
