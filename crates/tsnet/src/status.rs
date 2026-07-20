//! Status types for tsnet.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use rustscale_health::Warning;
use rustscale_ipnstate::PeerStatus;
use rustscale_key::NodePublic;
use rustscale_magicsock::{PathClass, PathTelemetry};
use rustscale_tailcfg::Node;

/// Copy freshness-gated magicsock evidence into the wire-compatible
/// `ipnstate::PeerStatus` fields. A configured candidate never becomes a
/// direct/relay claim: only a current authenticated transport observation does.
pub(crate) fn apply_path_telemetry(status: &mut PeerStatus, telemetry: PathTelemetry) {
    // StatusBuilder may reuse a PeerStatus. Clear every mutually-exclusive
    // path field before copying the one currently authenticated observation,
    // so a direct -> DERP -> idle transition cannot leak a stale label.
    status.CurAddr.clear();
    status.Relay.clear();
    status.PeerRelay.clear();
    status.LastHandshake = DateTime::UNIX_EPOCH;
    status.LastSeen = telemetry
        .last_rx_at
        .map(DateTime::<Utc>::from)
        .unwrap_or(DateTime::UNIX_EPOCH);
    status.LastWrite = telemetry
        .last_tx_at
        .map(DateTime::<Utc>::from)
        .unwrap_or(DateTime::UNIX_EPOCH);

    // PathTelemetry is produced internally, but LocalAPI is a wire boundary:
    // reject malformed or internally contradictory snapshots rather than
    // exposing Active without an identity. This keeps Active and the three
    // mutually-exclusive path fields truthful even if a future producer is
    // buggy or a test injects an incomplete observation.
    let current = telemetry.fresh
        && match telemetry.class {
            PathClass::Direct | PathClass::Relay => telemetry.addr.is_some(),
            PathClass::Derp => telemetry.derp_region.is_some_and(|region| region > 0),
            PathClass::None => false,
        };
    status.Active = current;
    if !current {
        return;
    }

    match telemetry.class {
        PathClass::Direct => {
            // `current` above proves the address is present.
            status.CurAddr = telemetry.addr.expect("checked direct address").to_string();
            status.LastHandshake = telemetry
                .observed_at
                .map(DateTime::<Utc>::from)
                .unwrap_or(DateTime::UNIX_EPOCH);
        }
        PathClass::Derp => {
            // `current` above proves the observed region is positive.
            status.Relay = format!(
                "derp-{}",
                telemetry.derp_region.expect("checked DERP region")
            );
        }
        PathClass::Relay => {
            // `current` above proves the address is present.
            status.PeerRelay = telemetry.addr.expect("checked relay address").to_string();
        }
        PathClass::None => unreachable!("non-empty telemetry must have a path class"),
    }
}

/// Build the active exit-node status shared by in-process and LocalAPI views.
pub(crate) fn selected_exit_node_status(
    peers: &[Node],
    exit_key: Option<&NodePublic>,
) -> Option<Box<rustscale_ipnstate::ExitNodeStatus>> {
    let exit_key = exit_key?;
    let peer = peers.iter().find(|peer| &peer.Key == exit_key)?;
    let online = peer.Online.unwrap_or(false);
    let tailscale_ips = peer
        .Addresses
        .iter()
        .filter_map(|address| address.split('/').next().map(String::from))
        .collect();
    Some(Box::new(rustscale_ipnstate::ExitNodeStatus {
        ID: peer.StableID.clone(),
        Online: online,
        TailscaleIPs: tailscale_ips,
    }))
}

/// Information about a single peer in the netmap.
///
/// Deprecated: use `ipnstate::PeerStatus` via `Server::ipn_status()` instead.
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
///
/// Deprecated: use `ipnstate::Status` via `Server::ipn_status()` instead.
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
    /// Active health warnings (id, severity, text, since).
    pub health: Vec<Warning>,
    /// Whether the control server has signalled that our node key has
    /// expired. When true the client is in a "NeedsLogin" state.
    pub key_expired: bool,
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::NodePrivate;

    #[test]
    fn telemetry_populates_only_the_current_path_fields() {
        let at = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100);
        let direct_addr = "198.51.100.7:41641".parse().unwrap();
        let mut direct = PeerStatus::default();
        apply_path_telemetry(
            &mut direct,
            PathTelemetry {
                class: PathClass::Direct,
                addr: Some(direct_addr),
                observed_at: Some(at),
                last_rx_at: Some(at),
                fresh: true,
                ..Default::default()
            },
        );
        assert!(direct.Active);
        assert_eq!(direct.CurAddr, "198.51.100.7:41641");
        assert!(direct.Relay.is_empty());
        assert!(direct.PeerRelay.is_empty());

        let mut derp = PeerStatus::default();
        apply_path_telemetry(
            &mut derp,
            PathTelemetry {
                class: PathClass::Derp,
                derp_region: Some(7),
                observed_at: Some(at),
                fresh: true,
                ..Default::default()
            },
        );
        assert!(derp.Active);
        assert_eq!(derp.Relay, "derp-7");
        assert!(derp.CurAddr.is_empty());

        let mut relay = PeerStatus::default();
        apply_path_telemetry(
            &mut relay,
            PathTelemetry {
                class: PathClass::Relay,
                addr: Some("203.0.113.7:3478".parse().unwrap()),
                observed_at: Some(at),
                fresh: true,
                ..Default::default()
            },
        );
        assert!(relay.Active);
        assert_eq!(relay.PeerRelay, "203.0.113.7:3478");
        assert!(relay.CurAddr.is_empty());
        assert!(relay.Relay.is_empty());

        let mut idle = PeerStatus::default();
        apply_path_telemetry(
            &mut idle,
            PathTelemetry {
                observed_at: Some(at),
                fresh: false,
                ..Default::default()
            },
        );
        assert!(!idle.Active);
        assert!(idle.CurAddr.is_empty());
        assert!(idle.Relay.is_empty());
        assert!(idle.PeerRelay.is_empty());
    }

    #[test]
    fn reused_status_clears_previous_path_fields_on_each_transition() {
        let at = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100);
        let direct_addr = "198.51.100.7:41641".parse().unwrap();
        let mut status = PeerStatus::default();

        apply_path_telemetry(
            &mut status,
            PathTelemetry {
                class: PathClass::Direct,
                addr: Some(direct_addr),
                observed_at: Some(at),
                last_rx_at: Some(at),
                fresh: true,
                ..Default::default()
            },
        );
        assert!(status.Active);
        assert_eq!(status.CurAddr, direct_addr.to_string());
        assert_eq!(status.LastSeen, DateTime::<Utc>::from(at));
        assert_eq!(status.LastHandshake, DateTime::<Utc>::from(at));

        apply_path_telemetry(
            &mut status,
            PathTelemetry {
                class: PathClass::Derp,
                derp_region: Some(7),
                observed_at: Some(at + std::time::Duration::from_secs(1)),
                last_rx_at: Some(at + std::time::Duration::from_secs(1)),
                fresh: true,
                ..Default::default()
            },
        );
        assert!(status.Active);
        assert!(status.CurAddr.is_empty());
        assert_eq!(status.Relay, "derp-7");
        assert!(status.PeerRelay.is_empty());
        assert_eq!(
            status.LastSeen,
            DateTime::<Utc>::from(at + std::time::Duration::from_secs(1))
        );
        assert_eq!(status.LastHandshake, DateTime::UNIX_EPOCH);

        apply_path_telemetry(
            &mut status,
            PathTelemetry {
                observed_at: Some(at + std::time::Duration::from_secs(1)),
                last_rx_at: Some(at + std::time::Duration::from_secs(1)),
                fresh: false,
                ..Default::default()
            },
        );
        assert!(!status.Active);
        assert!(status.CurAddr.is_empty());
        assert!(status.Relay.is_empty());
        assert!(status.PeerRelay.is_empty());
        assert_eq!(
            status.LastSeen,
            DateTime::<Utc>::from(at + std::time::Duration::from_secs(1))
        );
        assert_eq!(status.LastHandshake, DateTime::UNIX_EPOCH);
    }

    #[test]
    fn malformed_or_stale_telemetry_fails_closed() {
        let at = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100);
        for telemetry in [
            PathTelemetry {
                class: PathClass::Direct,
                observed_at: Some(at),
                fresh: true,
                ..Default::default()
            },
            PathTelemetry {
                class: PathClass::Derp,
                derp_region: Some(0),
                observed_at: Some(at),
                fresh: true,
                ..Default::default()
            },
            PathTelemetry {
                class: PathClass::Relay,
                observed_at: Some(at),
                fresh: true,
                ..Default::default()
            },
            PathTelemetry {
                class: PathClass::Direct,
                addr: Some("198.51.100.7:41641".parse().unwrap()),
                observed_at: Some(at),
                fresh: false,
                ..Default::default()
            },
        ] {
            let mut status = PeerStatus::default();
            apply_path_telemetry(&mut status, telemetry);
            assert!(!status.Active);
            assert!(status.CurAddr.is_empty());
            assert!(status.Relay.is_empty());
            assert!(status.PeerRelay.is_empty());
            assert_eq!(status.LastHandshake, DateTime::UNIX_EPOCH);
        }
    }

    #[test]
    fn exit_status_uses_stable_id_across_node_key_rotation() {
        let old_key = NodePrivate::generate().public();
        let new_key = NodePrivate::generate().public();
        let peer = |key| Node {
            ID: 42,
            StableID: "n-stable-exit".into(),
            Key: key,
            Addresses: vec!["100.64.0.9/32".into()],
            Online: Some(true),
            ..Default::default()
        };

        let old = selected_exit_node_status(&[peer(old_key.clone())], Some(&old_key)).unwrap();
        let rotated = selected_exit_node_status(&[peer(new_key.clone())], Some(&new_key)).unwrap();
        assert_eq!(old.ID, "n-stable-exit");
        assert_eq!(rotated.ID, old.ID);
        assert!(selected_exit_node_status(&[peer(new_key)], Some(&old_key)).is_none());
    }
}
