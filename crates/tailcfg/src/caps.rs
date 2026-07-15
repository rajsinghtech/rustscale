//! Peer relay capability constants, node attributes, and helpers.
//!
//! Ports the relay-related constants from Go's `tailcfg/tailcfg.go`:
//! - `PeerCapabilityRelay` / `PeerCapabilityRelayTarget` (lines 1578-1583)
//! - `NodeAttrDisableRelayServer` / `NodeAttrDisableRelayClient` (lines 2715-2727)
//! - `capVerIsRelayCapable` threshold `CAP_VERSION_RELAY = 120` (lines 169-170)

use crate::NodeCapMap;

/// A peer capability string set by the ACL engine on nodes (matches Go's
/// `tailcfg.PeerCapability`, which is a string alias).
#[allow(dead_code)]
pub type PeerCapability = str;

/// Grants the ability for a peer to allocate relay endpoints.
pub const PEER_CAPABILITY_RELAY: &str = "tailscale.com/cap/relay";

/// Grants the current node the ability to allocate relay endpoints to the peer
/// which has this capability.
pub const PEER_CAPABILITY_RELAY_TARGET: &str = "tailscale.com/cap/relay-target";

/// Prevents the node from acting as an underlay UDP relay server. The key only
/// needs to be present in `NodeCapMap` to take effect.
pub const NODE_ATTR_DISABLE_RELAY_SERVER: &str = "disable-relay-server";

/// Prevents the node from both allocating UDP relay server endpoints itself,
/// and from using endpoints allocated by its peers.
pub const NODE_ATTR_DISABLE_RELAY_CLIENT: &str = "disable-relay-client";

/// Enables the Linux UDP GSO smaller-sentinel-tail workaround. Capability
/// version 141 advertises support for this live node attribute.
pub const NODE_ATTR_NEVER_GSO_EQUAL_TAIL: &str = "never-gso-equal-tail";

/// Minimum capability version for relay support. Clients with `Cap` < this
/// value are not relay-capable and will be skipped during relay server
/// discovery.
pub const CAP_VERSION_RELAY: i32 = 120;

/// Check whether a capability version is relay-capable (>= 120).
pub fn cap_ver_is_relay_capable(cap: i32) -> bool {
    cap >= CAP_VERSION_RELAY
}

/// Check whether a `NodeCapMap` contains the given capability key.
///
/// This mirrors Go's `PeerCapMap.HasCapability` — the key only needs to be
/// present (values are ignored for boolean capabilities).
pub fn has_capability(cap_map: &NodeCapMap, cap: &str) -> bool {
    cap_map.contains_key(cap)
}

/// Check whether a `NodeCapMap` has the `disable-relay-server` attribute set.
pub fn relay_server_disabled(cap_map: &NodeCapMap) -> bool {
    has_capability(cap_map, NODE_ATTR_DISABLE_RELAY_SERVER)
}

/// Check whether a `NodeCapMap` has the `disable-relay-client` attribute set.
pub fn relay_client_disabled(cap_map: &NodeCapMap) -> bool {
    has_capability(cap_map, NODE_ATTR_DISABLE_RELAY_CLIENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RawMessage;
    use std::collections::BTreeMap;

    #[test]
    fn cap_version_relay_check() {
        assert!(!cap_ver_is_relay_capable(119));
        assert!(cap_ver_is_relay_capable(120));
        assert!(cap_ver_is_relay_capable(200));
        assert!(!cap_ver_is_relay_capable(0));
    }

    #[test]
    fn has_capability_present() {
        let mut map = BTreeMap::new();
        map.insert(
            PEER_CAPABILITY_RELAY_TARGET.to_string(),
            vec![RawMessage::default()],
        );
        assert!(has_capability(&map, PEER_CAPABILITY_RELAY_TARGET));
        assert!(!has_capability(&map, PEER_CAPABILITY_RELAY));
    }

    #[test]
    fn has_capability_empty_map() {
        let map = BTreeMap::new();
        assert!(!has_capability(&map, PEER_CAPABILITY_RELAY));
        assert!(!has_capability(&map, PEER_CAPABILITY_RELAY_TARGET));
    }

    #[test]
    fn relay_disabled_checks() {
        let mut map = BTreeMap::new();
        assert!(!relay_server_disabled(&map));
        assert!(!relay_client_disabled(&map));

        map.insert(
            NODE_ATTR_DISABLE_RELAY_SERVER.to_string(),
            vec![RawMessage::default()],
        );
        assert!(relay_server_disabled(&map));
        assert!(!relay_client_disabled(&map));

        map.insert(
            NODE_ATTR_DISABLE_RELAY_CLIENT.to_string(),
            vec![RawMessage::default()],
        );
        assert!(relay_server_disabled(&map));
        assert!(relay_client_disabled(&map));
    }

    #[test]
    fn relay_constants_match_go() {
        assert_eq!(PEER_CAPABILITY_RELAY, "tailscale.com/cap/relay");
        assert_eq!(
            PEER_CAPABILITY_RELAY_TARGET,
            "tailscale.com/cap/relay-target"
        );
        assert_eq!(NODE_ATTR_DISABLE_RELAY_SERVER, "disable-relay-server");
        assert_eq!(NODE_ATTR_DISABLE_RELAY_CLIENT, "disable-relay-client");
        assert_eq!(NODE_ATTR_NEVER_GSO_EQUAL_TAIL, "never-gso-equal-tail");
    }
}
