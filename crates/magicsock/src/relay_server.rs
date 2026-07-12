//! Relay server extension: owns a `udprelay::Server` and handles
//! `AllocateUDPRelayEndpointRequest` disco messages received via DERP.
//!
//! Ports Go's `feature/relayserver/relayserver.go`.
//!
//! When enabled via `MagicsockConfig::peer_relay_server`, the extension
//! creates a `udprelay::Server` on construction. Incoming allocation
//! requests (type 0x08) received over DERP are authenticated against the
//! known peer set, then routed to `Server::allocate_endpoint`. The
//! response is sent back via DERP to the requester.
//!
//! The in-process shortcut (Go `magicsock.go:1946-1963`) bypasses DERP
//! when the relay server is self: `handle_self_alloc_request` calls the
//! extension directly.

use std::sync::{Arc, RwLock};

use rustscale_disco::{AllocateUdpRelayEndpointResponse, UdpRelayEndpoint};
use rustscale_key::DiscoPublic;
use rustscale_tailcfg::{relay_server_disabled, NodeCapMap};
use rustscale_udprelay::{Server, ServerConfig};

use rustscale_udprelay::ServerEndpoint as UdprelayServerEndpoint;

/// Extension that owns a UDP relay server and handles allocation requests.
///
/// Created when `MagicsockConfig::peer_relay_server` is true. The extension
/// owns a `udprelay::Server` instance and translates between the disco wire
/// types (`AllocateUdpRelayEndpointRequest`/`Response`) and the server's
/// `allocate_endpoint` API.
pub struct RelayServerExtension {
    server: Option<Server>,
    self_cap_map: Arc<RwLock<NodeCapMap>>,
}

impl RelayServerExtension {
    /// Create a new extension. When `enabled`, starts the `udprelay::Server`
    /// immediately. The `config` override is used for testing (shortened
    /// lifetimes); `None` uses defaults.
    pub async fn new(
        enabled: bool,
        config: Option<ServerConfig>,
        self_cap_map: Arc<RwLock<NodeCapMap>>,
    ) -> Self {
        let server = if enabled {
            let cfg = config.unwrap_or_default();
            match Server::new(cfg).await {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("relay_server: failed to start udprelay server: {e}");
                    None
                }
            }
        } else {
            None
        };
        Self {
            server,
            self_cap_map,
        }
    }

    /// Whether the relay server is running.
    pub fn is_running(&self) -> bool {
        self.server.is_some()
    }

    /// The server's disco public key, if the server is running.
    pub fn disco_public(&self) -> Option<DiscoPublic> {
        self.server
            .as_ref()
            .map(rustscale_udprelay::Server::disco_public)
    }

    /// The server's local address, if running.
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.server
            .as_ref()
            .map(rustscale_udprelay::Server::local_addr_v4)
    }

    /// A reference to the underlying server (for testing).
    pub fn server(&self) -> Option<&Server> {
        self.server.as_ref()
    }

    /// Handle an allocation request. Authenticates that the relay server is
    /// not disabled via `NODE_ATTR_DISABLE_RELAY_SERVER`, then calls
    /// `allocate_endpoint` on the server.
    ///
    /// Returns `None` if the server is not running or disabled.
    pub fn handle_alloc_request(
        &self,
        client_disco: [DiscoPublic; 2],
        generation: u32,
    ) -> Option<AllocateUdpRelayEndpointResponse> {
        let server = self.server.as_ref()?;

        // Check NODE_ATTR_DISABLE_RELAY_SERVER from self CapMap.
        let disabled = {
            let cap_map = self
                .self_cap_map
                .read()
                .expect("self_cap_map lock poisoned");
            relay_server_disabled(&cap_map)
        };
        if disabled {
            return None;
        }

        let se = server
            .allocate_endpoint(client_disco[0].clone(), client_disco[1].clone())
            .ok()?;

        let mut resp = endpoint_to_response(&se);
        resp.generation = generation;
        Some(resp)
    }

    /// Update the self node's CapMap (called when the netmap changes).
    pub fn set_self_cap_map(&self, cap_map: NodeCapMap) {
        let mut guard = self
            .self_cap_map
            .write()
            .expect("self_cap_map lock poisoned");
        *guard = cap_map;
    }

    /// Close the relay server.
    pub fn close(&self) {
        if let Some(ref server) = self.server {
            server.close();
        }
    }
}

impl Drop for RelayServerExtension {
    fn drop(&mut self) {
        self.close();
    }
}

/// Convert a `udprelay::ServerEndpoint` to a disco
/// `AllocateUdpRelayEndpointResponse`.
fn endpoint_to_response(se: &UdprelayServerEndpoint) -> AllocateUdpRelayEndpointResponse {
    AllocateUdpRelayEndpointResponse {
        generation: 0,
        endpoint: UdpRelayEndpoint {
            server_disco: se.server_disco.clone(),
            client_disco: se.client_disco.clone(),
            lamport_id: se.lamport_id,
            vni: se.vni,
            bind_lifetime: se.bind_lifetime,
            steady_state_lifetime: se.steady_state_lifetime,
            addr_ports: se.addr_ports.iter().map(|ap| (*ap).into()).collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::DiscoPrivate;
    use rustscale_tailcfg::{RawMessage, NODE_ATTR_DISABLE_RELAY_SERVER};
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[tokio::test]
    async fn extension_starts_server_when_enabled() {
        let cap_map = Arc::new(RwLock::new(BTreeMap::new()));
        let ext = RelayServerExtension::new(true, None, cap_map).await;
        assert!(ext.is_running());
        assert!(ext.disco_public().is_some());
        assert!(ext.local_addr().is_some());
    }

    #[tokio::test]
    async fn extension_does_not_start_when_disabled() {
        let cap_map = Arc::new(RwLock::new(BTreeMap::new()));
        let ext = RelayServerExtension::new(false, None, cap_map).await;
        assert!(!ext.is_running());
        assert!(ext.disco_public().is_none());
    }

    #[tokio::test]
    async fn alloc_request_succeeds() {
        let cap_map = Arc::new(RwLock::new(BTreeMap::new()));
        let ext = RelayServerExtension::new(true, None, cap_map).await;

        let a = DiscoPrivate::generate().public();
        let b = DiscoPrivate::generate().public();
        let resp = ext
            .handle_alloc_request([a, b], 1)
            .expect("alloc should succeed");

        assert_eq!(resp.endpoint.client_disco.len(), 2);
        assert!(resp.endpoint.vni > 0);
        assert!(!resp.endpoint.addr_ports.is_empty());
    }

    #[tokio::test]
    async fn alloc_request_blocked_by_disable_attr() {
        let cap_map = Arc::new(RwLock::new(BTreeMap::new()));
        {
            let mut m = cap_map.write().unwrap();
            m.insert(
                NODE_ATTR_DISABLE_RELAY_SERVER.to_string(),
                vec![RawMessage::default()],
            );
        }
        let ext = RelayServerExtension::new(true, None, cap_map).await;

        let a = DiscoPrivate::generate().public();
        let b = DiscoPrivate::generate().public();
        let resp = ext.handle_alloc_request([a, b], 1);
        assert!(resp.is_none(), "should be blocked by disable attr");
    }

    #[tokio::test]
    async fn set_self_cap_map_updates_disability() {
        let cap_map = Arc::new(RwLock::new(BTreeMap::new()));
        let ext = RelayServerExtension::new(true, None, cap_map.clone()).await;

        let a = DiscoPrivate::generate().public();
        let b = DiscoPrivate::generate().public();
        assert!(ext
            .handle_alloc_request([a.clone(), b.clone()], 1)
            .is_some());

        // Now disable via cap map update.
        let mut m = BTreeMap::new();
        m.insert(
            NODE_ATTR_DISABLE_RELAY_SERVER.to_string(),
            vec![RawMessage::default()],
        );
        ext.set_self_cap_map(m);

        assert!(
            ext.handle_alloc_request([a, b], 1).is_none(),
            "should be disabled after cap map update"
        );
    }

    #[tokio::test]
    async fn custom_config_for_short_lifetime() {
        let cap_map = Arc::new(RwLock::new(BTreeMap::new()));
        let config = ServerConfig {
            bind_lifetime: Duration::from_millis(50),
            steady_state_lifetime: Duration::from_millis(100),
            ..Default::default()
        };
        let ext = RelayServerExtension::new(true, Some(config), cap_map).await;

        let a = DiscoPrivate::generate().public();
        let b = DiscoPrivate::generate().public();
        let resp = ext
            .handle_alloc_request([a, b], 1)
            .expect("alloc should succeed");
        assert_eq!(resp.endpoint.bind_lifetime, Duration::from_millis(50));
        assert_eq!(
            resp.endpoint.steady_state_lifetime,
            Duration::from_millis(100)
        );
    }
}

// Re-export DiscoPrivate for tests in this module.
