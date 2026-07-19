//! Public embedding API for rustscale — a Rust equivalent of Go's
//! [`tailscale.com/tsnet`](https://pkg.go.dev/tailscale.com/tsnet).
//!
//! # Quick start
//!
//! ```no_run
//! use rustscale_tsnet::Server;
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let mut server = Server::builder()
//!     .hostname("my-app")
//!     .auth_key("tskey-...")
//!     .ephemeral(true)
//!     .build()?;
//!
//! server.up().await?;
//!
//! let status = server.status();
//! println!("tailscale IP: {:?}", status.tailscale_ips);
//!
//! let mut listener = server.listen(8080).await?;
//! // loop { let stream = listener.accept().await?; ... }
//!
//! let stream = server.dial("100.64.0.2:443").await?;
//! server.close().await?;
//! # Ok(())
//! # }
//! ```

#![allow(unsafe_code)]

mod acme;
mod api;
mod appc;
mod c2n;
mod capture;
mod dns_resolve;
mod drive;
mod filter_build;
mod hostinfo;
mod lifecycle;
mod link_monitor;
pub mod localapi;
mod localapi_contract;
mod loopback;
mod map_update;
mod netstack_pump;
mod peer_map;
mod peerapi;
mod proxyproto;
mod routing;
mod serve;
mod service;
mod socks5;
mod state;
mod status;
mod taildrop;
mod tailnet_lock;
mod tls;
mod tun_pump;
mod util;

#[cfg(feature = "ssh")]
mod ssh;

pub use api::FallbackTcpGuard;
pub use appc::{
    extract_appc_config, is_app_connector_node, make_dns_observer, route_info_from_connector,
    TsnetRouteAdvertiser,
};
pub use loopback::{InMemoryClientError, InMemoryLocalClient, LoopbackHandle};
pub use routing::{peer_is_exit_capable, RouteTable};
pub use rustscale_health::Warning;
pub use rustscale_ipnstate;
pub use serve::{
    check_funnel_access, check_funnel_port, FunnelError, HTTPHandler, HostPort, ServeConfig,
    ServeError, ServiceConfig as ServeServiceConfig, TCPPortHandler, WebServerConfig, FUNNEL_PORTS,
};
pub use service::{ServiceError, ServiceListener, ServiceMode, ServiceStream};
pub use socks5::{
    spawn_socks5, BoxedStream, CancelToken as Socks5CancelToken, ServerSocksDialer, Socks5Handle,
    Socks5Server, SocksAddr, SocksDialer, SocksStream,
};
pub use state::{NetMapCache, PersistedState, StateError};
pub use status::{PeerInfo, ServerStatus, WhoIsInfo};
pub use taildrop::{resolve_conflict, ConflictMode, FileTarget, TaildropError, TaildropManager};
pub use tls::{
    AcmeCertFetcher, CertError, CertFetcher, CertMaterial, CertProvider, ControlCertProvider,
    SelfSignedCertProvider, TlsError, TlsListener, TlsStream,
};

pub use hostinfo::{
    apply_runtime_fields, collect_hostinfo, hostinfo_hash, populate_hostinfo, HostinfoOverrides,
    RuntimeHostinfo, SharedOverrides,
};

#[cfg(feature = "ssh")]
pub use ssh::SshListener;

// Re-exports of items moved into focused submodules. These keep the
// crate-internal paths (`crate::<name>`) used by sibling modules stable and
// expose the shared helpers to the new impl/pump modules via `use super::*`.
pub(crate) use dns_resolve::{resolve_addr, resolve_addr_with, resolve_exit_node};
pub(crate) use filter_build::{
    build_filter_from_map_response, extract_node_ips, extract_tailscale_ips, process_filter_deltas,
    rebuild_filter, whois_lookup,
};
pub(crate) use link_monitor::{
    connect_home_derp, spawn_hostinfo_update_loop, spawn_link_monitor,
    spawn_periodic_endpoint_updates, LinkRouteSync,
};
pub(crate) use map_update::{
    exit_node_pref, set_exit_node_pref, spawn_map_update_task, ExitNodeSelection, KeyRotationCtx,
    MapSessionTasks,
};
#[cfg(test)]
pub(crate) use netstack_pump::collect_tun_inbound;
pub(crate) use netstack_pump::{run_netstack_pump, tick_wg_timers};
pub(crate) use tun_pump::{
    clear_kernel_security_block_reason, create_tun_device, engage_kernel_security_block,
    kernel_security_block_latched, run_tun_pump, set_exit_route_state_latch_aware, sync_router,
    sync_router_with_connected_prefixes, SecurityBlockReason, SharedRouter,
};
pub use util::TunModeConfig;
pub(crate) use util::{
    break_tcp_conns_best_effort, ensure_ring_provider, first_v4, rand_index, CancelToken,
};

// Shared imports: a number of these are used directly by `lib.rs` (struct
// definitions, accessors, `TsnetError`), while the remainder are consumed by
// the focused submodules via `use super::*;`. The attribute suppresses the
// unused-import lint for the ones only referenced by child modules.
#[allow(unused_imports)]
use {
    rustscale_controlclient::client::{
        ControlClient, MapSessionState, RegisterError, StreamMapError,
    },
    rustscale_controlclient::controlhttp,
    rustscale_controlclient::{extract_knobs_from_map_response, C2nRouter},
    rustscale_controlknobs::ControlKnobs,
    rustscale_derp::DerpClient,
    rustscale_dns::{
        build_os_dns_config, config_from_dns, new_os_configurator, DnsResponder, Forwarder,
        MagicDnsResolver, OsConfig, OsConfigurator, MAGICDNS_VIP,
    },
    rustscale_filter::Filter,
    rustscale_health::{
        Severity, Tracker, Watchdog, WARN_CACHED_NETMAP, WARN_CERT_FALLBACK, WARN_CONTROL,
        WARN_DERP_HOME, WARN_EXIT_ROUTE_SECURITY, WARN_MAP_RESPONSE_TIMEOUT, WARN_NETMON_CHANGE,
        WARN_NOT_IN_MAP_POLL, WARN_OS_DNS,
    },
    rustscale_ipn::IpnBackend,
    rustscale_key::{DiscoPrivate, MachinePrivate, MachinePublic, NodePrivate, NodePublic},
    rustscale_magicsock::{Magicsock, MagicsockConfig, MagicsockError},
    rustscale_netstack::{Netstack, NetstackError, NetstackStream, UdpListener, DEFAULT_MTU},
    rustscale_tailcfg::{
        DERPMap, DNSConfig, FilterRule, Hostinfo, MapRequest, MapResponse, NetInfo, Node, OptBool,
        PeerChange, RegisterRequest, SSHPolicy, UserID, UserProfile,
    },
    rustscale_tun::Tun,
    rustscale_wg::{WgError, WgTunn},
    std::collections::{BTreeMap, BTreeSet, HashMap},
    std::net::{IpAddr, Ipv4Addr, SocketAddr},
    std::path::PathBuf,
    std::sync::atomic::{AtomicBool, AtomicU64},
    std::sync::Arc,
    tokio::sync::{mpsc, Mutex, RwLock},
    tokio::task::JoinHandle,
};

/// Default control-plane URL.
pub const DEFAULT_CONTROL_URL: &str = "controlplane.tailscale.com";

/// Capability version we advertise to the control plane (matches the
/// current Tailscale `CurrentCapabilityVersion`).
const CAPABILITY_VERSION: i32 = 141;

/// Protocol version for the Noise handshake (ts2021). This is the
/// `CurrentCapabilityVersion` as a u16, matching Go's
/// `cmp.Or(nc.opts.ProtocolVersion, uint16(tailcfg.CurrentCapabilityVersion))`.
const PROTOCOL_VERSION: u16 = 141;

/// Live posture preference plus the publication barrier that linearizes
/// preference revocation against sensitive C2N transport writes.
pub(crate) struct LivePosturePreference {
    value: AtomicBool,
    publication: Arc<rustscale_posture::PublicationBarrier>,
}

impl LivePosturePreference {
    pub(crate) fn new(value: bool) -> Self {
        Self::with_publication_barrier(
            value,
            Arc::new(rustscale_posture::PublicationBarrier::new()),
        )
    }

    pub(crate) fn with_publication_barrier(
        value: bool,
        publication: Arc<rustscale_posture::PublicationBarrier>,
    ) -> Self {
        Self {
            value: AtomicBool::new(value),
            publication,
        }
    }

    pub(crate) fn load(&self, ordering: std::sync::atomic::Ordering) -> bool {
        self.value.load(ordering)
    }

    pub(crate) fn store(&self, value: bool, ordering: std::sync::atomic::Ordering) {
        self.publication
            .update_preference(|| self.value.swap(value, ordering) != value);
    }

    pub(crate) fn snapshot(&self) -> (bool, u64, u64) {
        let (generation, (value, policy_generation)) = self.publication.snapshot_with(|policy| {
            (
                self.value.load(std::sync::atomic::Ordering::Acquire),
                policy.policy_generation,
            )
        });
        (value, generation, policy_generation)
    }

    pub(crate) fn with_generation<R>(
        &self,
        expected_generation: u64,
        operation: impl FnOnce(bool, &rustscale_posture::PublicationPolicyState) -> R,
    ) -> Option<R> {
        self.publication
            .with_generation(expected_generation, |policy| {
                operation(
                    self.value.load(std::sync::atomic::Ordering::Acquire),
                    policy,
                )
            })
    }
}

/// Errors from tsnet operations.
#[derive(Debug, thiserror::Error)]
pub enum TsnetError {
    #[error("server already up")]
    AlreadyUp,
    #[error("server is not up (call up() first)")]
    NotUp,
    #[error("builder validation: {0}")]
    Builder(String),
    #[error("state file error: {0}")]
    State(#[from] StateError),
    #[error("log ID error: {0}")]
    LogId(#[from] rustscale_logid::LogIdError),
    #[error("control register error: {0}")]
    Register(#[from] RegisterError),
    #[error("map stream error: {0}")]
    MapStream(#[from] StreamMapError),
    #[error("invalid network map: {0}")]
    InvalidNetmap(String),
    #[error("magicsock error: {0}")]
    Magicsock(#[from] MagicsockError),
    #[error("netstack error: {0}")]
    Netstack(#[from] NetstackError),
    #[error("wireguard error: {0}")]
    Wg(#[from] WgError),
    #[error("auth required: visit {0}")]
    AuthRequired(String),
    #[error("workload identity federation: {0}")]
    IdentityFederation(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hostname not found in netmap: {0}")]
    HostnameNotFound(String),
    #[error("exit node not found: {0}")]
    ExitNodeNotFound(String),
    #[error("peer is not exit-node-capable (both IPv4 and IPv6 defaults are required): {0}")]
    NotExitCapable(String),
    #[error("derp error: {0}")]
    Derp(#[from] rustscale_derp::DerpError),
    #[error("netcheck error: {0}")]
    Netcheck(#[from] rustscale_netcheck::NetcheckError),
    #[error("netlog error: {0}")]
    Netlog(#[from] rustscale_netlog::NetlogError),
    #[error("tun device error: {0}")]
    Tun(#[from] rustscale_tun::TunError),
    #[error("listen/dial not available in TUN mode (no userspace netstack)")]
    NotAvailableInTunMode,
    #[error("feature not supported: {0}")]
    NotSupported(String),
    #[error("Tailnet Lock state failed closed: {0}")]
    TailnetLock(String),
    #[error("extension host error: {0}")]
    Extension(String),
    #[error("server shutdown incomplete: {0}")]
    ShutdownIncomplete(String),
    #[error("timeout waiting for first map response")]
    MapTimeout,
    #[error("tls error: {0}")]
    Tls(#[from] TlsError),
    #[error("serve error: {0}")]
    Serve(#[from] ServeError),
    #[error("funnel error: {0}")]
    Funnel(#[from] FunnelError),
    #[error("service error: {0}")]
    Service(#[from] ServiceError),
}

/// A builder for configuring a [`Server`].
#[derive(Clone, Default)]
pub struct ServerBuilder {
    pub(crate) hostname: String,
    pub(crate) auth_key: Option<String>,
    /// OAuth client ID configured for workload identity federation.
    pub(crate) client_id: String,
    /// Provider ID token. Never included in Debug output or logs.
    pub(crate) id_token: String,
    /// Audience passed to an injected provider token source when no ID token
    /// is supplied.
    pub(crate) audience: String,
    /// Explicitly re-authenticate an already enrolled node. Workload identity
    /// credentials are otherwise ignored for persisted enrollments.
    pub(crate) force_login: bool,
    pub(crate) control_url: String,
    pub(crate) state_dir: Option<PathBuf>,
    pub(crate) ephemeral: bool,
    /// Subnet routes to advertise (e.g. `["192.0.2.0/24"]`). Sent in
    /// `Hostinfo.RoutableIPs`; control must approve them before peers install
    /// them.
    pub(crate) advertise_routes: Vec<String>,
    /// Whether to install peer-advertised subnet routes into the local
    /// routing table. When false (default), only tailnet-range IPs
    /// (100.64.0.0/10, fd7a:115c:a1e0::/48) are routed.
    pub(crate) accept_routes: bool,
    /// Whether to advertise this node as an exit node. When true, `0.0.0.0/0`
    /// and `::/0` are appended to `RoutableIPs` in `Hostinfo` (mirroring Go's
    /// `tsaddr.ExitRoutes()`). The tailnet admin must approve the exit routes
    /// before peers see them in this node's `AllowedIPs`. The filter's
    /// `localNets` is also extended with the default routes so forwarded
    /// exit traffic is admitted (same mechanism as subnet routes).
    pub(crate) advertise_exit_node: bool,
    /// Test-support: when true, magicsock suppresses all direct-path
    /// establishment and forces every send via DERP. See
    /// [`MagicsockConfig::disable_direct_paths`]. Production code should
    /// leave this false.
    pub(crate) disable_direct_paths: bool,
    /// Whether NAT-PMP/PCP/UPnP endpoint discovery is disabled. Production
    /// defaults to false; hermetic tests can opt out of host gateway state.
    pub(crate) disable_portmapping: bool,
    /// Runtime Hostinfo field overrides (mirror Go's
    /// `hostinfo.SetDeviceModel`/`SetApp`/`SetOSVersion`/`SetPackage`).
    /// Applied before platform detection so they win over auto-detected
    /// values. Shared with the periodic Hostinfo update loop.
    pub(crate) overrides: SharedOverrides,
    /// Whether to spawn the LocalAPI Unix-domain-socket server. Default OFF.
    pub(crate) localapi: bool,
    /// Explicit LocalAPI socket path. If None and localapi is enabled,
    /// defaults to `<state_dir>/rustscale.sock`.
    pub(crate) localapi_path: Option<PathBuf>,
    /// Whether to configure the OS DNS resolver in TUN mode. When true,
    /// `up_tun` writes `/etc/resolver/` entries (macOS) pointing at
    /// `100.100.100.100` for the MagicDNS suffix and split-DNS routes.
    /// **Requires root** (writing `/etc/resolver` needs privileged access).
    /// Default `false`. Ignored in netstack mode (`up()`).
    pub(crate) configure_os_dns: bool,
    /// Test-only factory for exercising the real TUN startup contract when
    /// the platform DNS configurator fails after making a partial change.
    #[cfg(test)]
    pub(crate) os_dns_configurator_factory:
        Option<Arc<dyn Fn() -> Box<dyn OsConfigurator + Send> + Send + Sync>>,
    /// Whether to run this node as a peer relay server. When true, a
    /// `udprelay::Server` is started in magicsock and
    /// `Hostinfo.PeerRelay = true` is advertised to the control plane.
    /// Default OFF.
    pub(crate) peer_relay_server: bool,
    /// Optional relay server config override (lifetimes, port, etc.). When
    /// `None`, defaults are used. Only effective when `peer_relay_server`
    /// is true. Used by integration tests to set shortened lifetimes.
    pub(crate) relay_server_config: Option<rustscale_udprelay::ServerConfig>,
    /// UDP port for WireGuard / peer-to-peer traffic. If 0 (default), a
    /// port is automatically selected. Mirrors Go's `Server.Port`.
    pub(crate) port: u16,
    /// ACL tags to advertise for this node (e.g. `["tag:prod"]`). Sent in
    /// `Hostinfo.RequestTags` during registration. The control server must
    /// permit the node to adopt each tag via `tagOwners` in the policy file.
    /// Mirrors Go's `Server.AdvertiseTags`.
    pub(crate) advertise_tags: Vec<String>,
    /// Pluggable logger callback. When set, diagnostic messages from the
    /// server are routed through this closure instead of `eprintln!`.
    /// Mirrors Go's `Server.UserLogf`.
    pub(crate) logger: Option<Logger>,
    /// Optional daemon logtail client. Embeddings leave this unset by default;
    /// rustscaled supplies it so C2N can request an immediate upload.
    pub(crate) logtail: Option<rustscale_logtail::LogTail>,
    /// Optional tailtraffic logtail client for network flow logging.
    pub(crate) netlog: Option<rustscale_logtail::LogTail>,
    /// Additional DER-encoded root CAs to trust alongside native and baked
    /// ISRG roots for control-plane TLS connections. Mirrors Go's
    /// `tsnet.Server.ExtraRootCAs`.
    pub(crate) extra_root_certs: Option<Vec<Vec<u8>>>,
    /// Path to the declarative config file (`--config` flag), if set.
    /// Threaded through to `LocalApiState` so `POST /reload-config` can
    /// re-read the file. Mirrors Go's `tsd.System.InitialConfig`.
    pub(crate) config_path: Option<PathBuf>,
    /// Enable collection of device posture serial numbers and hardware
    /// addresses through the C2N posture identity endpoint. Default: false.
    pub(crate) posture_checking: bool,
    /// Optional daemon policy reconciler applied to every persisted preference
    /// mutation. Embedding users leave this unset.
    pub(crate) preference_policy: Option<Arc<dyn PreferencePolicy>>,
    /// Optional extension registry override. The process-wide ipnext registry
    /// is used when this is unset.
    pub(crate) extension_registry: Option<Arc<rustscale_ipnext::ExtensionRegistry>>,
    /// Optional daemon dependency container supplied by the embedding.
    pub(crate) system: Option<Arc<rustscale_tsd::System>>,
}

/// A pluggable logger callback for diagnostic messages. Implementations
/// must be `Send + Sync`; the closure receives a pre-formatted message
/// string. When unset, messages fall through to `eprintln!`.
pub type Logger = Arc<dyn Fn(&str) + Send + Sync>;

/// Keeps a preference-policy change subscription alive.
pub trait PreferencePolicySubscription: Send + Sync {}

/// Daemon-supplied policy enforcement for persisted preferences.
///
/// This indirection keeps the tsnet embedding API independent of any concrete
/// system-policy implementation while allowing rustscaled to enforce managed
/// preferences at every mutation boundary.
pub trait PreferencePolicy: Send + Sync {
    /// Reconciles managed settings into `prefs`, returning whether it changed.
    fn reconcile(&self, prefs: &mut rustscale_ipn::Prefs) -> Result<bool, String>;

    /// Returns the effective policy generation used for startup handshakes.
    fn generation(&self) -> u64 {
        0
    }

    /// Applies managed update policy to lower-precedence user/environment
    /// permission. A managed denial must return `false`.
    fn allows_update(&self, lower_precedence_choice: bool) -> Result<bool, String> {
        Ok(lower_precedence_choice)
    }

    /// Registers a non-blocking policy-change callback.
    fn subscribe(
        &self,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Box<dyn PreferencePolicySubscription>;
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("hostname", &self.hostname)
            .field("auth_key", &self.auth_key.as_ref().map(|_| "<redacted>"))
            .field("client_id", &self.client_id)
            .field(
                "id_token",
                &if self.id_token.is_empty() {
                    None
                } else {
                    Some("<redacted>")
                },
            )
            .field("audience", &self.audience)
            .field("force_login", &self.force_login)
            .field("control_url", &self.control_url)
            .field("state_dir", &self.state_dir)
            .field("ephemeral", &self.ephemeral)
            .field("advertise_routes", &self.advertise_routes)
            .field("accept_routes", &self.accept_routes)
            .field("advertise_exit_node", &self.advertise_exit_node)
            .field("disable_direct_paths", &self.disable_direct_paths)
            .field("disable_portmapping", &self.disable_portmapping)
            .field("localapi", &self.localapi)
            .field("localapi_path", &self.localapi_path)
            .field("configure_os_dns", &self.configure_os_dns)
            .field("peer_relay_server", &self.peer_relay_server)
            .field("port", &self.port)
            .field("advertise_tags", &self.advertise_tags)
            .field("posture_checking", &self.posture_checking)
            .field(
                "preference_policy",
                &self.preference_policy.as_ref().map(|_| "<policy>"),
            )
            .field("logger", &self.logger.as_ref().map(|_| "<logger>"))
            .field("logtail", &self.logtail.as_ref().map(|_| "<logtail>"))
            .field("netlog", &self.netlog.as_ref().map(|_| "<netlog>"))
            .finish()
    }
}

impl ServerBuilder {
    /// Set the hostname.
    pub fn hostname(mut self, h: impl Into<String>) -> Self {
        self.hostname = h.into();
        self
    }

    /// Set the auth key.
    pub fn auth_key(mut self, k: impl Into<String>) -> Self {
        self.auth_key = Some(k.into());
        self
    }

    /// Set the OAuth client ID used for workload identity federation.
    ///
    /// The `identity-federation` Cargo feature must be enabled. A client ID
    /// may include `?ephemeral=` and `?preauthorized=` attributes matching the
    /// Tailscale client configuration format.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = client_id.into();
        self
    }

    /// Set an identity-provider ID token for workload identity federation.
    /// This is mutually exclusive with [`audience`](Self::audience).
    pub fn id_token(mut self, id_token: impl Into<String>) -> Self {
        self.id_token = id_token.into();
        self
    }

    /// Set the audience used by the workload identity provider token source.
    /// This is mutually exclusive with [`id_token`](Self::id_token). Install a
    /// client configured with a provider source through
    /// `rustscale_identityfederation::install_with_client` before calling
    /// `up()`.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Force an already enrolled node through login again.
    ///
    /// Without this flag, configured auth credentials are omitted for a
    /// persisted enrollment and workload identity federation is not invoked.
    pub fn force_login(mut self, force: bool) -> Self {
        self.force_login = force;
        self
    }

    /// Set the control-plane URL.
    pub fn control_url(mut self, u: impl Into<String>) -> Self {
        self.control_url = u.into();
        self
    }

    /// Set the state directory for persistent keys.
    pub fn state_dir(mut self, d: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(d.into());
        self
    }

    /// Set the ephemeral flag.
    pub fn ephemeral(mut self, e: bool) -> Self {
        self.ephemeral = e;
        self
    }

    /// Set the subnet routes to advertise (e.g. `["192.0.2.0/24"]`).
    ///
    /// These are sent to the control plane in `Hostinfo.RoutableIPs`. The
    /// tailnet admin must approve them (via the API or admin console) before
    /// peers see them in this node's `AllowedIPs`.
    ///
    /// **TUN mode + subnet routing**: the OS must have IP forwarding enabled
    /// for the node to actually forward packets between the tailnet and the
    /// advertised subnet. On Linux: `sysctl net.ipv4.ip_forward=1`. On macOS:
    /// `sysctl net.inet.ip.forwarding=1`. Without this, packets arriving from
    /// peers are written to the TUN device but the OS kernel drops them
    /// instead of forwarding onward.
    pub fn advertise_routes(mut self, routes: Vec<String>) -> Self {
        self.advertise_routes = routes;
        self
    }

    /// Installs a daemon preference-policy reconciler.
    pub fn preference_policy(mut self, policy: Arc<dyn PreferencePolicy>) -> Self {
        self.preference_policy = Some(policy);
        self
    }

    /// Set whether to accept peer-advertised subnet routes.
    ///
    /// When true, peer-advertised subnet CIDRs (non-tailnet ranges in peers'
    /// `AllowedIPs`) are installed into the local routing table. When false
    /// (default), only tailnet-range IPs are routed.
    pub fn accept_routes(mut self, accept: bool) -> Self {
        self.accept_routes = accept;
        self
    }

    /// Set whether to advertise this node as an exit node.
    ///
    /// When true, `0.0.0.0/0` and `::/0` are added to `Hostinfo.RoutableIPs`
    /// (mirroring Go's `tsaddr.ExitRoutes()`). The tailnet admin must approve
    /// the exit routes (via the API or admin console) before peers see them in
    /// this node's `AllowedIPs`. The packet filter's `localNets` is also
    /// extended with the default routes so forwarded exit traffic is admitted
    /// — consistent with how subnet routes are filtered.
    ///
    /// **TUN mode**: forwarded exit traffic flows via the data pump + OS IP
    /// forwarding, same as subnet routing. The OS must have IP forwarding
    /// enabled (see [`ServerBuilder::advertise_routes`] for the sysctls).
    pub fn advertise_exit_node(mut self, on: bool) -> Self {
        self.advertise_exit_node = on;
        self
    }

    /// Test-support: suppress direct-path establishment and force all sends
    /// via DERP relay. Use only in interop tests that need to assert relayed
    /// connectivity in isolation. See [`MagicsockConfig::disable_direct_paths`].
    pub fn disable_direct_paths(mut self, on: bool) -> Self {
        self.disable_direct_paths = on;
        self
    }

    /// Disable NAT-PMP, PCP, and UPnP endpoint discovery. This is primarily
    /// useful for hermetic tests that must not inspect or modify the host's
    /// gateway. Production callers should leave port mapping enabled.
    pub fn disable_portmapping(mut self, on: bool) -> Self {
        self.disable_portmapping = on;
        self
    }

    /// Override the `Hostinfo.DeviceModel` field (mirrors Go's
    /// `hostinfo.SetDeviceModel`). Takes priority over platform-detected
    /// values. Can be called before or after `up()`; the periodic Hostinfo
    /// update loop picks up changes on the next refresh.
    pub fn set_device_model(self, model: impl Into<String>) -> Self {
        if let Ok(mut o) = self.overrides.try_write() {
            o.set_device_model(model);
        }
        self
    }

    /// Override the `Hostinfo.App` field (mirrors Go's `hostinfo.SetApp`).
    /// Used to disambiguate tsnet-based clients (e.g. `"golinks"`,
    /// `"k8s-operator"`).
    pub fn set_app(self, app: impl Into<String>) -> Self {
        if let Ok(mut o) = self.overrides.try_write() {
            o.set_app(app);
        }
        self
    }

    /// Override the `Hostinfo.OSVersion` field (mirrors Go's
    /// `hostinfo.SetOSVersion`).
    pub fn set_os_version(self, version: impl Into<String>) -> Self {
        if let Ok(mut o) = self.overrides.try_write() {
            o.set_os_version(version);
        }
        self
    }

    /// Override the `Hostinfo.Package` field (mirrors Go's
    /// `hostinfo.SetPackage`).
    pub fn set_package(self, package: impl Into<String>) -> Self {
        if let Ok(mut o) = self.overrides.try_write() {
            o.set_package(package);
        }
        self
    }

    /// Set the frontend log ID supplied by the embedding application.
    pub fn set_frontend_log_id(self, id: impl Into<String>) -> Self {
        if let Ok(mut o) = self.overrides.try_write() {
            o.set_frontend_log_id(id);
        }
        self
    }

    /// Enable or disable the LocalAPI Unix-domain-socket server. When enabled,
    /// the socket is created at the path set by [`localapi_path`](Self::localapi_path),
    /// or `<state_dir>/rustscale.sock` by default. Default: OFF.
    pub fn localapi(mut self, on: bool) -> Self {
        self.localapi = on;
        self
    }

    /// Enable this node as a peer relay server. When true, a `udprelay::Server`
    /// is started in magicsock, `Hostinfo.PeerRelay = true` is advertised to
    /// the control plane, and incoming `AllocateUDPRelayEndpointRequest` disco
    /// messages received via DERP are handled locally. Default OFF.
    pub fn peer_relay_server(mut self, on: bool) -> Self {
        self.peer_relay_server = on;
        self
    }

    /// Set a custom `ServerConfig` for the relay server (lifetimes, port).
    /// Only effective when `peer_relay_server(true)` is also set. Used by
    /// integration tests to set shortened lifetimes for expiry scenarios.
    pub fn relay_server_config(mut self, config: rustscale_udprelay::ServerConfig) -> Self {
        self.relay_server_config = Some(config);
        self
    }

    /// Set the UDP port for WireGuard and peer-to-peer traffic. If 0
    /// (default), a port is automatically selected. Leave at zero unless
    /// you need a fixed port (e.g. firewall rules).
    ///
    /// Mirrors Go's `Server.Port`.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the ACL tags to advertise for this node (e.g.
    /// `["tag:prod", "tag:server"]`). Tags are sent in
    /// `Hostinfo.RequestTags` during registration. The control server
    /// must permit the node to adopt each tag via `tagOwners` in the
    /// tailnet policy file.
    ///
    /// Mirrors Go's `Server.AdvertiseTags`.
    pub fn advertise_tags(mut self, tags: Vec<String>) -> Self {
        self.advertise_tags = tags;
        self
    }

    /// Set a pluggable logger callback. When set, diagnostic messages
    /// from the server (status updates, auth URLs, non-fatal errors) are
    /// routed through this closure instead of `eprintln!`.
    ///
    /// Mirrors Go's `Server.UserLogf`.
    pub fn logger(mut self, logger: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.logger = Some(Arc::new(logger));
        self
    }

    /// Attach a logtail client to this server.
    ///
    /// This is opt-in so tsnet embeddings do not upload logs unless their
    /// host application explicitly configures a client.
    pub fn logtail(mut self, logtail: rustscale_logtail::LogTail) -> Self {
        self.logtail = Some(logtail);
        self
    }

    /// Enable network flow logging with a tailtraffic logtail client.
    ///
    /// This is separate from [`Self::logtail`] so configuring diagnostic logs
    /// never implicitly enables traffic accounting or sends flow records to
    /// the wrong collection.
    pub fn netlog(mut self, logtail: rustscale_logtail::LogTail) -> Self {
        self.netlog = Some(logtail);
        self
    }

    /// Set additional DER-encoded root CAs to trust for control-plane TLS
    /// connections. These are combined with native roots and the baked ISRG
    /// fallback roots. Mirrors Go's `tsnet.Server.ExtraRootCAs`.
    pub fn extra_root_certs(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.extra_root_certs = Some(certs);
        self
    }

    /// Set an explicit path for the LocalAPI Unix socket. Calling this
    /// implicitly enables the LocalAPI server (equivalent to
    /// `.localapi(true)`). The parent directory is created if it does not
    /// exist; any stale socket file at the path is removed before binding.
    pub fn localapi_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.localapi_path = Some(path.into());
        self.localapi = true;
        self
    }

    /// Set the declarative config file path (`--config` flag). When set,
    /// the config file is loaded at startup and its prefs are applied.
    /// `POST /localapi/v0/reload-config` re-reads this file.
    pub fn config_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_path = Some(path.into());
        self
    }

    /// Enable device posture data collection. When enabled, serial numbers
    /// and non-loopback MAC addresses are exposed on demand through
    /// `GET /posture/identity`. Default: `false`.
    pub fn posture_checking(mut self, on: bool) -> Self {
        self.posture_checking = on;
        self
    }

    /// Use an explicit extension registry instead of the process-wide
    /// [`rustscale_ipnext::global_registry`].
    pub fn extension_registry(
        mut self,
        registry: Arc<rustscale_ipnext::ExtensionRegistry>,
    ) -> Self {
        self.extension_registry = Some(registry);
        self
    }

    /// Use an explicit typed daemon dependency container.
    pub fn system(mut self, system: Arc<rustscale_tsd::System>) -> Self {
        self.system = Some(system);
        self
    }

    /// Enable OS-level DNS configuration in TUN mode (default: `false`).
    ///
    /// When enabled, [`Server::up_tun`] writes `/etc/resolver/` entries on
    /// macOS (or calls the platform-appropriate configurator) pointing at
    /// `100.100.100.100` for the MagicDNS suffix and any split-DNS routes
    /// from the control-plane DNS config. Search domains from the netmap are
    /// also installed.
    ///
    /// **Requires root** — writing `/etc/resolver` needs privileged access.
    /// A setup failure leaves `up_tun` usable only when its independent TUN
    /// data plane commits; status immediately reports the DNS degradation and
    /// retains the configurator for cleanup rather than silently looking
    /// healthy.
    ///
    /// Ignored in netstack mode ([`Server::up`]).
    pub fn configure_os_dns(mut self, on: bool) -> Self {
        self.configure_os_dns = on;
        self
    }

    #[cfg(test)]
    pub(crate) fn test_os_dns_configurator_factory(
        mut self,
        factory: impl Fn() -> Box<dyn OsConfigurator + Send> + Send + Sync + 'static,
    ) -> Self {
        self.os_dns_configurator_factory = Some(Arc::new(factory));
        self
    }

    /// Compute the effective advertised routes: `advertise_routes` plus the
    /// exit-node default routes (`0.0.0.0/0`, `::/0`) when
    /// `advertise_exit_node` is true. Used everywhere `RoutableIPs` is sent to
    /// control or the filter's `localNets` is built.
    pub(crate) fn effective_advertise_routes(&self) -> Vec<String> {
        let mut routes = self.advertise_routes.clone();
        if self.advertise_exit_node {
            // Avoid duplicates if the user also manually added the default
            // routes to advertise_routes.
            for r in &["0.0.0.0/0", "::/0"] {
                if !routes.iter().any(|x| x == r) {
                    routes.push((*r).to_string());
                }
            }
        }
        routes
    }

    /// Validate and construct a [`Server`].
    pub fn build(self) -> Result<Server, TsnetError> {
        if self.hostname.is_empty() {
            return Err(TsnetError::Builder("hostname must not be empty".into()));
        }
        let system = self
            .system
            .clone()
            .unwrap_or_else(|| Arc::new(rustscale_tsd::System::new()));
        let extension_host = match self.extension_registry.as_deref() {
            Some(registry) => rustscale_ipnext::ExtensionHost::new(registry, Arc::clone(&system)),
            None => rustscale_ipnext::ExtensionHost::new(
                rustscale_ipnext::global_registry(),
                Arc::clone(&system),
            ),
        }
        .map_err(|error| TsnetError::Extension(error.to_string()))?;
        Ok(Server {
            config: self,
            drive: drive::Runtime::new(),
            inner: None,
            pre_started: None,
            system,
            extension_host: Some(extension_host),
            bootstrap_supervisor: Arc::new(BootstrapSupervisor::default()),
            startup_supervisor: Arc::new(BootstrapSupervisor::default()),
            shutdown_supervisor: Arc::new(BootstrapSupervisor::default()),
            logout_trigger: Arc::new(tokio::sync::Notify::new()),
            logout_completion: localapi::LogoutCompletion::new(),
            #[cfg(test)]
            logout_test_hook: None,
            #[cfg(test)]
            logout_state_save_failures: 0,
            #[cfg(test)]
            startup_localapi_test_hook: None,
        })
    }
}

/// Internal running state.
/// Serializes every map-driven and explicit exit-route mutation.
///
/// Lock order is `exit_map_gate` -> `peer_map.gate` -> prefs/snapshots ->
/// route table -> synchronous router. A router-only apply may run after the
/// peer gate is released, but no caller may acquire the peer gate while
/// holding the route table, or acquire `exit_map_gate` from an inner lock.
pub(crate) type ExitMapGate = Arc<tokio::sync::Mutex<()>>;

pub(crate) struct RunningState {
    pub(crate) tailscale_ips: Vec<IpAddr>,
    pub(crate) magicsock: Arc<Magicsock>,
    /// Network flow logger when the embedding configured tailtraffic logging.
    pub(crate) netlog: Option<Arc<rustscale_netlog::Logger>>,
    pub(crate) data_plane: DataPlane,
    pub(crate) peers: Arc<RwLock<Vec<Node>>>,
    #[allow(dead_code)]
    pub(crate) peer_map: Arc<peer_map::Runtime>,
    pub(crate) routecheck: Arc<rustscale_routecheck::Client>,
    pub(crate) route_table: Arc<RwLock<RouteTable>>,
    /// Live signed packet filter, mutated only under `peer_map.gate.write()`.
    pub(crate) filter: Arc<std::sync::Mutex<Filter>>,
    pub(crate) exit_map_gate: ExitMapGate,
    /// OS-route manager in TUN mode when `TunModeConfig::apply_routes` is set.
    pub(crate) router: Option<SharedRouter>,
    pub(crate) cancel: Arc<CancelToken>,
    pub(crate) tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Dynamically rebound control-map stream generations. This remains
    /// separate from the outer task vector so key rotation can replace one
    /// generation without losing profile cleanup ownership.
    pub(crate) map_tasks: Arc<MapSessionTasks>,
    /// Synchronous cancellation handles for every outer task. Join ownership
    /// remains in `tasks` and transfers with the transactional cleanup owner.
    pub(crate) task_aborts: std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
    pub(crate) loopback_controls: std::sync::Mutex<Vec<Arc<loopback::LoopbackControl>>>,
    pub(crate) in_memory_clients: std::sync::Mutex<Vec<Arc<loopback::InMemoryClientControl>>>,
    pub(crate) packet_drops: Arc<AtomicU64>,
    /// Optional packet-capture sink. Disabled capture costs pumps one cheap
    /// read-lock/Option check per observed packet.
    pub(crate) capture: capture::CaptureSlot,
    /// File capture registrations retained until server shutdown.
    pub(crate) capture_handles: std::sync::Mutex<Vec<capture::CaptureHandle>>,
    /// Shared MagicDNS resolver (dial path + DNS responder).
    pub(crate) resolver: Arc<RwLock<MagicDnsResolver>>,
    /// Generation-bound TUN user dialer retained with LocalAPI ownership.
    pub(crate) user_dialer: Arc<rustscale_tsdial::Dialer>,
    /// Our node's FQDN (with trailing dot), from the netmap.
    pub(crate) our_fqdn: String,
    /// Tailnet domain / MagicDNS suffix (e.g. "tailnet.ts.net").
    pub(crate) domain: String,
    /// DNS config from control (carries `CertDomains` for cert provisioning).
    pub(crate) dns_config: Arc<RwLock<Option<DNSConfig>>>,
    /// User profiles keyed by `UserID` (for WhoIs).
    pub(crate) user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    /// Current SSH policy from the netmap (`MapResponse.SSHPolicy`).
    /// `None` until the control server sends one; the SSH server rejects
    /// all connections while this is `None`. Updated on each map response
    /// that carries a new policy.
    #[cfg_attr(not(feature = "ssh"), allow(dead_code))]
    pub(crate) ssh_policy: Arc<RwLock<Option<SSHPolicy>>>,
    /// SSH host keys currently advertised through Hostinfo.
    #[cfg_attr(not(feature = "ssh"), allow(dead_code))]
    pub(crate) ssh_host_keys: Arc<RwLock<Vec<String>>>,
    /// Generation-bound SSH callback admission owned by the current map Noise session.
    pub(crate) ssh_callbacks: rustscale_controlclient::SshCallbackDispatcher,
    /// Network change monitor handle (None if the monitor couldn't start).
    pub(crate) monitor: Option<rustscale_netmon::MonitorHandle>,
    /// Machine private key (for control-plane set-dns during cert issuance).
    pub(crate) machine_key: MachinePrivate,
    /// Server (control) public key (for control-plane set-dns).
    pub(crate) server_pub_key: MachinePublic,
    /// Node private key (for SetDNSRequest.NodeKey during cert issuance).
    pub(crate) node_key: NodePrivate,
    /// Serve/Funnel runner (None in TUN mode — serve requires netstack).
    pub(crate) serve: Option<Arc<serve::ServeRunner>>,
    /// Health tracker (shared with all subsystems).
    pub(crate) health: Tracker,
    /// Map-poll staleness watchdog (fires if no MapResponse for >3 min).
    pub(crate) health_watchdog: Watchdog,
    /// C2N request router (control-to-node handler dispatch).
    pub(crate) c2n_router: Arc<C2nRouter>,
    /// Live posture preference shared with LocalAPI and C2N.
    pub(crate) posture_checking: Arc<LivePosturePreference>,
    /// Control-plane feature flags extracted from netmap updates.
    pub(crate) control_knobs: Arc<ControlKnobs>,
    /// PeerAPI listen port (deterministic, from tailscale IPs).
    pub(crate) peerapi_port: Option<u16>,
    /// Runtime Hostinfo field overrides (shared with the update loop).
    pub(crate) overrides: SharedOverrides,
    /// LocalAPI socket path (if the server was spawned). Used for cleanup on
    /// close().
    pub(crate) localapi_socket: Option<PathBuf>,
    pub(crate) localapi_handle: Option<localapi::LocalApiHandle>,
    /// Node key expired flag — set when the control server signals
    /// `NodeKeyExpired` in a MapResponse. The client should transition to
    /// a "NeedsLogin" state; un-expiring clears it.
    pub(crate) key_expired: Arc<std::sync::atomic::AtomicBool>,
    /// OS DNS configurator, active only in TUN mode when
    /// `configure_os_dns` is enabled. `close()` is called on server
    /// shutdown to remove `/etc/resolver` entries.
    pub(crate) os_dns_configurator: Option<Box<dyn OsConfigurator + Send>>,
    /// IPN state machine backend — tracks the current IPN state, holds
    /// the notification bus, and drives state transitions.
    pub(crate) ipn_backend: Arc<IpnBackend>,
    /// Notify fired by POST /logout so the daemon can tear down the server
    /// and transition to NeedsLogin. Stored here so the daemon can select
    /// on it alongside shutdown signals.
    pub(crate) logout_trigger: Arc<tokio::sync::Notify>,
    pub(crate) logout_completion: Arc<localapi::LogoutCompletion>,
    /// Registered fallback TCP handlers (called when no listener matches an
    /// incoming TCP flow). Each entry is a boxed callback keyed by a unique
    /// ID; `register_fallback_tcp_handler` returns a guard whose `Drop`
    /// removes the entry.
    pub(crate) fallback_tcp_handlers:
        Arc<std::sync::Mutex<Vec<(u64, Box<dyn FallbackTCPHandler + Send + Sync>)>>>,
    /// Next fallback handler ID (monotonic).
    pub(crate) fallback_next_id: Arc<std::sync::atomic::AtomicU64>,
    /// Shared prefs — same Arc as `LocalApiState.prefs`, giving the daemon
    /// direct access for SIGHUP-driven config reload without going through
    /// the LocalAPI endpoint.
    pub(crate) prefs: Arc<RwLock<rustscale_ipn::Prefs>>,
    /// Serializes profile/preference commits and callback enqueue order.
    pub(crate) profile_mutations: Arc<tokio::sync::Mutex<()>>,
    /// Mutation epoch shared by socket, loopback, and in-memory LocalAPI.
    pub(crate) localapi_mutation_fence: Arc<localapi::LocalApiMutationFence>,
    pub(crate) localapi_mutation_generation: u64,
    /// Tracks the one persisted exit-node selection that may be retried after
    /// a map update. Explicit API/config choices clear this pending state.
    pub(crate) exit_node_selection: Arc<RwLock<ExitNodeSelection>>,
    /// Ephemeral `(proto, localhost ip:port) -> Tailscale IP` mapping for
    /// proxied connections. Used by WhoIs to attribute netstack-proxied
    /// connections to their originating peer. Mirrors Go's `proxymap.Mapper`.
    pub(crate) proxy_mapper: Arc<rustscale_proxymap::Mapper>,
    /// Shared portlist state — the background portlist task writes here and
    /// the hostinfo hook reads here. Mirrors Go's `portlist.Poller` EventBus
    /// integration. Held in `RunningState` to keep the Arc alive for the
    /// server's lifetime; the background task and hook operate on clones.
    #[allow(dead_code)]
    pub(crate) portlist_ports: Arc<std::sync::Mutex<Vec<rustscale_portlist::Port>>>,
    /// Client update checker — fed by the map-update loop, read by
    /// `ipn_status()` and the LocalAPI `/status` endpoint.
    pub(crate) client_updater: Arc<std::sync::Mutex<rustscale_clientupdate::ClientUpdater>>,
    /// Persistent client audit logger for this profile/control client.
    pub(crate) audit_logger: Arc<rustscale_auditlog::Logger>,
    /// Tailnet Lock authority shared by map filtering and LocalAPI.
    pub(crate) tailnet_lock: Arc<tailnet_lock::TailnetLock>,
    /// Startup-scoped hostinfo registrations removed on rollback/shutdown.
    pub(crate) hostinfo_hooks: Vec<hostinfo::HostinfoHookHandle>,
    /// Atomic backend/profile subscription feeding extension hooks.
    pub(crate) extension_subscription: Option<rustscale_ipn::CallbackSubscription>,
}

/// A fallback TCP handler: called when an incoming TCP flow doesn't match any
/// listener. Mirrors Go's `tsnet.FallbackTCPHandler`.
///
/// If `intercept` is `true` and `handler` is `Some`, the handler takes over
/// the connection. If `intercept` is `false` or `handler` is `None`, the flow
/// is rejected and the next registered handler is tried.
pub trait FallbackTCPHandler: Send + Sync {
    /// Decide whether to handle the TCP flow from `src` to `dst`.
    fn handle(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> (bool, Option<Box<dyn FnOnce(NetstackStream) + Send>>);
}

/// Which data plane is wired up: userspace netstack (tsnet listen/dial) or a
/// real TUN device (full-client packet routing).
pub(crate) enum DataPlane {
    Netstack(Arc<Netstack>),
    Tun,
}

/// Result of the shared control-plane bootstrap — everything `up()` and
/// `up_tun()` need to start their respective data-plane pumps.
pub(crate) struct Bootstrap {
    pub(crate) tailscale_ips: Vec<IpAddr>,
    pub(crate) our_v4: Ipv4Addr,
    pub(crate) magicsock: Arc<Magicsock>,
    pub(crate) netlog: Option<Arc<rustscale_netlog::Logger>>,
    pub(crate) wg_recv: mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
    pub(crate) wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    /// Unfiltered control peer set retained so authority changes can
    /// re-evaluate peers that were previously withdrawn.
    pub(crate) raw_peers: Vec<Node>,
    pub(crate) peers: Arc<RwLock<Vec<Node>>>,
    pub(crate) peer_map: Arc<peer_map::Runtime>,
    pub(crate) routecheck: Arc<rustscale_routecheck::Client>,
    pub(crate) route_table: Arc<RwLock<RouteTable>>,
    pub(crate) exit_map_gate: ExitMapGate,
    pub(crate) cancel: Arc<CancelToken>,
    pub(crate) map_rx: mpsc::Receiver<Result<MapResponse, StreamMapError>>,
    pub(crate) map_tasks: Arc<MapSessionTasks>,
    pub(crate) node_key: NodePrivate,
    pub(crate) filter: Arc<std::sync::Mutex<Filter>>,
    /// Last successfully received named ACL fragments, including the initial
    /// map, for safe delta reconstruction.
    pub(crate) named_filters: BTreeMap<String, Vec<FilterRule>>,
    pub(crate) packet_drops: Arc<AtomicU64>,
    /// Shared MagicDNS resolver (dial path + DNS responder).
    pub(crate) resolver: Arc<RwLock<MagicDnsResolver>>,
    /// Generation-bound user dialer initialized from this complete netmap.
    pub(crate) user_dialer: Arc<rustscale_tsdial::Dialer>,
    /// Last complete self node retained when control sends peer-only deltas.
    pub(crate) dial_self_node: Option<Node>,
    /// Our node's FQDN (with trailing dot).
    pub(crate) our_fqdn: String,
    /// Tailnet domain / MagicDNS suffix (from `MapResponse.Domain`).
    pub(crate) domain: String,
    /// DNS config (carries CertDomains).
    pub(crate) dns_config: Arc<RwLock<Option<DNSConfig>>>,
    /// User profiles keyed by UserID.
    pub(crate) user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    /// Current SSH policy from the netmap (fed to the SSH server).
    pub(crate) ssh_policy: Arc<RwLock<Option<SSHPolicy>>>,
    /// SSH host keys currently advertised through Hostinfo.
    pub(crate) ssh_host_keys: Arc<RwLock<Vec<String>>>,
    /// Generation-bound SSH callback admission shared with map polling.
    pub(crate) ssh_callbacks: rustscale_controlclient::SshCallbackDispatcher,
    /// Machine private key (for link-change endpoint updates).
    pub(crate) machine_key: MachinePrivate,
    /// Server (control) public key (for link-change endpoint updates).
    pub(crate) server_pub_key: MachinePublic,
    /// Disco private key (for link-change endpoint updates).
    pub(crate) disco_key: DiscoPrivate,
    /// Control-plane URL (for link-change endpoint updates).
    pub(crate) control_url: String,
    /// Hostname (for link-change endpoint updates).
    pub(crate) hostname: String,
    /// Advertised subnet routes (for link-change endpoint updates).
    pub(crate) advertise_routes: Vec<String>,
    /// Bound UDP port (for link-change endpoint re-gathering).
    pub(crate) udp_port: u16,
    /// DERP map (for link-change re-STUN).
    pub(crate) derp_map: DERPMap,
    /// Home DERP region ID (for NetInfo in endpoint updates).
    pub(crate) home_derp: i32,
    /// Health tracker (shared with all subsystems).
    pub(crate) health: Tracker,
    /// Map-poll staleness watchdog (fires if no MapResponse for >3 min).
    pub(crate) health_watchdog: Watchdog,
    /// C2N request router (control-to-node handler dispatch).
    pub(crate) c2n_router: Arc<C2nRouter>,
    /// Live persisted posture preference used by C2N collection.
    pub(crate) posture_checking: Arc<LivePosturePreference>,
    /// Control-plane feature flags extracted from netmap updates.
    pub(crate) control_knobs: Arc<ControlKnobs>,
    /// Runtime Hostinfo field overrides (shared with the update loop).
    pub(crate) overrides: SharedOverrides,
    /// Node key expired flag (shared with the map update task).
    pub(crate) key_expired: Arc<std::sync::atomic::AtomicBool>,
    /// IPN state machine backend (shared with LocalApiState).
    pub(crate) ipn_backend: Arc<IpnBackend>,
    /// Admission token whose owner alone may publish public Running.
    pub(crate) startup_generation: u64,
    /// Shared map-session state for delta-tracking across reconnections.
    pub(crate) map_session: Arc<MapSessionState>,
    /// Per-label socket TX/RX counter registry (shared with magicsock,
    /// DERP, DNS, and the C2N/PeerAPI debug endpoints).
    pub(crate) sockstats: Arc<rustscale_sockstats::SockStats>,
    /// Public backend log ID, derived from the state-directory-private ID.
    pub(crate) backend_log_id: String,
    /// Private half of `backend_log_id`, retained so daemon logtail uses the
    /// exact persisted identity that hostinfo advertises publicly.
    #[allow(dead_code)]
    pub(crate) private_log_id: rustscale_logid::PrivateID,
    /// Tailnet Lock authority and fail-closed peer verifier.
    pub(crate) tailnet_lock: Arc<tailnet_lock::TailnetLock>,
    /// Durable profile/control namespace for identity, netmap, and TKA data.
    pub(crate) state_scope: Option<state::StateScope>,
    /// False when the bootstrap peer set came from cache; only a present full
    /// snapshot from fresh control may make it eligible for activation.
    pub(crate) peer_snapshot_fresh: bool,
}

#[derive(Default)]
pub(crate) struct BootstrapSupervisor {
    state: std::sync::Mutex<CleanupGenerationState>,
    changed: tokio::sync::Notify,
    terminal: std::sync::atomic::AtomicBool,
}

pub(crate) struct CleanupOwner {
    extension_host: Option<rustscale_ipnext::ExtensionHost>,
    inner: Option<RunningState>,
    pre_started: Option<PreStartedLocalApi>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogoutPhase {
    Quiesce,
    ControlLogout,
    RotateIdentity,
    ClearCache,
    SavePrefs,
    PublishLoggedOut,
    Cleanup,
}

/// Durable continuation for logout. Generic close cleanup must never consume
/// this owner because doing so would silently skip unfinished logout phases.
pub(crate) struct LogoutTransaction {
    owner: CleanupOwner,
    drive: Arc<drive::Runtime>,
    control_url: String,
    hostname: String,
    state_dir: Option<PathBuf>,
    state_scope: Option<state::StateScope>,
    tailnet_identity: String,
    prefs: rustscale_ipn::Prefs,
    completion: Arc<localapi::LogoutCompletion>,
    phase: LogoutPhase,
    #[cfg(test)]
    state_save_failures: usize,
}

impl CleanupOwner {
    fn take_from(server: &mut Server) -> Self {
        Self {
            extension_host: server.extension_host.take(),
            inner: server.inner.take(),
            pre_started: server.pre_started.take(),
        }
    }

    fn empty() -> Self {
        Self {
            extension_host: None,
            inner: None,
            pre_started: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.extension_host.is_none() && self.inner.is_none() && self.pre_started.is_none()
    }
}

#[derive(Default)]
struct CleanupGenerationState {
    active: usize,
    epoch: u64,
    retained_owners: Vec<CleanupOwner>,
    retained_logouts: Vec<LogoutTransaction>,
}

pub(crate) struct CleanupCompletion(Arc<BootstrapSupervisor>);

impl Drop for CleanupCompletion {
    fn drop(&mut self) {
        self.0.finish_cleanup();
    }
}

impl BootstrapSupervisor {
    pub(crate) async fn wait(&self) {
        self.wait_for_at_most(0).await;
    }

    pub(crate) async fn wait_for_at_most(&self, maximum: usize) {
        loop {
            let observed_epoch = {
                let state = self.state.lock().expect("cleanup generation lock poisoned");
                if state.active <= maximum {
                    return;
                }
                state.epoch
            };
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.state.lock().expect("cleanup generation lock poisoned");
                if state.active <= maximum {
                    return;
                }
                if state.epoch != observed_epoch {
                    continue;
                }
            }
            changed.await;
        }
    }

    pub(crate) fn begin_cleanup(self: &Arc<Self>) -> CleanupCompletion {
        let mut state = self.state.lock().expect("cleanup generation lock poisoned");
        state.active = state.active.checked_add(1).expect("cleanup count overflow");
        state.epoch = state.epoch.wrapping_add(1);
        drop(state);
        self.changed.notify_waiters();
        CleanupCompletion(Arc::clone(self))
    }

    pub(crate) fn finish_cleanup(&self) {
        let mut state = self.state.lock().expect("cleanup generation lock poisoned");
        debug_assert!(state.active > 0, "cleanup completion underflow");
        state.active = state.active.saturating_sub(1);
        state.epoch = state.epoch.wrapping_add(1);
        drop(state);
        self.changed.notify_waiters();
    }

    pub(crate) fn retain_owner(&self, owner: CleanupOwner) {
        debug_assert!(!owner.is_empty());
        self.state
            .lock()
            .expect("cleanup generation lock poisoned")
            .retained_owners
            .push(owner);
    }

    pub(crate) fn take_retained_owner(&self) -> Option<CleanupOwner> {
        self.state
            .lock()
            .expect("cleanup generation lock poisoned")
            .retained_owners
            .pop()
    }

    pub(crate) fn retain_logout(&self, transaction: LogoutTransaction) {
        if self.terminal.load(std::sync::atomic::Ordering::Acquire) {
            crate::lifecycle::retain_terminal_logout(transaction);
            return;
        }
        self.state
            .lock()
            .expect("cleanup generation lock poisoned")
            .retained_logouts
            .push(transaction);
    }

    pub(crate) fn mark_terminal(&self) {
        self.terminal
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn take_retained_logout(&self) -> Option<LogoutTransaction> {
        self.state
            .lock()
            .expect("cleanup generation lock poisoned")
            .retained_logouts
            .pop()
    }

    pub(crate) fn has_retained_logout(&self) -> bool {
        !self
            .state
            .lock()
            .expect("cleanup generation lock poisoned")
            .retained_logouts
            .is_empty()
    }

    pub(crate) fn has_retained_owner(&self) -> bool {
        !self
            .state
            .lock()
            .expect("cleanup generation lock poisoned")
            .retained_owners
            .is_empty()
    }

    pub(crate) fn has_active_cleanup(&self) -> bool {
        self.state
            .lock()
            .expect("cleanup generation lock poisoned")
            .active
            > 0
    }

    #[cfg(test)]
    pub(crate) fn retained_logout_phase(&self) -> Option<LogoutPhase> {
        self.state
            .lock()
            .expect("cleanup generation lock poisoned")
            .retained_logouts
            .last()
            .map(|transaction| transaction.phase)
    }

    #[cfg(test)]
    pub(crate) fn retained_extension_host_count(&self) -> usize {
        self.state
            .lock()
            .expect("cleanup generation lock poisoned")
            .retained_owners
            .iter()
            .filter(|owner| owner.extension_host.is_some())
            .count()
    }

    #[cfg(test)]
    pub(crate) fn active_count(&self) -> usize {
        self.state
            .lock()
            .expect("cleanup generation lock poisoned")
            .active
    }
}

/// An embedded Tailscale server.
pub struct Server {
    pub(crate) config: ServerBuilder,
    pub(crate) drive: Arc<drive::Runtime>,
    pub(crate) inner: Option<RunningState>,
    pub(crate) pre_started: Option<PreStartedLocalApi>,
    pub(crate) system: Arc<rustscale_tsd::System>,
    pub(crate) extension_host: Option<rustscale_ipnext::ExtensionHost>,
    pub(crate) bootstrap_supervisor: Arc<BootstrapSupervisor>,
    pub(crate) startup_supervisor: Arc<BootstrapSupervisor>,
    pub(crate) shutdown_supervisor: Arc<BootstrapSupervisor>,
    /// One trigger shared by every LocalAPI generation and the daemon owner.
    pub(crate) logout_trigger: Arc<tokio::sync::Notify>,
    pub(crate) logout_completion: Arc<localapi::LogoutCompletion>,
    #[cfg(test)]
    pub(crate) logout_test_hook: Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>)>,
    #[cfg(test)]
    pub(crate) logout_state_save_failures: usize,
    #[cfg(test)]
    pub(crate) startup_localapi_test_hook:
        Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>, bool)>,
}

/// State from `start_localapi_only()` — used by `up()` to reuse the
/// pre-started IpnBackend and login trigger, and to clean up the
/// pre-started LocalAPI server.
pub(crate) struct PreStartedLocalApi {
    pub(crate) backend: Arc<IpnBackend>,
    pub(crate) handle: Option<localapi::LocalApiHandle>,
    pub(crate) magicsock: Option<Arc<Magicsock>>,
    pub(crate) login_trigger: Arc<tokio::sync::Notify>,
    #[allow(dead_code)]
    pub(crate) auth_url: Arc<std::sync::Mutex<Option<String>>>,
    pub(crate) command_rx: Option<mpsc::UnboundedReceiver<localapi::DaemonCommand>>,
    /// Clone of the command sender stored in LocalApiState, so up() can
    /// reuse it in the new LocalApiState (keeping the daemon's rx live).
    pub(crate) command_tx: Option<mpsc::UnboundedSender<localapi::DaemonCommand>>,
    /// Logout trigger shared with LocalApiState, so up() can reuse it.
    pub(crate) logout_trigger: Arc<tokio::sync::Notify>,
    pub(crate) mutation_fence: Arc<localapi::LocalApiMutationFence>,
    pub(crate) mutation_generation: u64,
    #[allow(dead_code)]
    pub(crate) socket_path: PathBuf,
}

impl Server {
    /// Create a new builder with defaults.
    pub fn builder() -> ServerBuilder {
        ServerBuilder {
            hostname: "rustscale".into(),
            control_url: DEFAULT_CONTROL_URL.into(),
            overrides: hostinfo::shared_overrides(),
            ..Default::default()
        }
    }

    /// Whether the server is up.
    pub fn is_up(&self) -> bool {
        self.inner.is_some()
    }

    /// Returns the typed daemon dependency container shared with extensions.
    pub fn system(&self) -> &Arc<rustscale_tsd::System> {
        &self.system
    }

    /// Returns a weak API handle to the server's extension host.
    pub fn extension_host(&self) -> Option<rustscale_ipnext::Host> {
        self.extension_host
            .as_ref()
            .map(rustscale_ipnext::ExtensionHost::host)
    }

    /// The node's public key, if the server is up. Used by test harnesses
    /// and diagnostics to identify this node on the control plane.
    pub fn node_key(&self) -> Option<NodePublic> {
        self.inner.as_ref().map(|i| i.node_key.public())
    }

    /// The shared health tracker, if the server is up. Callers can report
    /// custom warnable conditions via [`Tracker::set_unhealthy`] using the
    /// built-in warnable IDs or their own registered codes.
    pub fn health(&self) -> Option<Tracker> {
        self.inner.as_ref().map(|i| i.health.clone())
    }

    /// The shared C2N router, if the server is up. Callers can register
    /// additional control-to-node handlers (e.g. debug endpoints) before or
    /// after `up()`.
    pub fn c2n_router(&self) -> Option<Arc<C2nRouter>> {
        self.inner.as_ref().map(|i| i.c2n_router.clone())
    }

    /// C2N is never exposed on an unauthenticated loopback listener.
    /// Control-to-node requests are accepted only on the authenticated Noise
    /// map session, so this compatibility accessor always returns `None`.
    pub const fn c2n_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// The PeerAPI listen port, if the server is up. The PeerAPI listens on
    /// a deterministic port derived from the node's primary Tailscale IP
    /// (matching Go's `peerapi.go` port selection). The full address is
    /// `http://<tailscale_ip>:<port>/`.
    pub fn peerapi_port(&self) -> Option<u16> {
        self.inner.as_ref().and_then(|i| i.peerapi_port)
    }

    /// The PeerAPI listen address (first tailscale IP + port), if the server
    /// is up. Returns `None` if the PeerAPI listener failed to start.
    pub fn peerapi_addr(&self) -> Option<SocketAddr> {
        let inner = self.inner.as_ref()?;
        let port = inner.peerapi_port?;
        let ip = inner.tailscale_ips.first()?;
        Some(SocketAddr::new(*ip, port))
    }

    /// The shared control-knobs store, if the server is up. Downstream
    /// consumers can query feature flags pushed by the control plane via
    /// [`ControlKnobs::get_bool`] / [`ControlKnobs::get_float`] /
    /// [`ControlKnobs::get_string`], and register change callbacks via
    /// [`ControlKnobs::on_change`].
    pub fn control_knobs(&self) -> Option<Arc<ControlKnobs>> {
        self.inner.as_ref().map(|i| i.control_knobs.clone())
    }

    /// The relay server extension, if this node was started with
    /// `peer_relay_server(true)`. Returns `None` otherwise.
    pub fn relay_server(&self) -> Option<Arc<rustscale_magicsock::RelayServerExtension>> {
        self.inner
            .as_ref()
            .and_then(|i| i.magicsock.relay_server().cloned())
    }

    /// The magicsock instance, if the server is up. Exposed for integration
    /// tests that need to inspect path state or trigger link changes.
    pub fn magicsock(&self) -> Option<Arc<Magicsock>> {
        self.inner.as_ref().map(|i| i.magicsock.clone())
    }

    /// Trigger a link change: re-gather local endpoints, reset direct paths,
    /// and close DERP connections for reconnection. Delegates to magicsock.
    pub fn link_changed(&self) {
        if let Some(ref inner) = self.inner {
            inner.magicsock.link_changed();
        }
    }

    /// The current path class for a peer (for testing). Returns `None` if
    /// the server is not up or the peer is not in the netmap.
    pub fn peer_path_class(&self, peer: &NodePublic) -> Option<rustscale_magicsock::PathClass> {
        self.inner
            .as_ref()
            .map(|i| i.magicsock.peer_path_class(peer))
    }

    /// The LocalAPI Unix socket path, if the server was spawned. Returns
    /// `None` if the LocalAPI was not enabled or the server is not up.
    pub fn localapi_path(&self) -> Option<&PathBuf> {
        self.inner.as_ref().and_then(|i| i.localapi_socket.as_ref())
    }

    /// The IPN state machine backend, if the server is up. Exposed for
    /// integration tests and external consumers that need to query the
    /// current IPN state or subscribe to the notification bus.
    pub fn ipn_backend(&self) -> Option<&Arc<IpnBackend>> {
        self.inner.as_ref().map(|i| &i.ipn_backend)
    }

    /// Override `Hostinfo.DeviceModel` at runtime (mirrors Go's
    /// `hostinfo.SetDeviceModel`). Takes effect on the next periodic
    /// Hostinfo refresh (within 10 minutes) or the next manual collection.
    /// Requires the server to be up; use [`ServerBuilder::set_device_model`]
    /// before `up()` instead for startup-time overrides.
    pub async fn set_device_model(&self, model: impl Into<String>) {
        if let Some(ref inner) = self.inner {
            inner.overrides.write().await.set_device_model(model);
        }
    }

    /// Override `Hostinfo.App` at runtime (mirrors Go's `hostinfo.SetApp`).
    pub async fn set_app(&self, app: impl Into<String>) {
        if let Some(ref inner) = self.inner {
            inner.overrides.write().await.set_app(app);
        }
    }

    /// Override `Hostinfo.OSVersion` at runtime (mirrors Go's
    /// `hostinfo.SetOSVersion`).
    pub async fn set_os_version(&self, version: impl Into<String>) {
        if let Some(ref inner) = self.inner {
            inner.overrides.write().await.set_os_version(version);
        }
    }

    /// Override `Hostinfo.Package` at runtime (mirrors Go's
    /// `hostinfo.SetPackage`).
    pub async fn set_package(&self, package: impl Into<String>) {
        if let Some(ref inner) = self.inner {
            inner.overrides.write().await.set_package(package);
        }
    }

    /// Set the frontend log ID supplied by the embedding application.
    pub async fn set_frontend_log_id(&self, id: impl Into<String>) {
        if let Some(ref inner) = self.inner {
            inner.overrides.write().await.set_frontend_log_id(id);
        }
    }

    /// Re-read the config file at `path` and apply the resulting `MaskedPrefs`
    /// to the live prefs. Used by the daemon's SIGHUP handler. The server
    /// must be up (i.e. `up()` or `up_tun()` has been called).
    ///
    /// Mirrors Go's `LocalBackend.ReloadConfig()` → `setConfigLocked()` →
    /// `ToPrefs()` → `ApplyEdits()` → `setPrefsLocked()`.
    pub async fn reload_config(&self, path: &str) -> Result<(), String> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| "server not up".to_string())?;

        let config =
            rustscale_conffile::Config::load(path).map_err(|e| format!("config load: {e}"))?;
        let masked = config.parsed.to_prefs();
        let _exit_map_guard = inner.exit_map_gate.lock().await;
        let authorization_changed = masked.ShieldsUpSet
            || masked.ExitNodeAllowLANAccessSet
            || masked.ExitNodeIDSet
            || masked.ExitNodeIPSet;
        let map_commit = if authorization_changed {
            Some(inner.peer_map.gate.write().await)
        } else {
            None
        };
        let notification = {
            let _commit = inner.profile_mutations.lock().await;
            let profile = self
                .config
                .state_dir
                .as_ref()
                .and_then(|dir| {
                    let current = rustscale_ipn::LoginProfile::load_current_id(dir).ok()??;
                    rustscale_ipn::LoginProfile::load_all(dir)
                        .ok()?
                        .into_iter()
                        .find(|profile| profile.ID == current)
                })
                .unwrap_or_default();
            let mut prefs_guard = inner.prefs.write().await;
            let old_prefs = prefs_guard.clone();
            let mut next_prefs = old_prefs.clone();
            masked.apply_to(&mut next_prefs);
            if let Some(policy) = &self.config.preference_policy {
                policy.reconcile(&mut next_prefs)?;
            }
            let exit_changed =
                masked.ExitNodeAllowLANAccessSet || masked.ExitNodeIDSet || masked.ExitNodeIPSet;
            if let Some(ref dir) = self.config.state_dir {
                next_prefs
                    .save(dir)
                    .map_err(|error| format!("prefs save: {error}"))?;
            }
            if exit_changed {
                let selected_exit = if let Some(selector) = exit_node_pref(&next_prefs) {
                    let peers = inner.peers.read().await;
                    localapi::resolve_exit_node_peer(&peers, &selector)
                } else {
                    None
                };
                let requested = exit_node_pref(&next_prefs).is_some();
                let pending = requested && selected_exit.is_none();
                let mut selection = inner.exit_node_selection.write().await;
                let mut routes = inner.route_table.write().await;
                let old_exit_state = routes.exit_route_state();
                let selected_exit = selected_exit.or_else(|| {
                    if pending {
                        routes.exit_node().cloned()
                    } else {
                        None
                    }
                });
                set_exit_route_state_latch_aware(
                    &mut routes,
                    inner.router.as_ref(),
                    selected_exit,
                    requested,
                );
                if let Some(router) = inner.router.as_ref() {
                    let control_url = if next_prefs.ControlURL.is_empty() {
                        DEFAULT_CONTROL_URL
                    } else {
                        &next_prefs.ControlURL
                    };
                    if let Err(error) = sync_router(
                        router,
                        &inner.tailscale_ips,
                        &mut routes,
                        &inner.magicsock,
                        control_url,
                        next_prefs.ExitNodeAllowLANAccess,
                    ) {
                        routes.restore_exit_route_state(old_exit_state);
                        if let Some(ref dir) = self.config.state_dir {
                            if let Err(rollback_error) = old_prefs.save(dir) {
                                return Err(format!(
                                    "router update failed: {error}; prefs rollback failed: {rollback_error}"
                                ));
                            }
                        }
                        return Err(error.to_string());
                    }
                }
                let committed_peer = routes.exit_node().cloned();
                set_exit_route_state_latch_aware(
                    &mut routes,
                    inner.router.as_ref(),
                    committed_peer,
                    requested,
                );
                inner.peer_map.advance_dial_epoch_locked();
                if pending {
                    selection.replace_from_prefs(&next_prefs);
                } else {
                    selection.clear_pending();
                }
            }
            *prefs_guard = next_prefs.clone();
            inner.posture_checking.store(
                next_prefs.PostureChecking,
                std::sync::atomic::Ordering::Release,
            );
            if masked.ShieldsUpSet {
                inner
                    .filter
                    .lock()
                    .unwrap()
                    .set_shields_up(next_prefs.ShieldsUp);
                inner.peer_map.advance_authorization_epoch_locked();
            }
            let notification = inner
                .ipn_backend
                .queue_profile_state(profile, next_prefs, true);
            drop(prefs_guard);
            notification
        };
        inner.ipn_backend.dispatch_profile_state(notification);
        drop(map_commit);

        Ok(())
    }

    /// Route a diagnostic message through the pluggable logger, or
    /// `eprintln!` if no logger is set. Used internally by lifecycle
    /// methods instead of bare `eprintln!`.
    pub(crate) fn log_msg(&self, msg: impl std::fmt::Display) {
        if let Some(ref logger) = self.config.logger {
            logger(&msg.to_string());
        } else {
            log::debug!("{msg}");
        }
    }
}

#[cfg(test)]
mod tests;
