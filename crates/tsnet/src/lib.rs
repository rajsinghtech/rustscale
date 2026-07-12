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
//! server.close().await;
//! # Ok(())
//! # }
//! ```

#![allow(unsafe_code)]

mod acme;
mod appc;
mod c2n;
mod hostinfo;
pub mod localapi;
mod peerapi;
mod proxyproto;
mod routing;
mod serve;
mod service;
mod socks5;
mod state;
mod status;
mod taildrop;
mod tls;

#[cfg(feature = "ssh")]
mod ssh;

pub use appc::{
    extract_appc_config, is_app_connector_node, make_dns_observer, route_info_from_connector,
    TsnetRouteAdvertiser,
};
pub use routing::{peer_is_exit_capable, RouteTable};
pub use rustscale_health::Warning;
pub use serve::{
    check_funnel_access, check_funnel_port, FunnelError, HTTPHandler, HostPort, ServeConfig,
    ServeError, TCPPortHandler, WebServerConfig, FUNNEL_PORTS,
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
    collect_hostinfo, hostinfo_hash, populate_hostinfo, HostinfoOverrides, SharedOverrides,
};

#[cfg(feature = "ssh")]
pub use ssh::SshListener;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use rustscale_controlclient::client::{ControlClient, RegisterError, StreamMapError};
use rustscale_controlclient::controlhttp;
use rustscale_controlclient::{extract_knobs_from_map_response, C2nRouter};
use rustscale_controlknobs::ControlKnobs;
use rustscale_derp::DerpClient;
use rustscale_dns::{
    build_os_dns_config, config_from_dns, new_os_configurator, DnsResponder, Forwarder,
    MagicDnsResolver, OsConfig, OsConfigurator, MAGICDNS_VIP,
};
use rustscale_filter::Filter;
use rustscale_health::{
    Severity, Tracker, Watchdog, WARN_CERT_FALLBACK, WARN_CONTROL, WARN_DERP_HOME,
    WARN_NETMON_CHANGE,
};
use rustscale_ipn::IpnBackend;
use rustscale_key::{DiscoPrivate, MachinePrivate, MachinePublic, NodePrivate, NodePublic};
use rustscale_magicsock::{Magicsock, MagicsockConfig, MagicsockError};
use rustscale_netstack::{Netstack, NetstackError, NetstackStream, DEFAULT_MTU};
use rustscale_tailcfg::{
    DERPMap, DNSConfig, FilterRule, Hostinfo, MapRequest, MapResponse, NetInfo, Node, OptBool,
    RegisterRequest, SSHPolicy, UserID, UserProfile,
};
use rustscale_tun::Tun;
use rustscale_wg::{WgError, WgTunn};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;

/// Default control-plane URL.
pub const DEFAULT_CONTROL_URL: &str = "controlplane.tailscale.com";

/// Capability version we advertise to the control plane (matches the
/// current Tailscale `CurrentCapabilityVersion`).
const CAPABILITY_VERSION: i32 = 141;

/// Protocol version for the Noise handshake (ts2021). This is the
/// `CurrentCapabilityVersion` as a u16, matching Go's
/// `cmp.Or(nc.opts.ProtocolVersion, uint16(tailcfg.CurrentCapabilityVersion))`.
const PROTOCOL_VERSION: u16 = 141;

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
    #[error("control register error: {0}")]
    Register(#[from] RegisterError),
    #[error("map stream error: {0}")]
    MapStream(#[from] StreamMapError),
    #[error("magicsock error: {0}")]
    Magicsock(#[from] MagicsockError),
    #[error("netstack error: {0}")]
    Netstack(#[from] NetstackError),
    #[error("wireguard error: {0}")]
    Wg(#[from] WgError),
    #[error("auth required: visit {0}")]
    AuthRequired(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hostname not found in netmap: {0}")]
    HostnameNotFound(String),
    #[error("exit node not found: {0}")]
    ExitNodeNotFound(String),
    #[error("peer is not exit-node-capable (no 0.0.0.0/0 in AllowedIPs): {0}")]
    NotExitCapable(String),
    #[error("derp error: {0}")]
    Derp(#[from] rustscale_derp::DerpError),
    #[error("netcheck error: {0}")]
    Netcheck(#[from] rustscale_netcheck::NetcheckError),
    #[error("tun device error: {0}")]
    Tun(#[from] rustscale_tun::TunError),
    #[error("listen/dial not available in TUN mode (no userspace netstack)")]
    NotAvailableInTunMode,
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
#[derive(Clone, Debug, Default)]
pub struct ServerBuilder {
    hostname: String,
    auth_key: Option<String>,
    control_url: String,
    state_dir: Option<PathBuf>,
    ephemeral: bool,
    /// Subnet routes to advertise (e.g. `["192.0.2.0/24"]`). Sent in
    /// `Hostinfo.RoutableIPs`; control must approve them before peers install
    /// them.
    advertise_routes: Vec<String>,
    /// Whether to install peer-advertised subnet routes into the local
    /// routing table. When false (default), only tailnet-range IPs
    /// (100.64.0.0/10, fd7a:115c:a1e0::/48) are routed.
    accept_routes: bool,
    /// Whether to advertise this node as an exit node. When true, `0.0.0.0/0`
    /// and `::/0` are appended to `RoutableIPs` in `Hostinfo` (mirroring Go's
    /// `tsaddr.ExitRoutes()`). The tailnet admin must approve the exit routes
    /// before peers see them in this node's `AllowedIPs`. The filter's
    /// `localNets` is also extended with the default routes so forwarded
    /// exit traffic is admitted (same mechanism as subnet routes).
    advertise_exit_node: bool,
    /// Test-support: when true, magicsock suppresses all direct-path
    /// establishment and forces every send via DERP. See
    /// [`MagicsockConfig::disable_direct_paths`]. Production code should
    /// leave this false.
    disable_direct_paths: bool,
    /// Runtime Hostinfo field overrides (mirror Go's
    /// `hostinfo.SetDeviceModel`/`SetApp`/`SetOSVersion`/`SetPackage`).
    /// Applied before platform detection so they win over auto-detected
    /// values. Shared with the periodic Hostinfo update loop.
    overrides: SharedOverrides,
    /// Whether to spawn the LocalAPI Unix-domain-socket server. Default OFF.
    localapi: bool,
    /// Explicit LocalAPI socket path. If None and localapi is enabled,
    /// defaults to `<state_dir>/rustscale.sock`.
    localapi_path: Option<PathBuf>,
    /// Whether to configure the OS DNS resolver in TUN mode. When true,
    /// `up_tun` writes `/etc/resolver/` entries (macOS) pointing at
    /// `100.100.100.100` for the MagicDNS suffix and split-DNS routes.
    /// **Requires root** (writing `/etc/resolver` needs privileged access).
    /// Default `false`. Ignored in netstack mode (`up()`).
    configure_os_dns: bool,
    /// Whether to run this node as a peer relay server. When true, a
    /// `udprelay::Server` is started in magicsock and
    /// `Hostinfo.PeerRelay = true` is advertised to the control plane.
    /// Default OFF.
    peer_relay_server: bool,
    /// Optional relay server config override (lifetimes, port, etc.). When
    /// `None`, defaults are used. Only effective when `peer_relay_server`
    /// is true. Used by integration tests to set shortened lifetimes.
    relay_server_config: Option<rustscale_udprelay::ServerConfig>,
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

    /// Set an explicit path for the LocalAPI Unix socket. Calling this
    /// implicitly enables the LocalAPI server (equivalent to
    /// `.localapi(true)`). The parent directory is created if it does not
    /// exist; any stale socket file at the path is removed before binding.
    pub fn localapi_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.localapi_path = Some(path.into());
        self.localapi = true;
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
    /// Permission failures are logged as warnings and do not prevent `up_tun`
    /// from completing; the TUN data plane and MagicDNS responder still
    /// operate.
    ///
    /// Ignored in netstack mode ([`Server::up`]).
    pub fn configure_os_dns(mut self, on: bool) -> Self {
        self.configure_os_dns = on;
        self
    }

    /// Compute the effective advertised routes: `advertise_routes` plus the
    /// exit-node default routes (`0.0.0.0/0`, `::/0`) when
    /// `advertise_exit_node` is true. Used everywhere `RoutableIPs` is sent to
    /// control or the filter's `localNets` is built.
    fn effective_advertise_routes(&self) -> Vec<String> {
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
        Ok(Server {
            config: self,
            inner: None,
            pre_started: None,
        })
    }
}

/// Internal running state.
struct RunningState {
    tailscale_ips: Vec<IpAddr>,
    magicsock: Arc<Magicsock>,
    data_plane: DataPlane,
    peers: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    cancel: Arc<CancelToken>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    packet_drops: Arc<AtomicU64>,
    /// Shared MagicDNS resolver (dial path + DNS responder).
    resolver: Arc<RwLock<MagicDnsResolver>>,
    /// Our node's FQDN (with trailing dot), from the netmap.
    our_fqdn: String,
    /// Tailnet domain / MagicDNS suffix (e.g. "tailnet.ts.net").
    domain: String,
    /// DNS config from control (carries `CertDomains` for cert provisioning).
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    /// User profiles keyed by `UserID` (for WhoIs).
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    /// Current SSH policy from the netmap (`MapResponse.SSHPolicy`).
    /// `None` until the control server sends one; the SSH server rejects
    /// all connections while this is `None`. Updated on each map response
    /// that carries a new policy.
    #[cfg_attr(not(feature = "ssh"), allow(dead_code))]
    ssh_policy: Arc<RwLock<Option<SSHPolicy>>>,
    /// Network change monitor handle (None if the monitor couldn't start).
    monitor: Option<rustscale_netmon::MonitorHandle>,
    /// Machine private key (for control-plane set-dns during cert issuance).
    machine_key: MachinePrivate,
    /// Server (control) public key (for control-plane set-dns).
    server_pub_key: MachinePublic,
    /// Node private key (for SetDNSRequest.NodeKey during cert issuance).
    node_key: NodePrivate,
    /// Serve/Funnel runner (None in TUN mode — serve requires netstack).
    serve: Option<Arc<serve::ServeRunner>>,
    /// Health tracker (shared with all subsystems).
    health: Tracker,
    /// Map-poll staleness watchdog (fires if no MapResponse for >3 min).
    health_watchdog: Watchdog,
    /// C2N request router (control-to-node handler dispatch).
    c2n_router: Arc<C2nRouter>,
    /// C2N HTTP server address (loopback, bound on up()).
    c2n_addr: Option<SocketAddr>,
    /// Control-plane feature flags extracted from netmap updates.
    control_knobs: Arc<ControlKnobs>,
    /// PeerAPI listen port (deterministic, from tailscale IPs).
    peerapi_port: Option<u16>,
    /// Runtime Hostinfo field overrides (shared with the update loop).
    overrides: SharedOverrides,
    /// LocalAPI socket path (if the server was spawned). Used for cleanup on
    /// close().
    localapi_socket: Option<PathBuf>,
    /// Node key expired flag — set when the control server signals
    /// `NodeKeyExpired` in a MapResponse. The client should transition to
    /// a "NeedsLogin" state; un-expiring clears it.
    key_expired: Arc<std::sync::atomic::AtomicBool>,
    /// OS DNS configurator, active only in TUN mode when
    /// `configure_os_dns` is enabled. `close()` is called on server
    /// shutdown to remove `/etc/resolver` entries.
    os_dns_configurator: Option<Box<dyn OsConfigurator + Send>>,
    /// IPN state machine backend — tracks the current IPN state, holds
    /// the notification bus, and drives state transitions.
    ipn_backend: Arc<IpnBackend>,
}

/// Which data plane is wired up: userspace netstack (tsnet listen/dial) or a
/// real TUN device (full-client packet routing).
enum DataPlane {
    Netstack(Arc<Netstack>),
    Tun,
}

/// Configuration for TUN-mode operation ([`Server::up_tun`]).
///
/// In TUN mode the server routes plaintext IP packets between a real OS TUN
/// device and the WireGuard/magicsock data plane, instead of an in-process
/// userspace netstack. `listen`/`dial` are unavailable in this mode.
#[derive(Clone, Debug, Default)]
pub struct TunModeConfig {
    /// TUN device parameters (name hint + MTU). On macOS the default name
    /// `"utun"` auto-selects a unit.
    pub tun: rustscale_tun::TunConfig,
    /// If true, bring the interface up and add tailnet routes on macOS via
    /// `ifconfig`/`route`. **Requires root.** Default `false`, in which case
    /// you must configure the interface and routes yourself (or rely on the
    /// data-plane pump alone for in-process traffic).
    pub apply_routes: bool,
    /// If set, select this peer as the exit node at startup. The value is a
    /// tailnet IP or MagicDNS hostname, resolved against the netmap after the
    /// first `MapResponse`. The peer must be exit-node-capable (`AllowedIPs`
    /// containing `0.0.0.0/0`); otherwise `up_tun` returns an error.
    ///
    /// When `apply_routes` is also true, OS-level default-route overrides are
    /// installed so that all non-tailnet traffic enters the TUN device:
    /// - **macOS**: two `/1` routes (`0.0.0.0/1` + `128.0.0.0/1`) pointing at
    ///   the utun, which together cover all of IPv4 and are more specific than
    ///   the default route — mirroring how `tailscaled` overrides the default
    ///   without deleting it. IPv6 uses `::/1` + `8000::/1`.
    /// - **Linux**: `ip route add 0.0.0.0/0 dev <tun>` and `::/0 dev <tun>`
    ///   (best-effort; may conflict with an existing default route).
    ///
    /// **Known limitation (TUN + exit node):** magicsock's UDP socket is bound
    /// to `0.0.0.0` and sends DERP/control/peer-discovery traffic via the OS
    /// routing table. With `/1` exit routes installed, that traffic enters the
    /// TUN and would loop back through the exit node. rustscale does **not**
    /// yet install bypass routes (host routes for DERP/control IPs via the
    /// physical gateway) like the Go client does. For exit-node usage without
    /// this limitation, use netstack mode ([`Server::up`] +
    /// [`Server::set_exit_node`]), which has no loop issue because magicsock
    /// uses the OS stack directly and the TUN is not in the path.
    pub exit_node: Option<String>,
}

/// Simple cancellation token.
struct CancelToken {
    cancelled: std::sync::atomic::AtomicBool,
}

impl CancelToken {
    fn new() -> Self {
        Self {
            cancelled: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Result of the shared control-plane bootstrap — everything `up()` and
/// `up_tun()` need to start their respective data-plane pumps.
struct Bootstrap {
    tailscale_ips: Vec<IpAddr>,
    our_v4: Ipv4Addr,
    magicsock: Arc<Magicsock>,
    wg_recv: mpsc::Receiver<rustscale_magicsock::WgDatagram>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    peers: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    cancel: Arc<CancelToken>,
    map_rx: mpsc::Receiver<Result<MapResponse, StreamMapError>>,
    map_task: JoinHandle<()>,
    node_key: NodePrivate,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    /// Shared MagicDNS resolver (dial path + DNS responder).
    resolver: Arc<RwLock<MagicDnsResolver>>,
    /// Our node's FQDN (with trailing dot).
    our_fqdn: String,
    /// Tailnet domain / MagicDNS suffix (from `MapResponse.Domain`).
    domain: String,
    /// DNS config (carries CertDomains).
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    /// User profiles keyed by UserID.
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    /// Current SSH policy from the netmap (fed to the SSH server).
    ssh_policy: Arc<RwLock<Option<SSHPolicy>>>,
    /// Machine private key (for link-change endpoint updates).
    machine_key: MachinePrivate,
    /// Server (control) public key (for link-change endpoint updates).
    server_pub_key: MachinePublic,
    /// Disco private key (for link-change endpoint updates).
    disco_key: DiscoPrivate,
    /// Control-plane URL (for link-change endpoint updates).
    control_url: String,
    /// Hostname (for link-change endpoint updates).
    hostname: String,
    /// Advertised subnet routes (for link-change endpoint updates).
    advertise_routes: Vec<String>,
    /// Bound UDP port (for link-change endpoint re-gathering).
    udp_port: u16,
    /// DERP map (for link-change re-STUN).
    derp_map: DERPMap,
    /// Home DERP region ID (for NetInfo in endpoint updates).
    home_derp: i32,
    /// Health tracker (shared with all subsystems).
    health: Tracker,
    /// Map-poll staleness watchdog (fires if no MapResponse for >3 min).
    health_watchdog: Watchdog,
    /// C2N request router (control-to-node handler dispatch).
    c2n_router: Arc<C2nRouter>,
    /// C2N backend (shared by HTTP server + Noise-channel router).
    c2n_backend: Arc<c2n::TsnetC2nBackend>,
    /// Control-plane feature flags extracted from netmap updates.
    control_knobs: Arc<ControlKnobs>,
    /// Runtime Hostinfo field overrides (shared with the update loop).
    overrides: SharedOverrides,
    /// Node key expired flag (shared with the map update task).
    key_expired: Arc<std::sync::atomic::AtomicBool>,
    /// IPN state machine backend (shared with LocalApiState).
    ipn_backend: Arc<IpnBackend>,
}

/// An embedded Tailscale server.
pub struct Server {
    config: ServerBuilder,
    inner: Option<RunningState>,
    pre_started: Option<PreStartedLocalApi>,
}

/// State from `start_localapi_only()` — used by `up()` to reuse the
/// pre-started IpnBackend and login trigger, and to clean up the
/// pre-started LocalAPI server.
struct PreStartedLocalApi {
    backend: Arc<IpnBackend>,
    handle: Option<localapi::LocalApiHandle>,
    login_trigger: Arc<tokio::sync::Notify>,
    #[allow(dead_code)]
    auth_url: Arc<std::sync::Mutex<Option<String>>>,
    command_rx: Option<mpsc::UnboundedReceiver<localapi::DaemonCommand>>,
    #[allow(dead_code)]
    socket_path: PathBuf,
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

    /// The C2N HTTP server address (loopback), if the server is up.
    pub fn c2n_addr(&self) -> Option<SocketAddr> {
        self.inner.as_ref().and_then(|i| i.c2n_addr)
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

    /// Bring the server online in userspace netstack mode (tsnet listen/dial).
    ///
    /// This is the classic tsnet embedding path: an in-process smoltcp netstack
    /// backs `listen`/`dial`. For a full-client TUN device instead, use
    /// [`Server::up_tun`].
    pub async fn up(&mut self) -> Result<(), TsnetError> {
        if self.inner.is_some() {
            return Err(TsnetError::AlreadyUp);
        }

        ensure_ring_provider();

        let b = self.bootstrap().await?;

        let monitor = spawn_link_monitor(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.udp_port,
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            b.health.clone(),
        );

        // Userspace netstack bound to our tailnet IPv4.
        let netstack = Arc::new(Netstack::new(b.our_v4, DEFAULT_MTU));

        // Periodic endpoint update (Bug 4): pushes a non-streaming
        // MapRequest with OmitPeers=true every 5 minutes so the control
        // server always has fresh endpoint data.
        let periodic_ep = spawn_periodic_endpoint_updates(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            self.config.peer_relay_server,
        );

        // Netstack data-plane pump: netstack <-> WG <-> magicsock.
        let pump = tokio::spawn(run_netstack_pump(
            b.magicsock.clone(),
            b.wg_recv,
            netstack.clone(),
            b.wg_tunnels.clone(),
            b.route_table.clone(),
            b.filter.clone(),
            b.packet_drops.clone(),
            b.cancel.clone(),
        ));

        // Map-stream update task (peer/route deltas).
        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.tailscale_ips.clone(),
            self.config.accept_routes,
            b.advertise_routes.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.user_profiles.clone(),
            b.ssh_policy.clone(),
            b.cancel.clone(),
            b.health.clone(),
            b.health_watchdog.clone(),
            self.config.state_dir.clone(),
            b.node_key.public(),
            b.control_knobs.clone(),
            b.key_expired.clone(),
            b.ipn_backend.clone(),
        );

        // MagicDNS responder: best-effort UDP server at 100.100.100.100:53.
        // Binding to :53 typically requires root and the MagicDNS VIP to be
        // assigned to an interface; failure is non-fatal (dial still resolves
        // via the shared resolver). The responder serves A/AAAA/PTR for peer
        // hostnames, handles split-DNS routes, ExtraRecords, .onion NXDOMAIN,
        // 4via6 synthesis, and forwards the rest upstream (with TCP fallback
        // and DoH support).
        let mut tasks = vec![b.map_task, pump, map_update, periodic_ep];
        let dns_cfg_snapshot = b.dns_config.read().await.clone();
        let forwarder = Arc::new(Forwarder::from_dns_config(dns_cfg_snapshot.as_ref()));
        let responder = DnsResponder::with_forwarder(
            b.resolver.clone(),
            SocketAddr::new(IpAddr::V4(MAGICDNS_VIP), 53),
            forwarder,
        );
        match responder.spawn().await {
            Ok(handle) => tasks.push(handle),
            Err(e) => eprintln!(
                "tsnet: MagicDNS responder not started ({e}); dial still resolves via netmap"
            ),
        }

        // Serve/Funnel runner (netstack mode only).
        let serve = Some(Arc::new(serve::ServeRunner::new(
            netstack.clone(),
            b.peers.clone(),
            b.user_profiles.clone(),
            b.our_fqdn.clone(),
        )));

        let (c2n_task, c2n_addr) =
            c2n::spawn_c2n_server(b.c2n_backend.clone(), "rustscale".into()).await;
        tasks.push(c2n_task);

        // Taildrop file manager (shared between PeerAPI receive handler
        // and LocalAPI endpoints). Created from the state directory; if
        // no state dir, taildrop is disabled.
        let taildrop = Arc::new(taildrop::TaildropManager::new(
            self.config.state_dir.as_deref(),
            Some(b.ipn_backend.clone()),
        ));

        // PeerAPI server (netstack mode): listens on a deterministic port on
        // the node's tailnet IP, serving DoH DNS + debug endpoints to peers.
        let offering_exit_node = self.config.advertise_exit_node;
        let (peerapi_task, peerapi_port) = peerapi::spawn_peerapi_netstack(
            netstack.clone(),
            b.peers.clone(),
            b.user_profiles.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.tailscale_ips.clone(),
            offering_exit_node,
            Some(taildrop.clone()),
        )
        .await;
        tasks.push(peerapi_task);

        // Advertise peerapi4/peerapi6 services to the control plane so peers
        // can discover our PeerAPI port.
        if let Some(port) = peerapi_port {
            let has_v6 = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
            let services =
                peerapi::peerapi_services(Some(port), if has_v6 { Some(port) } else { None });
            if !services.is_empty() {
                let cc_ep = ControlClient::new(
                    &b.control_url,
                    b.machine_key.clone(),
                    b.server_pub_key.clone(),
                    PROTOCOL_VERSION,
                );
                let node_pub = b.node_key.public();
                let disco_pub = b.disco_key.public();
                let svc_req = MapRequest {
                    Version: CAPABILITY_VERSION,
                    KeepAlive: false,
                    NodeKey: node_pub,
                    DiscoKey: disco_pub,
                    Stream: false,
                    OmitPeers: true,
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: b.hostname.clone(),
                        RoutableIPs: b.advertise_routes.clone(),
                        Services: services,
                        PeerRelay: self.config.peer_relay_server,
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                match cc_ep.send_map_request(&svc_req).await {
                    Ok(()) => eprintln!("tsnet: peerapi services advertised (port {port})"),
                    Err(e) => {
                        eprintln!("tsnet: peerapi service advertisement failed (non-fatal): {e}");
                    }
                }
            }
        }

        // Periodic Hostinfo refresh (every 10 min, dedup by content hash).
        let hostinfo_loop = spawn_hostinfo_update_loop(
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.home_derp,
            b.peers.clone(),
            b.route_table.clone(),
            serve.clone(),
            b.overrides.clone(),
        );
        tasks.push(hostinfo_loop);

        // LocalAPI Unix-domain-socket server (optional, default OFF).
        let localapi_socket = if self.config.localapi {
            let path = self.config.localapi_path.clone().unwrap_or_else(|| {
                let dir = self
                    .config
                    .state_dir
                    .clone()
                    .unwrap_or_else(|| std::env::temp_dir().join("rustscale"));
                localapi::default_socket_path(&dir)
            });
            let state = localapi::LocalApiState {
                peers: b.peers.clone(),
                user_profiles: b.user_profiles.clone(),
                health: b.health.clone(),
                dns_config: b.dns_config.clone(),
                packet_drops: b.packet_drops.clone(),
                prefs: Arc::new(RwLock::new(self.load_prefs().unwrap_or_default())),
                tailscale_ips: b.tailscale_ips.clone(),
                our_fqdn: b.our_fqdn.clone(),
                hostname: self.config.hostname.clone(),
                magicsock: b.magicsock.clone(),
                tun_mode: false,
                home_derp: b.home_derp,
                ipn_backend: b.ipn_backend.clone(),
                derp_map: b.derp_map.clone(),
                command_tx: None,
                state_dir: self.config.state_dir.clone(),
                auth_url: Arc::new(std::sync::Mutex::new(None)),
                login_trigger: Arc::new(tokio::sync::Notify::new()),
                serve_config: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| serve::ServeConfig::load(d).ok())
                        .unwrap_or_default(),
                )),
                serve_runner: serve.clone(),
                profiles: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                        .unwrap_or_default(),
                )),
                current_profile: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                        .flatten(),
                )),
                cert_params: self
                    .config
                    .state_dir
                    .clone()
                    .map(|dir| localapi::CertParams {
                        state_dir: dir,
                        control_url: self.config.control_url.clone(),
                        machine_key: b.machine_key.clone(),
                        server_pub_key: b.server_pub_key.clone(),
                        node_key: b.node_key.clone(),
                        capability_version: CAPABILITY_VERSION,
                        protocol_version: PROTOCOL_VERSION,
                    }),
                taildrop: Some(taildrop.clone()),
                netstack: Some(netstack.clone()),
                filter: std::sync::OnceLock::new(),
            };
            // Publish the live filter so `PATCH /prefs` can toggle
            // shields-up mode without a full rebuild.
            let _ = state.filter.set(b.filter.clone());
            if let Some(h) = localapi::spawn_localapi(Arc::new(state), path.clone()) {
                tasks.push(h.task);
                if let Some(ref ps) = self.pre_started {
                    if let Some(ref handle) = ps.handle {
                        handle.task.abort();
                    }
                }
                eprintln!("tsnet: LocalAPI listening at {}", path.display());
                Some(h.socket_path)
            } else {
                eprintln!(
                    "tsnet: LocalAPI failed to bind socket at {}",
                    path.display()
                );
                None
            }
        } else {
            None
        };

        self.inner = Some(RunningState {
            tailscale_ips: b.tailscale_ips,
            magicsock: b.magicsock,
            data_plane: DataPlane::Netstack(netstack),
            peers: b.peers,
            route_table: b.route_table,
            cancel: b.cancel,
            tasks: Mutex::new(tasks),
            packet_drops: b.packet_drops,
            resolver: b.resolver,
            our_fqdn: b.our_fqdn,
            domain: b.domain.clone(),
            dns_config: b.dns_config,
            user_profiles: b.user_profiles,
            ssh_policy: b.ssh_policy,
            monitor,
            machine_key: b.machine_key,
            server_pub_key: b.server_pub_key,
            node_key: b.node_key,
            serve,
            health: b.health,
            health_watchdog: b.health_watchdog,
            c2n_router: b.c2n_router,
            c2n_addr: Some(c2n_addr),
            control_knobs: b.control_knobs,
            peerapi_port,
            overrides: b.overrides,
            localapi_socket,
            key_expired: b.key_expired,
            os_dns_configurator: None,
            ipn_backend: b.ipn_backend,
        });
        Ok(())
    }

    /// Bring the server online in **TUN mode**: route plaintext IP packets
    /// between a real OS TUN device and the WireGuard/magicsock data plane,
    /// instead of an in-process netstack.
    ///
    /// `listen`/`dial` are unavailable in TUN mode. Creating the TUN device
    /// requires root on both macOS (`utun`) and Linux (`/dev/net/tun`). If
    /// `config.apply_routes` is true, the interface is brought up and tailnet
    /// routes are added via `ifconfig`/`route` (macOS) or `ip` (Linux) — also
    /// requiring root.
    pub async fn up_tun(&mut self, config: TunModeConfig) -> Result<(), TsnetError> {
        if self.inner.is_some() {
            return Err(TsnetError::AlreadyUp);
        }

        ensure_ring_provider();

        let b = self.bootstrap().await?;

        // Resolve and apply the exit node selection from TunModeConfig, if
        // set. This sets the in-process RouteTable's exit node so the data
        // pump routes non-tailnet traffic to the exit peer. OS-level
        // default-route overrides are installed after the TUN is created.
        if let Some(ref exit) = config.exit_node {
            let peers = b.peers.read().await;
            let peer_key = resolve_exit_node(&peers, exit)?;
            drop(peers);
            b.route_table.write().await.set_exit_node(peer_key);
        }

        let monitor = spawn_link_monitor(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.udp_port,
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            b.health.clone(),
        );

        // Real TUN device.
        let tun: Arc<dyn Tun> = {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                let dev = rustscale_tun::create(&config.tun)?;
                if config.apply_routes {
                    apply_tun_routes(dev.name(), &b.tailscale_ips, config.tun.mtu)?;
                    // When accept_routes is enabled, install peer-advertised
                    // subnet routes as OS routes pointing at the TUN device.
                    if self.config.accept_routes {
                        let rt = b.route_table.read().await;
                        apply_accepted_subnet_routes(dev.name(), &rt)?;
                    }
                    // When an exit node is selected, install OS-level
                    // default-route overrides so all non-tailnet traffic
                    // enters the TUN. See TunModeConfig::exit_node docs for
                    // the known loop limitation.
                    if config.exit_node.is_some() {
                        apply_exit_node_routes(dev.name())?;
                    }
                }
                Arc::new(dev)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                return Err(TsnetError::Builder(
                    "TUN mode not supported on this platform".into(),
                ));
            }
        };

        // TUN data-plane pump: TUN <-> WG <-> magicsock.
        let pump = tokio::spawn(run_tun_pump(
            b.magicsock.clone(),
            b.wg_recv,
            tun.clone(),
            b.wg_tunnels.clone(),
            b.route_table.clone(),
            b.filter.clone(),
            b.packet_drops.clone(),
            b.cancel.clone(),
        ));

        // Periodic endpoint update (Bug 4).
        let periodic_ep = spawn_periodic_endpoint_updates(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            self.config.peer_relay_server,
        );

        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.tailscale_ips.clone(),
            self.config.accept_routes,
            b.advertise_routes.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.user_profiles.clone(),
            b.ssh_policy.clone(),
            b.cancel.clone(),
            b.health.clone(),
            b.health_watchdog.clone(),
            self.config.state_dir.clone(),
            b.node_key.public(),
            b.control_knobs.clone(),
            b.key_expired.clone(),
            b.ipn_backend.clone(),
        );

        let (c2n_task, c2n_addr) =
            c2n::spawn_c2n_server(b.c2n_backend.clone(), "rustscale".into()).await;

        // Taildrop file manager (shared between PeerAPI receive handler
        // and LocalAPI endpoints). Created from the state directory.
        let taildrop = Arc::new(taildrop::TaildropManager::new(
            self.config.state_dir.as_deref(),
            Some(b.ipn_backend.clone()),
        ));

        // PeerAPI server (TUN mode): binds TCP listeners on the node's
        // tailnet IPs (v4 + v6) on the deterministic port.
        let offering_exit_node = self.config.advertise_exit_node;
        let (peerapi_task, peerapi_port) = peerapi::spawn_peerapi_tun(
            b.peers.clone(),
            b.user_profiles.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.tailscale_ips.clone(),
            offering_exit_node,
            Some(taildrop.clone()),
        )
        .await;

        // Advertise peerapi4/peerapi6 services to the control plane.
        if let Some(port) = peerapi_port {
            let has_v6 = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
            let services =
                peerapi::peerapi_services(Some(port), if has_v6 { Some(port) } else { None });
            if !services.is_empty() {
                let cc_ep = ControlClient::new(
                    &b.control_url,
                    b.machine_key.clone(),
                    b.server_pub_key.clone(),
                    PROTOCOL_VERSION,
                );
                let node_pub = b.node_key.public();
                let disco_pub = b.disco_key.public();
                let svc_req = MapRequest {
                    Version: CAPABILITY_VERSION,
                    KeepAlive: false,
                    NodeKey: node_pub,
                    DiscoKey: disco_pub,
                    Stream: false,
                    OmitPeers: true,
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: b.hostname.clone(),
                        RoutableIPs: b.advertise_routes.clone(),
                        Services: services,
                        PeerRelay: self.config.peer_relay_server,
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                match cc_ep.send_map_request(&svc_req).await {
                    Ok(()) => eprintln!("tsnet: peerapi services advertised (port {port})"),
                    Err(e) => {
                        eprintln!("tsnet: peerapi service advertisement failed (non-fatal): {e}");
                    }
                }
            }
        }

        // Periodic Hostinfo refresh (every 10 min, dedup by content hash).
        // In TUN mode, serve/funnel is not available so pass None.
        let hostinfo_loop = spawn_hostinfo_update_loop(
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.home_derp,
            b.peers.clone(),
            b.route_table.clone(),
            None,
            b.overrides.clone(),
        );

        let mut tasks = vec![
            b.map_task,
            pump,
            map_update,
            periodic_ep,
            c2n_task,
            peerapi_task,
            hostinfo_loop,
        ];

        // LocalAPI Unix-domain-socket server (optional, default OFF).
        let localapi_socket = if self.config.localapi {
            let path = self.config.localapi_path.clone().unwrap_or_else(|| {
                let dir = self
                    .config
                    .state_dir
                    .clone()
                    .unwrap_or_else(|| std::env::temp_dir().join("rustscale"));
                localapi::default_socket_path(&dir)
            });
            let state = localapi::LocalApiState {
                peers: b.peers.clone(),
                user_profiles: b.user_profiles.clone(),
                health: b.health.clone(),
                dns_config: b.dns_config.clone(),
                packet_drops: b.packet_drops.clone(),
                prefs: Arc::new(RwLock::new(self.load_prefs().unwrap_or_default())),
                tailscale_ips: b.tailscale_ips.clone(),
                our_fqdn: b.our_fqdn.clone(),
                hostname: self.config.hostname.clone(),
                magicsock: b.magicsock.clone(),
                tun_mode: true,
                home_derp: b.home_derp,
                ipn_backend: b.ipn_backend.clone(),
                derp_map: b.derp_map.clone(),
                command_tx: None,
                state_dir: self.config.state_dir.clone(),
                auth_url: Arc::new(std::sync::Mutex::new(None)),
                login_trigger: Arc::new(tokio::sync::Notify::new()),
                serve_config: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| serve::ServeConfig::load(d).ok())
                        .unwrap_or_default(),
                )),
                serve_runner: None, // TUN mode has no serve runner
                profiles: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                        .unwrap_or_default(),
                )),
                current_profile: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                        .flatten(),
                )),
                cert_params: self
                    .config
                    .state_dir
                    .clone()
                    .map(|dir| localapi::CertParams {
                        state_dir: dir,
                        control_url: self.config.control_url.clone(),
                        machine_key: b.machine_key.clone(),
                        server_pub_key: b.server_pub_key.clone(),
                        node_key: b.node_key.clone(),
                        capability_version: CAPABILITY_VERSION,
                        protocol_version: PROTOCOL_VERSION,
                    }),
                taildrop: Some(taildrop.clone()),
                netstack: None, // TUN mode has no netstack
                filter: std::sync::OnceLock::new(),
            };
            // Publish the live filter so `PATCH /prefs` can toggle
            // shields-up mode without a full rebuild.
            let _ = state.filter.set(b.filter.clone());
            if let Some(h) = localapi::spawn_localapi(Arc::new(state), path.clone()) {
                tasks.push(h.task);
                if let Some(ref ps) = self.pre_started {
                    if let Some(ref handle) = ps.handle {
                        handle.task.abort();
                    }
                }
                eprintln!("tsnet: LocalAPI listening at {}", path.display());
                Some(h.socket_path)
            } else {
                eprintln!(
                    "tsnet: LocalAPI failed to bind socket at {}",
                    path.display()
                );
                None
            }
        } else {
            None
        };

        // OS DNS configuration (macOS: /etc/resolver entries pointing at
        // 100.100.100.100). Opt-in via `configure_os_dns(true)` — requires
        // root. Best-effort: permission errors are logged and do not prevent
        // up_tun from completing.
        let os_dns_configurator = if self.config.configure_os_dns {
            let dns_cfg_snapshot = b.dns_config.read().await.clone();
            let os_cfg = if let Some(ref dc) = dns_cfg_snapshot {
                build_os_dns_config(dc, &b.domain)
            } else {
                OsConfig {
                    nameservers: vec![IpAddr::V4(MAGICDNS_VIP)],
                    ..Default::default()
                }
            };
            let mut configurator: Box<dyn OsConfigurator + Send> = Box::new(new_os_configurator());
            match configurator.set_dns(&os_cfg) {
                Ok(()) => {
                    eprintln!(
                        "tsnet: OS DNS configured ({} match domains, {} search domains)",
                        os_cfg.match_domains.len(),
                        os_cfg.search_domains.len()
                    );
                    Some(configurator)
                }
                Err(e) => {
                    eprintln!("tsnet: OS DNS configuration failed (non-fatal, needs root?): {e}");
                    None
                }
            }
        } else {
            None
        };

        self.inner = Some(RunningState {
            tailscale_ips: b.tailscale_ips,
            magicsock: b.magicsock,
            data_plane: DataPlane::Tun,
            peers: b.peers,
            route_table: b.route_table,
            cancel: b.cancel,
            tasks: Mutex::new(tasks),
            packet_drops: b.packet_drops,
            resolver: b.resolver,
            our_fqdn: b.our_fqdn,
            domain: b.domain.clone(),
            dns_config: b.dns_config,
            user_profiles: b.user_profiles,
            ssh_policy: b.ssh_policy,
            monitor,
            machine_key: b.machine_key,
            server_pub_key: b.server_pub_key,
            node_key: b.node_key,
            serve: None,
            health: b.health,
            health_watchdog: b.health_watchdog,
            c2n_router: b.c2n_router,
            c2n_addr: Some(c2n_addr),
            control_knobs: b.control_knobs,
            peerapi_port,
            overrides: b.overrides,
            localapi_socket,
            key_expired: b.key_expired,
            os_dns_configurator,
            ipn_backend: b.ipn_backend,
        });
        Ok(())
    }

    // --- shared control-plane bootstrap ---

    /// Load prefs from the state directory, or return default if not found.
    fn load_prefs(&self) -> Result<rustscale_ipn::Prefs, TsnetError> {
        if let Some(ref dir) = self.config.state_dir {
            rustscale_ipn::Prefs::load(dir).map_err(|e| TsnetError::Builder(e.to_string()))
        } else {
            Ok(rustscale_ipn::Prefs::default())
        }
    }

    /// Set the auth key after construction (used by the daemon when the CLI
    /// provides it via `POST /start`).
    pub fn set_auth_key(&mut self, key: impl Into<String>) {
        self.config.auth_key = Some(key.into());
    }

    /// Start only the LocalAPI server without full bootstrap. Used by the
    /// daemon when no auth key is available — the server enters NeedsLogin
    /// state and waits for CLI-driven `up()` via `POST /start` or
    /// `POST /login-interactive`.
    ///
    /// Returns a command receiver for the daemon to listen on, and the
    /// login trigger Notify (used by `/login-interactive` to unblock
    /// bootstrap's auth wait).
    pub async fn start_localapi_only(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<localapi::DaemonCommand>, TsnetError> {
        let ipn_backend = Arc::new(IpnBackend::new("rustscale"));
        ipn_backend.set_want_running();
        ipn_backend.set_auth_cant_continue(true);

        let state = self.load_or_create_state()?;
        let was_fresh = state.is_zero();
        let state = if was_fresh {
            let s = PersistedState::generate();
            self.save_state(&s)?;
            s
        } else {
            state
        };
        ipn_backend.set_has_node_key(!state.is_zero());

        let prefs = self.load_prefs().unwrap_or_default();
        let prefs = Arc::new(RwLock::new(prefs));

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let login_trigger = Arc::new(tokio::sync::Notify::new());
        let auth_url = Arc::new(std::sync::Mutex::new(None));

        let (magicsock, _wg_rx) = Magicsock::new(MagicsockConfig {
            private_key: state.node_key.clone(),
            disco_key: state.disco_key.clone(),
            derp_client: None,
            derp_map: Some(DERPMap::default()),
            home_derp_region: 0,
            udp_bind: None,
            udp_socket: None,
            portmapper: None,
            health: None,
            disable_direct_paths: false,
            peer_relay_server: false,
            relay_server_config: None,
        })
        .await
        .map_err(TsnetError::Magicsock)?;
        let magicsock = Arc::new(magicsock);

        let socket_path = if let Some(ref p) = self.config.localapi_path {
            p.clone()
        } else if let Some(ref dir) = self.config.state_dir {
            localapi::default_socket_path(dir)
        } else {
            localapi::default_socket_path(&std::env::temp_dir().join("rustscale"))
        };

        let api_state = Arc::new(localapi::LocalApiState {
            peers: Arc::new(RwLock::new(vec![])),
            user_profiles: Arc::new(RwLock::new(BTreeMap::new())),
            health: Tracker::new(),
            dns_config: Arc::new(RwLock::new(None)),
            packet_drops: Arc::new(AtomicU64::new(0)),
            prefs: prefs.clone(),
            tailscale_ips: vec![],
            our_fqdn: String::new(),
            hostname: self.config.hostname.clone(),
            magicsock: magicsock.clone(),
            tun_mode: false,
            home_derp: 0,
            ipn_backend: ipn_backend.clone(),
            derp_map: DERPMap::default(),
            command_tx: Some(command_tx),
            state_dir: self.config.state_dir.clone(),
            auth_url: auth_url.clone(),
            login_trigger: login_trigger.clone(),
            serve_config: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| serve::ServeConfig::load(d).ok())
                    .unwrap_or_default(),
            )),
            serve_runner: None,
            profiles: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                    .unwrap_or_default(),
            )),
            current_profile: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                    .flatten(),
            )),
            cert_params: None,
            taildrop: None,
            netstack: None,
            filter: std::sync::OnceLock::new(),
        });

        let handle = localapi::spawn_localapi(api_state.clone(), socket_path.clone());
        if handle.is_some() {
            eprintln!(
                "tsnet: LocalAPI (needs-login) listening at {}",
                socket_path.display()
            );
        } else {
            eprintln!("tsnet: LocalAPI failed to bind {}", socket_path.display());
        }

        self.pre_started = Some(PreStartedLocalApi {
            backend: ipn_backend,
            handle,
            login_trigger,
            auth_url,
            command_rx: Some(command_rx),
            socket_path,
        });

        Ok(self
            .pre_started
            .as_mut()
            .unwrap()
            .command_rx
            .take()
            .unwrap())
    }

    /// Shared bootstrapping for `up()` and `up_tun()`: load state, register
    /// with control, start the map long-poll, wait for the first `MapResponse`,
    /// netcheck for a home DERP, connect it, build magicsock + per-peer WG
    /// tunnels + the routing table. Returns the shared handles plus the
    /// still-open map receiver for the update task.
    async fn bootstrap(&mut self) -> Result<Bootstrap, TsnetError> {
        // Effective advertised routes: user-specified subnet routes plus the
        // exit-node default routes (0.0.0.0/0, ::/0) when advertise_exit_node
        // is enabled. Used for Hostinfo.RoutableIPs, the filter's localNets,
        // and link-change endpoint updates.
        let advertise = self.config.effective_advertise_routes();

        // Health tracker + map-poll staleness watchdog (fires if no
        // MapResponse for more than 3 minutes).
        let health = Tracker::new();
        let health_watchdog = Watchdog::new(
            health.clone(),
            WARN_CONTROL,
            "Control connection",
            Severity::High,
            "control connection lost: no map activity for over 3 minutes",
            std::time::Duration::from_mins(3),
        );

        // IPN state machine backend. Created early so state transitions
        // are tracked from the start. Want_running is set immediately;
        // other inputs are set as bootstrap progresses.
        let ipn_backend = if let Some(ref ps) = self.pre_started {
            ps.backend.clone()
        } else {
            Arc::new(IpnBackend::new("rustscale"))
        };
        ipn_backend.set_want_running();

        // 1. Load or generate persistent state.
        let mut state = self.load_or_create_state()?;
        let was_fresh = state.is_zero();
        if was_fresh {
            state = PersistedState::generate();
            self.save_state(&state)?;
        }

        let node_pub = state.node_key.public();
        let disco_pub = state.disco_key.public();

        // We have a node key (generated or loaded from state).
        ipn_backend.set_has_node_key(!state.is_zero());

        // Try to load a cached netmap from the state directory. On a restart
        // with an existing state dir, this lets us skip the blocking first
        // MapResponse fetch (2-5s) and use the cached peers immediately —
        // the streaming long-poll delivers fresh updates in the background.
        let cached_netmap = self
            .config
            .state_dir
            .as_ref()
            .and_then(|dir| PersistedState::load_netmap(dir, &node_pub));

        // 2. Fetch the server's Noise public key (GET /key?v=<version>).
        let server_pub_key =
            controlhttp::fetch_server_pub_key(&self.config.control_url, PROTOCOL_VERSION)
                .await
                .map_err(|e| {
                    TsnetError::Register(rustscale_controlclient::RegisterError::Dial(e))
                })?;

        // 3. Register with the control plane.
        let auth_key = self.config.auth_key.clone().unwrap_or_default();

        let cc = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );

        let reg_req = RegisterRequest {
            Version: CAPABILITY_VERSION,
            NodeKey: node_pub.clone(),
            Auth: if auth_key.is_empty() {
                None
            } else {
                Some(rustscale_tailcfg::RegisterResponseAuth {
                    AuthKey: auth_key.clone(),
                })
            },
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            Ephemeral: self.config.ephemeral,
            ..Default::default()
        };

        let reg_resp = cc.register(&reg_req).await.map_err(|e| {
            // Auth/network failure: the cached netmap may be stale or the
            // node key may have been revoked. Clear it so a restart doesn't
            // boot from a stale cache. Mirrors Go's discardDiskCacheLocked
            // call on register failures (ipn/ipnlocal/local.go:7415).
            if let Some(ref dir) = self.config.state_dir {
                PersistedState::clear_netmap(dir);
                eprintln!("tsnet: cleared netmap cache after register error: {e}");
            }
            ipn_backend.emit_err_message(e.to_string());
            TsnetError::Register(e)
        })?;

        // Server-side error string (e.g. "invalid auth key", "node key revoked").
        if !reg_resp.Error.is_empty() {
            if let Some(ref dir) = self.config.state_dir {
                PersistedState::clear_netmap(dir);
                eprintln!(
                    "tsnet: cleared netmap cache after register error: {}",
                    reg_resp.Error
                );
            }
            ipn_backend.emit_err_message(&reg_resp.Error);
            return Err(TsnetError::Builder(format!(
                "control register rejected: {}",
                reg_resp.Error
            )));
        }

        // Node key expired — the server says our key is no longer valid.
        // Clear the cache so we don't reuse a netmap bound to the old key.
        if reg_resp.NodeKeyExpired {
            if let Some(ref dir) = self.config.state_dir {
                PersistedState::clear_netmap(dir);
                eprintln!("tsnet: cleared netmap cache: node key expired");
            }
            ipn_backend.set_key_expired(true);
        }

        if reg_resp.AuthURL.is_empty() {
            ipn_backend.set_machine_authorized(reg_resp.MachineAuthorized);
            ipn_backend.emit_login_finished();
            state.node_id = reg_resp.User.ID;
            self.save_state(&state)?;
        } else {
            ipn_backend.set_auth_cant_continue(true);
            ipn_backend.emit_browse_to_url(&reg_resp.AuthURL);

            if let Some(ref ps) = self.pre_started {
                {
                    let mut au = ps.auth_url.lock().unwrap();
                    *au = Some(reg_resp.AuthURL.clone());
                }
                ps.login_trigger.notified().await;
                {
                    let mut au = ps.auth_url.lock().unwrap();
                    *au = None;
                }
                ipn_backend.set_auth_cant_continue(false);

                let followup_req = RegisterRequest {
                    Version: CAPABILITY_VERSION,
                    NodeKey: node_pub.clone(),
                    Followup: reg_resp.AuthURL.clone(),
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: self.config.hostname.clone(),
                        RoutableIPs: advertise.clone(),
                        PeerRelay: self.config.peer_relay_server,
                        ..Default::default()
                    }),
                    Ephemeral: self.config.ephemeral,
                    ..Default::default()
                };
                let followup_resp = cc.register(&followup_req).await.map_err(|e| {
                    if let Some(ref dir) = self.config.state_dir {
                        PersistedState::clear_netmap(dir);
                    }
                    ipn_backend.emit_err_message(e.to_string());
                    TsnetError::Register(e)
                })?;

                if followup_resp.Error.is_empty() {
                    ipn_backend.set_machine_authorized(followup_resp.MachineAuthorized);
                    ipn_backend.emit_login_finished();
                    state.node_id = followup_resp.User.ID;
                    self.save_state(&state)?;
                } else {
                    ipn_backend.emit_err_message(&followup_resp.Error);
                    return Err(TsnetError::Builder(format!(
                        "control register (followup) rejected: {}",
                        followup_resp.Error
                    )));
                }
            } else {
                return Err(TsnetError::AuthRequired(reg_resp.AuthURL));
            }
        }

        // 3b. Bind the UDP socket early so we can gather local interface
        // endpoints (interface IP + bound port) and advertise them in the
        // MapRequest. Magicsock takes ownership of this socket later, once
        // the DERPMap/home-DERP are known from the first MapResponse.
        // Without advertised endpoints, peers only learn our addresses via
        // CallMeMaybe (one-shot, racy) and two nodes on the same machine
        // never establish a direct UDP path — they stay on DERP.
        let udp_socket = Arc::new(
            tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0u16)))
                .await
                .map_err(TsnetError::Io)?,
        );
        let udp_port = udp_socket.local_addr().map_err(TsnetError::Io)?.port();
        let local_endpoints = rustscale_magicsock::gather_local_endpoints(udp_port);
        eprintln!("tsnet: local UDP endpoints: {local_endpoints:?}");

        // Create a port-mapping client (NAT-PMP/PCP/UPnP) so magicsock can
        // publish a port-mapped external endpoint alongside local/STUN
        // endpoints. Best-effort: if the gateway doesn't support any
        // port-mapping protocol, this silently produces no endpoint.
        let portmapper = rustscale_portmapper::Client::new();
        portmapper.set_local_port(udp_port);

        // 3c. Send a lightweight non-streaming MapRequest to push our
        // DiscoKey + Endpoints to the control server BEFORE starting the
        // streaming long-poll. The control server processes the MapRequest
        // body asynchronously and the first streaming MapResponse is
        // generated from registration data (which lacks DiscoKey/Endpoints).
        // Without this pre-update, peers see DiscoKey=zero and Endpoints=[]
        // and can never initiate disco probing for a direct path.
        let endpoint_update_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: false,
            OmitPeers: true,
            Endpoints: local_endpoints.clone(),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        let cc_ep = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        match cc_ep.send_map_request(&endpoint_update_req).await {
            Ok(()) => eprintln!("tsnet: endpoint update sent (DiscoKey + {local_endpoints:?})"),
            Err(e) => eprintln!("tsnet: endpoint update failed (non-fatal): {e}"),
        }

        // 4. Fetch the first MapResponse. If we have a cached netmap, skip
        // the blocking fetch and use the cached data — the streaming
        // long-poll (started below) will deliver fresh updates in the
        // background. This eliminates the 2-5s startup delay on restarts.
        let map_resp: MapResponse = if let Some(ref cached) = cached_netmap {
            let peer_count = cached.Peers.len();
            eprintln!(
                "tsnet: using cached netmap ({peer_count} peers); streaming poll will refresh in background"
            );
            cached.clone()
        } else {
            let fetch_req = MapRequest {
                Version: CAPABILITY_VERSION,
                KeepAlive: false,
                NodeKey: node_pub.clone(),
                DiscoKey: disco_pub.clone(),
                Stream: false,
                Endpoints: local_endpoints.clone(),
                Hostinfo: Some(Hostinfo {
                    OS: std::env::consts::OS.to_string(),
                    Hostname: self.config.hostname.clone(),
                    RoutableIPs: advertise.clone(),
                    PeerRelay: self.config.peer_relay_server,
                    ..Default::default()
                }),
                ..Default::default()
            };
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                cc_ep.fetch_map(&fetch_req),
            )
            .await
            .map_err(|_| TsnetError::MapTimeout)??
        };

        let tailscale_ips = extract_tailscale_ips(&map_resp);
        if tailscale_ips.is_empty() {
            return Err(TsnetError::Builder("no tailscale IPs assigned".into()));
        }
        let our_v4 = first_v4(&tailscale_ips)?;

        // We have a netmap — update the IPN state machine. Set netmap_present
        // and engine status (peer count + DERP home as a proxy for live
        // connections). This may transition the state from Starting to Running.
        let peer_count = map_resp.Peers.iter().filter(|p| !p.Key.is_zero()).count() as i32;
        let has_derp_home = map_resp.Node.as_ref().is_some_and(|n| n.HomeDERP > 0);
        ipn_backend.set_netmap_present(true);
        ipn_backend.set_engine_status(peer_count, i32::from(has_derp_home));

        // 6. Pick home DERP. Prefer the control-assigned HomeDERP from our
        // own node in the MapResponse — this ensures both nodes in the same
        // tailnet use the same DERP region. Fall back to netcheck, then to
        // the first available region.
        let derp_map = map_resp.DERPMap.clone().unwrap_or_default();
        let home_derp = if derp_map.Regions.is_empty() {
            0
        } else {
            // Try control-assigned HomeDERP first.
            let assigned = map_resp
                .Node
                .as_ref()
                .map(|n| n.HomeDERP)
                .filter(|&d| d > 0);
            if let Some(d) = assigned {
                eprintln!("tsnet: using control-assigned home DERP region {d}");
                d
            } else {
                // Fall back to netcheck.
                match rustscale_netcheck::Prober
                    .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                    .await
                {
                    Ok(r) if r.preferred_derp > 0 => r.preferred_derp,
                    _ => derp_map
                        .Regions
                        .values()
                        .find(|r| !r.Avoid)
                        .or_else(|| derp_map.Regions.values().next())
                        .map_or(0, |r| r.RegionID),
                }
            }
        };

        // 7. Connect home DERP.
        eprintln!("tsnet: home DERP region = {home_derp}");
        let derp_client = match connect_home_derp(&derp_map, home_derp, &state.node_key).await {
            Ok(mut c) => {
                // Tell the DERP server this is our preferred (home) node.
                // Go's derphttp.Client sets preferred=true after connecting
                // to the home DERP and calls NotePreferred(true). This lets
                // the DERP server track home-client metrics and is part of
                // the expected handshake.
                if let Err(e) = c.note_preferred(true).await {
                    eprintln!("tsnet: DERP note_preferred failed (non-fatal): {e}");
                }
                eprintln!("tsnet: DERP connected to region {home_derp}");
                health.set_healthy(WARN_DERP_HOME);
                Some(c)
            }
            Err(e) => {
                eprintln!("tsnet: DERP connection to region {home_derp} failed: {e}");
                health.set_unhealthy(
                    WARN_DERP_HOME,
                    format!("derp home region {home_derp} unreachable: {e}"),
                );
                None
            }
        };

        let netinfo = NetInfo {
            PreferredDERP: home_derp,
            WorkingUDP: OptBool::True,
            ..Default::default()
        };
        let netinfo_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: false,
            OmitPeers: true,
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                NetInfo: Some(netinfo.clone()),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        match cc_ep.send_map_request(&netinfo_req).await {
            Ok(()) => eprintln!("tsnet: NetInfo (PreferredDERP={home_derp}) sent to control"),
            Err(e) => eprintln!("tsnet: NetInfo update failed (non-fatal): {e}"),
        }

        // 7b. Run a STUN probe now that DERPMap is known, to discover our
        // external (NAT-mapped) IP:port and include it in the endpoint list.
        // This is critical for peers on different networks — without STUN
        // endpoints they can never establish a direct UDP connection.
        let stun_ep: Option<String> = if derp_map.Regions.is_empty() {
            None
        } else {
            // Run STUN probe to discover external IP:port
            match rustscale_netcheck::Prober
                .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                .await
            {
                Ok(report) => {
                    if let Some(g) = report.global_v4 {
                        eprintln!("tsnet: STUN endpoint: {g}");
                        Some(g.to_string())
                    } else {
                        eprintln!("tsnet: STUN probe returned no global_v4");
                        None
                    }
                }
                Err(e) => {
                    eprintln!("tsnet: STUN probe failed (non-fatal): {e}");
                    None
                }
            }
        };

        // Build the enhanced endpoint list: filtered local endpoints + STUN.
        let mut all_endpoints = local_endpoints.clone();
        if let Some(ref stun) = stun_ep {
            all_endpoints.push(stun.clone());
        }
        // Re-send endpoint update with STUN results included.
        let stun_ep_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: false,
            OmitPeers: true,
            Endpoints: all_endpoints,
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                NetInfo: Some(netinfo.clone()),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        match cc_ep.send_map_request(&stun_ep_req).await {
            Ok(()) => eprintln!("tsnet: STUN endpoint update sent ({stun_ep:?})"),
            Err(e) => eprintln!("tsnet: STUN endpoint update failed (non-fatal): {e}"),
        }

        // Start the streaming map long-poll with NetInfo included. This is
        // done after the home DERP is known and connected so the streaming
        // MapRequest carries NetInfo.PreferredDERP from the start.
        // stream_map_loop reconnects automatically when the stream ends.
        let map_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: true,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: true,
            Endpoints: local_endpoints.clone(),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                NetInfo: Some(netinfo.clone()),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };

        let (map_tx, map_rx) = mpsc::channel(32);
        let cc2 = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        let map_task = tokio::spawn(async move {
            cc2.stream_map_loop(&map_req, map_tx).await;
        });

        // 8. Create magicsock, reusing the UDP socket bound in step 3b so
        // the local endpoints advertised in the MapRequest match the socket
        // magicsock actually owns and reads from.
        let (magicsock_inner, wg_recv) = Magicsock::new(MagicsockConfig {
            private_key: state.node_key.clone(),
            disco_key: state.disco_key.clone(),
            derp_client,
            derp_map: Some(derp_map.clone()),
            home_derp_region: home_derp,
            udp_bind: None,
            udp_socket: Some(udp_socket),
            portmapper: Some(portmapper),
            health: Some(health.clone()),
            disable_direct_paths: self.config.disable_direct_paths,
            peer_relay_server: self.config.peer_relay_server,
            relay_server_config: self.config.relay_server_config.clone(),
        })
        .await?;
        let magicsock = Arc::new(magicsock_inner);

        // Start a background port-mapping probe + creation (best-effort, 2s
        // timeout). The cached mapping will be picked up by subsequent
        // `all_endpoints()` calls and published to the control plane.
        magicsock.start_portmap();

        // The server may send peers via Peers (full list) or PeersChanged
        // (delta). The first response often uses PeersChanged.
        let mut peers = map_resp.Peers.clone();
        if peers.is_empty() && !map_resp.PeersChanged.is_empty() {
            peers = map_resp.PeersChanged.clone();
        }
        // Update the self node's CapMap from the first MapResponse so the
        // relay server extension can check NODE_ATTR_DISABLE_RELAY_SERVER.
        if let Some(ref node) = map_resp.Node {
            magicsock.set_self_cap_map(node.CapMap.clone());
        }
        magicsock.set_netmap(peers.clone()).await?;

        // 9. Per-peer WG tunnels + routing table.
        let wg_tunnels = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut tunnels = wg_tunnels.write().await;
            for peer in &peers {
                if peer.Key.is_zero() {
                    continue;
                }
                let tunn = WgTunn::new(&state.node_key, &peer.Key, rand_index())?;
                tunnels.insert(peer.Key.clone(), Arc::new(Mutex::new(tunn)));
            }
        }

        let peers_arc = Arc::new(RwLock::new(peers.clone()));
        let route_table = Arc::new(RwLock::new(RouteTable::from_peers_with_opts(
            &peers,
            self.config.accept_routes,
        )));
        let cancel = Arc::new(CancelToken::new());

        // Build the initial packet filter from the first MapResponse. Add our
        // advertised subnet routes to the filter's localNets so packets
        // destined to those subnets are admitted (needed by subnet routers).
        // The peer list supplies the capability map for `cap:<name>` source
        // predicates, and the ShieldsUp pref enables shields-up mode.
        let shields_up = self.load_prefs().unwrap_or_default().ShieldsUp;
        let (mut filter, _named_filters) =
            build_filter_from_map_response(&map_resp, &tailscale_ips, &peers, shields_up);
        if !advertise.is_empty() {
            filter.add_local_cidrs(&advertise);
        }
        let filter = Arc::new(std::sync::Mutex::new(filter));
        let packet_drops = Arc::new(AtomicU64::new(0));

        // MagicDNS: build the shared resolver from the first map response.
        // `Domain` is the tailnet domain (e.g. "tailnet.ts.net"); `DNSConfig`
        // carries `Proxied` and `CertDomains`; peer `Name`s are FQDNs.
        let domain = map_resp.Domain.clone();
        let our_fqdn = map_resp
            .Node
            .as_ref()
            .map(|n| n.Name.clone())
            .unwrap_or_default();
        let dns_config = Arc::new(RwLock::new(map_resp.DNSConfig.clone()));
        let user_profiles = Arc::new(RwLock::new(
            map_resp
                .UserProfiles
                .iter()
                .map(|p| (p.ID, p.clone()))
                .collect(),
        ));
        // SSH policy from the first MapResponse. `None` means the control
        // server hasn't sent a policy yet (SSH server rejects all connections
        // until one arrives). Updated on each subsequent map response.
        let ssh_policy = Arc::new(RwLock::new(map_resp.SSHPolicy.clone()));
        let resolver = Arc::new(RwLock::new(MagicDnsResolver::new(
            peers.clone(),
            &domain,
            map_resp.DNSConfig.as_ref(),
        )));

        let c2n_prefs = serde_json::json!({
            "hostname": self.config.hostname,
            "control_url": self.config.control_url,
            "ephemeral": self.config.ephemeral,
            "advertise_routes": self.config.advertise_routes,
            "accept_routes": self.config.accept_routes,
            "advertise_exit_node": self.config.advertise_exit_node,
        });
        let c2n_log_level = rustscale_c2n::LogLevelState::new();
        let c2n_backend = Arc::new(c2n::TsnetC2nBackend::new(
            c2n::C2nBackendData {
                peers: peers_arc.clone(),
                user_profiles: user_profiles.clone(),
                health: health.clone(),
                dns_config: dns_config.clone(),
                packet_drops: packet_drops.clone(),
                prefs: c2n_prefs,
                tailscale_ips: tailscale_ips.clone(),
                our_fqdn: our_fqdn.clone(),
                magicsock: magicsock.clone(),
            },
            c2n_log_level,
        ));
        let c2n_router = {
            let mut r = C2nRouter::new();
            c2n::register_c2n_handlers(&mut r, c2n_backend.clone());
            Arc::new(r)
        };

        // Control knobs: shared feature-flag store updated from each netmap.
        let control_knobs = Arc::new(ControlKnobs::new());
        let initial_knobs = extract_knobs_from_map_response(&map_resp);
        if !initial_knobs.is_empty() {
            control_knobs.apply(initial_knobs);
        }

        Ok(Bootstrap {
            tailscale_ips: tailscale_ips.clone(),
            our_v4,
            magicsock,
            wg_recv,
            wg_tunnels,
            peers: peers_arc,
            route_table,
            cancel,
            map_rx,
            map_task,
            node_key: state.node_key.clone(),
            filter,
            packet_drops,
            resolver,
            our_fqdn,
            domain,
            dns_config,
            user_profiles,
            ssh_policy,
            machine_key: state.machine_key.clone(),
            server_pub_key,
            disco_key: state.disco_key.clone(),
            control_url: self.config.control_url.clone(),
            hostname: self.config.hostname.clone(),
            advertise_routes: advertise,
            udp_port,
            derp_map,
            home_derp,
            health,
            health_watchdog,
            c2n_router,
            c2n_backend,
            control_knobs,
            overrides: self.config.overrides.clone(),
            key_expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ipn_backend,
        })
    }

    /// Get the current server status.
    pub fn status(&self) -> ServerStatus {
        let Some(ref inner) = self.inner else {
            return ServerStatus {
                up: false,
                tailscale_ips: vec![],
                peer_count: 0,
                peers: vec![],
                hostname: self.config.hostname.clone(),
                packet_drops: 0,
                health: vec![],
                key_expired: false,
            };
        };
        let peers: Vec<PeerInfo> = inner
            .peers
            .try_read()
            .map(|p| {
                p.iter()
                    .filter(|n| !n.Key.is_zero())
                    .map(|n| PeerInfo {
                        node_key: n.Key.clone(),
                        name: n.Name.clone(),
                        ips: extract_node_ips(n),
                        path_class: inner.magicsock.peer_path_class(&n.Key),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let packet_drops = inner
            .packet_drops
            .load(std::sync::atomic::Ordering::Relaxed);
        ServerStatus {
            up: true,
            tailscale_ips: inner.tailscale_ips.clone(),
            peer_count: peers.len(),
            peers,
            hostname: self.config.hostname.clone(),
            packet_drops,
            health: inner.health.current_warnings(),
            key_expired: inner.key_expired.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Listen for incoming TCP connections on `port` (netstack mode only).
    ///
    /// Returns an error in TUN mode — there is no in-process netstack to
    /// accept connections.
    pub async fn listen(&self, port: u16) -> Result<rustscale_netstack::Listener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        match &inner.data_plane {
            DataPlane::Netstack(ns) => Ok(ns.listen(port).await?),
            DataPlane::Tun => Err(TsnetError::NotAvailableInTunMode),
        }
    }

    /// Listen for incoming TLS connections on `port` (netstack mode only).
    ///
    /// Attempts to use a Let's Encrypt certificate provisioned via the
    /// control plane ([`Server::control_cert_provider`]); on any error
    /// (HTTPS not enabled for the tailnet, ACME client unavailable, cache
    /// miss) it falls back to a self-signed per-node certificate with a
    /// warning. Call [`Server::control_cert_provider`] directly to observe
    /// the typed [`CertError`] when you need to distinguish the cases.
    ///
    /// Returns an error in TUN mode.
    pub async fn listen_tls(&self, port: u16) -> Result<TlsListener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let provider = match self.control_cert_provider().await {
            Ok(p) => {
                inner.health.set_healthy(WARN_CERT_FALLBACK);
                p
            }
            Err(e) => {
                eprintln!("tsnet: control cert unavailable ({e}); using self-signed");
                inner.health.set_unhealthy(
                    WARN_CERT_FALLBACK,
                    format!("serving self-signed fallback: {e}"),
                );
                tls::default_cert_provider(&inner.tailscale_ips)
            }
        };
        self.listen_tls_with_provider(port, provider).await
    }

    /// Build a Let's Encrypt-via-control [`CertProvider`] for this node's
    /// FQDN, fetching/caching the cert material. Returns a typed
    /// [`CertError`] when HTTPS certs are not enabled for the tailnet
    /// ([`CertError::NotEnabled`]) or the ACME order flow fails
    /// ([`CertError::Acme`]); callers can fall back to a self-signed cert
    /// in those cases.
    ///
    /// Requires the server to be up. The cert+key are cached in
    /// `state_dir` (`<fqdn>.crt.pem` / `<fqdn>.key.pem`) and refreshed when
    /// within 14 days of expiry. The ACME account key is persisted in
    /// `state_dir/acme-account.key.pem`.
    pub async fn control_cert_provider(&self) -> Result<Arc<dyn CertProvider>, CertError> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| CertError::CacheInvalid(String::new(), "server not up".into()))?;
        let cert_domains = inner
            .dns_config
            .read()
            .await
            .as_ref()
            .map(|c| c.CertDomains.clone())
            .unwrap_or_default();
        let state_dir = self.config.state_dir.clone().unwrap_or_else(|| {
            let mut p = std::env::temp_dir();
            p.push("rustscale-certs");
            p
        });
        let _ = std::fs::create_dir_all(&state_dir);
        let fetcher = Arc::new(AcmeCertFetcher::new(
            cert_domains,
            state_dir.clone(),
            self.config.control_url.clone(),
            inner.machine_key.clone(),
            inner.server_pub_key.clone(),
            inner.node_key.clone(),
            CAPABILITY_VERSION,
            PROTOCOL_VERSION,
        ));
        let prov = Arc::new(
            ControlCertProvider::new(state_dir, &inner.our_fqdn, fetcher)
                .with_health(inner.health.clone()),
        );
        prov.refresh().await?;
        Ok(prov)
    }

    /// Listen for incoming TLS connections on `port` using a caller-supplied
    /// [`CertProvider`] (netstack mode only).
    ///
    /// This is the lower-level entry point behind [`Server::listen_tls`]; use
    /// it when you need a custom certificate source (e.g. pre-provisioned
    /// certs). Returns an error in TUN mode.
    pub async fn listen_tls_with_provider(
        &self,
        port: u16,
        provider: Arc<dyn CertProvider>,
    ) -> Result<TlsListener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        match &inner.data_plane {
            DataPlane::Netstack(ns) => {
                let listener = ns.listen(port).await?;
                TlsListener::new(listener, provider).map_err(TsnetError::Tls)
            }
            DataPlane::Tun => Err(TsnetError::NotAvailableInTunMode),
        }
    }

    /// Dial a remote `ip:port` or `hostname:port` (netstack mode only).
    ///
    /// Resolves tailnet hostnames via MagicDNS (short name, FQDN) and
    /// non-tailnet hostnames via the system resolver (requires an exit
    /// node for the traffic to reach the internet). Returns an error in
    /// TUN mode.
    pub async fn dial(&self, addr: &str) -> Result<NetstackStream, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let socket_addr = resolve_addr(addr, inner).await?;
        match &inner.data_plane {
            DataPlane::Netstack(ns) => Ok(ns.dial(socket_addr).await?),
            DataPlane::Tun => Err(TsnetError::NotAvailableInTunMode),
        }
    }

    /// Start a local SOCKS5 proxy (RFC 1928) bound to `bind_addr` on the **OS**
    /// TCP stack (e.g. `"127.0.0.1:1080"`, `":1080"`, or `"1080"`). Each
    /// CONNECT request is dialed *through the tailnet* via [`Server::dial`]
    /// (resolving MagicDNS names and honoring the selected exit node).
    ///
    /// Only the no-auth method and the CONNECT command are supported; BIND and
    /// UDP-ASSOCIATE are rejected with command-not-supported. Address types
    /// IPv4, IPv6, and domain-name are accepted.
    ///
    /// The returned [`Socks5Handle`] exposes the bound address (useful for
    /// `:0`) and a graceful `stop`; the background task is also registered in
    /// the server's task set so [`Server::close`] aborts it. Requires netstack
    /// mode (returns [`TsnetError::NotAvailableInTunMode`] in TUN mode).
    ///
    /// C-representable: string in, handle + bound-port out (see FFI
    /// `ts_listen_socks5`).
    pub async fn listen_socks5(&self, bind_addr: &str) -> Result<Socks5Handle, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let netstack = match &inner.data_plane {
            DataPlane::Netstack(ns) => ns.clone(),
            DataPlane::Tun => return Err(TsnetError::NotAvailableInTunMode),
        };
        let dialer = ServerSocksDialer::new(netstack, inner.resolver.clone(), inner.peers.clone());
        let mut handle = socks5::spawn_socks5(bind_addr, dialer)
            .await
            .map_err(TsnetError::Io)?;
        // Register the task in the server's set so close() aborts it.
        if let Some(task) = handle.take_task() {
            inner.tasks.lock().await.push(task);
        }
        Ok(handle)
    }

    /// Look up which peer owns the route for a destination IP (longest-prefix
    /// match). Returns `None` if no route matches or the server is not up.
    ///
    /// This is the in-process routing table's view — it reflects the latest
    /// netmap peers and the `accept_routes` setting. Useful for testing
    /// subnet-route installation and for the FFI layer.
    pub fn route_lookup(&self, ip: IpAddr) -> Option<NodePublic> {
        let inner = self.inner.as_ref()?;
        let rt = inner.route_table.try_read().ok()?;
        rt.lookup(ip)
    }

    /// Snapshot of the current route table entries as `(cidr_string, peer_key)`
    /// pairs, sorted by longest prefix first. Useful for diagnostics and
    /// testing subnet-route installation.
    pub fn routes(&self) -> Vec<(String, NodePublic)> {
        let Some(inner) = self.inner.as_ref() else {
            return vec![];
        };
        let Ok(rt) = inner.route_table.try_read() else {
            return vec![];
        };
        rt.entries()
            .map(|(net, prefix, peer)| (format!("{net}/{prefix}"), peer.clone()))
            .collect()
    }

    /// Select an exit node by tailnet IP or MagicDNS hostname. After this,
    /// all non-tailnet traffic routes to the selected peer — in netstack mode
    /// via the in-process `RouteTable`, in TUN mode via the data pump (OS
    /// default-route overrides must be installed separately, see
    /// [`TunModeConfig::exit_node`]).
    ///
    /// `ip_or_name` may be a tailnet IP (e.g. `"100.64.0.5"`) or a MagicDNS
    /// hostname (e.g. `"peer"` or `"peer.tailnet.ts.net"`). The peer must be
    /// exit-node-capable (its `AllowedIPs` must contain `0.0.0.0/0`); otherwise
    /// returns [`TsnetError::NotExitCapable`]. Returns
    /// [`TsnetError::ExitNodeNotFound`] if no peer matches.
    ///
    /// In TUN mode, existing TCP connections are broken best-effort after the
    /// route change (mirroring Go's `breakTCPConns`), since the old routes no
    /// longer apply. This is **not** done in netstack mode — it would kill the
    /// process's own DERP/control TCP connections.
    ///
    /// C-representable: string in, error code out (see FFI `ts_set_exit_node`).
    pub async fn set_exit_node(&self, ip_or_name: &str) -> Result<(), TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let peers = inner.peers.read().await;
        let peer_key = resolve_exit_node(&peers, ip_or_name)?;
        drop(peers);
        inner.route_table.write().await.set_exit_node(peer_key);
        if matches!(inner.data_plane, DataPlane::Tun) {
            break_tcp_conns_best_effort();
        }
        Ok(())
    }

    /// Clear the selected exit node. After this, non-tailnet destinations no
    /// longer route through a peer (unless `accept_routes` installed them).
    ///
    /// In TUN mode, existing TCP connections are broken best-effort after the
    /// route change (mirroring Go's `breakTCPConns`), since the old routes no
    /// longer apply. This is **not** done in netstack mode — it would kill the
    /// process's own DERP/control TCP connections.
    ///
    /// C-representable: no args, error code out (see FFI `ts_clear_exit_node`).
    pub async fn clear_exit_node(&self) -> Result<(), TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        inner.route_table.write().await.clear_exit_node();
        if matches!(inner.data_plane, DataPlane::Tun) {
            break_tcp_conns_best_effort();
        }
        Ok(())
    }

    /// The currently selected exit node's peer key, if any.
    pub async fn exit_node(&self) -> Option<NodePublic> {
        let inner = self.inner.as_ref()?;
        let rt = inner.route_table.read().await;
        rt.exit_node().cloned()
    }

    /// Look up which peer owns a tailnet IP address ([WhoIs]). Returns the
    /// peer's MagicDNS name, tailscale IPs, and the owning user's login/
    /// display name (from `MapResponse.UserProfiles`).
    ///
    /// Returns `None` only if the server is not up; if the server is up but
    /// no peer matches, returns `Some(WhoIsInfo { found: false, .. })`.
    pub async fn whois(&self, remote_addr: IpAddr) -> Option<WhoIsInfo> {
        let inner = self.inner.as_ref()?;
        let peers = inner.peers.read().await;
        let ups = inner.user_profiles.read().await;
        Some(
            whois_lookup(&peers, &ups, remote_addr).unwrap_or_else(|| WhoIsInfo {
                found: false,
                node_name: String::new(),
                tailscale_ips: vec![],
                user_id: 0,
                login_name: String::new(),
                display_name: String::new(),
            }),
        )
    }

    /// Set the serve configuration. Starts netstack listeners on the
    /// configured tailnet ports and dispatches each connection to the matching
    /// handler (TCP forward, HTTP/HTTPS web, reverse proxy, static text).
    ///
    /// For configs with HTTPS or TLS-terminated TCP-forward handlers, a
    /// Let's Encrypt cert is provisioned via the control plane (falling back
    /// to self-signed on error). Returns the list of ports now being served.
    ///
    /// Requires the server to be up in netstack mode (not TUN mode).
    /// C-representable: the config is a plain serde struct; the FFI layer
    /// exposes a minimal `ts_serve_tcp` for the common TCP-forward case.
    pub async fn set_serve_config(&self, cfg: ServeConfig) -> Result<Vec<u16>, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let runner = inner
            .serve
            .as_ref()
            .ok_or(TsnetError::NotAvailableInTunMode)?;

        // If the config has HTTPS or TLS-terminated handlers, provision a cert.
        let needs_tls = cfg
            .TCP
            .values()
            .any(|h| h.HTTPS || !h.TerminateTLS.is_empty());
        let cert = if needs_tls {
            match self.control_cert_provider().await {
                Ok(p) => {
                    inner.health.set_healthy(WARN_CERT_FALLBACK);
                    Some(p)
                }
                Err(e) => {
                    eprintln!("tsnet: serve cert unavailable ({e}); using self-signed");
                    inner.health.set_unhealthy(
                        WARN_CERT_FALLBACK,
                        format!("serving self-signed fallback: {e}"),
                    );
                    Some(tls::default_cert_provider(&inner.tailscale_ips))
                }
            }
        } else {
            None
        };

        let started = runner.set_config(cfg, cert).await?;
        Ok(started)
    }

    /// Listen for incoming Funnel connections on `port` (443, 8443, or 10000).
    ///
    /// Validates that the node has the `funnel` node attribute from the
    /// netmap. On API-only tailnets where control never grants funnel, returns
    /// a typed [`FunnelError::NotEnabled`] — the expected clean error.
    ///
    /// Funnel ingress arrives via DERP-relayed connections from Tailscale's
    /// ingress servers; the node appears as a peer and no special transport
    /// is needed beyond accepting TLS conns on the port. The returned
    /// [`TlsListener`] terminates TLS with the control cert provider (or
    /// self-signed fallback).
    ///
    /// **What remains for full Funnel**: wiring the ingress peer's
    /// `Tailscale-Ingress-Target` header dispatch (Go's `handleServeIngress`)
    /// and advertising `Hostinfo.IngressEnabled` to control. The listener
    /// itself works — connections from the tailnet (and, when control grants
    /// the funnel attr, from the internet) are accepted and TLS-terminated.
    pub async fn listen_funnel(&self, port: u16) -> Result<TlsListener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let _runner = inner
            .serve
            .as_ref()
            .ok_or(TsnetError::NotAvailableInTunMode)?;

        // Validate the port is a funnel port.
        if !FUNNEL_PORTS.contains(&port) {
            return Err(TsnetError::Funnel(FunnelError::PortNotAllowed(port)));
        }

        // Check the node has the funnel capability from the netmap.
        // Use our own node from the netmap (MapResponse.Node is not retained
        // separately, so we check via the self node's capabilities). The self
        // node's capabilities come from the DNSConfig/cert domains (HTTPS) and
        // the node attributes delivered in the map stream.
        let self_node = self.self_node().await;
        check_funnel_access(port, &self_node)?;

        // Provision a cert (LE via control, self-signed fallback).
        let provider = match self.control_cert_provider().await {
            Ok(p) => {
                inner.health.set_healthy(WARN_CERT_FALLBACK);
                p
            }
            Err(e) => {
                eprintln!("tsnet: funnel cert unavailable ({e}); using self-signed");
                inner.health.set_unhealthy(
                    WARN_CERT_FALLBACK,
                    format!("serving self-signed fallback: {e}"),
                );
                tls::default_cert_provider(&inner.tailscale_ips)
            }
        };

        self.listen_tls_with_provider(port, provider).await
    }

    /// Listen for incoming connections addressed to a Tailscale VIP Service
    /// (netstack mode only).
    ///
    /// Resolves the service's VIP v4 addresses from the netmap (self node's
    /// `CapMap` under the `service-host` key), adds them to the userspace
    /// netstack interface, and listens on the specified `port` on each VIP.
    /// Connections addressed to the service's VIP IP on the port are accepted
    /// and surface as normal tsnet streams via [`ServiceListener::accept`].
    ///
    /// The service name must be of the form `svc:dns-label` (e.g.
    /// `"svc:my-service"`). The node must be tagged and the service must be
    /// approved by an admin or ACL auto-approval rules; otherwise the netmap
    /// will not carry VIP addresses for the service and this method returns
    /// [`ServiceError::NoVipAddrs`].
    ///
    /// # PROXY protocol v2
    ///
    /// When [`ServiceMode::proxy_protocol`] is `true`, a PROXY protocol v2
    /// binary header is prepended to each accepted stream so the backend
    /// learns the real client address. See
    /// <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustscale_tsnet::{Server, ServiceMode};
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut server = Server::builder()
    ///     .hostname("my-svc")
    ///     .auth_key("tskey-...")
    ///     .build()?;
    /// server.up().await?;
    ///
    /// let mode = ServiceMode::tcp(8080).with_proxy_protocol(true);
    /// let mut listener = server.listen_service("svc:my-service", mode).await?;
    /// // loop { let stream = listener.accept().await?; ... }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Returns an error in TUN mode.
    pub async fn listen_service(
        &self,
        svc_name: &str,
        mode: ServiceMode,
    ) -> Result<ServiceListener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let netstack = match &inner.data_plane {
            DataPlane::Netstack(ns) => ns.clone(),
            DataPlane::Tun => return Err(TsnetError::NotAvailableInTunMode),
        };

        // Build a self node with the CapMap from magicsock (the authoritative
        // source for the self node's capabilities, updated from each
        // MapResponse).
        let cap_map = inner.magicsock.self_cap_map();
        let self_node = Node {
            Name: inner.our_fqdn.clone(),
            Addresses: inner
                .tailscale_ips
                .iter()
                .map(|ip| format!("{ip}/32"))
                .collect(),
            CapMap: cap_map,
            Tags: self.self_tags().await,
            ..Default::default()
        };

        let listener =
            service::create_service_listener(&netstack, &self_node, &inner.domain, svc_name, mode)
                .await?;

        Ok(listener)
    }

    /// Snapshot of this node's ACL tags from the self node in the peers list.
    /// Returns an empty vec if the self node is not found in the peers list.
    async fn self_tags(&self) -> Vec<String> {
        let Some(inner) = self.inner.as_ref() else {
            return vec![];
        };
        let peers = inner.peers.read().await;
        let our_fqdn = inner.our_fqdn.trim_end_matches('.');
        for peer in peers.iter() {
            if peer.Name.trim_end_matches('.') == our_fqdn {
                return peer.Tags.clone();
            }
        }
        vec![]
    }

    /// Snapshot of our own node from the netmap (peers list includes self
    /// on some control servers; otherwise we synthesize a minimal node from
    /// the retained DNS config + tailscale IPs for capability checks).
    async fn self_node(&self) -> Node {
        let inner = self.inner.as_ref().expect("self_node called before up()");
        let dns = inner.dns_config.read().await;
        let cert_domains: Vec<String> = dns
            .as_ref()
            .map(|c| c.CertDomains.clone())
            .unwrap_or_default();
        // If cert domains are present, the node has the `https` capability.
        let mut caps: Vec<String> = Vec::new();
        if !cert_domains.is_empty() {
            caps.push("https".to_string());
        }
        // The funnel node attribute is delivered in the self node's CapMap.
        // Since we don't retain the self node separately, we check the peers
        // list for our own node (by FQDN). If not found, the capability check
        // will return NotEnabled — the expected behavior on API-only tailnets.
        let peers = inner.peers.read().await;
        let our_fqdn = inner.our_fqdn.trim_end_matches('.');
        for peer in peers.iter() {
            if peer.Name.trim_end_matches('.') == our_fqdn {
                let mut n = peer.clone();
                if !caps.is_empty() && !n.Capabilities.contains(&caps[0]) {
                    n.Capabilities.extend(caps.clone());
                }
                return n;
            }
        }
        // Self not in peers list — synthesize a minimal node.
        Node {
            Name: inner.our_fqdn.clone(),
            Addresses: inner
                .tailscale_ips
                .iter()
                .map(|ip| format!("{ip}/32"))
                .collect(),
            Capabilities: caps,
            ..Default::default()
        }
    }

    /// Shut down the server.
    pub async fn close(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            // Stop serve listeners first (graceful).
            if let Some(serve) = inner.serve.take() {
                serve.stop().await;
            }
            inner.cancel.cancel();
            inner.health_watchdog.stop();
            if let Some(m) = inner.monitor.take() {
                m.shutdown();
            }
            let mut tasks = inner.tasks.lock().await;
            for task in tasks.drain(..) {
                task.abort();
            }
            // Clean up the LocalAPI socket file if it was created.
            if let Some(ref path) = inner.localapi_socket {
                let _ = std::fs::remove_file(path);
            }
            // Remove OS DNS configuration (e.g. /etc/resolver entries) if
            // we installed it. Best-effort: log on error.
            if let Some(mut cfg) = inner.os_dns_configurator.take() {
                if let Err(e) = cfg.close() {
                    eprintln!("tsnet: OS DNS cleanup failed (non-fatal): {e}");
                }
            }
        }
    }

    // --- internal helpers ---

    fn load_or_create_state(&self) -> Result<PersistedState, TsnetError> {
        if let Some(ref dir) = self.config.state_dir {
            let path = dir.join("tsnet-state.json");
            if path.exists() {
                return Ok(PersistedState::load(&path)?);
            }
        }
        Ok(PersistedState::default())
    }

    fn save_state(&self, state: &PersistedState) -> Result<(), TsnetError> {
        if let Some(ref dir) = self.config.state_dir {
            let path = dir.join("tsnet-state.json");
            state.save(&path)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Data-plane pumps
// ---------------------------------------------------------------------------

/// Netstack data-plane pump: netstack <-> WG <-> magicsock.
///
/// Inbound: magicsock recv → WG decapsulate → netstack.push_rx.
/// Outbound: netstack.pop_tx → route lookup → WG encapsulate → magicsock send.
/// Also ticks WG timers every loop iteration.
async fn run_netstack_pump(
    magicsock: Arc<Magicsock>,
    mut wg_recv: mpsc::Receiver<rustscale_magicsock::WgDatagram>,
    netstack: Arc<Netstack>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
) {
    let tx_notify = netstack.tx_notify();
    let mut wg_timer = tokio::time::interval(std::time::Duration::from_millis(250));
    wg_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if cancel.is_cancelled() {
            break;
        }

        tokio::select! {
            () = tx_notify.notified() => {}
            _ = wg_timer.tick() => {}
            result = wg_recv.recv() => {
                if let Some(dgram) = result {
                    let f = filter.clone();
                    let drops = packet_drops.clone();
                    let ns = netstack.clone();
                    handle_inbound_wg(&magicsock, &wg_tunnels, &dgram, move |pt| {
                        let dropped = {
                            let mut filt = f.lock().unwrap();
                            filt.check_in(&pt).is_drop()
                        };
                        if dropped {
                            drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        ns.push_rx(pt);
                    }).await;

                    // Drain any additional immediately-available datagrams
                    // to batch a burst of packets (e.g. TCP handshake +
                    // data) into a single scheduler turn.
                    while let Ok(more) = wg_recv.try_recv() {
                        let f = filter.clone();
                        let drops = packet_drops.clone();
                        let ns = netstack.clone();
                        handle_inbound_wg(&magicsock, &wg_tunnels, &more, move |pt| {
                            let dropped = {
                                let mut filt = f.lock().unwrap();
                                filt.check_in(&pt).is_drop()
                            };
                            if dropped {
                                drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                return;
                            }
                            ns.push_rx(pt);
                        }).await;
                    }
                } else {
                    eprintln!("tsnet: magicsock wg channel closed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }

        // Drain outbound IP packets from netstack → route → WG → magicsock.
        // Cap the batch size so inbound packets aren't starved under heavy
        // outbound load (e.g. bulk TCP transfer). A full drain can take long
        // enough for the magicsock receive buffer to fill and drop inbound.
        const DRAIN_BATCH: usize = 64;
        let mut drained = 0;
        while drained < DRAIN_BATCH {
            let Some(pkt) = netstack.pop_tx() else { break };
            {
                let mut filt = filter.lock().unwrap();
                filt.update_outbound(&pkt);
            }
            encapsulate_and_send(&magicsock, &wg_tunnels, &route_table, &pkt).await;
            drained += 1;
        }

        tick_wg_timers(&magicsock, &wg_tunnels).await;
    }
}

/// TUN data-plane pump: TUN device <-> WG <-> magicsock.
///
/// Inbound (from network): magicsock recv -> WG decapsulate -> TUN write.
/// Outbound (from OS): TUN read -> route lookup -> WG encapsulate -> magicsock send.
/// WG timer ticks run on a 250ms interval.
async fn run_tun_pump(
    magicsock: Arc<Magicsock>,
    mut wg_recv: mpsc::Receiver<rustscale_magicsock::WgDatagram>,
    tun: Arc<dyn Tun>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if cancel.is_cancelled() {
            break;
        }

        tokio::select! {
            // TUN read -> route -> WG encapsulate -> magicsock send.
            result = tun.read_packet() => {
                match result {
                    Ok(pkt) => {
                        {
                            let mut filt = filter.lock().unwrap();
                            filt.update_outbound(&pkt);
                        }
                        encapsulate_and_send(&magicsock, &wg_tunnels, &route_table, &pkt).await;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        eprintln!("tun read error: {e}");
                        break;
                    }
                }
            }
            // magicsock recv -> WG decapsulate -> filter -> TUN write.
            result = wg_recv.recv() => {
                if let Some(dgram) = result {
                    process_tun_inbound(
                        &magicsock, &wg_tunnels, &filter, &packet_drops, &tun, &dgram,
                    ).await;

                    // Drain any additional immediately-available datagrams
                    // to batch a burst of packets into a single scheduler turn.
                    while let Ok(more) = wg_recv.try_recv() {
                        process_tun_inbound(
                            &magicsock, &wg_tunnels, &filter, &packet_drops, &tun, &more,
                        ).await;
                    }
                } else {
                    eprintln!("tsnet: magicsock wg channel closed (tun)");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
            _ = ticker.tick() => {
                tick_wg_timers(&magicsock, &wg_tunnels).await;
            }
        }
    }
}

/// Handle an inbound WG datagram: decapsulate, deliver plaintext via `deliver`,
/// and send any WG protocol replies back over magicsock.
async fn handle_inbound_wg(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    dgram: &rustscale_magicsock::WgDatagram,
    deliver: impl Fn(Vec<u8>),
) {
    let tunn = {
        let tunnels = wg_tunnels.read().await;
        tunnels.get(&dgram.peer).cloned()
    };
    if let Some(tunn) = tunn {
        // Lock the tunnel, decapsulate (synchronous), then drop the lock
        // before any async I/O (magicsock.send). This prevents packet drops
        // from try_lock failures and avoids holding the lock across .await.
        let decap_result = {
            let mut t = tunn.lock().await;
            t.decapsulate(&dgram.data)
        };
        if let Ok(decap) = decap_result {
            if let Some(pt) = decap.plaintext {
                deliver(pt);
            }
            for reply in decap.replies {
                let _ = magicsock.send(dgram.peer.clone(), &reply).await;
            }
        }
    }
}

/// Process a single inbound WG datagram for the TUN pump: look up the peer
/// tunnel, decapsulate, filter, write plaintext to TUN, and send any WG
/// protocol replies over magicsock. The tunnel lock is dropped before any
/// async I/O to avoid holding it across .await points.
async fn process_tun_inbound(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    filter: &Arc<std::sync::Mutex<Filter>>,
    packet_drops: &Arc<AtomicU64>,
    tun: &Arc<dyn Tun>,
    dgram: &rustscale_magicsock::WgDatagram,
) {
    let tunn = {
        let tunnels = wg_tunnels.read().await;
        tunnels.get(&dgram.peer).cloned()
    };
    if let Some(tunn) = tunn {
        let decap_result = {
            let mut t = tunn.lock().await;
            t.decapsulate(&dgram.data)
        };
        if let Ok(decap) = decap_result {
            if let Some(pt) = decap.plaintext {
                let dropped = {
                    let mut filt = filter.lock().unwrap();
                    filt.check_in(&pt).is_drop()
                };
                if dropped {
                    packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                } else {
                    let _ = tun.write_packet(&pt).await;
                }
            }
            for reply in decap.replies {
                let _ = magicsock.send(dgram.peer.clone(), &reply).await;
            }
        }
    }
}

/// Route a plaintext IP packet to the right peer, encapsulate it via WG, and
/// send the resulting datagrams over magicsock.
async fn encapsulate_and_send(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    route_table: &RwLock<RouteTable>,
    pkt: &[u8],
) {
    let Some(dst) = WgTunn::dst_address(pkt) else {
        return;
    };
    let peer_key = {
        let rt = route_table.read().await;
        rt.lookup(dst)
    };
    let Some(peer_key) = peer_key else {
        return;
    };
    let tunn = {
        let tunnels = wg_tunnels.read().await;
        tunnels.get(&peer_key).cloned()
    };
    if let Some(tunn) = tunn {
        // Lock the tunnel, encapsulate (synchronous), then drop the lock
        // before async magicsock.send to avoid holding it across .await.
        let dgrams = {
            let mut t = tunn.lock().await;
            t.encapsulate(pkt)
        };
        if let Ok(dgrams) = dgrams {
            for dg in dgrams {
                let _ = magicsock.send(peer_key.clone(), &dg).await;
            }
        }
    }
}

/// Tick WG timers for all peers and send any resulting datagrams.
///
/// Collects all timer-generated datagrams while holding the read lock, then
/// releases the lock before sending. This prevents blocking `spawn_map_update_task`
/// (which needs a write lock to add new peers) during the potentially many
/// `magicsock.send().await` calls.
async fn tick_wg_timers(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
) {
    let pending: Vec<(NodePublic, Vec<u8>)> = {
        let tunnels = wg_tunnels.read().await;
        let mut out = Vec::new();
        for (peer_key, tunn) in tunnels.iter() {
            let mut t = tunn.lock().await;
            for dg in t.tick_timers() {
                out.push((peer_key.clone(), dg));
            }
        }
        out
    };
    for (peer_key, dg) in pending {
        let _ = magicsock.send(peer_key, &dg).await;
    }
}

/// Spawn the map-stream delta update task. Shared by `up()` and `up_tun()`:
/// processes Peers/PeersChanged/PeersRemoved, feeds the new peer list to
/// magicsock, rebuilds the route table, and creates WG tunnels for new peers.
fn spawn_map_update_task(
    mut map_rx: mpsc::Receiver<Result<MapResponse, StreamMapError>>,
    magicsock: Arc<Magicsock>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    peers_arc: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    node_key: NodePrivate,
    filter_arc: Arc<std::sync::Mutex<Filter>>,
    tailscale_ips: Vec<IpAddr>,
    accept_routes: bool,
    advertise_routes: Vec<String>,
    resolver: Arc<RwLock<MagicDnsResolver>>,
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    ssh_policy: Arc<RwLock<Option<SSHPolicy>>>,
    cancel: Arc<CancelToken>,
    health: Tracker,
    health_watchdog: Watchdog,
    state_dir: Option<PathBuf>,
    node_pub: NodePublic,
    control_knobs: Arc<ControlKnobs>,
    key_expired: Arc<std::sync::atomic::AtomicBool>,
    ipn_backend: Arc<IpnBackend>,
) -> JoinHandle<()> {
    let mut named_filters: BTreeMap<String, Vec<FilterRule>> = BTreeMap::new();
    // Create the netmap cache helper once so that save_if_changed can
    // dedup identical writes via the in-memory SHA-256 hash.
    let netmap_cache = state_dir.as_ref().map(|dir| NetMapCache::new(dir));
    tokio::spawn(async move {
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match map_rx.recv().await {
                Some(Ok(resp)) => {
                    // Map activity: feed the staleness watchdog + mark control
                    // healthy. Even keep-alive messages count as activity.
                    health_watchdog.feed();
                    health.set_healthy(WARN_CONTROL);

                    if resp.KeepAlive {
                        continue;
                    }

                    // Handle key expiry from the control server. The
                    // testcontrol server signals expiry by setting
                    // Node.KeyExpiry to a past time in MapResponse. The
                    // real control server may also set NodeKeyExpired on
                    // the RegisterResponse. We check both sources.
                    let expired = resp.NodeKeyExpired
                        || resp
                            .Node
                            .as_ref()
                            .and_then(|n| n.KeyExpiry)
                            .is_some_and(|expiry| expiry < chrono::Utc::now());
                    key_expired.store(expired, std::sync::atomic::Ordering::Relaxed);
                    ipn_backend.set_key_expired(expired);
                    if expired {
                        eprintln!("tsnet: node key expired (signalled by control)");
                        if let Some(ref dir) = state_dir {
                            PersistedState::clear_netmap(dir);
                        }
                    }

                    // Extract control knobs from the self-node's CapMap and
                    // apply them. Mirrors Go's
                    // `controlKnobs.UpdateFromNodeAttributes(resp.Node.CapMap)`
                    // (controlclient/map.go:302).
                    let knobs = extract_knobs_from_map_response(&resp);
                    if !knobs.is_empty() {
                        control_knobs.apply(knobs);
                    }

                    // Update the self node's CapMap in magicsock so the relay
                    // server extension can check NODE_ATTR_DISABLE_RELAY_SERVER.
                    if let Some(ref node) = resp.Node {
                        magicsock.set_self_cap_map(node.CapMap.clone());
                    }

                    // Merge peer deltas. Track whether the peer set changed
                    // so the filter's capability map can be refreshed.
                    let peers_changed = !resp.Peers.is_empty()
                        || !resp.PeersChanged.is_empty()
                        || !resp.PeersRemoved.is_empty();
                    {
                        let mut peers = peers_arc.write().await;
                        if !resp.Peers.is_empty() {
                            peers.clone_from(&resp.Peers);
                        }
                        if !resp.PeersChanged.is_empty() {
                            for changed in &resp.PeersChanged {
                                if let Some(existing) =
                                    peers.iter_mut().find(|p| p.Key == changed.Key)
                                {
                                    *existing = changed.clone();
                                } else {
                                    peers.push(changed.clone());
                                }
                            }
                        }
                        if !resp.PeersRemoved.is_empty() {
                            peers.retain(|p| !resp.PeersRemoved.contains(&p.ID));
                        }
                    }

                    // Feed the updated peer list to magicsock + rebuild routes.
                    let peers = peers_arc.read().await.clone();
                    let _ = magicsock.set_netmap(peers.clone()).await;
                    route_table
                        .write()
                        .await
                        .rebuild_with_opts(&peers, accept_routes);

                    // Update IPN engine status: peer count as NumLive, DERP
                    // home connection as LiveDERPs. This may transition the
                    // state machine from Starting to Running.
                    let live_count = peers.iter().filter(|p| !p.Key.is_zero()).count() as i32;
                    ipn_backend.set_engine_status(live_count, 1);

                    // Refresh the shared MagicDNS resolver with the new peers.
                    resolver.write().await.set_peers(peers.clone());

                    // Apply DNSConfig delta (None means unchanged).
                    if let Some(cfg) = &resp.DNSConfig {
                        dns_config.write().await.clone_from(&resp.DNSConfig);
                        // Rebuild the resolver config from the new DNSConfig,
                        // preserving the current peers and domain. This wires
                        // split-DNS Routes, ExtraRecords hosts, and local
                        // domains from the control plane.
                        let mut r = resolver.write().await;
                        let domain = r.domain().to_string();
                        let new_config = config_from_dns(cfg, &domain, &peers);
                        r.set_config(new_config);
                    }

                    // Merge UserProfiles delta (add/update; never removed).
                    if !resp.UserProfiles.is_empty() {
                        let mut ups = user_profiles.write().await;
                        for up in &resp.UserProfiles {
                            ups.insert(up.ID, up.clone());
                        }
                    }

                    // Apply SSHPolicy delta (None = unchanged; Some = replace).
                    // Mirrors Go's `ipn/ipnlocal/local.go` feeding
                    // `netMap.SSHPolicy` into the SSH server on each netmap
                    // update.
                    if resp.SSHPolicy.is_some() {
                        ssh_policy.write().await.clone_from(&resp.SSHPolicy);
                    }

                    // Create WG tunnels for new peers.
                    let mut tunnels = wg_tunnels.write().await;
                    for peer in &peers {
                        if peer.Key.is_zero() {
                            continue;
                        }
                        if !tunnels.contains_key(&peer.Key) {
                            if let Ok(t) = WgTunn::new(&node_key, &peer.Key, rand_index()) {
                                tunnels.insert(peer.Key.clone(), Arc::new(Mutex::new(t)));
                            }
                        }
                    }
                    drop(tunnels);

                    // Process PacketFilter / PacketFilters deltas and rebuild
                    // the filter if anything changed. The peer list supplies
                    // the capability map; the existing shields-up state is
                    // preserved across the rebuild (mirrors Go passing
                    // `oldFilter` to `filter.New`). A peer-set change also
                    // triggers a rebuild so `cap:<name>` source predicates
                    // see the latest peer `CapMap`s.
                    let filter_changed = process_filter_deltas(&resp, &mut named_filters);
                    if filter_changed || peers_changed {
                        let shields_up = filter_arc.lock().unwrap().shields_up();
                        let peers_snapshot = peers_arc.read().await.clone();
                        rebuild_filter(
                            &filter_arc,
                            &named_filters,
                            &tailscale_ips,
                            &advertise_routes,
                            &peers_snapshot,
                            shields_up,
                        );
                    }

                    // Save the updated netmap to disk (best-effort) so a
                    // restart can skip the blocking first fetch. Dedup via
                    // SHA-256 skips the write if the content is unchanged
                    // since the last successful save.
                    if let Some(ref cache) = netmap_cache {
                        if let Err(e) = cache.save_if_changed(&node_pub, &resp) {
                            eprintln!("tsnet: netmap cache save failed (non-fatal): {e}");
                        }
                    }
                }
                Some(Err(e)) => {
                    health.set_unhealthy(WARN_CONTROL, format!("control connection lost: {e}"));
                    break;
                }
                None => {
                    health.set_unhealthy(WARN_CONTROL, "control connection lost: stream closed");
                    break;
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Packet filter helpers
// ---------------------------------------------------------------------------

/// Build a [`Filter`] from a [`MapResponse`]'s PacketFilter/PacketFilters
/// fields. Returns the filter and the initial named-filter map.
///
/// `peers` is used to build the peer IP → capability-set map so the filter
/// can evaluate `cap:<name>` source predicates. `shields_up` enables
/// shields-up mode (deny new inbound flows).
fn build_filter_from_map_response(
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
    let mut filter =
        Filter::new(&all_rules, local_ips, &cap_holders).unwrap_or_else(|_| Filter::allow_all());
    filter.set_shields_up(shields_up);
    (filter, named)
}

/// Process PacketFilter/PacketFilters deltas from a MapResponse into the
/// named-filter map. Returns true if the map changed (and the filter should
/// be rebuilt).
fn process_filter_deltas(
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
fn rebuild_filter(
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
    if let Ok(mut new_filter) = Filter::new(&all_rules, local_ips, &cap_holders) {
        if !advertise_routes.is_empty() {
            new_filter.add_local_cidrs(advertise_routes);
        }
        new_filter.set_shields_up(shields_up);
        *filter_arc.lock().unwrap() = new_filter;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_tailscale_ips(map: &MapResponse) -> Vec<IpAddr> {
    map.Node.as_ref().map(extract_node_ips).unwrap_or_default()
}

fn extract_node_ips(node: &Node) -> Vec<IpAddr> {
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

/// Spawn the network change monitor. On a major link change (interface IP
/// change, up/down transition, or wall-clock time jump), re-gathers local
/// endpoints, resets peer direct paths, closes DERP connections, re-STUNs,
/// and pushes a lightweight non-streaming MapRequest to the control plane.
fn spawn_link_monitor(
    magicsock: Arc<Magicsock>,
    cancel: Arc<CancelToken>,
    control_url: String,
    machine_key: MachinePrivate,
    server_pub_key: MachinePublic,
    node_key: NodePrivate,
    disco_key: DiscoPrivate,
    udp_port: u16,
    hostname: String,
    advertise_routes: Vec<String>,
    derp_map: DERPMap,
    home_derp: i32,
    health: Tracker,
) -> Option<rustscale_netmon::MonitorHandle> {
    let monitor = rustscale_netmon::Monitor::new().ok()?;

    let handle = monitor.start();
    handle.register_change_callback(move |delta| {
        let magicsock = magicsock.clone();
        let cancel = cancel.clone();
        let control_url = control_url.clone();
        let machine_key = machine_key.clone();
        let server_pub_key = server_pub_key.clone();
        let node_key = node_key.clone();
        let disco_key = disco_key.clone();
        let hostname = hostname.clone();
        let advertise_routes = advertise_routes.clone();
        let derp_map = derp_map.clone();
        let health = health.clone();
        let home_derp = home_derp;
        async move {
            if !delta.major {
                return;
            }
            if cancel.is_cancelled() {
                return;
            }
            eprintln!(
                "tsnet: major link change detected; re-gathering endpoints + re-STUN (udp_port={udp_port})"
            );

            // Transient health warning while re-probing.
            health.set_unhealthy(WARN_NETMON_CHANGE, "network changed, re-probing");

            magicsock.link_changed();

            let mut eps = magicsock.all_endpoints();
            if !derp_map.Regions.is_empty() {
                if let Ok(report) = rustscale_netcheck::Prober
                    .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                    .await
                {
                    if let Some(g) = report.global_v4 {
                        eps.push(g.to_string());
                    }
                }
            }

            let node_pub = node_key.public();
            let disco_pub = disco_key.public();
            let req = MapRequest {
                Version: CAPABILITY_VERSION,
                KeepAlive: false,
                NodeKey: node_pub,
                DiscoKey: disco_pub,
                Stream: false,
                OmitPeers: true,
                Endpoints: eps,
                Hostinfo: Some(Hostinfo {
                    OS: std::env::consts::OS.into(),
                    Hostname: hostname,
                    RoutableIPs: advertise_routes,
                    NetInfo: Some(NetInfo {
                        PreferredDERP: home_derp,
                        WorkingUDP: OptBool::True,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let cc = ControlClient::new(&control_url, machine_key, server_pub_key, PROTOCOL_VERSION);
            match cc.send_map_request(&req).await {
                Ok(()) => {
                    eprintln!("tsnet: link-change endpoint update sent");
                    // Endpoints re-published: clear the transient warning.
                    health.set_healthy(WARN_NETMON_CHANGE);
                }
                Err(e) => eprintln!("tsnet: link-change endpoint update failed (non-fatal): {e}"),
            }
        }
    });

    Some(handle)
}

/// Periodic endpoint update task (Bug 4).
///
/// Sends a non-streaming MapRequest with `OmitPeers=true` every 5 minutes
/// so the control server always has fresh endpoint data (local IPs, STUN
/// results, port-mapped endpoints). Go's controlclient does this via
/// `setEndpoints` on a timer; rustscale only sent endpoints once at startup
/// and on link-change (netmon), which could leave the control server with
/// stale data for the lifetime of a long-lived session.
///
/// The task is self-contained: it creates its own `ControlClient` per
/// update (to avoid sharing the streaming map-poll client) and respects
/// the shared `CancelToken`.
fn spawn_periodic_endpoint_updates(
    magicsock: Arc<Magicsock>,
    cancel: Arc<CancelToken>,
    control_url: String,
    machine_key: MachinePrivate,
    server_pub_key: MachinePublic,
    node_key: NodePrivate,
    disco_key: DiscoPrivate,
    hostname: String,
    advertise_routes: Vec<String>,
    derp_map: DERPMap,
    home_derp: i32,
    peer_relay_server: bool,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let node_pub = node_key.public();
        let disco_pub = disco_key.public();
        loop {
            tokio::time::sleep(std::time::Duration::from_mins(5)).await;
            if cancel.is_cancelled() {
                break;
            }

            let mut eps = magicsock.all_endpoints();
            if !derp_map.Regions.is_empty() {
                if let Ok(report) = rustscale_netcheck::Prober
                    .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                    .await
                {
                    if let Some(g) = report.global_v4 {
                        eps.push(g.to_string());
                    }
                }
            }

            let req = MapRequest {
                Version: CAPABILITY_VERSION,
                KeepAlive: false,
                NodeKey: node_pub.clone(),
                DiscoKey: disco_pub.clone(),
                Stream: false,
                OmitPeers: true,
                Endpoints: eps,
                Hostinfo: Some(Hostinfo {
                    OS: std::env::consts::OS.into(),
                    Hostname: hostname.clone(),
                    RoutableIPs: advertise_routes.clone(),
                    NetInfo: Some(NetInfo {
                        PreferredDERP: home_derp,
                        WorkingUDP: OptBool::True,
                        ..Default::default()
                    }),
                    PeerRelay: peer_relay_server,
                    ..Default::default()
                }),
                ..Default::default()
            };
            let cc = ControlClient::new(
                &control_url,
                machine_key.clone(),
                server_pub_key.clone(),
                PROTOCOL_VERSION,
            );
            match cc.send_map_request(&req).await {
                Ok(()) => eprintln!("tsnet: periodic endpoint update sent"),
                Err(e) => eprintln!("tsnet: periodic endpoint update failed (non-fatal): {e}"),
            }
        }
    })
}

/// Periodic Hostinfo refresh loop (mirrors Go's
/// `controlclient.Direct.hostinfoUpdateLoop`).
///
/// Recollects `Hostinfo` every 10 minutes. If the content hash differs from
/// the last-sent hash, sends a lightweight non-streaming `MapRequest` with
/// `OmitPeers=true` carrying the new `Hostinfo`. An initial collection is
/// performed at startup so the control server has the full platform-detected
/// Hostinfo (the bootstrap sends a minimal one); the dedup hash prevents a
/// redundant send if the content matches.
#[allow(clippy::too_many_arguments)]
fn spawn_hostinfo_update_loop(
    cancel: Arc<CancelToken>,
    control_url: String,
    machine_key: MachinePrivate,
    server_pub_key: MachinePublic,
    node_key: NodePrivate,
    disco_key: DiscoPrivate,
    hostname: String,
    advertise_routes: Vec<String>,
    home_derp: i32,
    peers: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    serve: Option<Arc<serve::ServeRunner>>,
    overrides: SharedOverrides,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let node_pub = node_key.public();
        let disco_pub = disco_key.public();

        // Initial collection: build the full Hostinfo and send it so control
        // has platform-detected fields. The bootstrap already sent a minimal
        // Hostinfo; this updates it to the full set. Dedup by content hash
        // prevents redundant sends on subsequent ticks.
        let mut last_hash: u64 = 0;

        loop {
            if cancel.is_cancelled() {
                break;
            }

            // Determine the exit node's StableNodeID (if any).
            let exit_node_id: Option<rustscale_tailcfg::StableNodeID> = {
                let exit_key = {
                    let rt = route_table.read().await;
                    rt.exit_node().cloned()
                };
                if let Some(key) = exit_key {
                    let peers_guard = peers.read().await;
                    peers_guard
                        .iter()
                        .find(|p| p.Key == key)
                        .map(|p| p.StableID.clone())
                        .filter(|id| !id.is_empty())
                } else {
                    None
                }
            };

            // Check whether funnel is active.
            let ingress_enabled = if let Some(ref runner) = serve {
                runner.is_funnel_on().await
            } else {
                false
            };

            // Build the base Hostinfo with fields the bootstrap sets.
            let base = Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: hostname.clone(),
                RoutableIPs: advertise_routes.clone(),
                NetInfo: Some(NetInfo {
                    PreferredDERP: home_derp,
                    WorkingUDP: OptBool::True,
                    ..Default::default()
                }),
                ..Default::default()
            };

            // Apply overrides + platform detection + runtime fields.
            let ov = overrides.read().await.clone();
            let hi = collect_hostinfo(base, &ov, exit_node_id.as_ref(), ingress_enabled);

            let hash = hostinfo_hash(&hi);
            if hash != last_hash {
                let req = MapRequest {
                    Version: CAPABILITY_VERSION,
                    KeepAlive: false,
                    NodeKey: node_pub.clone(),
                    DiscoKey: disco_pub.clone(),
                    Stream: false,
                    OmitPeers: true,
                    Hostinfo: Some(hi),
                    ..Default::default()
                };
                let cc = ControlClient::new(
                    &control_url,
                    machine_key.clone(),
                    server_pub_key.clone(),
                    PROTOCOL_VERSION,
                );
                match cc.send_map_request(&req).await {
                    Ok(()) => {
                        last_hash = hash;
                    }
                    Err(e) => {
                        eprintln!("tsnet: hostinfo update send failed (non-fatal): {e}");
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_mins(10)).await;
        }
    })
}

async fn connect_home_derp(
    derp_map: &DERPMap,
    home_region: i32,
    node_key: &NodePrivate,
) -> Result<DerpClient, rustscale_derp::DerpError> {
    let region = derp_map
        .Regions
        .get(&home_region)
        .ok_or_else(|| rustscale_derp::DerpError::BadFrame("unknown DERP region".into()))?;
    let nodes = region
        .Nodes
        .as_ref()
        .ok_or_else(|| rustscale_derp::DerpError::BadFrame("no DERP nodes".into()))?;
    let node = nodes
        .iter()
        .find(|n| !n.STUNOnly)
        .or_else(|| nodes.first())
        .ok_or_else(|| rustscale_derp::DerpError::BadFrame("no DERP node".into()))?;
    let port = if node.DERPPort > 0 {
        node.DERPPort as u16
    } else {
        443
    };

    // Use the explicit IPv4 for TCP dialing if available, but always use
    // the hostname for TLS SNI (DERP servers reject IP-based SNI).
    let tls_host = node.HostName.clone();
    let dial_addr = if !node.IPv4.is_empty() && node.IPv4 != "none" {
        node.IPv4.clone()
    } else {
        node.HostName.clone()
    };

    DerpClient::connect_with_upgrade_dial_insecure(
        &dial_addr,
        &tls_host,
        port,
        !node.InsecureForTests,
        node.InsecureForTests,
        node_key.clone(),
        None,
    )
    .await
}

/// Ensure the rustls ring crypto provider is installed process-wide.
fn ensure_ring_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn rand_index() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Extract the first IPv4 from a list of tailnet IPs.
fn first_v4(ips: &[IpAddr]) -> Result<Ipv4Addr, TsnetError> {
    ips.iter()
        .find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .ok_or_else(|| TsnetError::Builder("no IPv4 tailnet address".into()))
}

/// Bring the TUN interface up and add tailnet routes. Requires root.
///
/// On macOS: `ifconfig <name> up <our_v4>/32`, `route add 100.64.0.0/10 -interface <name>`.
/// On Linux: `ip link set <name> up`, `ip addr add <our_v4>/32 dev <name>`,
/// `ip route add 100.64.0.0/10 dev <name>`.
fn apply_tun_routes(ifname: &str, tailscale_ips: &[IpAddr], _mtu: usize) -> Result<(), TsnetError> {
    let our_v4 = first_v4(tailscale_ips)?;
    let v4_str = our_v4.to_string();

    #[cfg(target_os = "macos")]
    {
        run_cmd(
            "ifconfig",
            &["-v", ifname, "inet", &format!("{v4_str}/32"), "up"],
        )?;
        run_cmd(
            "route",
            &["-q", "add", "-net", "100.64.0.0/10", "-interface", ifname],
        )?;
    }
    #[cfg(target_os = "linux")]
    {
        run_cmd("ip", &["link", "set", ifname, "up"])?;
        run_cmd(
            "ip",
            &["addr", "add", &format!("{v4_str}/32"), "dev", ifname],
        )?;
        run_cmd("ip", &["route", "add", "100.64.0.0/10", "dev", ifname])?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ifname, v4_str);
    }
    Ok(())
}

/// Install peer-advertised subnet routes (non-tailnet CIDRs from the route
/// table) as OS routes pointing at the TUN device. Only called in TUN mode
/// when both `apply_routes` and `accept_routes` are enabled. Requires root.
///
/// **Note**: this installs the routes known at `up_tun` time. Dynamically
/// appearing routes (from later map-stream deltas) are not yet reflected in
/// the OS table — a future improvement. The in-process `RouteTable` always
/// has the latest entries.
fn apply_accepted_subnet_routes(ifname: &str, rt: &RouteTable) -> Result<(), TsnetError> {
    for (net, prefix, _peer) in rt.entries() {
        let cidr = format!("{net}/{prefix}");
        // Skip tailnet-range prefixes — those are handled by apply_tun_routes
        // (100.64.0.0/10) and don't need per-prefix OS routes.
        if is_tailnet_cidr(net, prefix) {
            continue;
        }
        #[cfg(target_os = "macos")]
        {
            // Best-effort: ignore "route already exists" failures.
            let _ = run_cmd("route", &["-q", "add", "-net", &cidr, "-interface", ifname]);
        }
        #[cfg(target_os = "linux")]
        {
            let _ = run_cmd("ip", &["route", "add", &cidr, "dev", ifname]);
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (ifname, &cidr);
        }
    }
    Ok(())
}

/// Install OS-level default-route overrides so all non-tailnet traffic enters
/// the TUN device, enabling exit-node usage in TUN mode. Only called when
/// `apply_routes` is true and an exit node is selected. Requires root.
///
/// **macOS**: installs two `/1` routes per address family
/// (`0.0.0.0/1` + `128.0.0.0/1` for IPv4, `::/1` + `8000::/1` for IPv6).
/// Together these cover the entire address space and are more specific than
/// the default route (`0.0.0.0/0`), so they override it without deleting it —
/// mirroring how `tailscaled` overrides the default on macOS. The original
/// default route is preserved for traffic that explicitly avoids the TUN
/// (though rustscale does not yet install bypass routes for DERP/control;
/// see `TunModeConfig::exit_node` docs).
///
/// **Linux**: best-effort `ip route add 0.0.0.0/0 dev <tun>` and
/// `::/0 dev <tun>`. This may fail or conflict with an existing default
/// route; failures are logged but non-fatal.
fn apply_exit_node_routes(ifname: &str) -> Result<(), TsnetError> {
    #[cfg(target_os = "macos")]
    {
        // IPv4: two /1 routes covering 0.0.0.0 – 255.255.255.255.
        run_cmd(
            "route",
            &["-q", "add", "-net", "0.0.0.0/1", "-interface", ifname],
        )?;
        run_cmd(
            "route",
            &["-q", "add", "-net", "128.0.0.0/1", "-interface", ifname],
        )?;
        // IPv6: two /1 routes covering :: – ffff::.
        run_cmd(
            "route",
            &["-q", "add", "-inet6", "::/1", "-interface", ifname],
        )?;
        run_cmd(
            "route",
            &["-q", "add", "-inet6", "8000::/1", "-interface", ifname],
        )?;
    }
    #[cfg(target_os = "linux")]
    {
        // Best-effort: ignore failures (default route may already exist).
        let _ = run_cmd("ip", &["route", "add", "0.0.0.0/0", "dev", ifname]);
        let _ = run_cmd("ip", &["-6", "route", "add", "::/0", "dev", ifname]);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = ifname;
    }
    Ok(())
}

/// Whether a CIDR's network address falls within the tailnet ranges
/// (100.64.0.0/10 or fd7a:115c:a1e0::/48). Used by `apply_accepted_subnet_routes`
/// to skip tailnet-range prefixes (handled by the blanket tailnet route).
fn is_tailnet_cidr(net: IpAddr, _prefix: u8) -> bool {
    match net {
        IpAddr::V4(v4) => {
            // 100.64.0.0/10 — mask the network address and compare.
            let mask = u32::MAX << (32 - 10);
            (u32::from(v4) & mask) == (u32::from(std::net::Ipv4Addr::new(100, 64, 0, 0)) & mask)
        }
        IpAddr::V6(v6) => {
            // fd7a:115c:a1e0::/48 — compare the first 6 bytes.
            let tail: [u8; 16] = "fd7a:115c:a1e0::"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets();
            v6.octets()[..6] == tail[..6]
        }
    }
}

/// Run a command, returning an error if it exits non-zero.
fn run_cmd(prog: &str, args: &[&str]) -> Result<(), TsnetError> {
    let status = std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .map_err(|e| TsnetError::Builder(format!("spawn {prog}: {e}")))?;
    if !status.success() {
        return Err(TsnetError::Builder(format!(
            "{prog} {args:?} exited with {status}"
        )));
    }
    Ok(())
}

async fn resolve_addr(addr: &str, inner: &RunningState) -> Result<SocketAddr, TsnetError> {
    resolve_addr_with(addr, &inner.resolver, &inner.peers).await
}

/// Resolve `addr` (`ip:port`, `hostname:port`, or `host:port`) to a
/// [`SocketAddr`] using the shared MagicDNS resolver, the peer list, and
/// finally the system DNS resolver.
///
/// Factored out of [`resolve_addr`] so the SOCKS5 production dialer (which
/// holds clones of the shared refs, not a `&RunningState`) can reuse the exact
/// same resolution path as [`Server::dial`].
async fn resolve_addr_with(
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
fn resolve_exit_node(peers: &[Node], ip_or_name: &str) -> Result<NodePublic, TsnetError> {
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

/// Best-effort: close all TCP connections visible to this process. Called
/// after exit-node route changes in TUN mode so that existing TCP
/// connections pick up the new routing. Logs the closed count on success
/// and the error on failure. Never called in netstack mode or tests —
/// closing the process's own DERP/control TCP fds there would kill the
/// data plane.
fn break_tcp_conns_best_effort() {
    match rustscale_tcpinfo::break_tcp_conns() {
        Ok(n) => {
            eprintln!("tsnet: broke {n} TCP connection(s) on exit-node change");
        }
        Err(e) => {
            eprintln!("tsnet: break_tcp_conns failed (non-fatal): {e}");
        }
    }
}

#[cfg(test)]
mod tests;
