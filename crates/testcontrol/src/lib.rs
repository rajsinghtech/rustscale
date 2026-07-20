//! In-process fake Tailscale control server for integration testing.
//!
//! Mirrors Go's `tstest/integration/testcontrol` package. A single-tailnet
//! control server that speaks the ts2021 Noise protocol, serves `/key`,
//! `/ts2021` (Noise upgrade), and h2c routes including `/machine/register`,
//! `/machine/map` (streaming long-poll), and `/machine/id-token`.
//!
//! # Usage
//!
//! ```no_run
//! # use rustscale_testcontrol::Server;
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let mut server = Server::new();
//! let addr = server.start().await?;
//! let url = server.base_url();
//! // Point a tsnet Server::builder() at `url` with .control_url(url).
//! server.add_fake_node();
//! assert!(server.num_nodes() >= 1);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use rustscale_controlclient::controlbase::{server_handshake, NoiseIo};
use rustscale_key::{DiscoPrivate, MachinePrivate, MachinePublic, NodePrivate, NodePublic};
use rustscale_tailcfg::{
    filter_allow_all, DERPMap, DNSConfig, FilterRule, Login, MapRequest, MapResponse, Node,
    NodeCapMap, NodeID, RegisterRequest, RegisterResponse, TKABootstrapRequest,
    TKABootstrapResponse, TKADisableRequest, TKAInfo, TKAInitBeginRequest, TKAInitBeginResponse,
    TKAInitFinishRequest, TKASignInfo, TKASubmitSignatureRequest, TKASyncOfferRequest,
    TKASyncOfferResponse, TKASyncSendRequest, TKASyncSendResponse, TokenRequest, TokenResponse,
    User, UserProfile,
};
use rustscale_tka::{Aum, Authority, MemChonk, NodeKeySignature, SyncOffer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

/// Domain name for the fake tailnet (matches Go's testcontrol).
const DOMAIN: &str = "fake-control.example.net";

/// Maximum encrypted message size (matches Go's testcontrol `msgLimit`).
#[allow(dead_code)]
const MSG_LIMIT: usize = 1 << 20;

/// Why a long-polling map request is being woken up.
#[derive(Clone, Copy, Debug)]
enum UpdateType {
    PeerChanged,
    SelfChanged,
    DebugInjection,
}

/// Internal server state, protected by a `std::sync::Mutex`.
struct ServerInner {
    noise_priv: MachinePrivate,
    noise_pub: MachinePublic,
    nodes: HashMap<NodePublic, Node>,
    users: HashMap<NodePublic, (User, Login)>,
    updates: HashMap<NodeID, mpsc::Sender<UpdateType>>,
    all_expired: bool,
    dns_config: Option<DNSConfig>,
    derp_map: Option<DERPMap>,
    node_cap_maps: HashMap<NodePublic, NodeCapMap>,
    msg_to_send: HashMap<NodePublic, VecDeque<MapResponse>>,
    suppress_auto: HashSet<NodePublic>,
    in_serve_map: i32,
    next_node_id: i64,
    next_connection_id: u64,
    noise_connection_count: u64,
    active_noise_connections: HashSet<u64>,
    map_connection_by_node: HashMap<NodePublic, u64>,
    c2n_callbacks: HashMap<String, NodePublic>,
    c2n_replies: HashMap<String, Vec<u8>>,
    rejected_c2n_callbacks: u64,
    map_update_response_size: usize,
    require_auth: bool,
    auth_paths: HashMap<String, Arc<Notify>>,
    auth_path_nodes: HashMap<String, NodePublic>,
    authed_nodes: HashSet<NodePublic>,
    last_auth_url: Option<String>,
    /// Node keys that have been logged out (sent a RegisterRequest with
    /// Expiry in the far past). Tests can check this via `saw_logout`.
    logged_out_nodes: HashSet<NodePublic>,
    /// Per-node key expiry. When a node key is in this set, its
    /// MapResponse will carry `Node.KeyExpiry` in the past and
    /// `RegisterResponse.NodeKeyExpired = true`. Used by key-rotation
    /// tests to force expiry on a specific node.
    expired_nodes: HashSet<NodePublic>,
    /// Whether each valid register request carried an Auth key. Values only,
    /// never credentials, are retained for security-sensitive client tests.
    register_auth_present: Vec<bool>,
    /// Test-only fingerprints used to detect replay without retaining raw
    /// auth keys.
    register_auth_fingerprints: Vec<Option<u64>>,
    /// Process the next register request but drop its response, simulating an
    /// ambiguous network failure after control may have consumed a one-use key.
    drop_next_register_response: bool,
    /// Reject one non-streaming map request. Tests use this to prove that a
    /// reachable control server can still require cached-map fallback.
    fail_next_non_stream_map_request: bool,
    token_response: TokenResponse,
    last_token_request: Option<TokenRequest>,
    base_url: String,
    tka_storage: MemChonk,
    tka_authority: Option<Authority>,
    tka_genesis: Option<Aum>,
    pending_tka_genesis: Option<(u64, Aum)>,
    drop_next_tka_init_finish_response: bool,
    tka_disabled: bool,
    tka_disablement_secret: Vec<u8>,
    tka_requests: Vec<(String, u64)>,
}

/// An in-process fake Tailscale control server.
///
/// Listens on a random loopback port. Nodes register via the ts2021 Noise
/// protocol, receive a netmap, and get streaming map updates. The test API
/// (`add_fake_node`, `set_expire_all_nodes`, `add_raw_map_response`, etc.)
/// lets tests force netmap events that would take hours to happen naturally.
pub struct Server {
    inner: Arc<Mutex<ServerInner>>,
    notify: Arc<Notify>,
    addr: Option<SocketAddr>,
    accept_task: Option<JoinHandle<()>>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// Create a new fake control server with a generated Noise key pair.
    /// Call [`start`](Self::start) to bind a listener.
    pub fn new() -> Self {
        let noise_priv = MachinePrivate::generate();
        let noise_pub = noise_priv.public();
        Self {
            inner: Arc::new(Mutex::new(ServerInner {
                noise_priv,
                noise_pub,
                nodes: HashMap::new(),
                users: HashMap::new(),
                updates: HashMap::new(),
                all_expired: false,
                dns_config: None,
                derp_map: None,
                node_cap_maps: HashMap::new(),
                msg_to_send: HashMap::new(),
                suppress_auto: HashSet::new(),
                in_serve_map: 0,
                next_node_id: 1,
                next_connection_id: 1,
                noise_connection_count: 0,
                active_noise_connections: HashSet::new(),
                map_connection_by_node: HashMap::new(),
                c2n_callbacks: HashMap::new(),
                c2n_replies: HashMap::new(),
                rejected_c2n_callbacks: 0,
                map_update_response_size: 0,
                require_auth: false,
                auth_paths: HashMap::new(),
                auth_path_nodes: HashMap::new(),
                authed_nodes: HashSet::new(),
                last_auth_url: None,
                logged_out_nodes: HashSet::new(),
                expired_nodes: HashSet::new(),
                register_auth_present: Vec::new(),
                register_auth_fingerprints: Vec::new(),
                drop_next_register_response: false,
                fail_next_non_stream_map_request: false,
                token_response: TokenResponse {
                    IDToken: "test.header.payload.signature".into(),
                },
                last_token_request: None,
                base_url: String::new(),
                tka_storage: MemChonk::new(),
                tka_authority: None,
                tka_genesis: None,
                pending_tka_genesis: None,
                drop_next_tka_init_finish_response: false,
                tka_disabled: false,
                tka_disablement_secret: Vec::new(),
                tka_requests: Vec::new(),
            })),
            notify: Arc::new(Notify::new()),
            addr: None,
            accept_task: None,
        }
    }

    /// Start the TCP listener on a random loopback port and spawn the accept
    /// loop. Returns the bound address.
    pub async fn start(&mut self) -> Result<SocketAddr, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        self.addr = Some(addr);
        {
            let mut inner = self.inner.lock().unwrap();
            inner.base_url = format!("http://{addr}");
        }

        let inner = self.inner.clone();
        let notify = self.notify.clone();
        self.accept_task = Some(tokio::spawn(accept_loop(listener, inner, notify)));

        Ok(addr)
    }

    /// The base URL for connecting to this server (e.g. `http://127.0.0.1:12345`).
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr.unwrap())
    }

    /// Stop accepting new control connections while preserving test state.
    /// Existing test clients should be closed before calling this helper.
    pub fn stop(&mut self) {
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
    }

    /// The server's Noise public key (also returned by `GET /key`).
    pub fn noise_public_key(&self) -> MachinePublic {
        self.inner.lock().unwrap().noise_pub.clone()
    }

    // -----------------------------------------------------------------
    // Test API
    // -----------------------------------------------------------------

    /// Process the next register request but close its response stream.
    pub fn drop_next_register_response(&self) {
        self.inner.lock().unwrap().drop_next_register_response = true;
    }

    /// Reject the next non-streaming `/machine/map` request with HTTP 503.
    /// Streaming map polls remain available so tests can subsequently inject
    /// keepalives, deltas, or a complete authoritative snapshot.
    pub fn fail_next_non_stream_map_request(&self) {
        self.inner.lock().unwrap().fail_next_non_stream_map_request = true;
    }

    /// Prevent generated map frames for one node until
    /// [`resume_auto_map`](Self::resume_auto_map) is called.
    pub fn suppress_auto_map(&self, node_key: &NodePublic) {
        self.inner
            .lock()
            .unwrap()
            .suppress_auto
            .insert(node_key.clone());
    }

    /// Snapshot whether each valid register request carried an auth key.
    pub fn register_auth_presence(&self) -> Vec<bool> {
        self.inner.lock().unwrap().register_auth_present.clone()
    }

    /// Snapshot fingerprints of register auth keys without retaining them.
    pub fn register_auth_fingerprints(&self) -> Vec<Option<u64>> {
        self.inner
            .lock()
            .unwrap()
            .register_auth_fingerprints
            .clone()
    }

    /// Configure the response returned by `POST /machine/id-token`.
    pub fn set_id_token(&self, token: impl Into<String>) {
        self.inner.lock().unwrap().token_response.IDToken = token.into();
    }

    /// Return the most recent identity-token request received by control.
    pub fn last_token_request(&self) -> Option<TokenRequest> {
        self.inner.lock().unwrap().last_token_request.clone()
    }

    /// Number of registered nodes (real + fake).
    pub fn num_nodes(&self) -> usize {
        self.inner.lock().unwrap().nodes.len()
    }

    /// All nodes, sorted by StableID (matching Go's `AllNodes`).
    pub fn all_nodes(&self) -> Vec<Node> {
        let mut nodes: Vec<Node> = self.inner.lock().unwrap().nodes.values().cloned().collect();
        nodes.sort_by(|a, b| a.StableID.cmp(&b.StableID));
        nodes
    }

    /// Get a node by key (returns a clone).
    pub fn node(&self, key: &NodePublic) -> Option<Node> {
        self.inner.lock().unwrap().nodes.get(key).cloned()
    }

    /// Inject a fake node into the server's node map and notify all existing
    /// streaming map polls of the change (matching Go's `AddFakeNode` plus
    /// the TODO that Go leaves unimplemented — we actually send updates).
    pub fn add_fake_node(&self) {
        let mut inner = self.inner.lock().unwrap();
        let nk = NodePrivate::generate().public();
        let mk = MachinePrivate::generate().public();
        let dk = DiscoPrivate::generate().public();
        let id = inner.next_node_id;
        inner.next_node_id += 1;
        let ip4 = format!("100.64.{}.{}", (id >> 8) as u8, id as u8);
        let addr4 = format!("{ip4}/32");
        inner.nodes.insert(
            nk.clone(),
            Node {
                ID: id,
                StableID: format!("TESTCTRL{id:08x}"),
                User: id,
                Machine: mk,
                Key: nk,
                DiscoKey: dk,
                Addresses: vec![addr4.clone()],
                AllowedIPs: vec![addr4],
                ..Default::default()
            },
        );
        // Notify all existing streaming polls.
        for tx in inner.updates.values() {
            let _ = tx.try_send(UpdateType::PeerChanged);
        }
    }

    /// Inject a dual-stack, approved exit-node peer and return its exact map
    /// representation. This keeps CLI/LocalAPI route tests hermetic while
    /// exercising the same `AllowedIPs` capability predicate as production.
    pub fn add_fake_exit_node(&self, name: impl Into<String>, online: bool) -> Node {
        let mut inner = self.inner.lock().unwrap();
        let nk = NodePrivate::generate().public();
        let id = inner.next_node_id;
        inner.next_node_id += 1;
        let ip4 = format!("100.64.{}.{}", (id >> 8) as u8, id as u8);
        let ip6 = format!("fd7a:115c:a1e0::{id:x}");
        let addr4 = format!("{ip4}/32");
        let addr6 = format!("{ip6}/128");
        let node = Node {
            ID: id,
            StableID: format!("TESTCTRL{id:08x}"),
            User: id,
            Machine: MachinePrivate::generate().public(),
            Key: nk.clone(),
            DiscoKey: DiscoPrivate::generate().public(),
            Addresses: vec![addr4.clone(), addr6.clone()],
            AllowedIPs: vec![addr4, addr6, "0.0.0.0/0".into(), "::/0".into()],
            Name: name.into(),
            Online: Some(online),
            ..Default::default()
        };
        inner.nodes.insert(nk, node.clone());
        for tx in inner.updates.values() {
            let _ = tx.try_send(UpdateType::PeerChanged);
        }
        node
    }

    /// Replace a node's advertised transport endpoints and notify every live
    /// map stream. Tests use this to model a control-plane endpoint update
    /// without depending on host STUN or DERP connectivity.
    pub fn set_node_endpoints(&self, node_key: &NodePublic, endpoints: Vec<String>) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(node) = inner.nodes.get_mut(node_key) {
            node.Endpoints = endpoints;
        }
        for tx in inner.updates.values() {
            let _ = tx.try_send(UpdateType::PeerChanged);
        }
    }

    /// Set a node's control-plane online state and notify every live map
    /// stream. This is testcontrol state only; it does not imply transport
    /// activity, which remains independently evidenced by magicsock.
    pub fn set_node_online(&self, node_key: &NodePublic, online: bool) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(node) = inner.nodes.get_mut(node_key) {
            node.Online = Some(online);
        }
        for tx in inner.updates.values() {
            let _ = tx.try_send(UpdateType::PeerChanged);
        }
    }

    /// Override the capability map sent to a specific client.
    pub fn set_node_cap_map(&self, node_key: &NodePublic, cap_map: NodeCapMap) {
        let mut inner = self.inner.lock().unwrap();
        inner.node_cap_maps.insert(node_key.clone(), cap_map);
        for tx in inner.updates.values() {
            let _ = tx.try_send(UpdateType::PeerChanged);
        }
    }

    /// Mark all node keys as expired (or unexpired).
    pub fn set_expire_all_nodes(&self, expired: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.all_expired = expired;
        for tx in inner.updates.values() {
            let _ = tx.try_send(UpdateType::SelfChanged);
        }
    }

    /// Force key expiry on a specific node. The node's next MapResponse
    /// will carry `Node.KeyExpiry` in the past, and `RegisterResponse`
    /// will have `NodeKeyExpired = true`. Use this to test key rotation
    /// without affecting other nodes.
    pub fn expire_node_key(&self, node_key: &NodePublic) {
        let mut inner = self.inner.lock().unwrap();
        inner.expired_nodes.insert(node_key.clone());
        // Trigger a map update so the node sees the expiry immediately.
        if let Some(node) = inner.nodes.get(node_key) {
            if let Some(tx) = inner.updates.get(&node.ID) {
                let _ = tx.try_send(UpdateType::SelfChanged);
            }
        }
    }

    /// Clear key expiry on a specific node.
    pub fn unexpire_node_key(&self, node_key: &NodePublic) {
        let mut inner = self.inner.lock().unwrap();
        inner.expired_nodes.remove(node_key);
    }

    /// Returns true if the given node key has been force-expired via
    /// [`expire_node_key`].
    pub fn is_node_expired(&self, node_key: &NodePublic) -> bool {
        self.inner.lock().unwrap().expired_nodes.contains(node_key)
    }

    /// Set the DNS config to include in map responses.
    pub fn set_dns_config(&self, dns: DNSConfig) {
        let mut inner = self.inner.lock().unwrap();
        inner.dns_config = Some(dns);
        for tx in inner.updates.values() {
            let _ = tx.try_send(UpdateType::SelfChanged);
        }
    }

    /// Set the DERPMap to include in map responses. When set, all map
    /// responses will include this DERPMap instead of the empty default.
    /// Used by integration tests to point nodes at a local DERP server.
    pub fn set_derp_map(&self, derp_map: DERPMap) {
        let mut inner = self.inner.lock().unwrap();
        inner.derp_map = Some(derp_map);
        for tx in inner.updates.values() {
            let _ = tx.try_send(UpdateType::SelfChanged);
        }
    }

    /// Inject a raw `MapResponse` to a node's stream. Once injected, all
    /// future automatic map responses to that node are suppressed — only
    /// explicit injections are sent (matching Go's `AddRawMapResponse`).
    ///
    /// Returns `true` if the node was connected (had an active streaming poll).
    pub fn add_raw_map_response(&self, node_key: &NodePublic, mr: MapResponse) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let node = match inner.nodes.get(node_key) {
            Some(n) => n.clone(),
            None => return false,
        };
        if !inner.updates.contains_key(&node.ID) {
            return false;
        }
        inner.suppress_auto.insert(node_key.clone());
        inner
            .msg_to_send
            .entry(node_key.clone())
            .or_default()
            .push_back(mr);
        if let Some(tx) = inner.updates.get(&node.ID) {
            let _ = tx.try_send(UpdateType::DebugInjection);
        }
        true
    }

    /// Inject several map responses in one HTTP/2 DATA chunk. This is useful
    /// for testing client cancellation with already-buffered frames.
    pub fn add_raw_map_responses(
        &self,
        node_key: &NodePublic,
        responses: impl IntoIterator<Item = MapResponse>,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let node = match inner.nodes.get(node_key) {
            Some(node) => node.clone(),
            None => return false,
        };
        if !inner.updates.contains_key(&node.ID) {
            return false;
        }
        inner.suppress_auto.insert(node_key.clone());
        inner
            .msg_to_send
            .entry(node_key.clone())
            .or_default()
            .extend(responses);
        if let Some(tx) = inner.updates.get(&node.ID) {
            let _ = tx.try_send(UpdateType::DebugInjection);
        }
        true
    }

    /// Snapshot Tailnet Lock RPC paths and the Noise connection that carried
    /// each request. No request bodies or secret material are retained.
    pub fn tka_request_connections(&self) -> Vec<(String, u64)> {
        self.inner.lock().unwrap().tka_requests.clone()
    }

    /// Commit the next TKA init finish request, then drop its HTTP response.
    pub fn drop_next_tka_init_finish_response(&self) {
        self.inner
            .lock()
            .unwrap()
            .drop_next_tka_init_finish_response = true;
    }

    /// Resume generated map responses after `add_raw_map_response` suppressed
    /// them for deterministic delta testing.
    pub fn resume_auto_map(&self, node_key: &NodePublic) {
        self.inner.lock().unwrap().suppress_auto.remove(node_key);
    }

    /// Wait until the given node key has an active streaming map poll, or
    /// timeout. Mirrors Go's `AwaitNodeInMapRequest`.
    pub async fn await_node_in_map_request(
        &self,
        node_key: &NodePublic,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let inner = self.inner.lock().unwrap();
                if let Some(node) = inner.nodes.get(node_key) {
                    if inner.updates.contains_key(&node.ID) {
                        return Ok(());
                    }
                } else {
                    return Err("unknown node key".into());
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("timeout waiting for node in map request".into());
            }
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(50), self.notify.notified())
                    .await;
        }
    }

    /// Number of clients currently in a streaming map poll.
    pub fn in_serve_map(&self) -> i32 {
        self.inner.lock().unwrap().in_serve_map
    }

    /// Number of Noise connections accepted since server start.
    pub fn noise_connection_count(&self) -> u64 {
        self.inner.lock().unwrap().noise_connection_count
    }

    /// Number of currently active Noise connections.
    pub fn active_noise_connection_count(&self) -> usize {
        self.inner.lock().unwrap().active_noise_connections.len()
    }

    /// Create a callback URL that accepts a C2N reply only on this node's
    /// active map connection.
    pub fn c2n_callback_url(&self, node_key: &NodePublic) -> String {
        let mut inner = self.inner.lock().unwrap();
        let path = format!("/c2n/{}", inner.c2n_callbacks.len() + 1);
        inner.c2n_callbacks.insert(path.clone(), node_key.clone());
        format!("{}{}", inner.base_url, path)
    }

    /// Return a C2N reply body accepted by the callback endpoint.
    pub fn c2n_reply(&self, callback_url: &str) -> Option<Vec<u8>> {
        let path = callback_url
            .find("/c2n/")
            .map_or(callback_url, |index| &callback_url[index..]);
        self.inner.lock().unwrap().c2n_replies.get(path).cloned()
    }

    pub fn rejected_c2n_callbacks(&self) -> u64 {
        self.inner.lock().unwrap().rejected_c2n_callbacks
    }

    /// Configure a large successful response body for lite map updates.
    pub fn set_map_update_response_size(&self, size: usize) {
        self.inner.lock().unwrap().map_update_response_size = size;
    }

    /// Enable or disable interactive auth requirement. When enabled, new
    /// register requests receive an AuthURL and must be completed via
    /// [`complete_auth`](Self::complete_auth) before proceeding.
    pub fn set_require_auth(&self, v: bool) {
        self.inner.lock().unwrap().require_auth = v;
    }

    /// Complete the auth flow for the given auth URL or path. Finds the
    /// matching entry in `auth_paths`, marks the node as authed, and
    /// notifies the blocked register request. Returns `true` if the auth
    /// path was found and completed.
    pub fn complete_auth(&self, auth_url_or_path: &str) -> bool {
        let path = extract_auth_path(auth_url_or_path);
        let mut inner = self.inner.lock().unwrap();
        if let Some(notify) = inner.auth_paths.remove(&path) {
            if let Some(nk) = inner.auth_path_nodes.remove(&path) {
                inner.authed_nodes.insert(nk);
            }
            notify.notify_waiters();
            return true;
        }
        false
    }

    /// Wait until a register produces an AuthURL and return it. Times out
    /// after `timeout`.
    pub async fn await_auth_url(&self, timeout: std::time::Duration) -> Result<String, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let inner = self.inner.lock().unwrap();
                if let Some(ref url) = inner.last_auth_url {
                    return Ok(url.clone());
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("timeout waiting for auth URL".into());
            }
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(50), self.notify.notified())
                    .await;
        }
    }

    /// Returns true if the given node key sent a logout register request
    /// (RegisterRequest with Expiry in the far past).
    pub fn saw_logout(&self, nk: &NodePublic) -> bool {
        self.inner.lock().unwrap().logged_out_nodes.contains(nk)
    }
}

// -----------------------------------------------------------------
// Accept loop and HTTP/1.1 routing
// -----------------------------------------------------------------

/// Main accept loop: spawns a task per connection.
async fn accept_loop(listener: TcpListener, inner: Arc<Mutex<ServerInner>>, notify: Arc<Notify>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let inner = inner.clone();
                let notify = notify.clone();
                tokio::spawn(handle_connection(stream, inner, notify));
            }
            Err(_) => break,
        }
    }
}

/// Handle one TCP connection: read the HTTP/1.1 request line + headers,
/// then dispatch to the appropriate handler.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    inner: Arc<Mutex<ServerInner>>,
    notify: Arc<Notify>,
) {
    // Read the HTTP request headers (until \r\n\r\n).
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        match stream.read_exact(&mut byte).await {
            Ok(_) => {
                buf.push(byte[0]);
                if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                    break;
                }
                if buf.len() > 65536 {
                    return;
                }
            }
            Err(_) => return,
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let request_line = match lines.next() {
        Some(l) => l,
        None => return,
    };
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];

    let headers: HashMap<String, String> = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| {
            let mut split = l.splitn(2, ':');
            let key = split.next()?.trim().to_lowercase();
            let val = split.next()?.trim().to_string();
            Some((key, val))
        })
        .collect();

    match (method, path) {
        ("GET", p) if p.starts_with("/key") => {
            serve_key(&mut stream, &inner, p).await;
        }
        ("POST" | "GET", "/ts2021") => {
            serve_noise_upgrade(stream, &inner, &headers, notify).await;
        }
        _ => {
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes()).await;
        }
    }
}

/// `GET /key?v=<version>` → JSON with `publicKey` and `legacyPublicKey`.
async fn serve_key(
    stream: &mut tokio::net::TcpStream,
    inner: &Arc<Mutex<ServerInner>>,
    path: &str,
) {
    let noise_pub = inner.lock().unwrap().noise_pub.clone();
    let has_v = path.contains("?v=");
    let body = if has_v {
        serde_json::json!({
            "legacyPublicKey": noise_pub.clone(),
            "publicKey": noise_pub,
        })
        .to_string()
    } else {
        noise_pub.to_string()
    };
    let resp =
        format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        if has_v { "application/json" } else { "text/plain" },
        body.len(),
        body,
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

/// `POST /ts2021` → 101 Switching Protocols + Noise handshake + h2c.
async fn serve_noise_upgrade(
    mut stream: tokio::net::TcpStream,
    inner: &Arc<Mutex<ServerInner>>,
    headers: &HashMap<String, String>,
    notify: Arc<Notify>,
) {
    // Extract the base64-encoded Noise initiation from the header.
    let init_b64 = if let Some(v) = headers.get("x-tailscale-handshake") {
        v
    } else {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    };
    let init_bytes = if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(init_b64) {
        b
    } else {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    };

    let noise_priv = inner.lock().unwrap().noise_priv.clone();

    // Do the server-side Noise handshake. We use a Vec as the writer to
    // capture the 51-byte response, then write it to the TCP stream after
    // the HTTP 101 headers.
    let mut resp_buf: Vec<u8> = Vec::new();
    let conn = {
        let mut empty = std::io::empty();
        if let Ok(c) = server_handshake(&mut empty, &mut resp_buf, &noise_priv, Some(&init_bytes)) {
            c
        } else {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
    };
    let peer_machine_key = conn.peer();

    // Write the 101 response + Noise response bytes.
    let http_resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\r\n";
    if stream.write_all(http_resp.as_bytes()).await.is_err() {
        return;
    }
    if stream.write_all(&resp_buf).await.is_err() {
        return;
    }
    let _ = stream.flush().await;

    // Wrap the Noise connection in NoiseIo (byte-stream over Noise records).
    let noise_io = NoiseIo::new(conn, stream);

    // Run the h2 server over the Noise transport.
    let h2_conn = match h2::server::handshake(noise_io).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let connection_id = {
        let mut state = inner.lock().unwrap();
        let id = state.next_connection_id;
        state.next_connection_id += 1;
        state.noise_connection_count += 1;
        state.active_noise_connections.insert(id);
        id
    };
    notify.notify_waiters();

    handle_h2_connection(
        h2_conn,
        peer_machine_key,
        connection_id,
        inner.clone(),
        notify.clone(),
    )
    .await;
    {
        let mut state = inner.lock().unwrap();
        state.active_noise_connections.remove(&connection_id);
        if state
            .pending_tka_genesis
            .as_ref()
            .is_some_and(|(pending_connection, _)| *pending_connection == connection_id)
            && state.tka_authority.is_none()
        {
            state.pending_tka_genesis = None;
        }
    }
    notify.notify_waiters();
}

// -----------------------------------------------------------------
// h2c request handling
// -----------------------------------------------------------------

/// Process h2 requests over the Noise-upgraded connection.
async fn handle_h2_connection(
    mut h2_conn: h2::server::Connection<NoiseIo, bytes::Bytes>,
    peer_machine_key: MachinePublic,
    connection_id: u64,
    inner: Arc<Mutex<ServerInner>>,
    notify: Arc<Notify>,
) {
    while let Some(req) = h2_conn.accept().await {
        let (request, respond) = match req {
            Ok(r) => r,
            Err(_) => continue,
        };
        let path = request.uri().path().to_string();
        let method = request.method().to_string();
        let inner = inner.clone();
        let notify = notify.clone();
        let peer = peer_machine_key.clone();
        tokio::spawn(async move {
            let req_body = request.into_body();
            if let Err(()) = handle_h2_request(
                &method,
                &path,
                req_body,
                respond,
                &inner,
                &peer,
                connection_id,
                &notify,
            )
            .await
            {
                // Error already handled inside; nothing to do here.
            }
        });
    }
}

/// Read the full h2 request body.
async fn read_h2_body(body: &mut h2::RecvStream) -> Result<Vec<u8>, h2::Error> {
    read_h2_body_bounded(body, 16 * 1024 * 1024).await
}

async fn read_h2_body_bounded(
    body: &mut h2::RecvStream,
    limit: usize,
) -> Result<Vec<u8>, h2::Error> {
    let mut data = Vec::new();
    while let Some(frame) = body.data().await {
        let frame = frame?;
        let _ = body.flow_control().release_capacity(frame.len());
        if data.len().saturating_add(frame.len()) > limit {
            return Err(h2::Error::from(h2::Reason::ENHANCE_YOUR_CALM));
        }
        data.extend_from_slice(&frame);
    }
    Ok(data)
}

/// Route and handle one h2 request.
async fn handle_h2_request(
    method: &str,
    path: &str,
    mut req_body: h2::RecvStream,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    inner: &Arc<Mutex<ServerInner>>,
    peer_machine_key: &MachinePublic,
    connection_id: u64,
    notify: &Arc<Notify>,
) -> Result<(), ()> {
    let tka_get = method == "GET" && path.starts_with("/machine/tka/");
    if method != "POST" && !tka_get {
        let resp = http::Response::builder().status(400).body(()).unwrap();
        let _ = respond.send_response(resp, true);
        return Ok(());
    }

    match path {
        "/machine/register" => {
            let body = read_h2_body(&mut req_body).await.map_err(|_| ())?;
            let resp_body = serve_register(&body, peer_machine_key, inner, notify).await;
            let drop_response = {
                let mut state = inner.lock().unwrap();
                std::mem::take(&mut state.drop_next_register_response)
            };
            if drop_response {
                return Ok(());
            }
            let resp = http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(())
                .unwrap();
            let mut send = respond.send_response(resp, false).map_err(|_| ())?;
            send.send_data(bytes::Bytes::from(resp_body), true)
                .map_err(|_| ())?;
        }
        "/machine/map" => {
            let body = read_h2_body(&mut req_body).await.map_err(|_| ())?;
            serve_map(
                &body,
                peer_machine_key,
                connection_id,
                inner,
                notify,
                respond,
            )
            .await;
        }
        "/machine/update-health" => {
            // Drain body, respond 204.
            while req_body.data().await.is_some() {}
            let resp = http::Response::builder().status(204).body(()).unwrap();
            let _ = respond.send_response(resp, true);
        }
        "/machine/id-token" => {
            let body = read_h2_body(&mut req_body).await.map_err(|_| ())?;
            let request: TokenRequest = match serde_json::from_slice(&body) {
                Ok(request) => request,
                Err(error) => {
                    let resp = http::Response::builder()
                        .status(400)
                        .header("content-type", "text/plain")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(resp, false).map_err(|_| ())?;
                    send.send_data(bytes::Bytes::from(error.to_string()), true)
                        .map_err(|_| ())?;
                    return Ok(());
                }
            };
            let response = {
                let mut inner = inner.lock().unwrap();
                inner.last_token_request = Some(request);
                serde_json::to_vec(&inner.token_response).map_err(|_| ())?
            };
            let resp = http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(())
                .unwrap();
            let mut send = respond.send_response(resp, false).map_err(|_| ())?;
            send.send_data(bytes::Bytes::from(response), true)
                .map_err(|_| ())?;
        }
        path if path.starts_with("/machine/tka/") => {
            inner
                .lock()
                .unwrap()
                .tka_requests
                .push((path.to_string(), connection_id));
            let Ok(body) = read_h2_body_bounded(&mut req_body, 8 * 1024 * 1024).await else {
                let response = http::Response::builder().status(413).body(()).unwrap();
                let _ = respond.send_response(response, true);
                return Ok(());
            };
            let (status, response_body) =
                serve_tka(path, &body, peer_machine_key, connection_id, inner, notify);
            if path == "/machine/tka/init/finish"
                && std::mem::take(&mut inner.lock().unwrap().drop_next_tka_init_finish_response)
            {
                return Ok(());
            }
            let response = http::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).map_err(|_| ())?;
            send.send_data(bytes::Bytes::from(response_body), true)
                .map_err(|_| ())?;
        }
        path if path.starts_with("/c2n/") => {
            let body = read_h2_body(&mut req_body).await.map_err(|_| ())?;
            let accepted = {
                let mut state = inner.lock().unwrap();
                let node_key = state.c2n_callbacks.get(path).cloned();
                let accepted = node_key.as_ref().is_some_and(|node_key| {
                    state.map_connection_by_node.get(node_key) == Some(&connection_id)
                });
                if accepted {
                    state.c2n_replies.insert(path.to_string(), body);
                } else {
                    state.rejected_c2n_callbacks += 1;
                }
                accepted
            };
            notify.notify_waiters();
            let resp = http::Response::builder()
                .status(if accepted { 200 } else { 409 })
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
        }
        _ => {
            let resp = http::Response::builder().status(404).body(()).unwrap();
            let _ = respond.send_response(resp, true);
        }
    }
    Ok(())
}

// -----------------------------------------------------------------
// /machine/tka/*
// -----------------------------------------------------------------

fn serve_tka(
    path: &str,
    body: &[u8],
    peer_machine_key: &MachinePublic,
    connection_id: u64,
    inner: &Arc<Mutex<ServerInner>>,
    notify: &Arc<Notify>,
) -> (u16, Vec<u8>) {
    fn json<T: serde::Serialize>(value: &T) -> (u16, Vec<u8>) {
        (
            200,
            serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
        )
    }
    fn error(status: u16) -> (u16, Vec<u8>) {
        (
            status,
            b"{\"error\":\"Tailnet Lock request rejected\"}".to_vec(),
        )
    }
    fn authenticated(
        inner: &ServerInner,
        node_key: &NodePublic,
        machine_key: &MachinePublic,
    ) -> bool {
        !node_key.is_zero()
            && inner
                .nodes
                .get(node_key)
                .is_some_and(|node| node.Machine == *machine_key)
    }

    match path {
        "/machine/tka/init/begin" => {
            let Ok(request) = serde_json::from_slice::<TKAInitBeginRequest>(body) else {
                return error(400);
            };
            {
                let state = inner.lock().unwrap();
                if !authenticated(&state, &request.NodeKey, peer_machine_key)
                    || state.tka_authority.is_some()
                    || state.pending_tka_genesis.is_some()
                {
                    return error(409);
                }
            }
            let Ok(genesis) = Aum::decode(&request.GenesisAUM) else {
                return error(400);
            };
            let temporary = MemChonk::new();
            if Authority::bootstrap(&temporary, genesis.clone()).is_err() {
                return error(400);
            }
            let need_signatures = {
                let mut state = inner.lock().unwrap();
                state.pending_tka_genesis = Some((connection_id, genesis));
                state
                    .nodes
                    .values()
                    .map(|node| TKASignInfo {
                        NodeID: node.ID,
                        NodePublic: node.Key.clone(),
                        RotationPubkey: Vec::new(),
                    })
                    .collect()
            };
            json(&TKAInitBeginResponse {
                NeedSignatures: need_signatures,
            })
        }
        "/machine/tka/init/finish" => {
            let Ok(request) = serde_json::from_slice::<TKAInitFinishRequest>(body) else {
                return error(400);
            };
            let mut state = inner.lock().unwrap();
            if !authenticated(&state, &request.NodeKey, peer_machine_key) {
                return error(403);
            }
            let Some((begin_connection, genesis)) = state.pending_tka_genesis.clone() else {
                return error(409);
            };
            if begin_connection != connection_id {
                return error(409);
            }
            let storage = MemChonk::new();
            let Ok(authority) = Authority::bootstrap(&storage, genesis.clone()) else {
                return error(400);
            };
            if request.Signatures.len() != state.nodes.len() {
                return error(400);
            }
            let node_signatures = state
                .nodes
                .values()
                .map(|node| {
                    let signature = request.Signatures.get(&node.ID)?;
                    authority
                        .node_key_authorized(&node.Key.raw32(), signature)
                        .ok()?;
                    Some((node.Key.clone(), signature.clone()))
                })
                .collect::<Option<Vec<_>>>();
            let Some(node_signatures) = node_signatures else {
                return error(400);
            };
            for (node_key, signature) in node_signatures {
                if let Some(node) = state.nodes.get_mut(&node_key) {
                    node.KeySignature = Some(signature);
                }
            }
            state.tka_storage = storage;
            state.tka_authority = Some(authority);
            state.tka_genesis = Some(genesis);
            state.pending_tka_genesis = None;
            state.tka_disabled = false;
            state.tka_disablement_secret.clear();
            for sender in state.updates.values() {
                let _ = sender.try_send(UpdateType::PeerChanged);
            }
            drop(state);
            notify.notify_waiters();
            json(&serde_json::json!({}))
        }
        "/machine/tka/bootstrap" => {
            let Ok(request) = serde_json::from_slice::<TKABootstrapRequest>(body) else {
                return error(400);
            };
            let state = inner.lock().unwrap();
            if !authenticated(&state, &request.NodeKey, peer_machine_key) {
                return error(403);
            }
            if state.tka_disabled {
                return json(&TKABootstrapResponse {
                    GenesisAUM: Vec::new(),
                    DisablementSecret: state.tka_disablement_secret.clone(),
                });
            }
            let Some(genesis) = state.tka_genesis.as_ref() else {
                return error(409);
            };
            json(&TKABootstrapResponse {
                GenesisAUM: genesis.encode(),
                DisablementSecret: Vec::new(),
            })
        }
        "/machine/tka/sync/offer" => {
            let Ok(request) = serde_json::from_slice::<TKASyncOfferRequest>(body) else {
                return error(400);
            };
            let state = inner.lock().unwrap();
            if !authenticated(&state, &request.NodeKey, peer_machine_key) {
                return error(403);
            }
            let Some(authority) = state.tka_authority.as_ref() else {
                return error(409);
            };
            let Ok(remote) = SyncOffer::from_strings(&request.Head, &request.Ancestors) else {
                return error(400);
            };
            let Ok(local) = authority.sync_offer(&state.tka_storage) else {
                return error(500);
            };
            let missing = if local.head == remote.head {
                Vec::new()
            } else {
                let Ok(missing) = authority.missing_aums(&state.tka_storage, &remote) else {
                    return error(409);
                };
                missing.into_iter().map(|aum| aum.encode()).collect()
            };
            let (head, ancestors) = local.to_strings();
            json(&TKASyncOfferResponse {
                Head: head,
                Ancestors: ancestors,
                MissingAUMs: missing,
            })
        }
        "/machine/tka/sync/send" => {
            let Ok(request) = serde_json::from_slice::<TKASyncSendRequest>(body) else {
                return error(400);
            };
            if request.MissingAUMs.len() > 2000 {
                return error(413);
            }
            let updates = match request
                .MissingAUMs
                .iter()
                .map(|bytes| Aum::decode(bytes))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(updates) => updates,
                Err(_) => return error(400),
            };
            let mut state = inner.lock().unwrap();
            if !authenticated(&state, &request.NodeKey, peer_machine_key) {
                return error(403);
            }
            let Some(mut authority) = state.tka_authority.clone() else {
                return error(409);
            };
            if !updates.is_empty() && authority.inform(&state.tka_storage, &updates).is_err() {
                return error(400);
            }
            state.tka_authority = Some(authority.clone());
            for sender in state.updates.values() {
                let _ = sender.try_send(UpdateType::PeerChanged);
            }
            json(&TKASyncSendResponse {
                Head: authority.head().to_string(),
            })
        }
        "/machine/tka/sign" => {
            let Ok(request) = serde_json::from_slice::<TKASubmitSignatureRequest>(body) else {
                return error(400);
            };
            let mut state = inner.lock().unwrap();
            if !authenticated(&state, &request.NodeKey, peer_machine_key) {
                return error(403);
            }
            let Some(authority) = state.tka_authority.as_ref() else {
                return error(409);
            };
            let Ok(signature) = NodeKeySignature::decode(&request.Signature) else {
                return error(400);
            };
            let Some(public) = signature
                .pubkey
                .as_deref()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .map(NodePublic::from_raw32)
            else {
                return error(400);
            };
            if authority
                .node_key_authorized(&public.raw32(), &request.Signature)
                .is_err()
                || !state.nodes.contains_key(&public)
            {
                return error(400);
            }
            state.nodes.get_mut(&public).unwrap().KeySignature = Some(request.Signature);
            for sender in state.updates.values() {
                let _ = sender.try_send(UpdateType::PeerChanged);
            }
            json(&serde_json::json!({}))
        }
        "/machine/tka/disable" => {
            let Ok(request) = serde_json::from_slice::<TKADisableRequest>(body) else {
                return error(400);
            };
            if request.DisablementSecret.len() > 1024 {
                return error(413);
            }
            let mut state = inner.lock().unwrap();
            if !authenticated(&state, &request.NodeKey, peer_machine_key) {
                return error(403);
            }
            let Some(authority) = state.tka_authority.as_ref() else {
                return error(409);
            };
            if request.Head != authority.head().to_string()
                || !authority.valid_disablement(&request.DisablementSecret)
            {
                return error(400);
            }
            state.tka_disablement_secret = request.DisablementSecret;
            state.tka_authority = None;
            state.tka_storage = MemChonk::new();
            state.tka_disabled = true;
            for sender in state.updates.values() {
                let _ = sender.try_send(UpdateType::PeerChanged);
            }
            drop(state);
            notify.notify_waiters();
            json(&serde_json::json!({}))
        }
        _ => error(404),
    }
}

// -----------------------------------------------------------------
// /machine/register
// -----------------------------------------------------------------

/// Handle a register request: create/update the node, return a RegisterResponse.
/// When `require_auth` is enabled and the node hasn't been authed, returns an
/// AuthURL. When `Followup` is set, blocks until `complete_auth` is called.
async fn serve_register(
    body: &[u8],
    peer_machine_key: &MachinePublic,
    inner: &Arc<Mutex<ServerInner>>,
    notify: &Arc<Notify>,
) -> Vec<u8> {
    let req: RegisterRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => {
            return serde_json::to_vec(&RegisterResponse {
                Error: "bad register request".into(),
                ..Default::default()
            })
            .unwrap_or_default();
        }
    };
    if req.Version == 0 || req.NodeKey.is_zero() {
        return serde_json::to_vec(&RegisterResponse {
            Error: "invalid register request".into(),
            ..Default::default()
        })
        .unwrap_or_default();
    }
    let auth_fingerprint = req.Auth.as_ref().map(|auth| {
        let mut hasher = DefaultHasher::new();
        auth.AuthKey.hash(&mut hasher);
        hasher.finish()
    });
    {
        let mut state = inner.lock().unwrap();
        state.register_auth_present.push(req.Auth.is_some());
        state.register_auth_fingerprints.push(auth_fingerprint);
    }

    let nk = req.NodeKey.clone();

    // Key rotation: when OldNodeKey is non-zero and known to the server,
    // transfer the node's identity from the old key to the new key.
    // Matches Go testcontrol at testcontrol.go:930-950.
    if !req.OldNodeKey.is_zero() {
        let mut g = inner.lock().unwrap();
        if let Some(old_node) = g.nodes.get(&req.OldNodeKey).cloned() {
            if !g.nodes.contains_key(&nk) {
                let mut cloned = old_node.clone();
                cloned.Key = nk.clone();
                g.nodes.insert(nk.clone(), cloned);
            }
            // Transfer user/login mappings to the new key.
            if let Some((u, l)) = g.users.get(&req.OldNodeKey).cloned() {
                g.users.insert(nk.clone(), (u, l));
            }
            // On a followup (auth completed), retire the old key.
            if !req.Followup.is_empty() {
                g.nodes.remove(&req.OldNodeKey);
                g.users.remove(&req.OldNodeKey);
                // Clear per-node expiry on the old key.
                g.expired_nodes.remove(&req.OldNodeKey);
            }
        }
    }

    // Detect logout requests: Expiry set to the far past (before 2000).
    // The control server should expire the node key. We record it for
    // test verification and remove the node from the authed set.
    if let Some(ref expiry) = req.Expiry {
        if *expiry
            < chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        {
            let mut g = inner.lock().unwrap();
            g.logged_out_nodes.insert(nk.clone());
            g.authed_nodes.remove(&nk);
            let resp = RegisterResponse {
                MachineAuthorized: false,
                ..Default::default()
            };
            return serde_json::to_vec(&resp).unwrap_or_default();
        }
    }

    // If this is a followup request, block until auth is completed.
    if !req.Followup.is_empty() {
        let path = extract_auth_path(&req.Followup);
        wait_for_auth_completion(inner, &path, &nk).await;
        let mut g = inner.lock().unwrap();
        let (user, login) = get_or_create_user(&mut g, &nk);
        ensure_node_exists(&mut g, &nk, peer_machine_key, &req);
        let resp = RegisterResponse {
            User: user,
            Login: login,
            MachineAuthorized: true,
            ..Default::default()
        };
        return serde_json::to_vec(&resp).unwrap_or_default();
    }

    let (user, login) = {
        let mut g = inner.lock().unwrap();
        get_or_create_user(&mut g, &nk)
    };

    // Always create the node on first register, even if auth is required.
    // The node needs to exist before map requests can succeed.
    {
        let mut g = inner.lock().unwrap();
        ensure_node_exists(&mut g, &nk, peer_machine_key, &req);
    }

    // Check if auth is required and the node hasn't been authed yet.
    let needs_auth = {
        let g = inner.lock().unwrap();
        g.require_auth && !g.authed_nodes.contains(&nk)
    };

    if needs_auth {
        let auth_path = format!("/auth/{}", random_hex(16));
        let auth_notify = Arc::new(Notify::new());
        let auth_url = {
            let mut g = inner.lock().unwrap();
            let url = format!("{}{}", g.base_url, auth_path);
            g.auth_paths.insert(auth_path.clone(), auth_notify.clone());
            g.auth_path_nodes.insert(auth_path, nk.clone());
            g.last_auth_url = Some(url.clone());
            url
        };
        notify.notify_waiters();
        let resp = RegisterResponse {
            User: user,
            Login: login,
            AuthURL: auth_url,
            ..Default::default()
        };
        return serde_json::to_vec(&resp).unwrap_or_default();
    }

    let node_key_expired = {
        let g = inner.lock().unwrap();
        g.all_expired || g.expired_nodes.contains(&nk)
    };

    let resp = RegisterResponse {
        User: user,
        Login: login,
        NodeKeyExpired: node_key_expired,
        MachineAuthorized: true,
        AuthURL: String::new(),
        NodeKeySignature: None,
        Error: String::new(),
    };
    serde_json::to_vec(&resp).unwrap_or_default()
}

/// Wait until `complete_auth` has durably authorized `node_key`.
///
/// Auth completion removes its path entry and records the node in
/// `authed_nodes`; the latter is the predicate. The `Notify` merely wakes a
/// concurrent followup, so it must be enabled before the predicate recheck.
async fn wait_for_auth_completion(
    inner: &Arc<Mutex<ServerInner>>,
    path: &str,
    node_key: &NodePublic,
) {
    loop {
        let notify = {
            let state = inner.lock().unwrap();
            if state.authed_nodes.contains(node_key) {
                return;
            }
            state.auth_paths.get(path).cloned()
        };
        let Some(notify) = notify else {
            // Unknown or already-retired paths retain the historical
            // followup behavior; a completed path was handled above.
            return;
        };
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if inner.lock().unwrap().authed_nodes.contains(node_key) {
            return;
        }
        notified.await;
    }
}

/// Ensure a node exists in the server's node map. Creates it if not present.
fn ensure_node_exists(
    inner: &mut ServerInner,
    nk: &NodePublic,
    peer_machine_key: &MachinePublic,
    req: &RegisterRequest,
) {
    if inner.nodes.contains_key(nk) {
        return;
    }
    let id = inner.next_node_id;
    inner.next_node_id += 1;
    let ip4 = format!("100.64.{}.{}", (id >> 8) as u8, id as u8);
    let v4_prefix = format!("{ip4}/32");
    let v6_prefix = format!("fd7a:115c:a1e0::{id:x}/128");
    let allowed_ips = vec![v4_prefix, v6_prefix];

    let hostname = req
        .Hostinfo
        .as_ref()
        .map(|h| h.Hostname.clone())
        .unwrap_or_default();

    let (user, _) = get_or_create_user(inner, nk);

    inner.nodes.insert(
        nk.clone(),
        Node {
            ID: id,
            StableID: format!("TESTCTRL{id:08x}"),
            User: user.ID,
            Machine: peer_machine_key.clone(),
            Key: nk.clone(),
            Addresses: allowed_ips.clone(),
            AllowedIPs: allowed_ips,
            Name: hostname,
            Cap: req.Version,
            Hostinfo: req.Hostinfo.clone(),
            ..Default::default()
        },
    );
}

/// Extract the `/auth/...` path from a full URL or a bare path.
fn extract_auth_path(s: &str) -> String {
    if let Some(idx) = s.find("/auth/") {
        s[idx..].to_string()
    } else {
        s.to_string()
    }
}

/// Generate a random hex string of the given byte length.
fn random_hex(bytes: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    format!("{ts:024x}{pid:08x}")[..bytes * 2].to_string()
}

/// Get or create a User + Login for a node key (matching Go's `getUser`).
fn get_or_create_user(inner: &mut ServerInner, nk: &NodePublic) -> (User, Login) {
    if let Some((u, l)) = inner.users.get(nk) {
        return (u.clone(), l.clone());
    }
    let id = inner.users.len() as i64 + 1;
    let login_name = format!("user-{id}@{DOMAIN}");
    let display_name = format!("User {id}");
    let login = Login {
        ID: id,
        Provider: "testcontrol".into(),
        LoginName: login_name.clone(),
        DisplayName: display_name.clone(),
        ProfilePicURL: String::new(),
    };
    let user = User {
        ID: id,
        DisplayName: display_name,
        ProfilePicURL: String::new(),
        Created: None,
    };
    inner
        .users
        .insert(nk.clone(), (user.clone(), login.clone()));
    (user, login)
}

// -----------------------------------------------------------------
// /machine/map (streaming long-poll)
// -----------------------------------------------------------------

/// Handle a map request: send map responses as 4-byte LE length-prefixed
/// JSON frames. Streaming polls stay open for updates and keepalives.
async fn serve_map(
    body: &[u8],
    peer_machine_key: &MachinePublic,
    connection_id: u64,
    inner: &Arc<Mutex<ServerInner>>,
    notify: &Arc<Notify>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
) {
    let req: MapRequest = if let Ok(r) = serde_json::from_slice(body) {
        r
    } else {
        let resp = http::Response::builder().status(400).body(()).unwrap();
        let _ = respond.send_response(resp, true);
        return;
    };

    let nk = req.NodeKey.clone();
    let node_id;
    let compress_zstd = req.Compress == "zstd";

    // Validate the node and update its state.
    {
        let mut inner = inner.lock().unwrap();
        let node = if let Some(n) = inner.nodes.get(&nk) {
            n.clone()
        } else {
            let resp = http::Response::builder().status(400).body(()).unwrap();
            let _ = respond.send_response(resp, true);
            return;
        };
        if node.Machine != *peer_machine_key {
            let resp = http::Response::builder().status(400).body(()).unwrap();
            let _ = respond.send_response(resp, true);
            return;
        }
        node_id = node.ID;
        if req.Stream {
            inner
                .map_connection_by_node
                .insert(nk.clone(), connection_id);
        }

        // Update node state from the request (unless this is a streaming
        // non-update: Stream=true && Version>=68, which omits endpoint info).
        let streaming_non_update = req.Stream && req.Version >= 68;
        if !req.ReadOnly && !streaming_non_update {
            if let Some(live) = inner.nodes.get_mut(&nk) {
                live.Endpoints.clone_from(&req.Endpoints);
                live.DiscoKey = req.DiscoKey.clone();
                live.Cap = req.Version;
                if let Some(ref hi) = req.Hostinfo {
                    live.Hostinfo = Some(hi.clone());
                }
            }
        }
    }

    // A one-shot map request is the authoritative bootstrap snapshot. Tests
    // can fail exactly one such request while leaving the following stream
    // reachable, which distinguishes cache authority from transport liveness.
    let reject_non_stream = {
        let mut state = inner.lock().unwrap();
        !req.Stream && std::mem::take(&mut state.fail_next_non_stream_map_request)
    };
    if reject_non_stream {
        let resp = http::Response::builder().status(503).body(()).unwrap();
        let _ = respond.send_response(resp, true);
        return;
    }

    // Register the update channel for this node (only for streaming polls).
    let (tx, mut rx) = mpsc::channel::<UpdateType>(1);
    let streaming = req.Stream && !req.ReadOnly;
    if streaming {
        let mut inner = inner.lock().unwrap();
        inner.updates.insert(node_id, tx);
        inner.in_serve_map += 1;
        notify.notify_waiters();
    }

    // Send the 200 OK response headers (body follows as data frames).
    let resp = http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(())
        .unwrap();
    let mut send_stream = if let Ok(s) = respond.send_response(resp, false) {
        s
    } else {
        if streaming {
            cleanup_map_registration(inner, node_id, &nk, connection_id, notify);
        }
        return;
    };

    let large_update_body = {
        let state = inner.lock().unwrap();
        (!streaming && req.OmitPeers && state.map_update_response_size > 0)
            .then_some(state.map_update_response_size)
    };
    if let Some(size) = large_update_body {
        let chunk = vec![b'x'; 64 * 1024];
        let mut remaining = size;
        while remaining > 0 {
            let count = remaining.min(chunk.len());
            if send_stream
                .send_data(
                    bytes::Bytes::copy_from_slice(&chunk[..count]),
                    count == remaining,
                )
                .is_err()
            {
                break;
            }
            remaining -= count;
        }
        return;
    }

    // Main loop: send map responses, wait for updates/keepalives.
    let keepalive = std::time::Duration::from_secs(50);
    let mut first = true;

    loop {
        // Check for injected raw map responses first.
        if streaming {
            if let Some(frame) = take_injected_message(inner, &nk) {
                let mut frames = vec![frame];
                while let Some(frame) = take_injected_message(inner, &nk) {
                    frames.push(frame);
                }
                if send_map_frames(&mut send_stream, &frames, compress_zstd).is_err() {
                    break;
                }
                continue;
            }
        }

        // Generate and send an automatic map response (unless suppressed).
        if can_generate_auto(inner, &nk) {
            let map_resp = build_map_response(inner, &nk, first);
            first = false;
            if let Some(map_resp) = map_resp {
                let json = serde_json::to_vec(&map_resp).unwrap_or_default();
                // For non-streaming requests, close the stream after the
                // first response (end_of_stream=true). For streaming, keep
                // the stream open.
                let eos = !streaming;
                if send_map_frame_raw(&mut send_stream, &json, eos, compress_zstd).is_err() {
                    break;
                }
            }
        }

        if !streaming {
            break;
        }

        // Check for more pending injections before waiting.
        if has_pending_injection(inner, &nk) {
            continue;
        }

        // Wait for an update signal or keepalive timer.
        tokio::select! {
            _ = rx.recv() => {
                // Got an update signal; loop to send a response.
            }
            () = tokio::time::sleep(keepalive) => {
                // Send a keepalive frame.
                let keepalive = MapResponse {
                    KeepAlive: true,
                    ..Default::default()
                };
                let json = serde_json::to_vec(&keepalive).unwrap_or_default();
                if send_map_frame_raw(&mut send_stream, &json, false, compress_zstd).is_err() {
                    break;
                }
            }
            _ = std::future::poll_fn(|cx| send_stream.poll_reset(cx)) => break,
        }
    }

    // Close the h2 stream (sends an empty DATA frame with END_STREAM).
    let _ = send_stream.send_data(bytes::Bytes::new(), true);
    if streaming {
        cleanup_map_registration(inner, node_id, &nk, connection_id, notify);
    }
}

/// Remove the update channel and decrement in_serve_map.
fn cleanup_map_registration(
    inner: &Arc<Mutex<ServerInner>>,
    node_id: NodeID,
    node_key: &NodePublic,
    connection_id: u64,
    notify: &Arc<Notify>,
) {
    {
        let mut g = inner.lock().unwrap();
        g.updates.remove(&node_id);
        if g.map_connection_by_node.get(node_key) == Some(&connection_id) {
            g.map_connection_by_node.remove(node_key);
        }
        g.in_serve_map -= 1;
    }
    notify.notify_waiters();
}

/// Take one injected raw MapResponse from the queue (if any).
fn take_injected_message(inner: &Arc<Mutex<ServerInner>>, nk: &NodePublic) -> Option<MapResponse> {
    let mut g = inner.lock().unwrap();
    if let Some(queue) = g.msg_to_send.get_mut(nk) {
        if let Some(mr) = queue.pop_front() {
            if queue.is_empty() {
                g.msg_to_send.remove(nk);
            }
            return Some(mr);
        }
    }
    None
}

/// Whether the node has pending injected messages.
fn has_pending_injection(inner: &Arc<Mutex<ServerInner>>, nk: &NodePublic) -> bool {
    let g = inner.lock().unwrap();
    g.msg_to_send.get(nk).is_some_and(|q| !q.is_empty())
}

/// Whether automatic map responses are allowed for this node.
fn can_generate_auto(inner: &Arc<Mutex<ServerInner>>, nk: &NodePublic) -> bool {
    !inner.lock().unwrap().suppress_auto.contains(nk)
}

/// Build a full MapResponse for a node (matching Go's `MapResponse`).
fn build_map_response(
    inner: &Arc<Mutex<ServerInner>>,
    nk: &NodePublic,
    include_derp: bool,
) -> Option<MapResponse> {
    let g = inner.lock().unwrap();

    let node = g.nodes.get(nk)?.clone();

    // Apply per-node cap map override if set.
    let mut node = node;
    if let Some(cap_map) = g.node_cap_maps.get(nk) {
        node.CapMap = cap_map.clone();
    }

    // Apply all_expired or per-node expiry.
    if g.all_expired || g.expired_nodes.contains(nk) {
        node.KeyExpiry = Some(chrono::Utc::now() - chrono::Duration::minutes(1));
    }

    // Build peers list (all nodes except self), applying per-node cap maps.
    let mut peers: Vec<Node> = g.nodes.values().filter(|p| p.Key != *nk).cloned().collect();
    for p in &mut peers {
        if let Some(cap_map) = g.node_cap_maps.get(&p.Key) {
            p.CapMap = cap_map.clone();
        }
        // Set HomeDERP to region 1 (the test DERP region) if not already set.
        // This is needed for DERP-based relay allocation to work in tests.
        if p.HomeDERP == 0 {
            p.HomeDERP = 1;
        }
    }
    peers.sort_by_key(|p| p.ID);

    // Build user profiles.
    let user_profiles: Vec<UserProfile> = g
        .users
        .values()
        .map(|(u, l)| UserProfile {
            ID: u.ID,
            LoginName: l.LoginName.clone(),
            DisplayName: l.DisplayName.clone(),
            ProfilePicURL: String::new(),
        })
        .collect();

    let dns_config = g.dns_config.clone();

    // Set the node's addresses (matching Go's MapResponse).
    let id = node.ID;
    let v4 = format!("100.64.{}.{}", (id >> 8) as u8, id as u8);
    let v6 = format!("fd7a:115c:a1e0::{id:x}");
    node.Addresses = vec![format!("{v4}/32"), format!("{v6}/128")];
    node.AllowedIPs.clone_from(&node.Addresses);
    // Set HomeDERP to region 1 (the test DERP region) if not already set.
    if node.HomeDERP == 0 {
        node.HomeDERP = 1;
    }

    let derp_map = if include_derp {
        g.derp_map.clone().or_else(|| Some(DERPMap::default()))
    } else {
        None
    };

    let packet_filter: Vec<FilterRule> = filter_allow_all();
    let tka_info = if let Some(authority) = g.tka_authority.as_ref() {
        Some(TKAInfo {
            Head: authority.head().to_string(),
            Disabled: false,
        })
    } else if g.tka_disabled {
        Some(TKAInfo {
            Head: String::new(),
            Disabled: true,
        })
    } else {
        None
    };

    Some(MapResponse {
        Node: Some(node),
        DERPMap: derp_map,
        Domain: DOMAIN.to_string(),
        Peers: Some(peers),
        PacketFilter: Some(packet_filter),
        DNSConfig: dns_config,
        UserProfiles: user_profiles,
        TKAInfo: tka_info,
        ..Default::default()
    })
}

/// Encode a MapResponse as a 4-byte LE length-prefixed JSON frame and send it.
fn send_map_frames(
    send: &mut h2::SendStream<bytes::Bytes>,
    responses: &[MapResponse],
    compress_zstd: bool,
) -> Result<(), ()> {
    let mut batch = Vec::new();
    for response in responses {
        let json = serde_json::to_vec(response).map_err(|_| ())?;
        let payload = if compress_zstd {
            zstd::bulk::compress(&json, 1).map_err(|_| ())?
        } else {
            json
        };
        batch.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        batch.extend_from_slice(&payload);
    }
    send.send_data(bytes::Bytes::from(batch), false)
        .map_err(|_| ())
}

/// Send raw bytes as a 4-byte LE length-prefixed frame, honoring the map
/// request's zstd compression negotiation.
fn send_map_frame_raw(
    send: &mut h2::SendStream<bytes::Bytes>,
    payload: &[u8],
    end_of_stream: bool,
    compress_zstd: bool,
) -> Result<(), ()> {
    let compressed;
    let payload = if compress_zstd {
        compressed = zstd::bulk::compress(payload, 1).map_err(|_| ())?;
        compressed.as_slice()
    } else {
        payload
    };
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    send.send_data(bytes::Bytes::from(frame), end_of_stream)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_new_has_keys() {
        let s = Server::new();
        let key = s.noise_public_key();
        assert!(!key.is_zero(), "noise public key should be non-zero");
    }

    #[test]
    fn add_fake_node_increments_count() {
        let s = Server::new();
        assert_eq!(s.num_nodes(), 0);
        s.add_fake_node();
        assert_eq!(s.num_nodes(), 1);
        s.add_fake_node();
        assert_eq!(s.num_nodes(), 2);
    }

    #[test]
    fn all_nodes_sorted_by_stable_id() {
        let s = Server::new();
        s.add_fake_node();
        s.add_fake_node();
        let nodes = s.all_nodes();
        assert_eq!(nodes.len(), 2);
        assert!(nodes[0].StableID <= nodes[1].StableID);
    }

    #[tokio::test]
    async fn server_starts_and_serves_key() {
        let mut s = Server::new();
        let addr = s.start().await.unwrap();
        let url = format!("http://{addr}");

        // Fetch the server's key.
        let key = rustscale_controlclient::controlhttp::fetch_server_pub_key(&url, 141, None)
            .await
            .expect("fetch key");
        assert!(!key.is_zero(), "fetched key should be non-zero");
        assert_eq!(key, s.noise_public_key());
    }

    #[test]
    fn expire_and_unexpire_node_key() {
        let s = Server::new();
        let key = NodePublic::from_raw32([0xAB; 32]);
        assert!(!s.is_node_expired(&key));
        s.expire_node_key(&key);
        assert!(s.is_node_expired(&key));
        s.unexpire_node_key(&key);
        assert!(!s.is_node_expired(&key));
    }

    #[tokio::test]
    async fn old_node_key_transfers_identity() {
        use rustscale_controlclient::client::ControlClient;
        use rustscale_key::{MachinePrivate, NodePrivate};
        use rustscale_tailcfg::{Hostinfo, RegisterRequest};

        let mut s = Server::new();
        let addr = s.start().await.unwrap();
        let url = format!("http://{addr}");

        let server_key = s.noise_public_key();
        let machine_key = MachinePrivate::generate();
        let node_key = NodePrivate::generate();
        let node_pub = node_key.public();

        // Register the initial node.
        let cc = ControlClient::new(&url, machine_key.clone(), server_key.clone(), 141);
        let req = RegisterRequest {
            Version: 141,
            NodeKey: node_pub.clone(),
            Hostinfo: Some(Hostinfo {
                Hostname: "rot-test".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resp = cc.register(&req).await.expect("initial register");
        assert!(
            resp.Error.is_empty(),
            "initial register error: {}",
            resp.Error
        );
        assert_eq!(s.num_nodes(), 1);

        // Now rotate: register with OldNodeKey + new NodeKey.
        let new_key = NodePrivate::generate();
        let new_pub = new_key.public();
        let rot_req = RegisterRequest {
            Version: 141,
            NodeKey: new_pub.clone(),
            OldNodeKey: node_pub.clone(),
            Hostinfo: Some(Hostinfo {
                Hostname: "rot-test".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let rot_resp = cc.register(&rot_req).await.expect("rotation register");
        assert!(
            rot_resp.Error.is_empty(),
            "rotation register error: {}",
            rot_resp.Error
        );

        // Both nodes should exist (old key is not retired without followup).
        assert_eq!(s.num_nodes(), 2, "old + new node should both exist");

        // The new node should have the same addresses as the old node.
        let all = s.all_nodes();
        let old_node = all.iter().find(|n| n.Key == node_pub).expect("old node");
        let new_node = all.iter().find(|n| n.Key == new_pub).expect("new node");
        assert_eq!(
            new_node.Addresses, old_node.Addresses,
            "new node should inherit old node's addresses"
        );
    }
}
