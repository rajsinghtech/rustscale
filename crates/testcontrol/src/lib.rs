//! In-process fake Tailscale control server for integration testing.
//!
//! Mirrors Go's `tstest/integration/testcontrol` package. A single-tailnet
//! control server that speaks the ts2021 Noise protocol, serves `/key`,
//! `/ts2021` (Noise upgrade), and h2c routes `/machine/register` and
//! `/machine/map` (streaming long-poll).
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
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use rustscale_controlclient::controlbase::{server_handshake, NoiseIo};
use rustscale_key::{DiscoPrivate, MachinePrivate, MachinePublic, NodePrivate, NodePublic};
use rustscale_tailcfg::{
    filter_allow_all, DERPMap, DNSConfig, FilterRule, Login, MapRequest, MapResponse, Node,
    NodeCapMap, NodeID, RegisterRequest, RegisterResponse, User, UserProfile,
};
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
    require_auth: bool,
    auth_paths: HashMap<String, Arc<Notify>>,
    auth_path_nodes: HashMap<String, NodePublic>,
    authed_nodes: HashSet<NodePublic>,
    last_auth_url: Option<String>,
    base_url: String,
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
                require_auth: false,
                auth_paths: HashMap::new(),
                auth_path_nodes: HashMap::new(),
                authed_nodes: HashSet::new(),
                last_auth_url: None,
                base_url: String::new(),
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

    /// The server's Noise public key (also returned by `GET /key`).
    pub fn noise_public_key(&self) -> MachinePublic {
        self.inner.lock().unwrap().noise_pub.clone()
    }

    // -----------------------------------------------------------------
    // Test API
    // -----------------------------------------------------------------

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

    handle_h2_connection(h2_conn, peer_machine_key, inner.clone(), notify).await;
}

// -----------------------------------------------------------------
// h2c request handling
// -----------------------------------------------------------------

/// Process h2 requests over the Noise-upgraded connection.
async fn handle_h2_connection(
    mut h2_conn: h2::server::Connection<NoiseIo, bytes::Bytes>,
    peer_machine_key: MachinePublic,
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
            if let Err(()) =
                handle_h2_request(&method, &path, req_body, respond, &inner, &peer, &notify).await
            {
                // Error already handled inside; nothing to do here.
            }
        });
    }
}

/// Read the full h2 request body.
async fn read_h2_body(body: &mut h2::RecvStream) -> Result<Vec<u8>, h2::Error> {
    let mut data = Vec::new();
    while let Some(frame) = body.data().await {
        let frame = frame?;
        let _ = body.flow_control().release_capacity(frame.len());
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
    notify: &Arc<Notify>,
) -> Result<(), ()> {
    if method != "POST" {
        let resp = http::Response::builder().status(400).body(()).unwrap();
        let _ = respond.send_response(resp, true);
        return Ok(());
    }

    match path {
        "/machine/register" => {
            let body = read_h2_body(&mut req_body).await.map_err(|_| ())?;
            let resp_body = serve_register(&body, peer_machine_key, inner, notify).await;
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
            serve_map(&body, peer_machine_key, inner, notify, respond).await;
        }
        "/machine/update-health" => {
            // Drain body, respond 204.
            while req_body.data().await.is_some() {}
            let resp = http::Response::builder().status(204).body(()).unwrap();
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

    let nk = req.NodeKey.clone();

    // If this is a followup request, block until auth is completed.
    if !req.Followup.is_empty() {
        let path = extract_auth_path(&req.Followup);
        let auth_notify = {
            let g = inner.lock().unwrap();
            g.auth_paths.get(&path).cloned()
        };
        if let Some(an) = auth_notify {
            an.notified().await;
        }
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

    let node_key_expired = inner.lock().unwrap().all_expired;

    let resp = RegisterResponse {
        User: user,
        Login: login,
        NodeKeyExpired: node_key_expired,
        MachineAuthorized: true,
        AuthURL: String::new(),
        Error: String::new(),
    };
    serde_json::to_vec(&resp).unwrap_or_default()
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
            cleanup_map_registration(inner, node_id, notify);
        }
        return;
    };

    // Main loop: send map responses, wait for updates/keepalives.
    let keepalive = std::time::Duration::from_secs(50);
    let mut first = true;

    loop {
        // Check for injected raw map responses first.
        if streaming {
            if let Some(frame) = take_injected_message(inner, &nk) {
                if send_map_frame(&mut send_stream, &frame).is_err() {
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
                if send_map_frame_raw(&mut send_stream, &json, eos).is_err() {
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
                if send_map_frame_raw(&mut send_stream, &json, false).is_err() {
                    break;
                }
            }
        }
    }

    // Close the h2 stream (sends an empty DATA frame with END_STREAM).
    let _ = send_stream.send_data(bytes::Bytes::new(), true);
    if streaming {
        cleanup_map_registration(inner, node_id, notify);
    }
}

/// Remove the update channel and decrement in_serve_map.
fn cleanup_map_registration(
    inner: &Arc<Mutex<ServerInner>>,
    node_id: NodeID,
    notify: &Arc<Notify>,
) {
    {
        let mut g = inner.lock().unwrap();
        g.updates.remove(&node_id);
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

    // Apply all_expired.
    if g.all_expired {
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
    peers.sort_by(|a, b| a.ID.cmp(&b.ID));

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

    Some(MapResponse {
        Node: Some(node),
        DERPMap: derp_map,
        Domain: DOMAIN.to_string(),
        Peers: peers,
        PacketFilter: Some(packet_filter),
        DNSConfig: dns_config,
        UserProfiles: user_profiles,
        ..Default::default()
    })
}

/// Encode a MapResponse as a 4-byte LE length-prefixed JSON frame and send it.
fn send_map_frame(
    send: &mut h2::SendStream<bytes::Bytes>,
    mr: &MapResponse,
) -> Result<(), h2::Error> {
    let json = serde_json::to_vec(mr).unwrap_or_default();
    send_map_frame_raw(send, &json, false)
}

/// Send raw bytes as a 4-byte LE length-prefixed frame.
fn send_map_frame_raw(
    send: &mut h2::SendStream<bytes::Bytes>,
    payload: &[u8],
    end_of_stream: bool,
) -> Result<(), h2::Error> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    send.send_data(bytes::Bytes::from(frame), end_of_stream)
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
        let key = rustscale_controlclient::controlhttp::fetch_server_pub_key(&url, 141)
            .await
            .expect("fetch key");
        assert!(!key.is_zero(), "fetched key should be non-zero");
        assert_eq!(key, s.noise_public_key());
    }
}
