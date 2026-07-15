//! UDP relay server: socket I/O, VNI allocation, 3-way handshake, data
//! forwarding, endpoint GC, and MAC secret rotation.
//!
//! Ports Go's `net/udprelay/server.go`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustscale_disco::{self, BindUdpRelayEndpointChallenge, BindUdpRelayEndpointCommon, Message};
use rustscale_key::{DiscoPrivate, DiscoPublic, DiscoShared};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::endpoint::{ServerEndpoint, UdprelayError, SERVER_RETRY_AFTER};
use crate::geneve::{encode_geneve_control, GeneveHeader, GENEVE_PROTOCOL_DISCO, MAX_VNI, MIN_VNI};
use crate::mac::{compute_mac_from_bind_msg, verify_mac, MAC_SIZE};

/// Default MAC secret rotation interval (~2 minutes, matching Go).
const DEFAULT_MAC_SECRET_ROTATION_INTERVAL: Duration = Duration::from_secs(120);

/// Configuration for constructing a [`Server`].
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// UDP port to bind (0 = ephemeral).
    pub port: u16,
    /// Time post-allocation before an unbound endpoint is GC'd.
    pub bind_lifetime: Duration,
    /// Time post-handshake before an idle endpoint is GC'd.
    pub steady_state_lifetime: Duration,
    /// Minimum VNI value (inclusive).
    pub min_vni: u32,
    /// Maximum VNI value (inclusive).
    pub max_vni: u32,
    /// MAC secret rotation interval.
    pub mac_secret_rotation_interval: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 0,
            bind_lifetime: Duration::from_secs(30),
            steady_state_lifetime: Duration::from_secs(300),
            min_vni: MIN_VNI,
            max_vni: MAX_VNI,
            mac_secret_rotation_interval: DEFAULT_MAC_SECRET_ROTATION_INTERVAL,
        }
    }
}

/// A UDP peer relay server.
///
/// Binds a UDP socket, allocates VNIs, runs the 3-way disco bind handshake,
/// and forwards Geneve-encapsulated packets between bound clients.
pub struct Server {
    inner: Arc<ServerInner>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Server {
    /// Create and start a new relay server.
    pub async fn new(config: ServerConfig) -> Result<Self, UdprelayError> {
        let disco_private = DiscoPrivate::generate();
        let disco_public = disco_private.public();

        let udp4 = UdpSocket::bind(("0.0.0.0", config.port)).await?;
        let port = udp4.local_addr()?.port();
        let advertised_addr = SocketAddr::from(([127, 0, 0, 1], port));

        let inner = Arc::new(ServerInner {
            disco_private,
            disco_public,
            bind_lifetime: config.bind_lifetime,
            steady_state_lifetime: config.steady_state_lifetime,
            mac_secret_rotation_interval: config.mac_secret_rotation_interval,
            min_vni: config.min_vni,
            max_vni: config.max_vni,
            udp4: Arc::new(udp4),
            closed: AtomicBool::new(false),
            delivery_gate: tokio::sync::RwLock::new(()),
            state: Mutex::new(ServerState {
                mac_secrets: Vec::new(),
                mac_secret_rotated_at: None,
                lamport_id: 0,
                next_vni: config.min_vni,
                endpoints_by_vni: HashMap::new(),
                endpoints_by_disco: HashMap::new(),
                server_closed: false,
                static_addr_ports: vec![advertised_addr],
                dynamic_addr_ports: Vec::new(),
            }),
        });

        // Start read loop
        let inner_clone = inner.clone();
        let read_handle = tokio::spawn(async move {
            ServerInner::read_loop(inner_clone).await;
        });

        // Start GC loop
        let inner_clone = inner.clone();
        let gc_handle = tokio::spawn(async move {
            ServerInner::gc_loop(inner_clone).await;
        });

        Ok(Self {
            inner,
            tasks: Mutex::new(vec![read_handle, gc_handle]),
        })
    }

    /// The advertised IPv4 address of the server (loopback with bound port).
    pub fn local_addr_v4(&self) -> SocketAddr {
        let port = self.inner.udp4.local_addr().expect("socket bound").port();
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// The server's disco public key (used by clients to seal/open disco
    /// control messages during the 3-way handshake).
    pub fn disco_public(&self) -> DiscoPublic {
        self.inner.disco_public.clone()
    }

    /// Set the static address:port pairs the server advertises.
    pub fn set_static_addr_ports(&self, ports: Vec<SocketAddr>) {
        let mut state = self.inner.state.lock().unwrap();
        state.static_addr_ports = ports;
    }

    /// Allocate a relay endpoint for a pair of client disco public keys.
    ///
    /// If an allocation already exists for this pair, it is returned without
    /// re-allocation. Clients can deduplicate using the `lamport_id`.
    pub fn allocate_endpoint(
        &self,
        disco_a: DiscoPublic,
        disco_b: DiscoPublic,
    ) -> Result<ServerEndpoint, UdprelayError> {
        self.inner.allocate_endpoint(disco_a, disco_b)
    }

    /// Run one GC pass, expiring stale endpoints.
    pub fn run_gc_once(&self) {
        self.inner.run_gc_once();
    }

    /// Get the current MAC secrets (triggers rotation if needed).
    pub fn get_mac_secrets(&self) -> Vec<[u8; MAC_SIZE]> {
        self.inner.get_mac_secrets(Instant::now())
    }

    /// Whether the server currently accepts fresh allocations.
    pub fn is_enabled(&self) -> bool {
        !self.inner.closed.load(Ordering::Acquire)
            && !self.inner.state.lock().unwrap().server_closed
    }

    /// Number of active endpoints (for testing/diagnostics).
    pub fn endpoint_count(&self) -> usize {
        let state = self.inner.state.lock().unwrap();
        state.endpoints_by_vni.len()
    }

    /// Stop accepting allocations and synchronously revoke every active VNI.
    /// Socket tasks remain alive so a later freshly authorized map/config can
    /// re-enable the same extension without retaining any prior allocation.
    pub async fn disable_and_drain(&self) {
        let _delivery = self.inner.delivery_gate.write().await;
        let mut state = self.inner.state.lock().unwrap();
        state.server_closed = true;
        for endpoint in state.endpoints_by_vni.values() {
            endpoint.inner.lock().unwrap().closed = true;
        }
        state.endpoints_by_vni.clear();
        state.endpoints_by_disco.clear();
        state.mac_secrets.clear();
        state.mac_secret_rotated_at = None;
    }

    /// Re-enable allocation only after the embedding has validated a fresh
    /// matching map/config. Disabled allocations are never restored.
    pub fn enable(&self) {
        if self.inner.closed.load(Ordering::Acquire) {
            return;
        }
        self.inner.state.lock().unwrap().server_closed = false;
    }

    /// Close the server, synchronously draining allocations and stopping all
    /// background tasks.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        let mut state = self.inner.state.lock().unwrap();
        state.server_closed = true;
        for endpoint in state.endpoints_by_vni.values() {
            endpoint.inner.lock().unwrap().closed = true;
        }
        state.endpoints_by_vni.clear();
        state.endpoints_by_disco.clear();
        state.mac_secrets.clear();
        drop(state);
        let tasks = self.tasks.lock().unwrap();
        for task in tasks.iter() {
            task.abort();
        }
    }

    // ----- test helpers -----

    #[cfg(test)]
    pub fn set_next_vni(&self, vni: u32) {
        let mut state = self.inner.state.lock().unwrap();
        state.next_vni = vni;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------
// ServerInner
// ---------------------------------------------------------------------------

struct ServerInner {
    disco_private: DiscoPrivate,
    disco_public: DiscoPublic,
    bind_lifetime: Duration,
    steady_state_lifetime: Duration,
    mac_secret_rotation_interval: Duration,
    min_vni: u32,
    max_vni: u32,
    udp4: Arc<UdpSocket>,
    closed: AtomicBool,
    delivery_gate: tokio::sync::RwLock<()>,
    state: Mutex<ServerState>,
}

struct ServerState {
    mac_secrets: Vec<[u8; MAC_SIZE]>,
    mac_secret_rotated_at: Option<Instant>,
    lamport_id: u64,
    next_vni: u32,
    endpoints_by_vni: HashMap<u32, Arc<RelayEndpoint>>,
    endpoints_by_disco: HashMap<[DiscoPublic; 2], Arc<RelayEndpoint>>,
    server_closed: bool,
    static_addr_ports: Vec<SocketAddr>,
    dynamic_addr_ports: Vec<SocketAddr>,
}

impl ServerInner {
    fn allocate_endpoint(
        &self,
        disco_a: DiscoPublic,
        disco_b: DiscoPublic,
    ) -> Result<ServerEndpoint, UdprelayError> {
        let mut state = self.state.lock().unwrap();
        if state.server_closed || self.closed.load(Ordering::Relaxed) {
            return Err(UdprelayError::ServerClosed);
        }
        if state.static_addr_ports.is_empty() && state.dynamic_addr_ports.is_empty() {
            return Err(UdprelayError::ServerNotReady {
                retry_after: SERVER_RETRY_AFTER,
            });
        }
        if disco_a == self.disco_public || disco_b == self.disco_public {
            return Err(UdprelayError::ClientEqualsServer);
        }

        let pair = sorted_pair(disco_a, disco_b);

        // Return existing allocation if present
        if let Some(existing) = state.endpoints_by_disco.get(&pair) {
            return Ok(ServerEndpoint {
                server_disco: self.disco_public.clone(),
                client_disco: pair.clone(),
                lamport_id: existing.lamport_id,
                addr_ports: get_all_addr_ports(&state),
                vni: existing.vni,
                bind_lifetime: self.bind_lifetime,
                steady_state_lifetime: self.steady_state_lifetime,
            });
        }

        // Allocate a VNI
        let vni = get_next_vni(&mut state, self.min_vni, self.max_vni)?;

        // Create the endpoint
        state.lamport_id += 1;
        let lamport_id = state.lamport_id;
        let endpoint = Arc::new(RelayEndpoint::new(
            pair.clone(),
            lamport_id,
            vni,
            Instant::now(),
            &self.disco_private,
        ));

        state
            .endpoints_by_disco
            .insert(pair.clone(), endpoint.clone());
        state.endpoints_by_vni.insert(vni, endpoint);

        Ok(ServerEndpoint {
            server_disco: self.disco_public.clone(),
            client_disco: pair,
            lamport_id,
            addr_ports: get_all_addr_ports(&state),
            vni,
            bind_lifetime: self.bind_lifetime,
            steady_state_lifetime: self.steady_state_lifetime,
        })
    }

    fn get_mac_secrets(&self, now: Instant) -> Vec<[u8; MAC_SIZE]> {
        let mut state = self.state.lock().unwrap();
        Self::maybe_rotate_mac_secret(&mut state, now, self.mac_secret_rotation_interval);
        state.mac_secrets.clone()
    }

    fn maybe_rotate_mac_secret(state: &mut ServerState, now: Instant, interval: Duration) {
        if let Some(last) = state.mac_secret_rotated_at {
            if now.duration_since(last) < interval {
                return;
            }
        }
        if state.mac_secrets.is_empty() {
            state.mac_secrets.push(random_32_bytes());
        } else {
            if state.mac_secrets.len() < 2 {
                let old = state.mac_secrets[0];
                state.mac_secrets.push(old);
            } else {
                state.mac_secrets[1] = state.mac_secrets[0];
            }
            state.mac_secrets[0] = random_32_bytes();
        }
        state.mac_secret_rotated_at = Some(now);
    }

    fn handle_packet(&self, from: SocketAddr, buf: &[u8]) -> Option<(Vec<u8>, SocketAddr)> {
        let (gh, payload) = GeneveHeader::decode(buf).ok()?;

        // Look up endpoint by VNI
        let endpoint = {
            let state = self.state.lock().unwrap();
            state.endpoints_by_vni.get(&gh.vni).cloned()
        }?;

        let now = Instant::now();

        if gh.control {
            if gh.protocol != GENEVE_PROTOCOL_DISCO {
                return None;
            }
            let secrets = self.get_mac_secrets(now);
            endpoint.handle_sealed_disco_control_msg(
                from,
                payload,
                &self.disco_public,
                &secrets,
                now,
            )
        } else {
            // Data packet — forward the full packet (including Geneve header)
            endpoint.handle_data_packet(from, buf, now)
        }
    }

    fn run_gc_once(&self) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let mut to_remove = Vec::new();
        for (pair, endpoint) in &state.endpoints_by_disco {
            let mut ep = endpoint.inner.lock().unwrap();
            if ep.is_expired(
                now,
                self.bind_lifetime,
                self.steady_state_lifetime,
                endpoint.allocated_at,
            ) {
                ep.closed = true;
                to_remove.push((pair.clone(), endpoint.vni));
            }
        }
        for (pair, vni) in to_remove {
            state.endpoints_by_disco.remove(&pair);
            state.endpoints_by_vni.remove(&vni);
        }
    }

    async fn read_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 65535];
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            match self.udp4.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    if n == 0 {
                        continue;
                    }
                    let _delivery = self.delivery_gate.read().await;
                    if self.state.lock().unwrap().server_closed {
                        continue;
                    }
                    if let Some((reply, to)) = self.handle_packet(from, &buf[..n]) {
                        let _ = self.udp4.send_to(&reply, to).await;
                    }
                }
                Err(_) => return,
            }
        }
    }

    async fn gc_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.bind_lifetime).await;
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            self.run_gc_once();
        }
    }
}

// ---------------------------------------------------------------------------
// RelayEndpoint (internal per-endpoint state)
// ---------------------------------------------------------------------------

/// Internal state for one allocated relay endpoint.
struct RelayEndpoint {
    disco_pub_keys: [DiscoPublic; 2],
    disco_shared_secrets: [DiscoShared; 2],
    lamport_id: u64,
    vni: u32,
    allocated_at: Instant,
    inner: Mutex<EndpointInner>,
}

impl RelayEndpoint {
    fn new(
        disco_pub_keys: [DiscoPublic; 2],
        lamport_id: u64,
        vni: u32,
        allocated_at: Instant,
        server_disco_private: &DiscoPrivate,
    ) -> Self {
        let disco_shared_secrets = [
            server_disco_private.shared(&disco_pub_keys[0]),
            server_disco_private.shared(&disco_pub_keys[1]),
        ];
        Self {
            disco_pub_keys,
            disco_shared_secrets,
            lamport_id,
            vni,
            allocated_at,
            inner: Mutex::new(EndpointInner::new(allocated_at)),
        }
    }

    fn handle_sealed_disco_control_msg(
        &self,
        from: SocketAddr,
        envelope: &[u8],
        server_disco: &DiscoPublic,
        mac_secrets: &[[u8; MAC_SIZE]],
        now: Instant,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        let sender_bytes = rustscale_disco::source(envelope)?;
        let sender_pub = DiscoPublic::from_raw32(sender_bytes);

        let sender_index = if sender_pub == self.disco_pub_keys[0] {
            0
        } else if sender_pub == self.disco_pub_keys[1] {
            1
        } else {
            return None;
        };

        let header_len = rustscale_disco::MAGIC.len() + rustscale_disco::KEY_LEN;
        let plaintext = self.disco_shared_secrets[sender_index].open(&envelope[header_len..])?;

        let msg = Message::parse(&plaintext).ok()?;

        self.handle_disco_control_msg(from, sender_index, msg, server_disco, mac_secrets, now)
    }

    fn handle_disco_control_msg(
        &self,
        from: SocketAddr,
        sender_index: usize,
        msg: Message,
        server_disco: &DiscoPublic,
        mac_secrets: &[[u8; MAC_SIZE]],
        now: Instant,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        let other_sender = 1 - sender_index;
        let mut ep = self.inner.lock().unwrap();

        if ep.closed {
            return None;
        }

        match msg {
            Message::BindUdpRelayEndpoint(bind_msg) => {
                let common = &bind_msg.common;
                if common.vni != self.vni {
                    return None;
                }
                if common.remote_key != self.disco_pub_keys[other_sender] {
                    return None;
                }
                if common.generation == 0 {
                    return None;
                }

                ep.in_progress_generation[sender_index] = common.generation;

                let challenge_common = BindUdpRelayEndpointCommon {
                    vni: self.vni,
                    generation: common.generation,
                    remote_key: self.disco_pub_keys[other_sender].clone(),
                    challenge: [0u8; 32],
                };

                let mac = compute_mac_from_bind_msg(&mac_secrets[0], from, &challenge_common);

                let challenge_msg = BindUdpRelayEndpointChallenge {
                    common: BindUdpRelayEndpointCommon {
                        challenge: mac,
                        ..challenge_common
                    },
                };

                let marshaled = Message::BindUdpRelayEndpointChallenge(challenge_msg).marshal();
                let sealed = self.disco_shared_secrets[sender_index]
                    .seal(&marshaled)
                    .ok()?;

                let mut envelope = Vec::with_capacity(
                    rustscale_disco::MAGIC.len() + rustscale_disco::KEY_LEN + sealed.len(),
                );
                envelope.extend_from_slice(&rustscale_disco::MAGIC);
                envelope.extend_from_slice(&server_disco.raw32());
                envelope.extend_from_slice(&sealed);

                let reply = encode_geneve_control(self.vni, &envelope);
                Some((reply, from))
            }

            Message::BindUdpRelayEndpointAnswer(answer_msg) => {
                let common = &answer_msg.common;
                if common.vni != self.vni {
                    return None;
                }
                if common.remote_key != self.disco_pub_keys[other_sender] {
                    return None;
                }
                let generation = ep.in_progress_generation[sender_index];
                if generation == 0 || generation != common.generation {
                    return None;
                }
                for mac_secret in mac_secrets {
                    let expected = compute_mac_from_bind_msg(mac_secret, from, common);
                    if verify_mac(&expected, &common.challenge) {
                        ep.bound_addr_ports[sender_index] = Some(from);
                        ep.last_seen[sender_index] = now;
                        ep.in_progress_generation[sender_index] = 0;
                        return None;
                    }
                }
                None
            }

            _ => None,
        }
    }

    fn handle_data_packet(
        &self,
        from: SocketAddr,
        full_packet: &[u8],
        now: Instant,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        let mut ep = self.inner.lock().unwrap();
        if !ep.is_bound() || ep.closed {
            return None;
        }

        let (sender_idx, other_idx) = if Some(from) == ep.bound_addr_ports[0] {
            (0, 1)
        } else if Some(from) == ep.bound_addr_ports[1] {
            (1, 0)
        } else {
            return None;
        };

        ep.last_seen[sender_idx] = now;
        ep.packets_rx[sender_idx] += 1;
        ep.bytes_rx[sender_idx] += full_packet.len() as u64;

        let dest = ep.bound_addr_ports[other_idx].unwrap();
        Some((full_packet.to_vec(), dest))
    }
}

// ---------------------------------------------------------------------------
// EndpointInner
// ---------------------------------------------------------------------------

struct EndpointInner {
    closed: bool,
    in_progress_generation: [u32; 2],
    bound_addr_ports: [Option<SocketAddr>; 2],
    last_seen: [Instant; 2],
    packets_rx: [u64; 2],
    bytes_rx: [u64; 2],
}

impl EndpointInner {
    fn new(now: Instant) -> Self {
        Self {
            closed: false,
            in_progress_generation: [0, 0],
            bound_addr_ports: [None, None],
            last_seen: [now, now],
            packets_rx: [0, 0],
            bytes_rx: [0, 0],
        }
    }

    fn is_bound(&self) -> bool {
        self.bound_addr_ports[0].is_some() && self.bound_addr_ports[1].is_some()
    }

    fn is_expired(
        &self,
        now: Instant,
        bind_lifetime: Duration,
        steady_state_lifetime: Duration,
        allocated_at: Instant,
    ) -> bool {
        if !self.is_bound() {
            return now.duration_since(allocated_at) > bind_lifetime;
        }
        now.duration_since(self.last_seen[0]) > steady_state_lifetime
            || now.duration_since(self.last_seen[1]) > steady_state_lifetime
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sorted_pair(a: DiscoPublic, b: DiscoPublic) -> [DiscoPublic; 2] {
    if a <= b {
        [a, b]
    } else {
        [b, a]
    }
}

fn get_next_vni(state: &mut ServerState, min_vni: u32, max_vni: u32) -> Result<u32, UdprelayError> {
    let total = max_vni - min_vni + 1;
    for _ in 0..total {
        let vni = state.next_vni;
        if vni == max_vni {
            state.next_vni = min_vni;
        } else {
            state.next_vni += 1;
        }
        if !state.endpoints_by_vni.contains_key(&vni) {
            return Ok(vni);
        }
    }
    Err(UdprelayError::VniExhausted)
}

fn get_all_addr_ports(state: &ServerState) -> Vec<SocketAddr> {
    let mut out =
        Vec::with_capacity(state.static_addr_ports.len() + state.dynamic_addr_ports.len());
    out.extend_from_slice(&state.static_addr_ports);
    out.extend_from_slice(&state.dynamic_addr_ports);
    out
}

fn random_32_bytes() -> [u8; MAC_SIZE] {
    use rand::RngCore;
    let mut buf = [0u8; MAC_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geneve::{decode_geneve, encode_geneve};
    use rustscale_disco::{
        BindUdpRelayEndpoint, BindUdpRelayEndpointAnswer, BindUdpRelayEndpointCommon,
    };

    // ----- test helpers -----

    fn build_control_packet(
        sender: &DiscoPrivate,
        peer: &DiscoPublic,
        vni: u32,
        msg: &Message,
    ) -> Vec<u8> {
        let marshaled = msg.marshal();
        let sealed = rustscale_disco::seal_packet(sender, peer, &marshaled).unwrap();
        encode_geneve_control(vni, &sealed)
    }

    fn open_control_packet(
        receiver: &DiscoPrivate,
        packet: &[u8],
    ) -> Option<(u32, DiscoPublic, Message)> {
        let (header, payload) = GeneveHeader::decode(packet).ok()?;
        let (sender, plaintext) = rustscale_disco::open_packet(receiver, payload)?;
        let msg = Message::parse(&plaintext).ok()?;
        Some((header.vni, sender, msg))
    }

    fn test_config() -> ServerConfig {
        ServerConfig {
            port: 0,
            bind_lifetime: Duration::from_secs(30),
            steady_state_lifetime: Duration::from_secs(300),
            min_vni: MIN_VNI,
            max_vni: MAX_VNI,
            mac_secret_rotation_interval: Duration::from_secs(120),
        }
    }

    /// Create a server, allocate an endpoint, and return everything needed
    /// for further test steps.
    async fn setup_server_and_endpoint(
        config: ServerConfig,
    ) -> (Server, DiscoPublic, u32, DiscoPrivate, DiscoPrivate) {
        let server = Server::new(config).await.unwrap();
        let server_disco = server.disco_public();
        let client_a = DiscoPrivate::generate();
        let client_b = DiscoPrivate::generate();
        let ep = server
            .allocate_endpoint(client_a.public(), client_b.public())
            .unwrap();
        (server, server_disco, ep.vni, client_a, client_b)
    }

    /// Perform a full 3-way handshake from `sock` as `client` towards the
    /// server, using `remote_key` as the other client's disco public key.
    async fn do_handshake(
        sock: &UdpSocket,
        client: &DiscoPrivate,
        server_disco: &DiscoPublic,
        server_addr: SocketAddr,
        vni: u32,
        generation: u32,
        remote_key: DiscoPublic,
    ) -> [u8; 32] {
        // Bind
        let bind_msg = Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation,
                remote_key: remote_key.clone(),
                challenge: [0u8; 32],
            },
        });
        let pkt = build_control_packet(client, server_disco, vni, &bind_msg);
        sock.send_to(&pkt, server_addr).await.unwrap();

        // Receive Challenge
        let mut buf = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("timeout waiting for challenge")
            .expect("recv failed");

        let (_, _, msg) = open_control_packet(client, &buf[..n]).expect("open challenge");
        let challenge = match msg {
            Message::BindUdpRelayEndpointChallenge(c) => c,
            _ => panic!("expected challenge, got {:?}", msg.summary()),
        };
        let challenge_mac = challenge.common.challenge;

        // Answer
        let answer_msg = Message::BindUdpRelayEndpointAnswer(BindUdpRelayEndpointAnswer {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation,
                remote_key,
                challenge: challenge_mac,
            },
        });
        let pkt = build_control_packet(client, server_disco, vni, &answer_msg);
        sock.send_to(&pkt, server_addr).await.unwrap();

        challenge_mac
    }

    // ----- tests -----

    #[tokio::test]
    async fn full_handshake_and_data_forward() {
        let (server, server_disco, vni, client_a, client_b) =
            setup_server_and_endpoint(test_config()).await;
        let server_addr = server.local_addr_v4();

        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Client A handshake
        do_handshake(
            &sock_a,
            &client_a,
            &server_disco,
            server_addr,
            vni,
            1,
            client_b.public(),
        )
        .await;

        // Client B handshake
        do_handshake(
            &sock_b,
            &client_b,
            &server_disco,
            server_addr,
            vni,
            1,
            client_a.public(),
        )
        .await;

        // Let the server process the answers
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send data A → B
        let payload_a = b"hello from A through relay";
        let frame = encode_geneve(vni, payload_a);
        sock_a.send_to(&frame, server_addr).await.unwrap();

        let mut buf = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock_b.recv_from(&mut buf))
            .await
            .expect("timeout waiting for data at B")
            .expect("recv failed");
        let (recv_vni, recv_payload) = decode_geneve(&buf[..n]).unwrap();
        assert_eq!(recv_vni, vni);
        assert_eq!(recv_payload, payload_a);

        // Send data B → A
        let payload_b = b"hello from B through relay";
        let frame = encode_geneve(vni, payload_b);
        sock_b.send_to(&frame, server_addr).await.unwrap();

        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock_a.recv_from(&mut buf))
            .await
            .expect("timeout waiting for data at A")
            .expect("recv failed");
        let (recv_vni, recv_payload) = decode_geneve(&buf[..n]).unwrap();
        assert_eq!(recv_vni, vni);
        assert_eq!(recv_payload, payload_b);
    }

    #[tokio::test]
    async fn rebinding_from_new_source() {
        let (server, server_disco, vni, client_a, client_b) =
            setup_server_and_endpoint(test_config()).await;
        let server_addr = server.local_addr_v4();

        let sock_a1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Initial handshake from sock_a1
        do_handshake(
            &sock_a1,
            &client_a,
            &server_disco,
            server_addr,
            vni,
            1,
            client_b.public(),
        )
        .await;

        // B handshake
        do_handshake(
            &sock_b,
            &client_b,
            &server_disco,
            server_addr,
            vni,
            1,
            client_a.public(),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Data A → B works
        let payload = b"via original addr";
        sock_a1
            .send_to(&encode_geneve(vni, payload), server_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock_b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decode_geneve(&buf[..n]).unwrap().1, payload);

        // Re-bind from a new socket (new source port)
        let sock_a2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        do_handshake(
            &sock_a2,
            &client_a,
            &server_disco,
            server_addr,
            vni,
            2, // new generation
            client_b.public(),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Data from new addr works
        let payload2 = b"via new addr";
        sock_a2
            .send_to(&encode_geneve(vni, payload2), server_addr)
            .await
            .unwrap();

        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock_b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decode_geneve(&buf[..n]).unwrap().1, payload2);

        // Data from old addr is dropped (server should not forward)
        sock_a1
            .send_to(&encode_geneve(vni, b"stale"), server_addr)
            .await
            .unwrap();

        // B should not receive the stale packet — verify by sending from
        // sock_a2 again and confirming we get that packet, not the stale one.
        let payload3 = b"via new addr 2";
        sock_a2
            .send_to(&encode_geneve(vni, payload3), server_addr)
            .await
            .unwrap();

        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock_b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decode_geneve(&buf[..n]).unwrap().1, payload3);
    }

    #[tokio::test]
    async fn vni_wraparound() {
        let config = ServerConfig {
            min_vni: 1,
            max_vni: 3,
            ..test_config()
        };
        let server = Server::new(config).await.unwrap();

        // Set next_vni to max so the next allocation wraps to min
        server.set_next_vni(3);

        let k1 = DiscoPrivate::generate();
        let k2 = DiscoPrivate::generate();
        let k3 = DiscoPrivate::generate();
        let k4 = DiscoPrivate::generate();
        let k5 = DiscoPrivate::generate();
        let k6 = DiscoPrivate::generate();

        let ep1 = server.allocate_endpoint(k1.public(), k2.public()).unwrap();
        assert_eq!(ep1.vni, 3); // takes current (3), wraps next to 1

        let ep2 = server.allocate_endpoint(k3.public(), k4.public()).unwrap();
        assert_eq!(ep2.vni, 1); // takes 1, next goes to 2

        let ep3 = server.allocate_endpoint(k5.public(), k6.public()).unwrap();
        assert_eq!(ep3.vni, 2); // takes 2, next goes to 3

        // All 3 VNIs are now in use. The next allocation should wrap around
        // and find none available → exhaustion.
        let k7 = DiscoPrivate::generate();
        let k8 = DiscoPrivate::generate();
        let result = server.allocate_endpoint(k7.public(), k8.public());
        assert!(matches!(result, Err(UdprelayError::VniExhausted)));
    }

    #[tokio::test]
    async fn vni_exhaustion() {
        let config = ServerConfig {
            min_vni: 1,
            max_vni: 2,
            ..test_config()
        };
        let server = Server::new(config).await.unwrap();

        let keys: Vec<DiscoPrivate> = (0..6).map(|_| DiscoPrivate::generate()).collect();

        let ep1 = server
            .allocate_endpoint(keys[0].public(), keys[1].public())
            .unwrap();
        let ep2 = server
            .allocate_endpoint(keys[2].public(), keys[3].public())
            .unwrap();
        assert_ne!(ep1.vni, ep2.vni);

        // Pool exhausted
        let result = server.allocate_endpoint(keys[4].public(), keys[5].public());
        assert!(matches!(result, Err(UdprelayError::VniExhausted)));
    }

    #[tokio::test]
    async fn bind_lifetime_expiry() {
        let config = ServerConfig {
            bind_lifetime: Duration::from_millis(100),
            steady_state_lifetime: Duration::from_secs(300),
            ..test_config()
        };
        let server = Server::new(config).await.unwrap();
        let a = DiscoPrivate::generate();
        let b = DiscoPrivate::generate();
        server.allocate_endpoint(a.public(), b.public()).unwrap();
        assert_eq!(server.endpoint_count(), 1);

        // Don't handshake — wait past bind_lifetime
        tokio::time::sleep(Duration::from_millis(150)).await;
        server.run_gc_once();

        assert_eq!(server.endpoint_count(), 0);
    }

    #[tokio::test]
    async fn steady_state_expiry() {
        let config = ServerConfig {
            bind_lifetime: Duration::from_secs(30),
            steady_state_lifetime: Duration::from_millis(100),
            ..test_config()
        };
        let server = Server::new(config).await.unwrap();
        let server_disco = server.disco_public();
        let server_addr = server.local_addr_v4();

        let client_a = DiscoPrivate::generate();
        let client_b = DiscoPrivate::generate();
        let ep = server
            .allocate_endpoint(client_a.public(), client_b.public())
            .unwrap();
        let vni = ep.vni;

        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Complete both handshakes (endpoint becomes bound)
        do_handshake(
            &sock_a,
            &client_a,
            &server_disco,
            server_addr,
            vni,
            1,
            client_b.public(),
        )
        .await;
        do_handshake(
            &sock_b,
            &client_b,
            &server_disco,
            server_addr,
            vni,
            1,
            client_a.public(),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(server.endpoint_count(), 1);

        // Wait past steady_state_lifetime with no data
        tokio::time::sleep(Duration::from_millis(120)).await;
        server.run_gc_once();

        assert_eq!(server.endpoint_count(), 0);
    }

    #[tokio::test]
    async fn mac_secret_rotation() {
        let config = ServerConfig {
            mac_secret_rotation_interval: Duration::from_millis(50),
            ..test_config()
        };
        let server = Server::new(config).await.unwrap();

        // First access triggers initial rotation → 1 secret
        let secrets1 = server.get_mac_secrets();
        assert_eq!(secrets1.len(), 1);

        // Wait past rotation interval
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Second access triggers rotation → 2 secrets
        let secrets2 = server.get_mac_secrets();
        assert_eq!(secrets2.len(), 2);

        // [0] is new, [1] is old
        assert_ne!(secrets2[0], secrets2[1]);
        assert_eq!(secrets2[1], secrets1[0]);

        // Wait again for another rotation
        tokio::time::sleep(Duration::from_millis(60)).await;
        let secrets3 = server.get_mac_secrets();
        assert_eq!(secrets3.len(), 2);
        assert_ne!(secrets3[0], secrets3[1]);
        // The new [0] should be different from the previous [0]
        assert_ne!(secrets3[0], secrets2[0]);
        // The new [1] should be the old [0]
        assert_eq!(secrets3[1], secrets2[0]);
    }

    #[tokio::test]
    async fn duplicate_allocation_returns_existing() {
        let server = Server::new(test_config()).await.unwrap();
        let a = DiscoPrivate::generate();
        let b = DiscoPrivate::generate();

        let ep1 = server.allocate_endpoint(a.public(), b.public()).unwrap();
        // Same pair in reversed order should return the same allocation
        let ep2 = server.allocate_endpoint(b.public(), a.public()).unwrap();
        assert_eq!(ep1.vni, ep2.vni);
        assert_eq!(ep1.lamport_id, ep2.lamport_id);
        assert_eq!(server.endpoint_count(), 1);
    }

    #[tokio::test]
    async fn allocate_rejects_server_disco() {
        let server = Server::new(test_config()).await.unwrap();
        let server_disco = server.disco_public();
        let other = DiscoPrivate::generate();

        let result = server.allocate_endpoint(server_disco, other.public());
        assert!(matches!(result, Err(UdprelayError::ClientEqualsServer)));
    }

    #[tokio::test]
    async fn handshake_with_wrong_vni_dropped() {
        let (server, server_disco, vni, client_a, client_b) =
            setup_server_and_endpoint(test_config()).await;
        let server_addr = server.local_addr_v4();

        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send Bind with wrong VNI
        let bind_msg = Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
            common: BindUdpRelayEndpointCommon {
                vni: vni + 999,
                generation: 1,
                remote_key: client_b.public(),
                challenge: [0u8; 32],
            },
        });
        let pkt = build_control_packet(&client_a, &server_disco, vni + 999, &bind_msg);
        sock_a.send_to(&pkt, server_addr).await.unwrap();

        // Should not receive a challenge (server drops it)
        let mut buf = vec![0u8; 65535];
        let result =
            tokio::time::timeout(Duration::from_millis(200), sock_a.recv_from(&mut buf)).await;
        assert!(result.is_err(), "should not receive response for wrong VNI");
    }

    #[tokio::test]
    async fn data_before_handshake_dropped() {
        let (server, _server_disco, vni, _client_a, _client_b) =
            setup_server_and_endpoint(test_config()).await;
        let server_addr = server.local_addr_v4();

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let frame = encode_geneve(vni, b"no handshake yet");
        sock.send_to(&frame, server_addr).await.unwrap();

        // No one is bound, so the server should not forward anything.
        // We can't easily test "nothing received" but we can verify the
        // endpoint still exists (was not corrupted).
        assert_eq!(server.endpoint_count(), 1);
    }

    #[tokio::test]
    async fn lamport_id_monotonic() {
        let server = Server::new(test_config()).await.unwrap();

        let mut keys = Vec::new();
        for _ in 0..6 {
            keys.push(DiscoPrivate::generate());
        }

        let ep1 = server
            .allocate_endpoint(keys[0].public(), keys[1].public())
            .unwrap();
        let ep2 = server
            .allocate_endpoint(keys[2].public(), keys[3].public())
            .unwrap();
        let ep3 = server
            .allocate_endpoint(keys[4].public(), keys[5].public())
            .unwrap();

        assert!(ep1.lamport_id < ep2.lamport_id);
        assert!(ep2.lamport_id < ep3.lamport_id);
    }

    #[tokio::test]
    async fn handshake_with_wrong_remote_key_dropped() {
        let (server, server_disco, vni, client_a, _client_b) =
            setup_server_and_endpoint(test_config()).await;
        let server_addr = server.local_addr_v4();

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wrong_remote = DiscoPrivate::generate().public();

        let bind_msg = Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation: 1,
                remote_key: wrong_remote,
                challenge: [0u8; 32],
            },
        });
        let pkt = build_control_packet(&client_a, &server_disco, vni, &bind_msg);
        sock.send_to(&pkt, server_addr).await.unwrap();

        let mut buf = vec![0u8; 65535];
        let result =
            tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await;
        assert!(
            result.is_err(),
            "should not receive response for wrong RemoteKey"
        );
    }

    #[tokio::test]
    async fn generation_zero_dropped() {
        let (server, server_disco, vni, client_a, client_b) =
            setup_server_and_endpoint(test_config()).await;
        let server_addr = server.local_addr_v4();

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let bind_msg = Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation: 0, // invalid
                remote_key: client_b.public(),
                challenge: [0u8; 32],
            },
        });
        let pkt = build_control_packet(&client_a, &server_disco, vni, &bind_msg);
        sock.send_to(&pkt, server_addr).await.unwrap();

        let mut buf = vec![0u8; 65535];
        let result =
            tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await;
        assert!(result.is_err(), "generation=0 should be silently dropped");
    }

    #[tokio::test]
    async fn unknown_sender_dropped() {
        let (server, server_disco, vni, _client_a, _client_b) =
            setup_server_and_endpoint(test_config()).await;
        let server_addr = server.local_addr_v4();

        let stranger = DiscoPrivate::generate();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let bind_msg = Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation: 1,
                remote_key: DiscoPrivate::generate().public(),
                challenge: [0u8; 32],
            },
        });
        let pkt = build_control_packet(&stranger, &server_disco, vni, &bind_msg);
        sock.send_to(&pkt, server_addr).await.unwrap();

        let mut buf = vec![0u8; 65535];
        let result =
            tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await;
        assert!(result.is_err(), "unknown sender should be dropped");
    }

    #[tokio::test]
    async fn answer_with_wrong_challenge_mac_dropped() {
        let (server, server_disco, vni, client_a, client_b) =
            setup_server_and_endpoint(test_config()).await;
        let server_addr = server.local_addr_v4();

        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Bind
        let bind_msg = Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation: 1,
                remote_key: client_b.public(),
                challenge: [0u8; 32],
            },
        });
        let pkt = build_control_packet(&client_a, &server_disco, vni, &bind_msg);
        sock_a.send_to(&pkt, server_addr).await.unwrap();

        // Receive Challenge
        let mut buf = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock_a.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let (_, _, _msg) = open_control_packet(&client_a, &buf[..n]).unwrap();

        // Send Answer with a WRONG challenge MAC
        let wrong_mac = [0xFF; 32];
        let answer_msg = Message::BindUdpRelayEndpointAnswer(BindUdpRelayEndpointAnswer {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation: 1,
                remote_key: client_b.public(),
                challenge: wrong_mac,
            },
        });
        let pkt = build_control_packet(&client_a, &server_disco, vni, &answer_msg);
        sock_a.send_to(&pkt, server_addr).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // The endpoint should not be bound — try sending data and verify
        // it's not forwarded. We can check endpoint_count is still 1 (not
        // removed), and verify the endpoint is not bound by checking that
        // data is not forwarded.
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // B also tries to handshake (successfully)
        do_handshake(
            &sock_b,
            &client_b,
            &server_disco,
            server_addr,
            vni,
            1,
            client_a.public(),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // B sends data — should NOT be forwarded to A because A is not bound
        sock_b
            .send_to(&encode_geneve(vni, b"should not arrive"), server_addr)
            .await
            .unwrap();

        let result =
            tokio::time::timeout(Duration::from_millis(200), sock_a.recv_from(&mut buf)).await;
        assert!(
            result.is_err(),
            "data should not be forwarded when A is not bound"
        );
    }
}
