use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rustscale_controlclient::{
    controlhttp::fetch_server_pub_key, ControlClient, NoiseHttpClient, NoiseResponse,
    NoiseResponseBody,
};
use rustscale_key::{DiscoPublic, MachinePrivate, MachinePublic, NodePrivate};
use rustscale_tailcfg::{
    Hostinfo, MapRequest, MapResponse, PingRequest, RegisterRequest, RegisterResponse,
    RegisterResponseAuth,
};
use tokio::sync::watch;

use crate::frame::{FrameDecoder, FrameError};

pub const DEFAULT_SERVER_URL: &str = "https://controlplane.tailscale.com";
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 << 20;
pub const CURRENT_CAPABILITY_VERSION: i32 = 141;
const PROTOCOL_VERSION: u16 = 141;

/// Configuration for a TSP client. Construction performs no I/O.
#[derive(Clone)]
pub struct ClientOptions {
    pub server_url: String,
    pub machine_key: MachinePrivate,
    pub control_public_key: Option<MachinePublic>,
    pub extra_root_certs: Vec<Vec<u8>>,
}

impl ClientOptions {
    pub fn new(machine_key: MachinePrivate) -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.into(),
            machine_key,
            control_public_key: None,
            extra_root_certs: Vec::new(),
        }
    }

    pub fn server_url(mut self, server_url: impl Into<String>) -> Self {
        self.server_url = server_url.into();
        self
    }

    pub fn control_public_key(mut self, key: MachinePublic) -> Self {
        self.control_public_key = Some(key);
        self
    }
}

pub struct RegisterOptions {
    pub node_key: NodePrivate,
    pub hostinfo: Option<Hostinfo>,
    pub ephemeral: bool,
    pub auth_key: String,
    pub tags: Vec<String>,
    /// Maximum encoded registration response size; zero uses the default.
    pub max_response_size: usize,
}

impl RegisterOptions {
    pub fn new(node_key: NodePrivate) -> Self {
        Self {
            node_key,
            hostinfo: None,
            ephemeral: false,
            auth_key: String::new(),
            tags: Vec::new(),
            max_response_size: 0,
        }
    }
}

pub struct MapOptions {
    pub node_key: NodePrivate,
    pub hostinfo: Option<Hostinfo>,
    pub stream: bool,
    pub omit_peers: bool,
    /// Maximum size of both an encoded frame and its decoded JSON; zero uses
    /// [`DEFAULT_MAX_MESSAGE_SIZE`].
    pub max_message_size: usize,
}

impl MapOptions {
    pub fn new(node_key: NodePrivate) -> Self {
        Self {
            node_key,
            hostinfo: None,
            stream: false,
            omit_peers: false,
            max_message_size: 0,
        }
    }
}

pub struct SendMapUpdateOptions {
    pub node_key: NodePrivate,
    pub disco_key: DiscoPublic,
    pub hostinfo: Option<Hostinfo>,
}

impl SendMapUpdateOptions {
    pub fn new(node_key: NodePrivate) -> Self {
        Self {
            node_key,
            disco_key: DiscoPublic::default(),
            hostinfo: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TspError {
    #[error("machine key is required")]
    MissingMachineKey,
    #[error("node key is required")]
    MissingNodeKey,
    #[error("tsp client is closed")]
    ClientClosed,
    #[error("tsp map session is closed")]
    SessionClosed,
    #[error("discovering control server key: {0}")]
    Discovery(#[source] rustscale_controlclient::DialError),
    #[error("control request: {0}")]
    Request(#[source] rustscale_controlclient::NoiseRequestError),
    #[error("encoding request: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("decoding registration response: {0}")]
    DecodeRegister(#[source] serde_json::Error),
    #[error("HTTP {status}: {message}")]
    HttpStatus { status: u16, message: String },
    #[error("response body exceeds max {max}")]
    ResponseTooLarge { max: usize },
    #[error("reading response body: {0}")]
    ResponseBody(String),
    #[error("registration failed: {0}")]
    Registration(String),
    #[error("invalid C2N request: {0}")]
    InvalidC2n(String),
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// Fetch a control server's ts2021 Noise public key.
pub async fn discover_server_key(server_url: &str) -> Result<MachinePublic, TspError> {
    let server_url = if server_url.is_empty() {
        DEFAULT_SERVER_URL
    } else {
        server_url
    };
    fetch_server_pub_key(server_url, PROTOCOL_VERSION, None)
        .await
        .map_err(TspError::Discovery)
}

/// Alternative registration/map client built on `rustscale-controlclient`.
pub struct Client {
    server_url: String,
    machine_key: MachinePrivate,
    server_key: Mutex<Option<MachinePublic>>,
    transport: Mutex<Option<Arc<NoiseHttpClient>>>,
    transport_generation: AtomicU64,
    extra_root_certs: Vec<Vec<u8>>,
    closed: AtomicBool,
    close_tx: watch::Sender<bool>,
}

impl Client {
    pub fn new(mut options: ClientOptions) -> Result<Self, TspError> {
        if options.machine_key.is_zero() {
            return Err(TspError::MissingMachineKey);
        }
        if options.server_url.is_empty() {
            options.server_url = DEFAULT_SERVER_URL.into();
        }
        let (close_tx, _) = watch::channel(false);
        Ok(Self {
            server_url: options.server_url,
            machine_key: options.machine_key,
            server_key: Mutex::new(options.control_public_key),
            transport: Mutex::new(None),
            transport_generation: AtomicU64::new(0),
            extra_root_certs: options.extra_root_certs,
            closed: AtomicBool::new(false),
            close_tx,
        })
    }

    /// Configure a known server key. The existing Noise connection is closed;
    /// future requests establish a new connection with this key.
    pub fn set_control_public_key(&self, key: MachinePublic) {
        *lock_unpoisoned(&self.server_key) = Some(key);
        self.invalidate_transport();
    }

    /// Discover, store, and return the control server key.
    pub async fn discover_server_key(&self) -> Result<MachinePublic, TspError> {
        self.ensure_open()?;
        let mut close = self.close_tx.subscribe();
        let result = tokio::select! {
            biased;
            () = wait_closed(&mut close) => return Err(TspError::ClientClosed),
            result = fetch_server_pub_key(
                &self.server_url,
                PROTOCOL_VERSION,
                nonempty_roots(&self.extra_root_certs),
            ) => result,
        }
        .map_err(TspError::Discovery)?;
        *lock_unpoisoned(&self.server_key) = Some(result.clone());
        self.invalidate_transport();
        Ok(result)
    }

    /// Register a node key with the coordination server.
    pub async fn register(&self, options: RegisterOptions) -> Result<RegisterResponse, TspError> {
        if options.node_key.is_zero() {
            return Err(TspError::MissingNodeKey);
        }
        let mut hostinfo = options.hostinfo.unwrap_or_else(default_hostinfo);
        if !options.tags.is_empty() {
            hostinfo.RequestTags = options.tags;
        }
        let request = RegisterRequest {
            Version: CURRENT_CAPABILITY_VERSION,
            NodeKey: options.node_key.public(),
            Hostinfo: Some(hostinfo),
            Ephemeral: options.ephemeral,
            Auth: (!options.auth_key.is_empty()).then_some(RegisterResponseAuth {
                AuthKey: options.auth_key,
            }),
            ..Default::default()
        };
        let encoded = serde_json::to_vec(&request).map_err(TspError::Encode)?;
        let control = self.control_transport().await?;
        let mut close = self.close_tx.subscribe();
        let response = tokio::select! {
            biased;
            () = wait_closed(&mut close) => return Err(TspError::ClientClosed),
            response = control.post_json("/machine/register", encoded, Some(&request.NodeKey)) => response,
        }
        .map_err(TspError::Request)?;
        let status = response.status();
        let mut body = response.into_body();
        let max = default_limit(options.max_response_size);
        let data = read_body_limited(&mut body, max, &mut close).await?;
        if status != 200 {
            return Err(http_status(status, &data));
        }
        let response: RegisterResponse =
            serde_json::from_slice(&data).map_err(TspError::DecodeRegister)?;
        if !response.Error.is_empty() {
            return Err(TspError::Registration(response.Error));
        }
        Ok(response)
    }

    /// Start a one-shot or streaming map request.
    pub async fn map(&self, options: MapOptions) -> Result<MapSession, TspError> {
        if options.node_key.is_zero() {
            return Err(TspError::MissingNodeKey);
        }
        let request = MapRequest {
            Version: CURRENT_CAPABILITY_VERSION,
            NodeKey: options.node_key.public(),
            Hostinfo: Some(options.hostinfo.unwrap_or_else(default_hostinfo)),
            Stream: options.stream,
            Compress: "zstd".into(),
            OmitPeers: options.omit_peers,
            ReadOnly: !options.stream,
            ..Default::default()
        };
        let encoded = serde_json::to_vec(&request).map_err(TspError::Encode)?;
        let control = self.control_transport().await?;
        let mut close = self.close_tx.subscribe();
        let response = tokio::select! {
            biased;
            () = wait_closed(&mut close) => return Err(TspError::ClientClosed),
            response = control.post_json("/machine/map", encoded, Some(&request.NodeKey)) => response,
        }
        .map_err(TspError::Request)?;
        let status = response.status();
        let mut body = response.into_body();
        let max = default_limit(options.max_message_size);
        if status != 200 {
            let data = read_body_limited(&mut body, max, &mut close).await?;
            return Err(http_status(status, &data));
        }
        let (session_close, session_close_rx) = watch::channel(false);
        Ok(MapSession {
            transport: control,
            client_close_signal: close.clone(),
            state: tokio::sync::Mutex::new(MapReadState {
                body,
                decoder: FrameDecoder::new(max),
                stream: options.stream,
                read: 0,
                client_close: close,
                session_close: session_close_rx,
            }),
            closed: AtomicBool::new(false),
            session_close,
        })
    }

    /// Push a small node-state update without disturbing a map stream.
    pub async fn send_map_update(&self, options: SendMapUpdateOptions) -> Result<(), TspError> {
        if options.node_key.is_zero() {
            return Err(TspError::MissingNodeKey);
        }
        let request = MapRequest {
            Version: CURRENT_CAPABILITY_VERSION,
            NodeKey: options.node_key.public(),
            DiscoKey: options.disco_key,
            Hostinfo: Some(options.hostinfo.unwrap_or_else(default_hostinfo)),
            Compress: "zstd".into(),
            OmitPeers: true,
            Stream: false,
            ReadOnly: false,
            ..Default::default()
        };
        let encoded = serde_json::to_vec(&request).map_err(TspError::Encode)?;
        let control = self.control_transport().await?;
        let mut close = self.close_tx.subscribe();
        let response = tokio::select! {
            biased;
            () = wait_closed(&mut close) => return Err(TspError::ClientClosed),
            response = control.post_json("/machine/map", encoded, Some(&request.NodeKey)) => response,
        }
        .map_err(TspError::Request)?;
        let status = response.status();
        let mut body = response.into_body();
        let data = if (200..300).contains(&status) {
            drain_body(&mut body, &mut close).await?;
            Vec::new()
        } else {
            read_body_limited(&mut body, DEFAULT_MAX_MESSAGE_SIZE, &mut close).await?
        };
        if status != 200 {
            return Err(http_status(status, &data));
        }
        Ok(())
    }

    /// Cancel in-flight operations and prevent future requests.
    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.close_tx.send_replace(true);
            if let Some(transport) = lock_unpoisoned(&self.transport).take() {
                transport.close();
            }
        }
    }

    fn ensure_open(&self) -> Result<(), TspError> {
        if self.closed.load(Ordering::Acquire) {
            Err(TspError::ClientClosed)
        } else {
            Ok(())
        }
    }

    async fn control_transport(&self) -> Result<Arc<NoiseHttpClient>, TspError> {
        loop {
            self.ensure_open()?;
            if let Some(transport) = lock_unpoisoned(&self.transport).clone() {
                if !transport.is_closed() {
                    return Ok(transport);
                }
            }

            let generation = self.transport_generation.load(Ordering::Acquire);
            let configured_key = { lock_unpoisoned(&self.server_key).clone() };
            let Some(key) = configured_key else {
                self.discover_server_key().await?;
                continue;
            };
            if generation != self.transport_generation.load(Ordering::Acquire) {
                continue;
            }
            let mut client = ControlClient::new(
                self.server_url.clone(),
                self.machine_key.clone(),
                key,
                PROTOCOL_VERSION,
            );
            if !self.extra_root_certs.is_empty() {
                client.set_extra_root_certs(self.extra_root_certs.clone());
            }
            let created = Arc::new(client.connect().await.map_err(TspError::Request)?);
            self.ensure_open()?;

            let mut slot = lock_unpoisoned(&self.transport);
            if generation != self.transport_generation.load(Ordering::Acquire) {
                drop(slot);
                created.close();
                continue;
            }
            if let Some(existing) = slot.as_ref().filter(|transport| !transport.is_closed()) {
                created.close();
                return Ok(existing.clone());
            }
            *slot = Some(created.clone());
            return Ok(created);
        }
    }

    fn invalidate_transport(&self) {
        self.transport_generation.fetch_add(1, Ordering::AcqRel);
        if let Some(transport) = lock_unpoisoned(&self.transport).take() {
            transport.close();
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

struct MapReadState {
    body: NoiseResponseBody,
    decoder: FrameDecoder,
    stream: bool,
    read: usize,
    client_close: watch::Receiver<bool>,
    session_close: watch::Receiver<bool>,
}

/// An in-progress framed map response stream.
pub struct MapSession {
    transport: Arc<NoiseHttpClient>,
    client_close_signal: watch::Receiver<bool>,
    state: tokio::sync::Mutex<MapReadState>,
    closed: AtomicBool,
    session_close: watch::Sender<bool>,
}

impl MapSession {
    /// Read the next map response. `None` is a clean end-of-stream.
    ///
    /// Calls are serialized internally, and [`close`](Self::close) may be
    /// called concurrently to abort a blocked read.
    pub async fn next(&self) -> Result<Option<MapResponse>, TspError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TspError::SessionClosed);
        }
        let mut state = self.state.lock().await;
        if self.closed.load(Ordering::Acquire) || *state.session_close.borrow() {
            state.body.cancel();
            return Err(TspError::SessionClosed);
        }
        if *state.client_close.borrow() {
            state.body.cancel();
            return Err(TspError::ClientClosed);
        }
        if !state.stream && state.read > 0 {
            return Ok(None);
        }
        loop {
            if self.closed.load(Ordering::Acquire) || *state.session_close.borrow() {
                state.body.cancel();
                return Err(TspError::SessionClosed);
            }
            if *state.client_close.borrow() {
                state.body.cancel();
                return Err(TspError::ClientClosed);
            }
            if let Some(response) = state.decoder.next_response()? {
                state.read += 1;
                return Ok(Some(response));
            }
            let MapReadState {
                body,
                client_close,
                session_close,
                ..
            } = &mut *state;
            let chunk = tokio::select! {
                biased;
                () = wait_closed(session_close) => {
                    body.cancel();
                    return Err(TspError::SessionClosed);
                }
                () = wait_closed(client_close) => {
                    body.cancel();
                    return Err(TspError::ClientClosed);
                }
                result = body.data() => result.map_err(|error| TspError::ResponseBody(error.to_string()))?,
            };
            if let Some(chunk) = chunk {
                state.decoder.push(&chunk);
            } else {
                state.decoder.finish()?;
                return Ok(None);
            }
        }
    }

    /// Decode into caller-owned storage, returning false at clean EOF.
    pub async fn next_into(&self, response: &mut MapResponse) -> Result<bool, TspError> {
        *response = MapResponse::default();
        let Some(next) = self.next().await? else {
            return Ok(false);
        };
        *response = next;
        Ok(true)
    }

    /// Send a request over the exact Noise/H2 connection carrying this map.
    pub async fn noise_round_trip(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> Result<NoiseResponse, TspError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TspError::SessionClosed);
        }
        if *self.client_close_signal.borrow() {
            return Err(TspError::ClientClosed);
        }
        self.transport
            .request(request)
            .await
            .map_err(TspError::Request)
    }

    /// Handle a map-delivered C2N `/echo` ping and POST the serialized HTTP
    /// response back over this map session's Noise connection.
    pub async fn answer_c2n_ping(&self, ping: &PingRequest) -> Result<bool, TspError> {
        if ping.Types != "c2n" {
            return Ok(false);
        }
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Request::new(&mut headers);
        let body_offset = match parsed
            .parse(&ping.Payload)
            .map_err(|error| TspError::InvalidC2n(error.to_string()))?
        {
            httparse::Status::Complete(offset) => offset,
            httparse::Status::Partial => {
                return Err(TspError::InvalidC2n("truncated HTTP request".into()));
            }
        };
        if parsed.method.is_none() {
            return Err(TspError::InvalidC2n("missing HTTP method".into()));
        }
        let path = parsed
            .path
            .ok_or_else(|| TspError::InvalidC2n("missing HTTP path".into()))?;
        if path.split('?').next() != Some("/echo") {
            return Ok(false);
        }
        let body = &ping.Payload[body_offset..];
        let response_payload =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        let mut response_payload_with_body = response_payload;
        response_payload_with_body.extend_from_slice(body);
        let request = http::Request::builder()
            .method("POST")
            .uri(&ping.URL)
            .header("content-type", "application/octet-stream")
            .body(response_payload_with_body)
            .map_err(|error| TspError::InvalidC2n(error.to_string()))?;
        let response = self.noise_round_trip(request).await?;
        if !(200..300).contains(&response.status()) {
            return Err(TspError::HttpStatus {
                status: response.status(),
                message: "C2N callback rejected".into(),
            });
        }
        drop(response);
        Ok(true)
    }

    /// Cancel the map response stream. Safe to call repeatedly or concurrently
    /// with [`next`](Self::next).
    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.session_close.send_replace(true);
            if let Ok(mut state) = self.state.try_lock() {
                state.body.cancel();
            }
        }
    }
}

impl Drop for MapSession {
    fn drop(&mut self) {
        self.close();
    }
}

fn default_hostinfo() -> Hostinfo {
    Hostinfo {
        OS: std::env::consts::OS.into(),
        IPNVersion: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    }
}

fn default_limit(limit: usize) -> usize {
    if limit == 0 {
        DEFAULT_MAX_MESSAGE_SIZE
    } else {
        limit
    }
}

fn nonempty_roots(roots: &[Vec<u8>]) -> Option<&[Vec<u8>]> {
    (!roots.is_empty()).then_some(roots)
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn wait_closed(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow() {
            return;
        }
        if receiver.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn drain_body(
    body: &mut NoiseResponseBody,
    close: &mut watch::Receiver<bool>,
) -> Result<(), TspError> {
    loop {
        let chunk = tokio::select! {
            biased;
            () = wait_closed(close) => {
                body.cancel();
                return Err(TspError::ClientClosed);
            }
            result = body.data() => result.map_err(|error| TspError::ResponseBody(error.to_string()))?,
        };
        if chunk.is_none() {
            return Ok(());
        }
    }
}

async fn read_body_limited(
    body: &mut NoiseResponseBody,
    max: usize,
    close: &mut watch::Receiver<bool>,
) -> Result<Vec<u8>, TspError> {
    let mut output = Vec::new();
    loop {
        let chunk = tokio::select! {
            biased;
            () = wait_closed(close) => {
                body.cancel();
                return Err(TspError::ClientClosed);
            }
            result = body.data() => result.map_err(|error| TspError::ResponseBody(error.to_string()))?,
        };
        let Some(chunk) = chunk else {
            return Ok(output);
        };
        if chunk.len() > max.saturating_sub(output.len()) {
            body.cancel();
            return Err(TspError::ResponseTooLarge { max });
        }
        output.extend_from_slice(&chunk);
    }
}

fn http_status(status: u16, body: &[u8]) -> TspError {
    let body = &body[..body.len().min(200)];
    TspError::HttpStatus {
        status,
        message: String::from_utf8_lossy(body).trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rustscale_testcontrol::Server;

    use super::*;

    fn hostinfo(hostname: &str) -> Hostinfo {
        Hostinfo {
            Hostname: hostname.into(),
            ..Default::default()
        }
    }

    async fn register_node(
        server_url: &str,
        server_key: &MachinePublic,
        hostname: &str,
    ) -> (NodePrivate, MachinePrivate) {
        let node_key = NodePrivate::generate();
        let machine_key = MachinePrivate::generate();
        let client = Client::new(
            ClientOptions::new(machine_key.clone())
                .server_url(server_url)
                .control_public_key(server_key.clone()),
        )
        .unwrap();
        let mut options = RegisterOptions::new(node_key.clone());
        options.hostinfo = Some(hostinfo(hostname));
        client.register(options).await.unwrap();
        (node_key, machine_key)
    }

    #[tokio::test]
    async fn registration_map_stream_update_and_close_against_testcontrol() {
        let mut server = Server::new();
        server.start().await.unwrap();
        let url = server.base_url();
        let discovered = discover_server_key(&url).await.unwrap();
        assert_eq!(discovered, server.noise_public_key());

        let (node_b, machine_b) = register_node(&url, &discovered, "b").await;
        let node_a = NodePrivate::generate();
        let machine_a = MachinePrivate::generate();
        let connections_before_a = server.noise_connection_count();
        let client_a = Client::new(
            ClientOptions::new(machine_a.clone())
                .server_url(&url)
                .control_public_key(discovered.clone()),
        )
        .unwrap();
        let mut register_a = RegisterOptions::new(node_a.clone());
        register_a.hostinfo = Some(hostinfo("a"));
        client_a.register(register_a).await.unwrap();
        let mut map_options = MapOptions::new(node_a.clone());
        map_options.hostinfo = Some(hostinfo("a"));
        map_options.stream = true;
        let session = Arc::new(client_a.map(map_options).await.unwrap());
        let first = session.next().await.unwrap().unwrap();
        assert_eq!(first.Node.unwrap().Key, node_a.public());
        assert!(first
            .Peers
            .iter()
            .flatten()
            .any(|peer| peer.Key == node_b.public()));
        assert_eq!(
            server.noise_connection_count(),
            connections_before_a + 1,
            "register and map must reuse one Noise connection"
        );

        let injected = MapResponse {
            Domain: "injected.example.test".into(),
            ..Default::default()
        };
        assert!(server.add_raw_map_response(&node_a.public(), injected));
        assert_eq!(
            session.next().await.unwrap().unwrap().Domain,
            "injected.example.test"
        );

        let callback_url = server.c2n_callback_url(&node_a.public());
        assert!(server.add_raw_map_response(
            &node_a.public(),
            MapResponse {
                PingRequest: Some(PingRequest {
                    URL: callback_url.clone(),
                    Types: "c2n".into(),
                    Payload: b"POST /echo HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            }
        ));
        let c2n = session.next().await.unwrap().unwrap().PingRequest.unwrap();

        let wrong_client =
            ControlClient::new(url.clone(), machine_a, discovered.clone(), PROTOCOL_VERSION)
                .connect()
                .await
                .unwrap();
        let wrong_response = wrong_client
            .request(
                http::Request::builder()
                    .method("POST")
                    .uri(&callback_url)
                    .body(b"wrong connection".to_vec())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_response.status(), 409);
        drop(wrong_response);
        wrong_client.close();
        assert_eq!(server.rejected_c2n_callbacks(), 1);

        let connections_before_callback = server.noise_connection_count();
        assert!(session.answer_c2n_ping(&c2n).await.unwrap());
        assert_eq!(
            server.c2n_reply(&callback_url).unwrap(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
        assert_eq!(server.rejected_c2n_callbacks(), 1);
        assert_eq!(
            server.noise_connection_count(),
            connections_before_callback,
            "C2N callback must reuse the map connection"
        );

        let client_b = Client::new(
            ClientOptions::new(machine_b)
                .server_url(&url)
                .control_public_key(discovered.clone()),
        )
        .unwrap();
        let disco = rustscale_key::DiscoPrivate::generate().public();
        let mut update = SendMapUpdateOptions::new(node_b.clone());
        update.disco_key = disco.clone();
        update.hostinfo = Some(hostinfo("b"));
        client_b.send_map_update(update).await.unwrap();
        assert_eq!(server.node(&node_b.public()).unwrap().DiscoKey, disco);

        let mut map_b = MapOptions::new(node_b.clone());
        map_b.hostinfo = Some(hostinfo("b"));
        map_b.stream = true;
        let session_b = Arc::new(client_b.map(map_b).await.unwrap());
        session_b.next().await.unwrap().unwrap();
        let waiting_b = session_b.clone();
        let blocked_b = tokio::spawn(async move { waiting_b.next().await });
        tokio::task::yield_now().await;
        session_b.close();
        let error = tokio::time::timeout(Duration::from_secs(2), blocked_b)
            .await
            .expect("session close must unblock map read")
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, TspError::SessionClosed));

        let waiting_session = session.clone();
        let blocked_read = tokio::spawn(async move { waiting_session.next().await });
        tokio::task::yield_now().await;
        client_a.close();
        let error = tokio::time::timeout(Duration::from_secs(2), blocked_read)
            .await
            .expect("client close must unblock map read")
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, TspError::ClientClosed));
        session.close();
        assert!(matches!(session.next().await, Err(TspError::SessionClosed)));
    }

    #[tokio::test]
    async fn client_close_cleans_up_idle_map_without_next() {
        let mut server = Server::new();
        server.start().await.unwrap();
        let node = NodePrivate::generate();
        let client = Client::new(
            ClientOptions::new(MachinePrivate::generate())
                .server_url(server.base_url())
                .control_public_key(server.noise_public_key()),
        )
        .unwrap();
        client
            .register(RegisterOptions::new(node.clone()))
            .await
            .unwrap();
        let mut options = MapOptions::new(node);
        options.stream = true;
        let session = client.map(options).await.unwrap();
        session.next().await.unwrap().unwrap();
        assert_eq!(server.in_serve_map(), 1);

        client.close();
        tokio::time::timeout(Duration::from_secs(2), async {
            while server.in_serve_map() != 0 || server.active_noise_connection_count() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("closing the client must tear down an unread map stream");
        drop(session);
    }

    #[tokio::test]
    async fn close_wins_over_second_buffered_frame() {
        let mut server = Server::new();
        server.start().await.unwrap();
        let node = NodePrivate::generate();
        let client = Client::new(
            ClientOptions::new(MachinePrivate::generate())
                .server_url(server.base_url())
                .control_public_key(server.noise_public_key()),
        )
        .unwrap();
        client
            .register(RegisterOptions::new(node.clone()))
            .await
            .unwrap();
        let mut options = MapOptions::new(node.clone());
        options.stream = true;
        let session = client.map(options).await.unwrap();
        session.next().await.unwrap().unwrap();
        assert!(server.add_raw_map_responses(
            &node.public(),
            [
                MapResponse {
                    Domain: "first-buffered.example".into(),
                    ..Default::default()
                },
                MapResponse {
                    Domain: "second-buffered.example".into(),
                    ..Default::default()
                },
            ]
        ));
        assert_eq!(
            session.next().await.unwrap().unwrap().Domain,
            "first-buffered.example"
        );
        client.close();
        assert!(matches!(session.next().await, Err(TspError::ClientClosed)));
    }

    #[tokio::test]
    async fn map_update_drains_large_success_body() {
        let mut server = Server::new();
        server.start().await.unwrap();
        server.set_map_update_response_size(5 * 1024 * 1024);
        let node = NodePrivate::generate();
        let client = Client::new(
            ClientOptions::new(MachinePrivate::generate())
                .server_url(server.base_url())
                .control_public_key(server.noise_public_key()),
        )
        .unwrap();
        client
            .register(RegisterOptions::new(node.clone()))
            .await
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            client.send_map_update(SendMapUpdateOptions::new(node)),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn server_key_change_invalidates_shared_transport() {
        let mut server = Server::new();
        server.start().await.unwrap();
        let node = NodePrivate::generate();
        let client = Client::new(
            ClientOptions::new(MachinePrivate::generate())
                .server_url(server.base_url())
                .control_public_key(server.noise_public_key()),
        )
        .unwrap();
        client
            .register(RegisterOptions::new(node.clone()))
            .await
            .unwrap();
        assert_eq!(server.noise_connection_count(), 1);

        client.set_control_public_key(server.noise_public_key());
        client
            .send_map_update(SendMapUpdateOptions::new(node))
            .await
            .unwrap();
        assert_eq!(server.noise_connection_count(), 2);
    }

    #[tokio::test]
    async fn registration_response_limit_is_strict() {
        let mut server = Server::new();
        server.start().await.unwrap();
        let machine = MachinePrivate::generate();
        let client = Client::new(
            ClientOptions::new(machine)
                .server_url(server.base_url())
                .control_public_key(server.noise_public_key()),
        )
        .unwrap();
        let mut options = RegisterOptions::new(NodePrivate::generate());
        options.max_response_size = 1;
        assert!(matches!(
            client.register(options).await,
            Err(TspError::ResponseTooLarge { max: 1 })
        ));
    }

    #[test]
    fn rejects_zero_private_keys_without_io() {
        assert!(matches!(
            Client::new(ClientOptions::new(MachinePrivate::from_raw32([0; 32]))),
            Err(TspError::MissingMachineKey)
        ));
    }
}
