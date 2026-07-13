//! Control-plane client: register and map long-poll flows over HTTP/2-in-Noise.
//!
//! Ports Go's `control/ts2021` (HTTP/2 over Noise) and
//! `control/controlclient/direct.go` (register + map request).
//!
//! ## Architecture
//!
//! After the Noise handshake (controlbase), the connection becomes an
//! HTTP/2 transport (matching Go's `ts2021.Client` which uses
//! `http.Transport` with `SetUnencryptedHTTP2` over the Noise conn).
//!
//! - **Register**: `POST /machine/register` with a JSON body → standard
//!   HTTP/2 request/response. The response body is JSON `RegisterResponse`.
//! - **Map poll**: `POST /machine/map` with a JSON body → HTTP/2 `200 OK`,
//!   then the response body is a stream of 4-byte LE size-prefixed JSON
//!   `MapResponse` messages (application-level framing within the HTTP body).

use rustscale_key::{MachinePrivate, MachinePublic};
use rustscale_tailcfg::{
    MapRequest, MapResponse, RegisterRequest, RegisterResponse, SetDNSRequest, SetDNSResponse,
};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::controlbase::{NoiseIo, ProtocolVersion};
use crate::controlhttp::dial_control;

/// Shared map-session state for delta-tracking across reconnections.
///
/// The map-update task writes `handle` and `seq` as it processes each
/// `MapResponse`; [`ControlClient::stream_map_loop`] reads them before each
/// (re)connection to populate `MapRequest.MapSessionHandle` /
/// `MapRequest.MapSessionSeq` so the server can resume from the last
/// processed sequence number. Mirrors Go's `Auto.lastSeq` / `mapSessionHandle`
/// in `controlclient/auto.go`.
#[derive(Debug, Default)]
pub struct MapSessionState {
    inner: Mutex<(String, i64)>,
}

impl MapSessionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the session handle and sequence number.
    pub fn set(&self, handle: String, seq: i64) {
        *self.inner.lock().expect("MapSessionState lock poisoned") = (handle, seq);
    }

    /// Snapshot the current handle and sequence number.
    pub fn get(&self) -> (String, i64) {
        self.inner
            .lock()
            .expect("MapSessionState lock poisoned")
            .clone()
    }
}

/// Errors from a register request.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("dial: {0}")]
    Dial(#[from] crate::controlhttp::DialError),
    #[error("noise: {0}")]
    Noise(#[from] crate::controlbase::NoiseError),
    #[error("h2: {0}")]
    H2(#[from] h2::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http status {0}: {1}")]
    HttpStatus(u16, String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from the map long-poll stream.
#[derive(Debug, thiserror::Error)]
pub enum StreamMapError {
    #[error("dial: {0}")]
    Dial(#[from] crate::controlhttp::DialError),
    #[error("noise: {0}")]
    Noise(#[from] crate::controlbase::NoiseError),
    #[error("h2: {0}")]
    H2(#[from] h2::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http status {0}: {1}")]
    HttpStatus(u16, String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from establishing the HTTP/2 connection.
#[derive(Debug, thiserror::Error)]
pub enum H2SetupError {
    #[error("noise: {0}")]
    Noise(#[from] crate::controlbase::NoiseError),
    #[error("h2: {0}")]
    H2(#[from] h2::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<H2SetupError> for RegisterError {
    fn from(e: H2SetupError) -> Self {
        match e {
            H2SetupError::Noise(e) => RegisterError::Noise(e),
            H2SetupError::H2(e) => RegisterError::H2(e),
            H2SetupError::Io(e) => RegisterError::Io(e),
        }
    }
}

impl From<H2SetupError> for StreamMapError {
    fn from(e: H2SetupError) -> Self {
        match e {
            H2SetupError::Noise(e) => StreamMapError::Noise(e),
            H2SetupError::H2(e) => StreamMapError::H2(e),
            H2SetupError::Io(e) => StreamMapError::Io(e),
        }
    }
}

/// The high-level control-plane client.
///
/// Each request dials a fresh Noise + HTTP/2 connection (matching Go's
/// `ts2021.Client` which pools at most one connection).
pub struct ControlClient {
    host: String,
    machine_key: MachinePrivate,
    control_key: MachinePublic,
    version: ProtocolVersion,
    extra_root_certs: Option<Vec<Vec<u8>>>,
}

impl ControlClient {
    pub fn new(
        host: impl Into<String>,
        machine_key: MachinePrivate,
        control_key: MachinePublic,
        version: ProtocolVersion,
    ) -> Self {
        let host = host.into();
        if host == "https://controlplane.tailscale.com"
            && rustscale_envknob::bool("TS_PANIC_IF_HIT_MAIN_CONTROL").unwrap_or(false)
        {
            panic!("TS_PANIC_IF_HIT_MAIN_CONTROL: connecting to main control");
        }
        Self {
            host,
            machine_key,
            control_key,
            version,
            extra_root_certs: None,
        }
    }

    /// Set additional root CAs (DER-encoded) to trust alongside the webpki and
    /// baked ISRG roots. Mirrors Go's `tsnet.Server.ExtraRootCAs` plumbing.
    pub fn set_extra_root_certs(&mut self, certs: Vec<Vec<u8>>) {
        self.extra_root_certs = Some(certs);
    }

    /// Send a `RegisterRequest` to `/machine/register` and return the response.
    pub async fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegisterError> {
        let noise_stream = dial_control(
            &self.host,
            &self.machine_key,
            &self.control_key,
            self.version,
            self.extra_root_certs.as_deref(),
        )
        .await?;

        let (conn, stream) = noise_stream.into_parts();
        let noise_io = NoiseIo::new(conn, stream);

        let (mut h2_send, h2_conn) = establish_h2(noise_io).await?;
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let body = serde_json::to_vec(req)?;
        let request = http::Request::builder()
            .method("POST")
            .uri("/machine/register")
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        // h2 returns (ResponseFuture, SendStream).
        let (resp_future, mut send_stream) = h2_send.send_request(request, false)?;
        send_stream.send_data(bytes::Bytes::from(body), true)?;

        let resp = resp_future.await?;
        let status = resp.status().as_u16();
        let mut body = resp.into_body();

        let data = read_h2_body(&mut body).await?;

        if status != 200 {
            return Err(RegisterError::HttpStatus(
                status,
                String::from_utf8_lossy(&data).to_string(),
            ));
        }

        let resp: RegisterResponse = serde_json::from_slice(&data)?;
        Ok(resp)
    }

    /// Send a `MapRequest` to `/machine/map` and stream `MapResponse` updates
    /// over a channel.
    pub async fn stream_map(
        &self,
        req: &MapRequest,
        updates: mpsc::Sender<Result<MapResponse, StreamMapError>>,
    ) -> Result<(), StreamMapError> {
        let noise_stream = dial_control(
            &self.host,
            &self.machine_key,
            &self.control_key,
            self.version,
            self.extra_root_certs.as_deref(),
        )
        .await?;

        let (conn, stream) = noise_stream.into_parts();
        let noise_io = NoiseIo::new(conn, stream);

        let (mut h2_send, h2_conn) = establish_h2(noise_io).await?;
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let body = serde_json::to_vec(req)?;
        let request = http::Request::builder()
            .method("POST")
            .uri("/machine/map")
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let (resp_future, mut send_stream) = h2_send.send_request(request, false)?;
        send_stream.send_data(bytes::Bytes::from(body), true)?;

        let resp = resp_future.await?;
        let status = resp.status().as_u16();
        let mut resp_body = resp.into_body();

        if status != 200 {
            let data = read_h2_body(&mut resp_body).await?;
            return Err(StreamMapError::HttpStatus(
                status,
                String::from_utf8_lossy(&data).to_string(),
            ));
        }

        // Read 4-byte LE size-prefixed MapResponse messages from the body.
        // h2::RecvStream doesn't impl AsyncRead, so we read frames and
        // buffer them.
        let mut read_buf: Vec<u8> = Vec::new();
        loop {
            // Ensure we have at least 4 bytes for the size header.
            while read_buf.len() < 4 {
                match resp_body.data().await {
                    Some(Ok(frame)) => {
                        let _ = resp_body.flow_control().release_capacity(frame.len());
                        read_buf.extend_from_slice(&frame);
                    }
                    Some(Err(e)) => {
                        let _ = updates.send(Err(StreamMapError::H2(e))).await;
                        return Ok(());
                    }
                    None => {
                        // Stream ended.
                        if read_buf.is_empty() {
                            return Ok(());
                        }
                        // Partial data — treat as EOF.
                        return Ok(());
                    }
                }
            }

            let size =
                u32::from_le_bytes([read_buf[0], read_buf[1], read_buf[2], read_buf[3]]) as usize;
            read_buf.drain(..4);

            if size > 4 * 1024 * 1024 {
                let _ = updates
                    .send(Err(StreamMapError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "map response too large",
                    ))))
                    .await;
                return Ok(());
            }

            // Read until we have `size` bytes.
            while read_buf.len() < size {
                match resp_body.data().await {
                    Some(Ok(frame)) => {
                        let _ = resp_body.flow_control().release_capacity(frame.len());
                        read_buf.extend_from_slice(&frame);
                    }
                    Some(Err(e)) => {
                        let _ = updates.send(Err(StreamMapError::H2(e))).await;
                        return Ok(());
                    }
                    None => {
                        // Stream ended prematurely.
                        return Ok(());
                    }
                }
            }

            let msg: Vec<u8> = read_buf.drain(..size).collect();
            match serde_json::from_slice::<MapResponse>(&msg) {
                Ok(mr) => {
                    if updates.send(Ok(mr)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = updates.send(Err(StreamMapError::Json(e))).await;
                    break;
                }
            }
        }
        Ok(())
    }

    /// Stream `MapResponse` updates with automatic reconnection.
    ///
    /// Loops forever (until the `updates` channel is closed), calling
    /// [`stream_map`](Self::stream_map) on each iteration. When the stream
    /// ends — server closes, network glitch, HTTP/2 GOAWAY — sleeps with
    /// exponential backoff (2s → 4s → 8s → … → 60s cap) and reconnects.
    /// Resets the backoff to 2s after a clean stream end (Ok), since a
    /// clean disconnect typically means responses were received.
    ///
    /// When `session` is provided, each (re)connection clones `req` and
    /// populates `MapSessionHandle` / `MapSessionSeq` from the shared state
    /// so the server can resume the prior session from the last-processed
    /// sequence number.
    pub async fn stream_map_loop(
        &self,
        req: &MapRequest,
        updates: mpsc::Sender<Result<MapResponse, StreamMapError>>,
        session: Option<Arc<MapSessionState>>,
    ) {
        let mut backoff = std::time::Duration::from_secs(2);
        loop {
            if updates.is_closed() {
                return;
            }
            let req_for_iter: MapRequest = if let Some(ref ss) = session {
                let (handle, seq) = ss.get();
                let mut r = req.clone();
                r.MapSessionHandle = handle;
                r.MapSessionSeq = seq;
                r
            } else {
                req.clone()
            };
            match self.stream_map(&req_for_iter, updates.clone()).await {
                Ok(()) => {
                    backoff = std::time::Duration::from_secs(2);
                    eprintln!("control: map stream ended; reconnecting in {backoff:?}");
                }
                Err(e) => {
                    eprintln!("control: map stream error: {e}; reconnecting in {backoff:?}");
                    backoff = (backoff * 2).min(std::time::Duration::from_mins(1));
                }
            }
            tokio::time::sleep(backoff).await;
        }
    }

    /// Send a fire-and-forget `MapRequest` (no response body expected).
    ///
    /// Opens a Noise + h2 connection, POSTs the request, checks the HTTP
    /// status is 200, then discards the response body. Use for endpoint
    /// updates where `OmitPeers=true` and `Stream=false` — the control
    /// server responds with HTTP 200 and an empty body.
    pub async fn send_map_request(&self, req: &MapRequest) -> Result<(), StreamMapError> {
        let noise_stream = dial_control(
            &self.host,
            &self.machine_key,
            &self.control_key,
            self.version,
            self.extra_root_certs.as_deref(),
        )
        .await?;

        let (conn, stream) = noise_stream.into_parts();
        let noise_io = NoiseIo::new(conn, stream);

        let (mut h2_send, h2_conn) = establish_h2(noise_io).await?;
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let body = serde_json::to_vec(req)?;
        let request = http::Request::builder()
            .method("POST")
            .uri("/machine/map")
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let (resp_future, mut send_stream) = h2_send.send_request(request, false)?;
        send_stream.send_data(bytes::Bytes::from(body), true)?;

        let resp = resp_future.await?;
        let status = resp.status().as_u16();
        let mut body = resp.into_body();

        if status != 200 {
            let data = read_h2_body(&mut body).await?;
            return Err(StreamMapError::HttpStatus(
                status,
                String::from_utf8_lossy(&data).to_string(),
            ));
        }

        // Drain and discard the response body (expected to be empty).
        while body.data().await.is_some() {}

        Ok(())
    }

    /// Convenience: send a `MapRequest` and read the first `MapResponse`.
    pub async fn fetch_map(&self, req: &MapRequest) -> Result<MapResponse, StreamMapError> {
        let (tx, mut rx) = mpsc::channel(1);
        self.stream_map(req, tx).await?;
        rx.recv()
            .await
            .ok_or_else(|| StreamMapError::Io(std::io::Error::other("no map response")))?
    }

    /// Post a [`SetDNSRequest`] to `/machine/set-dns`.
    ///
    /// This asks the control plane to publish a DNS record in the tailnet's
    /// DNS zone. The primary use is answering ACME DNS-01 challenges for
    /// Let's Encrypt certificate issuance: `Name` is
    /// `_acme-challenge.<cert-domain>`, `Type` is `"TXT"`, `Value` is the
    /// challenge record (see Go's `ipn/ipnlocal/cert.go` → `SetDNS`).
    pub async fn set_dns(&self, req: &SetDNSRequest) -> Result<SetDNSResponse, RegisterError> {
        let noise_stream = dial_control(
            &self.host,
            &self.machine_key,
            &self.control_key,
            self.version,
            self.extra_root_certs.as_deref(),
        )
        .await?;

        let (conn, stream) = noise_stream.into_parts();
        let noise_io = NoiseIo::new(conn, stream);

        let (mut h2_send, h2_conn) = establish_h2(noise_io).await?;
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let body = serde_json::to_vec(req)?;
        let request = http::Request::builder()
            .method("POST")
            .uri("/machine/set-dns")
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let (resp_future, mut send_stream) = h2_send.send_request(request, false)?;
        send_stream.send_data(bytes::Bytes::from(body), true)?;

        let resp = resp_future.await?;
        let status = resp.status().as_u16();
        let mut body = resp.into_body();
        let data = read_h2_body(&mut body).await?;

        if status != 200 {
            return Err(RegisterError::HttpStatus(
                status,
                String::from_utf8_lossy(&data).to_string(),
            ));
        }

        // SetDNSResponse is empty; tolerate an empty body.
        if data.is_empty() {
            Ok(SetDNSResponse::default())
        } else {
            Ok(serde_json::from_slice(&data)?)
        }
    }
}

/// The 5-byte magic prefix indicating an early payload (from ts2021/conn.go).
const EARLY_PAYLOAD_MAGIC: &[u8] = b"\xff\xff\xffTS";

/// Handle the optional "early payload" and establish an HTTP/2 connection
/// over the Noise stream.
///
/// Returns (SendRequest, Connection) from the `h2` crate.
async fn establish_h2(
    mut noise_io: NoiseIo,
) -> Result<
    (
        h2::client::SendRequest<bytes::Bytes>,
        h2::client::Connection<tokio::io::DuplexStream, bytes::Bytes>,
    ),
    H2SetupError,
> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read the first 9 bytes to check for early payload.
    let mut hdr = [0u8; 9];
    noise_io.read_exact(&mut hdr).await?;

    let prepend: Vec<u8> = if &hdr[..5] == EARLY_PAYLOAD_MAGIC {
        // Early payload: read the JSON body and discard. No bytes to prepend.
        let ep_len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
        if ep_len < 10 * 1024 * 1024 {
            let mut ep = vec![0u8; ep_len];
            noise_io.read_exact(&mut ep).await?;
        }
        Vec::new()
    } else {
        // Not early payload — the 9 bytes are the server's first HTTP/2 frame.
        // Prepend them to the stream.
        hdr.to_vec()
    };

    // Bridge the NoiseIo through a duplex stream, optionally prepending bytes.
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    if !prepend.is_empty() {
        server.write_all(&prepend).await?;
    }

    tokio::spawn(async move {
        let mut io = noise_io;
        let mut read_buf = vec![0u8; 8192];
        let mut write_buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                result = io.read(&mut read_buf) => {
                    match result {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if server.write_all(&read_buf[..n]).await.is_err() { break; }
                            let _ = server.flush().await;
                        }
                    }
                }
                result = server.read(&mut write_buf) => {
                    match result {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if io.write_all(&write_buf[..n]).await.is_err() { break; }
                            let _ = io.flush().await;
                        }
                    }
                }
            }
        }
    });

    let (h2_send, h2_conn) = h2::client::handshake(client).await?;
    Ok((h2_send, h2_conn))
}

/// Read the full HTTP/2 response body.
async fn read_h2_body(body: &mut h2::RecvStream) -> Result<Vec<u8>, h2::Error> {
    let mut data = Vec::new();
    while let Some(frame) = body.data().await {
        let frame = frame?;
        let _ = body.flow_control().release_capacity(frame.len());
        data.extend_from_slice(&frame);
    }
    Ok(data)
}

/// Decode the 4-byte LE size-prefixed map response framing.
/// Matches Go's `direct.go` read loop: `binary.LittleEndian.Uint32(siz[:])`.
pub fn decode_map_frames(buf: &[u8]) -> Vec<&[u8]> {
    let mut frames = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        let size =
            u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + size > buf.len() {
            break;
        }
        frames.push(&buf[pos..pos + size]);
        pos += size;
    }
    frames
}

/// Encode a `MapResponse` JSON payload into the 4-byte LE size-prefixed
/// wire format (for test helpers and server-side encoding).
pub fn encode_map_frame(payload: &[u8]) -> Vec<u8> {
    let size = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests;
