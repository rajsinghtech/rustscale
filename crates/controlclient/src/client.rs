//! Control-plane client: `RegisterRequest` and `MapRequest` long-poll flows.
//!
//! Ports Go's `control/controlclient/direct.go` (register + map request) and
//! `control/ts2021/client.go` (HTTP-over-Noise transport).
//!
//! ## Register flow
//! POST `/machine/register` with a JSON `RegisterRequest` inside a Noise
//! record. The server responds with a JSON `RegisterResponse` in a Noise
//! record. If `AuthURL` is non-empty, interactive login is required.
//!
//! ## Map long-poll flow
//! POST `/machine/map` with a JSON `MapRequest` inside a Noise record. The
//! server responds with a stream of `MapResponse` messages, each prefixed
//! with a 4-byte little-endian size header (matching Go's
//! `sendMapRequest`/read loop in `direct.go`). Each decoded `MapResponse` is
//! delivered to the caller via a `tokio::sync::mpsc` channel.

use rustscale_key::{MachinePrivate, MachinePublic};
use rustscale_tailcfg::{MapRequest, MapResponse, RegisterRequest, RegisterResponse};
use tokio::sync::mpsc;

use crate::controlbase::ProtocolVersion;
use crate::controlhttp::dial_control;

/// Errors from a register request.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// The dial or Noise handshake failed.
    #[error("dial: {0}")]
    Dial(#[from] crate::controlhttp::DialError),
    /// The Noise transport reported an error.
    #[error("noise: {0}")]
    Noise(#[from] crate::controlbase::NoiseError),
    /// JSON serialization or deserialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The server returned an error in the `RegisterResponse.Error` field.
    #[error("server: {0}")]
    Server(String),
    /// An I/O error on the transport.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from the map long-poll stream.
#[derive(Debug, thiserror::Error)]
pub enum StreamMapError {
    /// The dial or Noise handshake failed.
    #[error("dial: {0}")]
    Dial(#[from] crate::controlhttp::DialError),
    /// The Noise transport reported an error.
    #[error("noise: {0}")]
    Noise(#[from] crate::controlbase::NoiseError),
    /// JSON deserialization of a `MapResponse` failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// An I/O error on the transport.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The high-level control-plane client.
///
/// Holds the machine key, server info, and protocol version. Each request
/// dials a fresh Noise connection (matching Go's `ts2021.Client` which
/// pools at most one connection).
pub struct ControlClient {
    host: String,
    machine_key: MachinePrivate,
    control_key: MachinePublic,
    version: ProtocolVersion,
}

impl ControlClient {
    /// Create a new client targeting `host` (e.g. `"controlserver.example.com"`).
    pub fn new(
        host: impl Into<String>,
        machine_key: MachinePrivate,
        control_key: MachinePublic,
        version: ProtocolVersion,
    ) -> Self {
        Self {
            host: host.into(),
            machine_key,
            control_key,
            version,
        }
    }

    /// Send a `RegisterRequest` to `/machine/register` and return the response.
    ///
    /// If `response.AuthURL` is non-empty, the caller must visit that URL to
    /// complete interactive login (then re-register with `Followup` set).
    pub async fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegisterError> {
        let mut stream = dial_control(
            &self.host,
            &self.machine_key,
            &self.control_key,
            self.version,
        )
        .await?;

        let body = serde_json::to_vec(req)?;
        stream.write_record(&body).await?;

        let resp_bytes = stream.read_record().await?;
        let resp: RegisterResponse = serde_json::from_slice(&resp_bytes)?;
        if !resp.Error.is_empty() {
            return Err(RegisterError::Server(resp.Error));
        }
        Ok(resp)
    }

    /// Send a `MapRequest` to `/machine/map` and stream `MapResponse` updates
    /// over a channel. The long-poll loop runs until the server closes the
    /// connection, an error occurs, or the `cancel` channel is signaled.
    ///
    /// Each `MapResponse` is delivered as `Ok(MapResponse)`. Errors terminate
    /// the stream and are delivered as `Err(StreamMapError)`.
    pub async fn stream_map(
        &self,
        req: &MapRequest,
        updates: mpsc::Sender<Result<MapResponse, StreamMapError>>,
    ) -> Result<(), StreamMapError> {
        let mut stream = dial_control(
            &self.host,
            &self.machine_key,
            &self.control_key,
            self.version,
        )
        .await?;

        let body = serde_json::to_vec(req)?;
        stream.write_record(&body).await?;

        // Stream loop: read 4-byte LE size + JSON body, decode MapResponse,
        // deliver to channel. Matches Go's direct.go sendMapRequest read loop.
        loop {
            match stream.read_record().await {
                Ok(record) => {
                    let map_resp: Result<MapResponse, serde_json::Error> =
                        serde_json::from_slice(&record);
                    match map_resp {
                        Ok(mr) => {
                            if updates.send(Ok(mr)).await.is_err() {
                                break; // receiver dropped
                            }
                        }
                        Err(e) => {
                            let _ = updates.send(Err(StreamMapError::Json(e))).await;
                            break;
                        }
                    }
                }
                Err(crate::controlbase::NoiseError::Io(_)) => break, // clean close
                Err(e) => {
                    let _ = updates.send(Err(StreamMapError::from(e))).await;
                    break;
                }
            }
        }
        Ok(())
    }

    /// Convenience: send a `MapRequest` and read the first `MapResponse`
    /// (non-streaming one-shot query).
    pub async fn fetch_map(&self, req: &MapRequest) -> Result<MapResponse, StreamMapError> {
        let mut stream = dial_control(
            &self.host,
            &self.machine_key,
            &self.control_key,
            self.version,
        )
        .await?;

        let body = serde_json::to_vec(req)?;
        stream.write_record(&body).await?;

        let resp_bytes = stream.read_record().await?;
        let resp: MapResponse = serde_json::from_slice(&resp_bytes)?;
        Ok(resp)
    }
}

/// Decode the 4-byte little-endian size-prefixed framing used by the map
/// response stream (matching Go's `direct.go` read loop).
///
/// Given a buffer of bytes, extracts successive `(size, payload)` pairs.
/// Returns a vector of payloads. Partial frames at the end are ignored.
pub fn decode_map_frames(buf: &[u8]) -> Vec<&[u8]> {
    let mut frames = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        let size =
            u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + size > buf.len() {
            break; // partial frame
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
