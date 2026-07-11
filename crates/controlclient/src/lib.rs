//! ts2021 Noise-based control plane client for rustscale.
//!
//! Ports the Tailscale control protocol stack:
//! - [`controlbase`] — Noise IK handshake and length-framed encrypted records
//!   (Go: `control/controlbase`).
//! - [`controlhttp`] — HTTP `/ts2021` upgrade dance
//!   (Go: `control/controlhttp`).
//! - [`client`] — `RegisterRequest` and `MapRequest` long-poll flows
//!   (Go: `control/controlclient`, `control/ts2021`).

#![forbid(unsafe_code)]

pub mod c2n;
pub mod client;
pub mod controlbase;
pub mod controlhttp;

pub use c2n::{C2nHandler, C2nRequest, C2nResponse, C2nRouter};
pub use client::{ControlClient, RegisterError, StreamMapError};
pub use controlbase::{NoiseConn, NoiseError, NoiseIo, ProtocolVersion};
pub use controlhttp::{dial_control, fetch_server_pub_key, DialError, NoiseStream};
