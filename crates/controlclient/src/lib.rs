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

pub mod client;
pub mod controlbase;
pub mod controlhttp;

pub use client::{ControlClient, RegisterError, StreamMapError};
pub use controlbase::{NoiseConn, NoiseError, ProtocolVersion};
pub use controlhttp::{dial_control, DialError, NoiseStream};
