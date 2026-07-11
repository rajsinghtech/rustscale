//! DERP relay client protocol for rustscale.
//!
//! Ports the wire format of Go's `derp` and `derp/derphttp` packages. Provides:
//!
//! - A pure-sync frame codec (`frame`) for testing without a network.
//! - Protocol types (`ClientInfo`, `ServerInfo`, `MeshKey`, `Received`).
//! - An async [`DerpClient`] over tokio + rustls.

#![forbid(unsafe_code)]

mod client;
mod frame;
mod protocol;
mod server;

pub use client::DerpClient;
pub use frame::{
    decode_frame_header, encode_frame_header, read_frame, read_frame_header, write_frame,
    write_frame_header, FRAME_HEADER_LEN, KEY_LEN, MAGIC, MAX_INFO_LEN, MAX_PACKET_SIZE, NONCE_LEN,
    PROTOCOL_VERSION,
};
pub use protocol::{ClientInfo, MeshKey, Received, ServerInfo};
pub use server::{DerpServer, DerpServerHandle};

/// Errors from the DERP client.
#[derive(Debug, thiserror::Error)]
pub enum DerpError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("bad frame: {0}")]
    BadFrame(String),
    #[error("bad DERP magic")]
    BadMagic,
    #[error("short frame")]
    ShortFrame,
    #[error("bad server info: {0}")]
    BadServerInfo(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("key error: {0}")]
    Key(#[from] rustscale_key::KeyError),
    #[error("packet too large: {0} bytes")]
    PacketTooLarge(usize),
}

// Re-export frame type constants for convenience.
pub mod frame_type {
    pub use crate::frame::frame_type::*;
}

pub mod peer_gone_reason {
    pub use crate::frame::peer_gone_reason::*;
}

pub mod peer_present_flags {
    pub use crate::frame::peer_present_flags::*;
}

pub mod headers {
    pub use crate::frame::headers::*;
}
