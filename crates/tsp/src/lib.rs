//! Alternative Tailscale protocol client over the shared ts2021 Noise transport.
//!
//! This crate is additive: it provides explicit registration and map-stream
//! operations without changing `rustscale-tsnet`'s existing control path.

#![forbid(unsafe_code)]

mod client;
mod frame;
mod nodefile;

pub use client::{
    discover_server_key, Client, ClientOptions, MapOptions, MapSession, RegisterOptions,
    SendMapUpdateOptions, TspError, CURRENT_CAPABILITY_VERSION, DEFAULT_MAX_MESSAGE_SIZE,
    DEFAULT_SERVER_URL,
};
pub use frame::{FrameDecoder, FrameError};
pub use nodefile::{NodeFile, NodeFileError, ServerInfo};
