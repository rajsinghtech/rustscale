//! Deterministic, in-memory TCP-like connections and listeners.
//!
//! This crate mirrors the observable behavior of Tailscale's `net/memnet`
//! package for hermetic async tests: bounded directional pipes, rendezvous
//! dialing, explicit addresses, fault-injection blocking, deadlines, close
//! wakeups, buffered-data draining, and registry cleanup. It performs no OS
//! networking.
#![forbid(unsafe_code)]

mod addr;
mod conn;
mod listener;
mod network;
mod pipe;

pub use addr::MemAddr;
pub use conn::MemConn;
pub use listener::MemListener;
pub use network::Network;
pub use pipe::MemPipe;

/// Backward-compatible name for [`MemPipe`].
pub type MemBuf = MemPipe;

/// Network name reported by logical (non-TCP) [`MemAddr`] values.
pub const NETWORK_NAME: &str = "mem";
