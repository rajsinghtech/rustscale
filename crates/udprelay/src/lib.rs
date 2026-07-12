//! UDP peer relay server for rustscale.
//!
//! Ports the server side of Tailscale's peer relay protocol from Go's
//! `net/udprelay/server.go`. The server opens a UDP socket, allocates VNIs
//! (24-bit Geneve Virtual Network Identifiers), runs a 3-way disco bind
//! handshake to authenticate clients, and forwards Geneve-encapsulated
//! WireGuard (or disco) packets between two bound endpoints.
//!
//! # Protocol
//!
//! All packets to/from the relay server carry an 8-byte Geneve header
//! (see [`geneve::GeneveHeader`]). Control packets use
//! `Control=true, Protocol=GeneveProtocolDisco`; data packets use
//! `Control=false, Protocol=GeneveProtocolWireGuard`.
//!
//! The 3-way bind handshake:
//!
//! 1. Client → Server: `BindUDPRelayEndpoint` (VNI, generation, RemoteKey)
//! 2. Server → Client: `BindUDPRelayEndpointChallenge` (same + BLAKE2s MAC)
//! 3. Client → Server: `BindUDPRelayEndpointAnswer` (echo Challenge MAC)
//!
//! After binding, the server forwards data packets between the two bound
//! client addresses.

#![forbid(unsafe_code)]

mod endpoint;
mod geneve;
mod mac;
mod server;

pub use endpoint::{ServerEndpoint, SERVER_RETRY_AFTER, UdprelayError};
pub use geneve::{
    decode_geneve, encode_geneve, encode_geneve_control, GeneveHeader,
    GENEVE_FIXED_HEADER_LENGTH, GENEVE_PROTOCOL_DISCO, GENEVE_PROTOCOL_WIREGUARD,
};
pub use server::{Server, ServerConfig};
