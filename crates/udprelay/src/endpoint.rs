//! Public endpoint type and errors for the UDP relay server.
//!
//! Ports Go's `net/udprelay/endpoint/endpoint.go`.

use std::net::SocketAddr;
use std::time::Duration;

use rustscale_key::DiscoPublic;

/// Default retry-after duration when the server is not yet ready (no advertised
/// addresses). Matches Go's `endpoint.ServerRetryAfter`.
pub const SERVER_RETRY_AFTER: Duration = Duration::from_secs(3);

/// Details for an endpoint served by a [`crate::Server`](crate::Server).
///
/// Clients use this to initiate the 3-way bind handshake directly over UDP.
#[derive(Debug, Clone)]
pub struct ServerEndpoint {
    /// The server's disco public key (used for the 3-way bind handshake).
    /// Combined with `lamport_id`, uniquely identifies an allocation.
    pub server_disco: DiscoPublic,

    /// Disco public keys of the two relay participants permitted to handshake.
    pub client_disco: [DiscoPublic; 2],

    /// Monotonically non-decreasing allocation counter. Lets clients detect and
    /// resolve races: if two clients both allocate on the same server, the
    /// higher `lamport_id` wins.
    pub lamport_id: u64,

    /// IP:port candidate pairs the server may be reachable over.
    pub addr_ports: Vec<SocketAddr>,

    /// 24-bit Geneve VNI the server uses for transmitted packets and expects
    /// for received packets associated with this endpoint.
    pub vni: u32,

    /// Time post-allocation the server considers the endpoint active while it
    /// has yet to be bound via 3-way handshake from both client parties.
    pub bind_lifetime: Duration,

    /// Time post-handshake the server considers the endpoint active lacking
    /// bidirectional data flow.
    pub steady_state_lifetime: Duration,
}

/// Errors returned by the UDP relay server.
#[derive(Debug, thiserror::Error)]
pub enum UdprelayError {
    /// The server has been closed.
    #[error("server closed")]
    ServerClosed,
    /// The server is not ready (no advertised addresses); retry after the
    /// given duration.
    #[error("server not ready, retry after {retry_after:?}")]
    ServerNotReady {
        /// How long to wait before retrying.
        retry_after: Duration,
    },
    /// The VNI pool is exhausted.
    #[error("VNI pool exhausted")]
    VniExhausted,
    /// A client disco key equals the server's own disco key.
    #[error("client disco equals server disco")]
    ClientEqualsServer,
    /// I/O error from the UDP socket.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
