//! SOCKS5 proxy server (RFC 1928) for rustscale tsnet.
//!
//! Ports `net/socks5/socks5.go` from the Go implementation. A local app
//! (Docker/k8s sidecar pattern) connects to a bound OS TCP address (e.g.
//! `127.0.0.1:1080`); the proxy negotiates the SOCKS5 handshake and dials the
//! target *through the tailnet* via a pluggable [`SocksDialer`] — wired to
//! [`Server::dial`](crate::Server::dial) in production.
//!
//! # Supported subset (RFC 1928)
//!
//! - **Version/method negotiation**: SOCKS5 (`0x05`), no-auth (`0x00`) only.
//!   Clients not offering no-auth are rejected with `0xFF`.
//! - **CONNECT command** (`0x01`) only. BIND (`0x02`) and UDP-ASSOCIATE
//!   (`0x03`) are rejected with reply `0x07` (command not supported).
//! - **Address types**: IPv4 (`0x01`), domain name (`0x03`), IPv6 (`0x04`).
//! - **Reply codes**: success (`0x00`), general failure (`0x01`),
//!   network unreachable (`0x03`), host unreachable (`0x04`),
//!   connection refused (`0x05`), command not supported (`0x07`),
//!   address type not supported (`0x08`).
//!
//! On a successful CONNECT the proxy replies with the bound address
//! (BND.ADDR/BND.PORT) then runs a bidirectional copy between the client and
//! the dialed tailnet stream.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::Duration;

use rustscale_dns::MagicDnsResolver;
use rustscale_netstack::Netstack;
use rustscale_tailcfg::Node;

use crate::TsnetError;

// ---------------------------------------------------------------------------
// Protocol constants (RFC 1928)
// ---------------------------------------------------------------------------

const SOCKS5_VERSION: u8 = 5;

/// Authentication methods (RFC 1928 §3).
const NO_AUTH_REQUIRED: u8 = 0x00;
const NO_ACCEPTABLE_AUTH: u8 = 0xFF;

/// Commands (RFC 1928 §3).
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// Address types (RFC 1928 §5).
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Reply codes (RFC 1928 §6).
#[allow(dead_code)] // protocol constants kept for completeness
mod reply {
    pub const SUCCESS: u8 = 0x00;
    pub const GENERAL_FAILURE: u8 = 0x01;
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECTION_REFUSED: u8 = 0x05;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// Bound address returned on a generic failure reply (0.0.0.0:0), matching
/// Go's `zeroSocksAddr`.
const ZERO_BIND: SocksAddr = SocksAddr::Ipv4 {
    addr: Ipv4Addr::UNSPECIFIED,
    port: 0,
};

/// How long to wait for the dialer to establish the outbound connection.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Dialer
// ---------------------------------------------------------------------------

/// A bidirectional byte stream the SOCKS5 proxy can copy to/from. Blanket-
/// implemented for any `AsyncRead + AsyncWrite + Unpin + Send` (covers both
/// [`NetstackStream`] and `tokio::net::TcpStream`).
///
/// Defined as a real trait (rather than `dyn AsyncRead + AsyncWrite`, which is
/// not object-safe) so a single boxed type can abstract over both stream kinds.
pub trait SocksStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> SocksStream for T {}

/// A boxed, name-erased [`SocksStream`].
pub type BoxedStream = Box<dyn SocksStream>;

/// A pluggable dialer: resolves and connects to a target `host:port`,
/// returning a bidirectional stream and the locally bound address (used for
/// the SOCKS5 BND.ADDR/BND.PORT reply).
///
/// [`ServerSocksDialer`] is the production implementation (wraps
/// [`Server::dial`](crate::Server::dial)); tests supply a mock.
#[async_trait]
pub trait SocksDialer: Send + Sync {
    /// Dial `addr` (e.g. `"100.64.0.2:443"` or `"peer:80"`).
    ///
    /// The returned [`io::Error`]`s `kind()` drives the SOCKS5 reply code:
    /// [`io::ErrorKind::ConnectionRefused`] → `0x05`, `HostUnreachable` →
    /// `0x04`, `NetworkUnreachable` → `0x03`, else `0x01`.
    async fn dial(&self, addr: &str) -> io::Result<(BoxedStream, SocketAddr)>;
}

/// Production dialer: dials through the tailnet via the shared netstack +
/// MagicDNS resolver, mirroring [`Server::dial`](crate::Server::dial).
///
/// Holds clones of the same shared refs stored in `RunningState`, so it can be
/// moved into a spawned task without borrowing the `Server`.
#[derive(Clone)]
pub struct ServerSocksDialer {
    netstack: Arc<Netstack>,
    resolver: Arc<tokio::sync::RwLock<MagicDnsResolver>>,
    peers: Arc<tokio::sync::RwLock<Vec<Node>>>,
}

impl ServerSocksDialer {
    /// Build from the shared handles also kept by `RunningState`.
    pub fn new(
        netstack: Arc<Netstack>,
        resolver: Arc<tokio::sync::RwLock<MagicDnsResolver>>,
        peers: Arc<tokio::sync::RwLock<Vec<Node>>>,
    ) -> Self {
        Self {
            netstack,
            resolver,
            peers,
        }
    }
}

#[async_trait]
impl SocksDialer for ServerSocksDialer {
    async fn dial(&self, addr: &str) -> io::Result<(BoxedStream, SocketAddr)> {
        let socket_addr = crate::resolve_addr_with(addr, &self.resolver, &self.peers)
            .await
            .map_err(tsnet_err_to_io)?;
        let stream = self
            .netstack
            .dial(socket_addr)
            .await
            .map_err(|e| tsnet_err_to_io(TsnetError::Netstack(e)))?;
        // NetstackStream does not expose a local bound address; report the
        // conventional unspecified bind (matches Go's zeroSocksAddr fallback).
        let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        Ok((Box::new(stream), bound))
    }
}

/// Map a [`TsnetError`] from the dial path onto an [`io::Error`] whose `kind`
/// selects the right SOCKS5 reply code.
fn tsnet_err_to_io(e: TsnetError) -> io::Error {
    match e {
        TsnetError::HostnameNotFound(_) => {
            io::Error::new(io::ErrorKind::HostUnreachable, e.to_string())
        }
        TsnetError::Netstack(rustscale_netstack::NetstackError::ConnectionRefused) => {
            io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string())
        }
        TsnetError::Netstack(rustscale_netstack::NetstackError::ConnectionReset) => {
            io::Error::new(io::ErrorKind::ConnectionReset, e.to_string())
        }
        TsnetError::Netstack(rustscale_netstack::NetstackError::ConnectionClosed) => {
            io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
        }
        TsnetError::Netstack(rustscale_netstack::NetstackError::ShuttingDown) => {
            io::Error::new(io::ErrorKind::NotConnected, e.to_string())
        }
        _ => io::Error::other(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Address model
// ---------------------------------------------------------------------------

/// A SOCKS5 address: the union of IPv4, IPv6, and domain-name forms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocksAddr {
    Ipv4 { addr: Ipv4Addr, port: u16 },
    Ipv6 { addr: Ipv6Addr, port: u16 },
    Domain { name: String, port: u16 },
}

impl SocksAddr {
    /// The `host:port` string handed to the dialer (brackets IPv6).
    pub fn host_port(&self) -> String {
        match self {
            SocksAddr::Ipv4 { addr, port } => format!("{addr}:{port}"),
            SocksAddr::Ipv6 { addr, port } => format!("[{addr}]:{port}"),
            SocksAddr::Domain { name, port } => format!("{name}:{port}"),
        }
    }

    /// Encode the address per RFC 1928 §5: `ATYP` + address bytes + port
    /// (big-endian). Returns `None` for an over-long domain (>255 bytes).
    pub fn marshal(&self) -> Option<Vec<u8>> {
        match self {
            SocksAddr::Ipv4 { addr, port } => {
                let mut v = Vec::with_capacity(1 + 4 + 2);
                v.push(ATYP_IPV4);
                v.extend_from_slice(&addr.octets());
                v.extend_from_slice(&port.to_be_bytes());
                Some(v)
            }
            SocksAddr::Ipv6 { addr, port } => {
                let mut v = Vec::with_capacity(1 + 16 + 2);
                v.push(ATYP_IPV6);
                v.extend_from_slice(&addr.octets());
                v.extend_from_slice(&port.to_be_bytes());
                Some(v)
            }
            SocksAddr::Domain { name, port } => {
                if name.len() > 255 {
                    return None;
                }
                let mut v = Vec::with_capacity(1 + 1 + name.len() + 2);
                v.push(ATYP_DOMAIN);
                v.push(name.len() as u8);
                v.extend_from_slice(name.as_bytes());
                v.extend_from_slice(&port.to_be_bytes());
                Some(v)
            }
        }
    }

    /// Parse a SOCKS5 address (ATYP + ...) from `r`. Returns the parsed
    /// address, or an error whose message names the failing field.
    pub async fn parse<R>(r: &mut R) -> Result<SocksAddr, String>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut atyp = [0u8; 1];
        r.read_exact(&mut atyp)
            .await
            .map_err(|_| "could not read address type".to_string())?;
        match atyp[0] {
            ATYP_IPV4 => {
                let mut ip = [0u8; 4];
                r.read_exact(&mut ip)
                    .await
                    .map_err(|_| "could not read IPv4 address".to_string())?;
                let port = read_port(r).await?;
                Ok(SocksAddr::Ipv4 {
                    addr: Ipv4Addr::from(ip),
                    port,
                })
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                r.read_exact(&mut len)
                    .await
                    .map_err(|_| "could not read domain name size".to_string())?;
                let mut name = vec![0u8; len[0] as usize];
                r.read_exact(&mut name)
                    .await
                    .map_err(|_| "could not read domain name".to_string())?;
                let port = read_port(r).await?;
                Ok(SocksAddr::Domain {
                    name: String::from_utf8(name)
                        .map_err(|_| "invalid domain name (non-UTF8)".to_string())?,
                    port,
                })
            }
            ATYP_IPV6 => {
                let mut ip = [0u8; 16];
                r.read_exact(&mut ip)
                    .await
                    .map_err(|_| "could not read IPv6 address".to_string())?;
                let port = read_port(r).await?;
                Ok(SocksAddr::Ipv6 {
                    addr: Ipv6Addr::from(ip),
                    port,
                })
            }
            other => Err(format!("unsupported address type {other:#x}")),
        }
    }
}

async fn read_port<R>(r: &mut R) -> Result<u16, String>
where
    R: AsyncReadExt + Unpin,
{
    let mut port = [0u8; 2];
    r.read_exact(&mut port)
        .await
        .map_err(|_| "could not read port".to_string())?;
    Ok(u16::from_be_bytes(port))
}

/// Encode a full SOCKS5 reply: `VER REPLY RSV` + bound address.
pub fn marshal_reply(reply: u8, bind: &SocksAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 1 + 16 + 2);
    out.push(SOCKS5_VERSION);
    out.push(reply);
    out.push(0); // reserved
    out.extend_from_slice(&bind.marshal().unwrap_or_else(|| {
        // Should not happen for a valid bind; fall back to 0.0.0.0:0.
        ZERO_BIND.marshal().unwrap()
    }));
    out
}

/// Map an [`io::Error`] from the dial path to the best SOCKS5 reply code.
fn dial_err_to_reply(e: &io::Error) -> u8 {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => reply::CONNECTION_REFUSED,
        io::ErrorKind::HostUnreachable => reply::HOST_UNREACHABLE,
        io::ErrorKind::NetworkUnreachable => reply::NETWORK_UNREACHABLE,
        _ => reply::GENERAL_FAILURE,
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// A SOCKS5 proxy server bound to an OS TCP listener. Construct directly with
/// a mock [`SocksDialer`] for tests, or via
/// [`Server::listen_socks5`](crate::Server::listen_socks5) for production.
pub struct Socks5Server<D: SocksDialer> {
    dialer: Arc<D>,
}

impl<D: SocksDialer + 'static> Socks5Server<D> {
    /// Wrap a dialer.
    pub fn new(dialer: D) -> Self {
        Self {
            dialer: Arc::new(dialer),
        }
    }

    /// Accept connections from `listener` until the cancel token fires. Each
    /// connection is handled in its own task. Returns when the listener is
    /// closed or cancelled.
    pub async fn serve(self, listener: TcpListener, cancel: Arc<CancelToken>) {
        loop {
            if cancel.is_cancelled() {
                break;
            }
            // Bounded accept so we can notice cancellation promptly.
            let accept = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
            let (stream, _peer) = match accept {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    eprintln!("socks5: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(_) => continue, // timeout — re-check cancel
            };
            let d = self.dialer.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, d).await {
                    eprintln!("socks5: connection ended: {e}");
                }
            });
        }
    }
}

/// Cancellation token for the SOCKS5 listener loop (mirrors the pattern used
/// by the serve runner).
pub struct CancelToken {
    cancelled: std::sync::atomic::AtomicBool,
}

impl CancelToken {
    /// New uncancelled token.
    pub fn new() -> Self {
        Self {
            cancelled: std::sync::atomic::AtomicBool::new(false),
        }
    }
    /// Fire the token.
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    /// Whether the token has fired.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle a single SOCKS5 client connection end-to-end.
async fn handle_conn<D: SocksDialer>(mut client: TcpStream, dialer: Arc<D>) -> io::Result<()> {
    // 1. Version/method negotiation (RFC 1928 §3).
    if let Err(e) = negotiate_greeting(&mut client).await {
        // On any greeting failure we still reply 0xFF per the RFC.
        let _ = client
            .write_all(&[SOCKS5_VERSION, NO_ACCEPTABLE_AUTH])
            .await;
        return Err(e);
    }
    client
        .write_all(&[SOCKS5_VERSION, NO_AUTH_REQUIRED])
        .await?;

    // 2. Request (RFC 1928 §4/§5).
    let req = match parse_request(&mut client).await {
        Ok(r) => r,
        Err(e) => {
            let _ = client
                .write_all(&marshal_reply(reply::GENERAL_FAILURE, &ZERO_BIND))
                .await;
            return Err(io::Error::new(io::ErrorKind::InvalidData, e));
        }
    };

    // 3. Dispatch by command.
    match req.command {
        CMD_CONNECT => handle_connect(client, &dialer, req.destination).await,
        CMD_BIND | CMD_UDP_ASSOCIATE => {
            client
                .write_all(&marshal_reply(reply::COMMAND_NOT_SUPPORTED, &ZERO_BIND))
                .await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported command {:#x}", req.command),
            ))
        }
        other => {
            client
                .write_all(&marshal_reply(reply::COMMAND_NOT_SUPPORTED, &ZERO_BIND))
                .await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported command {:#x}", other),
            ))
        }
    }
}

/// Parse and validate the client greeting: `VER NMETHODS METHODS...`.
/// Accepts only SOCKS5 with no-auth offered.
async fn negotiate_greeting(client: &mut TcpStream) -> io::Result<()> {
    let mut hdr = [0u8; 2];
    client
        .read_exact(&mut hdr)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "could not read greeting"))?;
    if hdr[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("incompatible SOCKS version {:#x}", hdr[0]),
        ));
    }
    let nmethods = hdr[1] as usize;
    if nmethods == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no auth methods offered",
        ));
    }
    let mut methods = vec![0u8; nmethods];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "could not read methods"))?;
    if !methods.contains(&NO_AUTH_REQUIRED) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no acceptable auth method (no-auth not offered)",
        ));
    }
    Ok(())
}

/// A parsed SOCKS5 request: command + destination address.
#[derive(Debug)]
pub struct Request {
    pub command: u8,
    pub destination: SocksAddr,
}

/// Parse a SOCKS5 request: `VER CMD RSV ATYP ... DST.PORT`.
pub async fn parse_request<R>(r: &mut R) -> Result<Request, String>
where
    R: AsyncReadExt + Unpin,
{
    let mut hdr = [0u8; 3];
    r.read_exact(&mut hdr)
        .await
        .map_err(|_| "could not read request header".to_string())?;
    if hdr[0] != SOCKS5_VERSION {
        return Err(format!("incompatible SOCKS version {:#x}", hdr[0]));
    }
    let command = hdr[1];
    // hdr[2] is reserved (RSV).
    let destination = SocksAddr::parse(r).await?;
    Ok(Request {
        command,
        destination,
    })
}

/// Handle the CONNECT command: dial the target, reply, then copy both ways.
async fn handle_connect<D: SocksDialer>(
    mut client: TcpStream,
    dialer: &Arc<D>,
    destination: SocksAddr,
) -> io::Result<()> {
    let target = destination.host_port();
    let dial = tokio::time::timeout(DIAL_TIMEOUT, dialer.dial(&target)).await;
    let (mut backend, bound) = match dial {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            let code = dial_err_to_reply(&e);
            client.write_all(&marshal_reply(code, &ZERO_BIND)).await?;
            return Err(e);
        }
        Err(_) => {
            client
                .write_all(&marshal_reply(reply::GENERAL_FAILURE, &ZERO_BIND))
                .await?;
            return Err(io::Error::new(io::ErrorKind::TimedOut, "dial timed out"));
        }
    };

    // Success reply with the bound address.
    let bind = SocksAddr::from_socket(bound);
    client
        .write_all(&marshal_reply(reply::SUCCESS, &bind))
        .await?;

    // Bidirectional copy until one side closes.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await?;
    Ok(())
}

impl SocksAddr {
    /// Build the address-type-appropriate [`SocksAddr`] for a bound socket.
    /// IPv4 and IPv6 map directly; a hostname bind (unlikely) is encoded as a
    /// domain entry.
    pub fn from_socket(sa: SocketAddr) -> SocksAddr {
        match sa.ip() {
            IpAddr::V4(v4) => SocksAddr::Ipv4 {
                addr: v4,
                port: sa.port(),
            },
            IpAddr::V6(v6) => SocksAddr::Ipv6 {
                addr: v6,
                port: sa.port(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Handle (returned to callers)
// ---------------------------------------------------------------------------

/// Handle to a running SOCKS5 proxy listener. Drop it to leak the task
/// (it is also aborted by [`Server::close`](crate::Server::close)); call
/// [`Socks5Handle::stop`] to stop it gracefully ahead of close.
pub struct Socks5Handle {
    local_addr: SocketAddr,
    cancel: Arc<CancelToken>,
    task: Option<JoinHandle<()>>,
}

impl Socks5Handle {
    /// The OS address the proxy is bound to (useful when binding `:0`).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop the listener gracefully (signals cancel) and await the task.
    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }

    /// Move the background task out so a caller (e.g. `Server::listen_socks5`)
    /// can store it elsewhere for lifecycle management. After this the handle
    /// still owns the cancel token for graceful stop.
    pub fn take_task(&mut self) -> Option<JoinHandle<()>> {
        self.task.take()
    }
}

impl Drop for Socks5Handle {
    fn drop(&mut self) {
        // Only hard-abort a task we still own. When the task was moved out
        // via `take_task` (the `Server::listen_socks5` path registers it in
        // `RunningState.tasks`, cleaned up by `Server::close`), drop is a
        // no-op so the proxy keeps running until the server closes.
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

/// Bind an OS TCP listener on `bind_addr` and spawn the SOCKS5 accept loop
/// using `dialer`. Returns a [`Socks5Handle`] owning the task.
///
/// `bind_addr` accepts `host:port`, `:port`, or a bare port.
pub async fn spawn_socks5<D: SocksDialer + 'static>(
    bind_addr: &str,
    dialer: D,
) -> io::Result<Socks5Handle> {
    let listener = TcpListener::bind(parse_bind_addr(bind_addr)?).await?;
    let local = listener.local_addr()?;
    let cancel = Arc::new(CancelToken::new());
    let cancel_task = cancel.clone();
    let server = Socks5Server::new(dialer);
    let task = tokio::spawn(async move {
        server.serve(listener, cancel_task).await;
    });
    Ok(Socks5Handle {
        local_addr: local,
        cancel,
        task: Some(task),
    })
}

/// Resolve a bind spec (`"127.0.0.1:1080"`, `":1080"`, or `"1080"`) to a
/// [`SocketAddr`] suitable for `TcpListener::bind`.
fn parse_bind_addr(spec: &str) -> io::Result<SocketAddr> {
    let s = spec.trim();
    if s.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty bind addr",
        ));
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    // ":port"
    if let Some(rest) = s.strip_prefix(':') {
        let port: u16 = rest
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?;
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    // bare port
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid bind addr: {spec}"),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "socks5_tests.rs"]
mod tests;
