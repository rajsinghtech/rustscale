//! Peer dial path — plain TCP to a peer IP:port. No netns, no proxy, no
//! tracking. Mirrors Go's `tsdial.Dialer.dialPeerAPI`.

use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::dns_map::split_host_port;

/// Dial a peer API connection. Plain `TcpStream::connect` — no netns binding,
/// no proxy, no SOCKS. The peer is reached directly over the tailnet.
pub(crate) async fn dial_peer_api(addr: &str) -> std::io::Result<TcpStream> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        let stream = TcpStream::connect(sa).await?;
        let _ = stream.set_nodelay(true);
        return Ok(stream);
    }
    if let Some((host, port)) = split_host_port(addr) {
        let stream = TcpStream::connect((host.as_str(), port)).await?;
        let _ = stream.set_nodelay(true);
        return Ok(stream);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("bad peer addr: {addr}"),
    ))
}
