#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod other;
mod socks;

#[cfg(target_os = "linux")]
use linux::{configure_udp_socket as configure_platform_udp_socket, control_and_connect};
#[cfg(target_os = "macos")]
use macos::{configure_udp_socket as configure_platform_udp_socket, control_and_connect};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use other::{configure_udp_socket as configure_platform_udp_socket, control_and_connect};

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(true);
static BIND_TO_INTERFACE_BY_ROUTE: AtomicBool = AtomicBool::new(false);
// Binding magicsock's own UDP sockets to the default physical interface is a
// route-loop bypass that is only needed when the OS route table sends the
// node's traffic back through our tunnel (TUN full-tunnel / exit-node mode).
// In userspace tsnet mode it is actively harmful: pinning to the physical
// interface breaks loopback and same-machine direct UDP (rustscale's
// localhost-direct path). Default to disabled; TUN/exit-node mode opts in via
// `set_disable_bind_conn_to_interface(false)`.
static DISABLE_BIND_CONN_TO_INTERFACE: AtomicBool = AtomicBool::new(true);

pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn set_bind_to_interface_by_route(v: bool) {
    BIND_TO_INTERFACE_BY_ROUTE.store(v, Ordering::Relaxed);
}

pub fn set_disable_bind_conn_to_interface(v: bool) {
    DISABLE_BIND_CONN_TO_INTERFACE.store(v, Ordering::Relaxed);
}

pub fn is_localhost(addr: &str) -> bool {
    let lower = addr.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost" | "localhost6" | "ip6-loopback" | "ip6-localhost"
    ) {
        return true;
    }
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return sa.ip().is_loopback();
    }
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            if let Ok(ip) = rest[..end].parse::<IpAddr>() {
                return ip.is_loopback();
            }
        }
    }
    if addr.chars().filter(|c| *c == ':').count() == 1 {
        if let Some((h, _)) = addr.rsplit_once(':') {
            let lower = h.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "localhost" | "localhost6" | "ip6-loopback" | "ip6-localhost"
            ) {
                return true;
            }
            if let Ok(ip) = h.parse::<IpAddr>() {
                return ip.is_loopback();
            }
        }
    }
    false
}

pub async fn dial_tcp(host: &str, port: u16) -> Result<tokio::net::TcpStream, std::io::Error> {
    if !is_enabled() || is_localhost(host) {
        let addr = format!("{host}:{port}");
        let stream = tokio::net::TcpStream::connect(&addr).await?;
        stream.set_nodelay(true).ok();
        return Ok(stream);
    }
    if let Some(proxy) = socks::all_proxy() {
        return socks::dial_sock5(&proxy, host, port).await;
    }
    let addrs = tokio::net::lookup_host(format!("{host}:{port}")).await?;
    let mut last_err = std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addresses");
    for addr in addrs {
        match control_and_connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

pub async fn dial_tcp_addr(addr: SocketAddr) -> Result<tokio::net::TcpStream, std::io::Error> {
    if !is_enabled() {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        return Ok(stream);
    }
    control_and_connect(addr).await
}

/// Apply this process's route-loop bypass policy to a UDP socket.
///
/// On Linux this uses the Tailscale bypass mark (or the default physical
/// device on kernels that do not permit socket marks); on macOS it binds the
/// socket to the default physical interface. This is used by magicsock before
/// its UDP socket starts sending traffic.
pub fn configure_udp_socket(socket: &tokio::net::UdpSocket) -> Result<(), std::io::Error> {
    if !is_enabled() {
        return Ok(());
    }
    configure_platform_udp_socket(socket)
}

#[cfg(test)]
mod tests {
    use super::is_localhost;
    #[test]
    fn test_localhost_str() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("localhost6"));
        assert!(is_localhost("ip6-loopback"));
        assert!(is_localhost("ip6-localhost"));
    }
    #[test]
    fn test_localhost_ip() {
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("::1"));
        assert!(is_localhost("127.5.5.5"));
    }
    #[test]
    fn test_not_localhost() {
        assert!(!is_localhost("example.com"));
        assert!(!is_localhost("8.8.8.8"));
    }
}
