#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod other;
mod socks;

#[cfg(target_os = "linux")]
use linux::control_and_connect;
#[cfg(target_os = "macos")]
use macos::control_and_connect;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use other::control_and_connect;

use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "macos")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(true);
static BIND_TO_INTERFACE_BY_ROUTE: AtomicBool = AtomicBool::new(false);
static DISABLE_BIND_CONN_TO_INTERFACE: AtomicBool = AtomicBool::new(false);

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

#[cfg(target_os = "macos")]
fn is_cgnat_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 0x40
}

#[cfg(target_os = "macos")]
fn is_tailscale_ula(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    o[0] == 0xfd && o[1] == 0x7a && o[2] == 0x11 && o[3] == 0x5c && o[4] == 0xa1 && o[5] == 0xe0
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
