#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod other;
mod socks;

#[cfg(target_os = "linux")]
use linux::{
    configure_udp_socket as configure_platform_udp_socket, control_and_connect,
    create_tun_tcp_socket as create_platform_tun_tcp_socket, system_control_and_connect,
    validate_underlay_bypass,
};
#[cfg(target_os = "macos")]
use macos::{
    configure_udp_socket as configure_platform_udp_socket, control_and_connect,
    create_tun_tcp_socket as create_platform_tun_tcp_socket, system_control_and_connect,
    validate_underlay_bypass,
};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use other::{
    configure_udp_socket as configure_platform_udp_socket, control_and_connect,
    create_tun_tcp_socket as create_platform_tun_tcp_socket, system_control_and_connect,
    validate_underlay_bypass,
};

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

static ENABLED: AtomicBool = AtomicBool::new(true);
static PHYSICAL_UNDERLAY_USERS: AtomicUsize = AtomicUsize::new(0);
static PHYSICAL_UNDERLAY_TUNS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
static BIND_TO_INTERFACE_BY_ROUTE: AtomicBool = AtomicBool::new(false);
// Binding magicsock's own UDP sockets to the default physical interface is a
// route-loop bypass that is only needed when the OS route table sends the
// node's traffic back through our tunnel (TUN full-tunnel / exit-node mode).
// In userspace tsnet mode it is actively harmful: pinning to the physical
// interface breaks loopback and same-machine direct UDP (rustscale's
// localhost-direct path). Default to disabled; TUN/exit-node owners opt in via
// `acquire_physical_underlay_bypass`.
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

/// Acquire process-wide UDP physical-underlay binding for one full-tunnel
/// owner. Calls are reference-counted so multiple embedded TUN servers cannot
/// disable each other's bypass policy.
pub fn acquire_physical_underlay_bypass(rustscale_tun_name: &str) -> Result<(), std::io::Error> {
    validate_underlay_bypass(rustscale_tun_name)?;
    PHYSICAL_UNDERLAY_TUNS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .map_err(|_| std::io::Error::other("underlay TUN registry poisoned"))?
        .push(rustscale_tun_name.to_owned());
    PHYSICAL_UNDERLAY_USERS.fetch_add(1, Ordering::AcqRel);
    set_disable_bind_conn_to_interface(false);
    Ok(())
}

/// Release one full-tunnel owner's UDP physical-underlay binding.
pub fn release_physical_underlay_bypass(rustscale_tun_name: &str) {
    let Some(tuns) = PHYSICAL_UNDERLAY_TUNS.get() else {
        return;
    };
    let removed = match tuns.lock() {
        Ok(mut tuns) => tuns
            .iter()
            .position(|name| name == rustscale_tun_name)
            .map(|index| tuns.remove(index))
            .is_some(),
        Err(_) => false,
    };
    if !removed {
        return;
    }
    let released_last = PHYSICAL_UNDERLAY_USERS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |users| {
            users.checked_sub(1)
        })
        .is_ok_and(|previous| previous == 1);
    if released_last {
        set_disable_bind_conn_to_interface(true);
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn is_managed_tun_name(name: &str) -> bool {
    PHYSICAL_UNDERLAY_TUNS
        .get()
        .and_then(|tuns| tuns.lock().ok())
        .is_some_and(|tuns| tuns.iter().any(|tun| tun == name))
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

/// Dial infrastructure TCP with an unconditional physical-underlay bypass.
/// Control, DERP, and bootstrap callers use this even before exit-node routes
/// are installed, matching upstream's `netns.NewDialer` call sites.
pub async fn dial_system_tcp(
    host: &str,
    port: u16,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    if !is_enabled() || is_localhost(host) {
        return dial_tcp(host, port).await;
    }
    if let Some(proxy) = socks::all_proxy() {
        return socks::dial_sock5_system(&proxy, host, port).await;
    }
    let addrs = tokio::net::lookup_host(format!("{host}:{port}")).await?;
    let mut last_err = std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addresses");
    for addr in addrs {
        match system_control_and_connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_err = error,
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

/// Dial user traffic according to the ordinary OS route table, without the
/// physical-underlay mark/interface binding reserved for control, DERP, and
/// magicsock infrastructure. In TUN mode this is what sends a daemon-owned
/// LocalAPI UserDial into the managed tunnel routes.
pub async fn dial_user_tcp_addr(addr: SocketAddr) -> Result<tokio::net::TcpStream, std::io::Error> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Create a nonblocking TCP socket pinned to the exact managed TUN.
///
/// LocalAPI uses this after route-generation validation. The interface bind
/// prevents a route withdrawal from turning an in-flight user dial into an
/// underlay or local-interface connection.
pub fn create_tun_tcp_socket(
    addr: SocketAddr,
    tun_name: &str,
) -> Result<tokio::net::TcpSocket, std::io::Error> {
    if tun_name.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "managed TUN name is unavailable",
        ));
    }
    create_platform_tun_tcp_socket(addr, tun_name)
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
    #[cfg(target_os = "macos")]
    use super::{is_managed_tun_name, PHYSICAL_UNDERLAY_TUNS};
    #[cfg(target_os = "macos")]
    #[test]
    fn managed_tun_identity_is_exact_not_a_name_pattern() {
        let registry = PHYSICAL_UNDERLAY_TUNS.get_or_init(|| std::sync::Mutex::new(Vec::new()));
        {
            let mut names = registry.lock().unwrap();
            names.clear();
            names.push("rustscale0".into());
        }
        assert!(is_managed_tun_name("rustscale0"));
        assert!(!is_managed_tun_name("rustscale01"));
        assert!(!is_managed_tun_name("utun9"));
        registry.lock().unwrap().clear();
    }

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
