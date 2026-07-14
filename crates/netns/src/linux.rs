use std::ffi::CString;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::OnceLock;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

const LINUX_BYPASS_MARK: u32 = 0x80000;

pub async fn control_and_connect(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    let fd = socket.as_raw_fd();
    configure_socket(fd)?;
    let stream = socket.connect(addr).await?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Configure a magicsock UDP socket with the same bypass policy as TCP.
pub fn configure_udp_socket(socket: &UdpSocket) -> Result<(), std::io::Error> {
    configure_socket(socket.as_raw_fd())
}

fn configure_socket(fd: std::os::fd::RawFd) -> Result<(), std::io::Error> {
    if use_socket_mark() {
        let mark: libc::c_int = LINUX_BYPASS_MARK as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&raw const mark).cast::<libc::c_void>(),
                std::mem::size_of_val(&mark) as libc::socklen_t,
            )
        };
        if ret != 0 && !ignore_errors() {
            return Err(std::io::Error::last_os_error());
        }
    } else {
        let ifname = rustscale_netmon::default_route_interface();
        let ifname = if ifname.is_empty() {
            "lo".to_string()
        } else {
            ifname
        };
        let cname = CString::new(ifname.as_str())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                cname.as_ptr().cast(),
                ifname.len() as libc::socklen_t,
            )
        };
        if ret != 0 && !ignore_errors() {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn use_socket_mark() -> bool {
    if std::env::var("TS_FORCE_LINUX_BIND_TO_DEVICE").is_ok() {
        return false;
    }
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(probe_socket_mark)
}

fn probe_socket_mark() -> bool {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return true;
    }
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 1u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
        },
        sin_zero: [0u8; 8],
    };
    let ret = unsafe {
        libc::connect(
            sock,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        unsafe { libc::close(sock) };
        return true;
    }
    let mark: libc::c_int = LINUX_BYPASS_MARK as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const mark).cast::<libc::c_void>(),
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    unsafe { libc::close(sock) };
    ret == 0
}

fn ignore_errors() -> bool {
    unsafe { libc::getuid() != 0 }
}
