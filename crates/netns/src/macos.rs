use std::ffi::CString;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

const IP_BOUND_IF: u32 = 25;
const IPV6_BOUND_IF: u32 = 125;

pub async fn control_and_connect(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    connect(addr, false).await
}

pub async fn system_control_and_connect(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    connect(addr, true).await
}

async fn connect(addr: SocketAddr, force_bypass: bool) -> Result<TcpStream, std::io::Error> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    let fd = socket.as_raw_fd();
    if force_bypass
        || !super::DISABLE_BIND_CONN_TO_INTERFACE.load(std::sync::atomic::Ordering::Relaxed)
    {
        let idx = get_interface_index(addr)?;
        bind_fd_to_interface(fd, addr.is_ipv4(), idx)?;
    }
    let stream = socket.connect(addr).await?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Configure a magicsock UDP socket to use the default physical interface.
pub fn configure_udp_socket(socket: &UdpSocket) -> Result<(), std::io::Error> {
    if super::DISABLE_BIND_CONN_TO_INTERFACE.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    let idx = default_interface_index(None)?;
    bind_fd_to_interface(socket.as_raw_fd(), socket.local_addr()?.is_ipv4(), idx)
}

fn bind_fd_to_interface(fd: std::os::fd::RawFd, ipv4: bool, idx: u32) -> std::io::Result<()> {
    let idx_val: libc::c_uint = idx;
    let (level, opt) = if ipv4 {
        (libc::IPPROTO_IP, IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt as libc::c_int,
            (&raw const idx_val).cast::<libc::c_void>(),
            std::mem::size_of_val(&idx_val) as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Verify both Darwin IP_BOUND_IF variants before any full-tunnel route lands.
pub fn validate_underlay_bypass(rustscale_tun_name: &str) -> std::io::Result<()> {
    validate_underlay_bypass_with(
        default_interface_index(Some(rustscale_tun_name)),
        |ipv4, idx| {
            let family = if ipv4 { libc::AF_INET } else { libc::AF_INET6 };
            let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let result = bind_fd_to_interface(fd, ipv4, idx);
            unsafe { libc::close(fd) };
            result
        },
    )
}

fn validate_underlay_bypass_with(
    index: std::io::Result<u32>,
    mut bind: impl FnMut(bool, u32) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let idx = index?;
    bind(true, idx)?;
    bind(false, idx)
}

fn get_interface_index(addr: SocketAddr) -> std::io::Result<u32> {
    let by_route_env = std::env::var("TS_BIND_TO_INTERFACE_BY_ROUTE").is_ok();
    if super::BIND_TO_INTERFACE_BY_ROUTE.load(std::sync::atomic::Ordering::Relaxed) || by_route_env
    {
        interface_index_for_route(addr.ip())
    } else {
        default_interface_index(None)
    }
}

fn default_interface_index(rustscale_tun_name: Option<&str>) -> std::io::Result<u32> {
    let name = rustscale_netmon::default_route_interface();
    if name.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "default physical interface is unknown",
        ));
    }
    if rustscale_tun_name == Some(name.as_str()) || super::is_managed_tun_name(&name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "default interface is the RustScale tunnel",
        ));
    }
    let cname = CString::new(name.as_str())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

#[repr(C)]
#[allow(clippy::struct_field_names)]
struct RtMsgHdr {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: u32,
    rtm_addrs: i32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_use: i32,
    rtm_inits: u32,
    rtm_rmx: [u8; 56],
}

const RTM_GET: u8 = 1;
const RTM_VERSION: u8 = 0x5;
const RTF_UP: u32 = 1;
const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_MAX: usize = 8;

#[repr(C)]
#[allow(clippy::struct_field_names)]
struct SockaddrIn {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
#[allow(clippy::struct_field_names)]
struct SockaddrIn6 {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

fn interface_index_for_route(ip: IpAddr) -> std::io::Result<u32> {
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dest_bytes: Vec<u8> = match ip {
        IpAddr::V4(v4) => {
            let sa = SockaddrIn {
                sin_len: 16,
                sin_family: libc::AF_INET as u8,
                sin_port: 0,
                sin_addr: v4.octets(),
                sin_zero: [0u8; 8],
            };
            unsafe {
                std::slice::from_raw_parts(
                    (&raw const sa).cast::<u8>(),
                    std::mem::size_of::<SockaddrIn>(),
                )
                .to_vec()
            }
        }
        IpAddr::V6(v6) => {
            let sa = SockaddrIn6 {
                sin6_len: 28,
                sin6_family: libc::AF_INET6 as u8,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: v6.octets(),
                sin6_scope_id: 0,
            };
            unsafe {
                std::slice::from_raw_parts(
                    (&raw const sa).cast::<u8>(),
                    std::mem::size_of::<SockaddrIn6>(),
                )
                .to_vec()
            }
        }
    };
    let msg_len = std::mem::size_of::<RtMsgHdr>() + dest_bytes.len();
    let mut msg = Vec::with_capacity(msg_len);
    let rtm = RtMsgHdr {
        rtm_msglen: msg_len as u16,
        rtm_version: RTM_VERSION,
        rtm_type: RTM_GET,
        rtm_index: 0,
        rtm_flags: RTF_UP,
        rtm_addrs: 1 << RTAX_DST,
        rtm_pid: unsafe { libc::getpid() },
        rtm_seq: 1,
        rtm_use: 0,
        rtm_inits: 0,
        rtm_rmx: [0u8; 56],
    };
    unsafe {
        let ptr = (&raw const rtm).cast::<u8>();
        msg.extend_from_slice(std::slice::from_raw_parts(
            ptr,
            std::mem::size_of::<RtMsgHdr>(),
        ));
    }
    msg.extend_from_slice(&dest_bytes);
    let written = unsafe { libc::write(fd, msg.as_ptr().cast(), msg.len()) };
    if written < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    let mut buf = [0u8; 2048];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    unsafe { libc::close(fd) };
    if n <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    parse_route_response(&buf[..n as usize]).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "route response contained no physical interface",
        )
    })
}

fn parse_route_response(buf: &[u8]) -> Option<u32> {
    if buf.len() < std::mem::size_of::<RtMsgHdr>() {
        return None;
    }
    let rtm_hdr_size = std::mem::size_of::<RtMsgHdr>();
    let rtm_addrs = {
        let hdr_bytes = &buf[..rtm_hdr_size];
        let addrs_offset = 16;
        let ab = &hdr_bytes[addrs_offset..addrs_offset + 4];
        i32::from_le_bytes([ab[0], ab[1], ab[2], ab[3]])
    };
    let mut offset = rtm_hdr_size;
    let bitmask = rtm_addrs;
    for i in 0..RTAX_MAX {
        if bitmask & (1 << i) == 0 {
            continue;
        }
        if offset >= buf.len() {
            break;
        }
        let sa_len = buf[offset] as usize;
        if sa_len == 0 {
            offset += 4;
            continue;
        }
        if i == RTAX_GATEWAY && buf[offset + 1] == libc::AF_LINK as u8 && offset + 4 <= buf.len() {
            let idx = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]);
            if idx != 0 {
                return Some(u32::from(idx));
            }
        }
        let aligned = (sa_len + 3) & !3;
        offset += aligned;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::validate_underlay_bypass_with;

    #[test]
    fn bypass_validation_fails_when_interface_discovery_fails() {
        let error = validate_underlay_bypass_with(
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "injected discovery failure",
            )),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn bypass_validation_propagates_each_bound_if_failure() {
        for failing_family in [true, false] {
            let error = validate_underlay_bypass_with(Ok(7), |ipv4, _| {
                if ipv4 == failing_family {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "injected IP_BOUND_IF failure",
                    ))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        }
    }
}
