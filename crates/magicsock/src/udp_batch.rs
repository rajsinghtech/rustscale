//! Linux `sendmmsg` support for direct WireGuard UDP batches.

#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::ptr;

use tokio::net::UdpSocket;

/// Matches the TUN batch cap. Keeping these arrays on the stack avoids a
/// header allocation for each WireGuard microburst.
pub(crate) const MAX_BATCH: usize = 128;

enum SockAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl SockAddr {
    fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => Self::V4(sockaddr_in(addr)),
            SocketAddr::V6(addr) => Self::V6(sockaddr_in6(addr)),
        }
    }

    fn as_ptr_len(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            Self::V4(addr) => (
                ptr::from_ref(addr).cast::<libc::sockaddr>(),
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            Self::V6(addr) => (
                ptr::from_ref(addr).cast::<libc::sockaddr>(),
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
        }
    }
}

fn sockaddr_in(addr: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        // `s_addr` is stored in network byte order. `from_ne_bytes` gives the
        // value whose in-memory representation is the IPv4 octet sequence.
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn sockaddr_in6(addr: SocketAddrV6) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: addr.port().to_be(),
        sin6_flowinfo: addr.flowinfo().to_be(),
        sin6_addr: libc::in6_addr {
            s6_addr: addr.ip().octets(),
        },
        sin6_scope_id: addr.scope_id(),
    }
}

/// Send an ordered nonempty batch to one destination with one `sendmmsg`.
///
/// A successful return is the exact successfully sent prefix length. This
/// helper borrows all packet data only for the duration of the syscall.
pub(crate) fn send<T: AsRef<[u8]>>(
    socket: &UdpSocket,
    addr: SocketAddr,
    datagrams: &[T],
) -> io::Result<usize> {
    if datagrams.is_empty() || datagrams.len() > MAX_BATCH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sendmmsg batch must contain 1..=128 datagrams",
        ));
    }

    let sockaddr = SockAddr::from_socket_addr(addr);
    let (name, name_len) = sockaddr.as_ptr_len();
    let mut iovecs = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; MAX_BATCH];
    // SAFETY: some supported libc targets keep ABI padding in `msghdr`
    // private. A zeroed header is valid because all fields are integer or
    // nullable pointers.
    let mut empty_hdr: libc::msghdr = unsafe { mem::zeroed() };
    empty_hdr.msg_name = name.cast_mut().cast::<libc::c_void>();
    empty_hdr.msg_namelen = name_len;
    empty_hdr.msg_iov = ptr::null_mut();
    empty_hdr.msg_iovlen = 1;
    let mut headers = [libc::mmsghdr {
        msg_hdr: empty_hdr,
        msg_len: 0,
    }; MAX_BATCH];

    for (index, datagram) in datagrams.iter().enumerate() {
        let data = datagram.as_ref();
        iovecs[index] = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: data.len(),
        };
        headers[index].msg_hdr.msg_iov = ptr::addr_of_mut!(iovecs[index]);
    }

    // SAFETY: `headers` and `iovecs` are initialized for exactly `datagrams.len()`
    // entries; each iovec points at caller-owned data that lives through this call;
    // and every header points at the one live `sockaddr` above. `sendmmsg` retains
    // none of these pointers after returning.
    let sent = unsafe {
        libc::sendmmsg(
            socket.as_raw_fd(),
            headers.as_mut_ptr(),
            datagrams.len() as libc::c_uint,
            libc::MSG_DONTWAIT as libc::c_uint,
        )
    };
    match sent.cmp(&0) {
        std::cmp::Ordering::Greater => Ok(sent as usize),
        std::cmp::Ordering::Equal => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        std::cmp::Ordering::Less => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn sockaddr_v4_preserves_address_and_port() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 3210);
        let got = sockaddr_in(addr);
        assert_eq!(got.sin_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(got.sin_port, 3210u16.to_be());
        assert_eq!(got.sin_addr.s_addr.to_ne_bytes(), [192, 0, 2, 7]);
    }

    #[test]
    fn sockaddr_v6_preserves_all_fields() {
        let addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3210, 0x1020_3040, 9);
        let got = sockaddr_in6(addr);
        assert_eq!(got.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        assert_eq!(got.sin6_port, 3210u16.to_be());
        assert_eq!(got.sin6_flowinfo, 0x1020_3040u32.to_be());
        assert_eq!(got.sin6_addr.s6_addr, Ipv6Addr::LOCALHOST.octets());
        assert_eq!(got.sin6_scope_id, 9);
    }

    #[tokio::test]
    async fn sendmmsg_loopback_preserves_order() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packets = [b"one".as_slice(), b"two", b"three"];
        assert_eq!(
            send(&sender, receiver.local_addr().unwrap(), &packets).unwrap(),
            3
        );
        let mut buf = [0; 16];
        for expected in packets {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], expected);
        }
    }

    #[tokio::test]
    async fn rejects_empty_and_over_capacity_without_sending() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = receiver.local_addr().unwrap();
        assert_eq!(
            send(&sender, addr, &[] as &[&[u8]]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let packets = vec![b"x".as_slice(); MAX_BATCH + 1];
        assert_eq!(
            send(&sender, addr, &packets).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            receiver.recv_from(&mut [0; 1])
        )
        .await
        .is_err());
    }
}
