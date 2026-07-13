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
const MAX_GSO_SEGMENTS: usize = 64;
const MAX_IPV4_PAYLOAD: usize = 65_507;
const MAX_IPV6_PAYLOAD: usize = 65_527;
// libc does not expose this on every supported Linux libc target.
const UDP_SEGMENT: libc::c_int = 103;

#[cfg(target_env = "gnu")]
const SENDMMSG_FLAGS: libc::c_int = libc::MSG_DONTWAIT as libc::c_int;

#[cfg(target_env = "musl")]
const SENDMMSG_FLAGS: libc::c_uint = libc::MSG_DONTWAIT as libc::c_uint;

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
            SENDMMSG_FLAGS,
        )
    };
    match sent.cmp(&0) {
        std::cmp::Ordering::Greater => Ok(sent as usize),
        std::cmp::Ordering::Equal => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        std::cmp::Ordering::Less => Err(io::Error::last_os_error()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlannedMessage {
    first: usize,
    datagrams: usize,
    segment_size: Option<u16>,
}

impl PlannedMessage {
    const EMPTY: Self = Self {
        first: 0,
        datagrams: 0,
        segment_size: None,
    };
}

/// Returns whether this socket supports per-message UDP GSO control data.
/// A successful zero-value read is only a capability probe; it does not set a
/// socket-wide segment size.
pub(crate) fn supports_gso(socket: &UdpSocket) -> bool {
    probe_gso(socket).is_ok()
}

fn probe_gso(socket: &UdpSocket) -> io::Result<()> {
    let mut segment_size = 0 as libc::c_int;
    let mut len = mem::size_of_val(&segment_size) as libc::socklen_t;
    // SAFETY: `segment_size` and `len` are valid writable storage for this
    // getsockopt call and the socket fd remains valid throughout it.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_UDP,
            UDP_SEGMENT,
            ptr::from_mut(&mut segment_size).cast(),
            ptr::from_mut(&mut len),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn plan<T: AsRef<[u8]>>(addr: SocketAddr, datagrams: &[T]) -> ([PlannedMessage; MAX_BATCH], usize) {
    let max_payload = if addr.is_ipv4() {
        MAX_IPV4_PAYLOAD
    } else {
        MAX_IPV6_PAYLOAD
    };
    let mut messages = [PlannedMessage::EMPTY; MAX_BATCH];
    let mut message_count = 0;
    let mut first = 0;

    while first < datagrams.len() {
        let segment_len = datagrams[first].as_ref().len();
        // UDP_SEGMENT is a nonzero u16. Empty datagrams stay standalone so
        // coalescing cannot elide them as a zero-length final segment.
        let gso_eligible = (1..=u16::MAX as usize).contains(&segment_len);
        let mut count = 1;
        let mut total = segment_len;
        let mut has_smaller_tail = false;
        while first + count < datagrams.len()
            && count < MAX_GSO_SEGMENTS
            && !has_smaller_tail
            && gso_eligible
        {
            let next_len = datagrams[first + count].as_ref().len();
            if next_len == 0 || next_len > segment_len || total + next_len > max_payload {
                break;
            }
            total += next_len;
            count += 1;
            has_smaller_tail = next_len < segment_len;
        }
        messages[message_count] = PlannedMessage {
            first,
            datagrams: count,
            segment_size: (count > 1 && gso_eligible).then_some(segment_len as u16),
        };
        message_count += 1;
        first += count;
    }
    (messages, message_count)
}

const UDP_SEGMENT_DATA_LEN: usize = mem::size_of::<u16>();
// `CMSG_SPACE` includes the trailing alignment padding required by the ABI.
const UDP_SEGMENT_CONTROL_SPACE: usize =
    unsafe { libc::CMSG_SPACE(UDP_SEGMENT_DATA_LEN as _) as usize };
const CONTROL_WORDS: usize = UDP_SEGMENT_CONTROL_SPACE.div_ceil(mem::size_of::<usize>());

/// Aligned storage for exactly one UDP_SEGMENT ancillary message. Rounding its
/// word count up makes it at least `CMSG_SPACE(2)` bytes on both 32- and
/// 64-bit Linux; `[usize; _]` also supplies the cmsghdr-required alignment.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Control([usize; CONTROL_WORDS]);

impl Control {
    const ZERO: Self = Self([0; CONTROL_WORDS]);

    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.0.as_mut_ptr().cast()
    }

    fn as_ptr(&self) -> *const libc::cmsghdr {
        self.0.as_ptr().cast()
    }
}

const _: () = assert!(mem::align_of::<Control>() >= mem::align_of::<libc::cmsghdr>());
const _: () = assert!(mem::size_of::<Control>() >= UDP_SEGMENT_CONTROL_SPACE);

fn set_segment_control(control: &mut Control, segment_size: u16) {
    debug_assert_ne!(segment_size, 0);
    let header_len = unsafe { libc::CMSG_LEN(UDP_SEGMENT_DATA_LEN as _) } as usize;
    // SAFETY: `Control` is cmsghdr-aligned and at least CMSG_SPACE(2) bytes.
    // Its first bytes hold one cmsghdr, followed by the aligned u16 payload.
    unsafe {
        let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
        (*header).cmsg_level = libc::IPPROTO_UDP;
        (*header).cmsg_type = UDP_SEGMENT;
        (*header).cmsg_len = header_len as _;
        ptr::copy_nonoverlapping(
            segment_size.to_ne_bytes().as_ptr(),
            libc::CMSG_DATA(header),
            UDP_SEGMENT_DATA_LEN,
        );
    }
}

/// Send an ordered batch with per-message UDP_SEGMENT control data.
///
/// The successful prefix is returned in original datagram units, not planned
/// kernel-message units.
pub(crate) fn send_gso<T: AsRef<[u8]>>(
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

    let (messages, message_count) = plan(addr, datagrams);
    let sockaddr = SockAddr::from_socket_addr(addr);
    let (name, name_len) = sockaddr.as_ptr_len();
    let mut iovecs = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; MAX_BATCH];
    let mut controls = [Control::ZERO; MAX_BATCH];
    // SAFETY: zeroed `msghdr` is valid; fields below initialize each used one.
    let mut empty_hdr: libc::msghdr = unsafe { mem::zeroed() };
    empty_hdr.msg_name = name.cast_mut().cast();
    empty_hdr.msg_namelen = name_len;
    let mut headers = [libc::mmsghdr {
        msg_hdr: empty_hdr,
        msg_len: 0,
    }; MAX_BATCH];

    for (index, datagram) in datagrams.iter().enumerate() {
        let data = datagram.as_ref();
        iovecs[index] = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
    }
    for (index, message) in messages[..message_count].iter().enumerate() {
        let header = &mut headers[index].msg_hdr;
        header.msg_iov = ptr::addr_of_mut!(iovecs[message.first]);
        header.msg_iovlen = message.datagrams;
        if let Some(segment_size) = message.segment_size {
            set_segment_control(&mut controls[index], segment_size);
            header.msg_control = controls[index].as_mut_ptr();
            header.msg_controllen = UDP_SEGMENT_CONTROL_SPACE as _;
        }
    }

    // SAFETY: all mmsghdr/iovec/control pointers refer to initialized stack
    // storage that remains live through the syscall; packet bytes are borrowed
    // from the caller and are neither copied nor retained by the kernel.
    let sent = unsafe {
        libc::sendmmsg(
            socket.as_raw_fd(),
            headers.as_mut_ptr(),
            message_count as libc::c_uint,
            SENDMMSG_FLAGS,
        )
    };
    match sent.cmp(&0) {
        std::cmp::Ordering::Greater => Ok(messages[..sent as usize]
            .iter()
            .map(|message| message.datagrams)
            .sum()),
        std::cmp::Ordering::Equal => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        std::cmp::Ordering::Less => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn packets(lengths: &[usize]) -> Vec<Vec<u8>> {
        lengths.iter().map(|&len| vec![0; len]).collect()
    }

    fn planned(lengths: &[usize], addr: SocketAddr) -> Vec<PlannedMessage> {
        let packets = packets(lengths);
        let (messages, count) = plan(addr, &packets);
        messages[..count].to_vec()
    }

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

    #[test]
    fn planner_coalesces_equal_packets_and_maps_progress() {
        let messages = planned(&[1200, 1200, 1200], "127.0.0.1:1".parse().unwrap());
        assert_eq!(
            messages,
            [PlannedMessage {
                first: 0,
                datagrams: 3,
                segment_size: Some(1200),
            }]
        );
        assert_eq!(
            messages[..1]
                .iter()
                .map(|message| message.datagrams)
                .sum::<usize>(),
            3
        );

        let messages = planned(&[1200, 1200, 1300, 1300], "127.0.0.1:1".parse().unwrap());
        assert_eq!(
            messages[..1]
                .iter()
                .map(|message| message.datagrams)
                .sum::<usize>(),
            2
        );
        assert_eq!(
            messages[..2]
                .iter()
                .map(|message| message.datagrams)
                .sum::<usize>(),
            4
        );
    }

    #[test]
    fn planner_allows_one_smaller_tail_then_starts_a_new_message() {
        let messages = planned(&[1200, 1200, 1000, 1000], "127.0.0.1:1".parse().unwrap());
        assert_eq!(
            messages,
            [
                PlannedMessage {
                    first: 0,
                    datagrams: 3,
                    segment_size: Some(1200),
                },
                PlannedMessage {
                    first: 3,
                    datagrams: 1,
                    segment_size: None,
                },
            ]
        );
    }

    #[test]
    fn planner_splits_larger_packets_and_all_limits_without_reordering() {
        let messages = planned(&[1200, 1300, 1300], "127.0.0.1:1".parse().unwrap());
        assert_eq!(messages[0].datagrams, 1);
        assert_eq!(messages[1].first, 1);
        assert_eq!(messages[1].datagrams, 2);

        let equal = planned(&vec![1000; 65], "127.0.0.1:1".parse().unwrap());
        assert_eq!(equal[0].datagrams, 64);
        assert_eq!(equal[1].first, 64);
        assert_eq!(equal[1].segment_size, None);

        let v4 = planned(&[40_000, 25_520], "127.0.0.1:1".parse().unwrap());
        assert_eq!(v4.iter().map(|message| message.datagrams).sum::<usize>(), 2);
        assert_eq!(v4.len(), 2);
        let v6 = planned(&[40_000, 25_520], "[::1]:1".parse().unwrap());
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].segment_size, Some(40_000));
    }

    #[test]
    fn planner_keeps_empty_and_oversized_datagrams_as_plain_singletons() {
        let too_large = u16::MAX as usize + 1;
        let messages = planned(
            &[0, 0, 1200, 1200, 0, too_large, too_large],
            "127.0.0.1:1".parse().unwrap(),
        );
        assert_eq!(
            messages,
            [
                PlannedMessage {
                    first: 0,
                    datagrams: 1,
                    segment_size: None
                },
                PlannedMessage {
                    first: 1,
                    datagrams: 1,
                    segment_size: None
                },
                PlannedMessage {
                    first: 2,
                    datagrams: 2,
                    segment_size: Some(1200)
                },
                PlannedMessage {
                    first: 4,
                    datagrams: 1,
                    segment_size: None
                },
                PlannedMessage {
                    first: 5,
                    datagrams: 1,
                    segment_size: None
                },
                PlannedMessage {
                    first: 6,
                    datagrams: 1,
                    segment_size: None
                },
            ]
        );
    }

    #[test]
    fn segment_control_has_the_linux_udp_segment_layout() {
        assert!(mem::size_of::<Control>() >= UDP_SEGMENT_CONTROL_SPACE);
        assert!(mem::align_of::<Control>() >= mem::align_of::<libc::cmsghdr>());
        let mut control = Control::ZERO;
        set_segment_control(&mut control, 1234);
        // SAFETY: `set_segment_control` initialized a cmsghdr and its u16.
        unsafe {
            let header = control.as_ptr();
            assert_eq!((*header).cmsg_level, libc::IPPROTO_UDP);
            assert_eq!((*header).cmsg_type, UDP_SEGMENT);
            assert_eq!(
                (*header).cmsg_len as usize,
                libc::CMSG_LEN(UDP_SEGMENT_DATA_LEN as _) as usize
            );
            let payload = std::slice::from_raw_parts(libc::CMSG_DATA(header), UDP_SEGMENT_DATA_LEN);
            assert_eq!(payload, 1234u16.to_ne_bytes());
        }
    }

    #[tokio::test]
    async fn gso_loopback_preserves_original_datagram_order_when_supported() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if let Err(error) = probe_gso(&sender) {
            match error.raw_os_error() {
                Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP) => return,
                _ => panic!("UDP_SEGMENT capability probe failed: {error}"),
            }
        }
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packets = [b"one".as_slice(), b"two", b"three", b"four"];
        assert_eq!(
            send_gso(&sender, receiver.local_addr().unwrap(), &packets).unwrap(),
            packets.len()
        );
        let mut buf = [0; 16];
        for expected in packets {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], expected);
        }
    }
}
