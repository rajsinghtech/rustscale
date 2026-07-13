//! Linux `sendmmsg`/`recvmmsg` support for direct WireGuard UDP batches.

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
/// Direct WireGuard, disco, and Geneve packets normally fit comfortably in
/// this buffer. Larger ordinary UDP packets are deliberately rejected rather
/// than silently truncated before they reach the protocol parsers.
const LOGICAL_PACKET_CAPACITY: usize = 2_048;
const GRO_PACKET_CAPACITY: usize = 65_536;
const GRO_TAIL_SLOTS: usize = 2;
// libc does not expose this on every supported Linux libc target.
const UDP_SEGMENT: libc::c_int = 103;
// libc does not expose this on every supported Linux libc target.
const UDP_GRO: libc::c_int = 104;

#[cfg(target_env = "gnu")]
const SENDMMSG_FLAGS: libc::c_int = libc::MSG_DONTWAIT as libc::c_int;

#[cfg(target_env = "musl")]
const SENDMMSG_FLAGS: libc::c_uint = libc::MSG_DONTWAIT as libc::c_uint;

type Packet = [u8; LOGICAL_PACKET_CAPACITY];

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

/// Best-effort enablement of UDP GRO for this socket. This is deliberately
/// independent from the UDP GSO capability probe: kernels and drivers can
/// support either direction without supporting the other.
pub(crate) fn try_enable_udp_gro(socket: &UdpSocket) -> bool {
    set_udp_gro(socket, true).is_ok()
}

/// Disable UDP GRO before changing to a receive implementation that cannot
/// interpret UDP_GRO control messages.
pub(crate) fn disable_udp_gro(socket: &UdpSocket) {
    let _ = set_udp_gro(socket, false);
}

fn set_udp_gro(socket: &UdpSocket, enabled: bool) -> io::Result<()> {
    let value = libc::c_int::from(enabled);
    // SAFETY: `value` is valid storage for the integer UDP_GRO option and the
    // socket fd remains valid for the duration of this synchronous syscall.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            UDP_GRO,
            ptr::from_ref(&value).cast(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// True when this process is running against a kernel too old to provide the
/// `recvmmsg` syscall. It is intentionally narrow: ordinary socket failures
/// still follow the receive task's existing error handling.
pub(crate) fn recvmmsg_is_unsupported(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOSYS)
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

    #[cfg(test)]
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

/// Reusable `recvmmsg` scratch owned by one UDP receive task.
///
/// The storage is allocated once when the task starts. In GRO mode only the
/// final two slots are submitted to the kernel, then split into the logical
/// packet buffers at the head; this preserves the bounded layout used by
/// Tailscale's Linux implementation.
pub(crate) struct ReceiveBatch {
    gro_enabled: bool,
    packets: Vec<Packet>,
    gro_packets: Vec<Vec<u8>>,
    iovecs: Vec<libc::iovec>,
    names: Vec<libc::sockaddr_storage>,
    controls: Vec<Control>,
    headers: Vec<libc::mmsghdr>,
    lengths: Vec<usize>,
    sources: Vec<Option<SocketAddr>>,
    count: usize,
}

// `ReceiveBatch` is moved only into its single Tokio receive task. The raw
// pointers in `mmsghdr`/`iovec` are recreated before every syscall and point
// exclusively at storage owned by the same batch; the kernel retains none of
// them after `recvmmsg` returns. It is therefore safe to move this task, but
// not to share a batch between tasks.
unsafe impl Send for ReceiveBatch {}

impl ReceiveBatch {
    pub(crate) fn new(socket: &UdpSocket) -> Self {
        Self::with_gro(try_enable_udp_gro(socket))
    }

    fn with_gro(gro_enabled: bool) -> Self {
        // These vectors never change length, so all pointer targets remain
        // stable for every recvmmsg call made by this batch.
        Self {
            gro_enabled,
            packets: vec![[0; LOGICAL_PACKET_CAPACITY]; MAX_BATCH],
            gro_packets: vec![vec![0; GRO_PACKET_CAPACITY]; GRO_TAIL_SLOTS],
            iovecs: vec![
                libc::iovec {
                    iov_base: ptr::null_mut(),
                    iov_len: 0,
                };
                MAX_BATCH
            ],
            // SAFETY: sockaddr_storage is a plain C storage struct; an all
            // zero value is valid prior to the kernel filling it.
            names: (0..MAX_BATCH).map(|_| unsafe { mem::zeroed() }).collect(),
            controls: vec![Control::ZERO; MAX_BATCH],
            // SAFETY: all fields are pointers or integer lengths/flags. Each
            // submitted entry is completely initialized by `prepare_slot`.
            headers: (0..MAX_BATCH).map(|_| unsafe { mem::zeroed() }).collect(),
            lengths: vec![0; MAX_BATCH],
            sources: vec![None; MAX_BATCH],
            count: 0,
        }
    }

    /// Number of logical datagrams returned by the preceding successful read.
    pub(crate) fn len(&self) -> usize {
        self.count
    }

    /// A logical datagram borrowed from this batch. It remains valid until the
    /// next call to `recv` on the same batch.
    pub(crate) fn datagram(&self, index: usize) -> Option<(&[u8], SocketAddr)> {
        if index >= self.count {
            return None;
        }
        let len = *self.lengths.get(index)?;
        let source = self.sources.get(index).copied().flatten()?;
        Some((&self.packets[index][..len], source))
    }

    /// Receive one nonblocking kernel batch. `WouldBlock` is returned without
    /// modifying readiness state, for Tokio's `async_io` to retry correctly.
    pub(crate) fn recv(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        self.lengths.fill(0);
        self.sources.fill(None);
        self.count = 0;

        let first = if self.gro_enabled {
            MAX_BATCH - GRO_TAIL_SLOTS
        } else {
            0
        };
        let slots = if self.gro_enabled {
            GRO_TAIL_SLOTS
        } else {
            MAX_BATCH
        };
        for index in first..first + slots {
            self.prepare_slot(index);
        }

        let received = raw_recvmmsg(socket.as_raw_fd(), &mut self.headers[first..first + slots])?;
        if received == 0 {
            return Ok(0);
        }
        if self.gro_enabled {
            self.split_gro_tail(first, received)?;
        } else {
            self.finish_plain(received)?;
        }
        Ok(self.len())
    }

    fn prepare_slot(&mut self, index: usize) {
        self.names[index] = unsafe { mem::zeroed() };
        self.controls[index] = Control::ZERO;
        let (data, len) = if self.gro_enabled {
            let tail = index - (MAX_BATCH - GRO_TAIL_SLOTS);
            (&mut self.gro_packets[tail][..], GRO_PACKET_CAPACITY)
        } else {
            (&mut self.packets[index][..], LOGICAL_PACKET_CAPACITY)
        };
        self.iovecs[index] = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: len,
        };
        // SAFETY: a zeroed msghdr is valid before its pointer and length fields
        // below are initialized. Resetting it also resets kernel-written flags,
        // name lengths, control lengths, and mmsghdr.msg_len every syscall.
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_name = ptr::addr_of_mut!(self.names[index]).cast();
        hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        hdr.msg_iov = ptr::addr_of_mut!(self.iovecs[index]);
        hdr.msg_iovlen = 1;
        hdr.msg_control = self.controls[index].as_mut_ptr();
        hdr.msg_controllen = UDP_SEGMENT_CONTROL_SPACE as _;
        self.headers[index] = libc::mmsghdr {
            msg_hdr: hdr,
            msg_len: 0,
        };
    }

    fn finish_plain(&mut self, received: usize) -> io::Result<()> {
        self.count = 0;
        for index in 0..received {
            self.validate_message(index, LOGICAL_PACKET_CAPACITY)?;
            self.lengths[index] = self.headers[index].msg_len as usize;
            self.sources[index] = Some(socket_addr(
                &self.names[index],
                self.headers[index].msg_hdr.msg_namelen,
            )?);
        }
        self.count = received;
        Ok(())
    }

    fn split_gro_tail(&mut self, first: usize, received: usize) -> io::Result<()> {
        self.count = 0;
        let mut output = 0;
        for index in first..first + received {
            self.validate_message(index, GRO_PACKET_CAPACITY)?;
            let length = self.headers[index].msg_len as usize;
            let source = socket_addr(&self.names[index], self.headers[index].msg_hdr.msg_namelen)?;
            let control_len = self.headers[index].msg_hdr.msg_controllen as usize;
            if control_len > UDP_SEGMENT_CONTROL_SPACE {
                return invalid_data("kernel returned oversized ancillary data");
            }
            let segment_size = gro_size(&self.controls[index].as_bytes()[..control_len])?;
            let segments = segment_size.map_or(1, |size| length.div_ceil(usize::from(size)).max(1));
            if output + segments > MAX_BATCH {
                return invalid_data("splitting UDP GRO packet would overflow batch");
            }
            let mut start = 0;
            for _ in 0..segments {
                let end =
                    segment_size.map_or(length, |size| (start + usize::from(size)).min(length));
                let logical_len = end - start;
                if logical_len > LOGICAL_PACKET_CAPACITY {
                    return invalid_data("logical UDP packet exceeds receive buffer");
                }
                self.packets[output][..logical_len]
                    .copy_from_slice(&self.gro_packets[index - first][start..end]);
                self.lengths[output] = logical_len;
                self.sources[output] = Some(source);
                output += 1;
                start = end;
            }
        }
        self.count = output;
        Ok(())
    }

    fn validate_message(&self, index: usize, capacity: usize) -> io::Result<()> {
        let header = &self.headers[index];
        if header.msg_len as usize > capacity {
            return invalid_data("kernel returned UDP length larger than receive buffer");
        }
        if header.msg_hdr.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return invalid_data("truncated UDP packet or ancillary data");
        }
        Ok(())
    }
}

impl Control {
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: `Control` is contiguous initialized storage. The kernel may
        // initialize only the reported prefix, which callers slice before use.
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast(), mem::size_of::<Self>()) }
    }
}

fn raw_recvmmsg(fd: libc::c_int, headers: &mut [libc::mmsghdr]) -> io::Result<usize> {
    // SAFETY: `headers` points at initialized mmsghdr/iovec/name/control
    // storage that lives until this syscall returns. The socket is nonblocking
    // because it is owned by Tokio, and the null timeout requests no timeout.
    #[cfg(target_env = "gnu")]
    let result = unsafe {
        libc::recvmmsg(
            fd,
            headers.as_mut_ptr(),
            headers.len() as libc::c_uint,
            libc::MSG_DONTWAIT,
            ptr::null_mut(),
        )
    };
    #[cfg(target_env = "musl")]
    let result = unsafe {
        libc::recvmmsg(
            fd,
            headers.as_mut_ptr(),
            headers.len() as libc::c_uint,
            libc::MSG_DONTWAIT as libc::c_uint,
            ptr::null_mut(),
        )
    };
    if result >= 0 {
        Ok(result as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn socket_addr(
    storage: &libc::sockaddr_storage,
    length: libc::socklen_t,
) -> io::Result<SocketAddr> {
    let length = length as usize;
    match i32::from(storage.ss_family) {
        libc::AF_INET if length >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: sockaddr_storage has sufficient alignment and the kernel
            // reported at least a complete sockaddr_in.
            let address = unsafe { ptr::read(ptr::from_ref(storage).cast::<libc::sockaddr_in>()) };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            )))
        }
        libc::AF_INET6 if length >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: sockaddr_storage has sufficient alignment and the kernel
            // reported at least a complete sockaddr_in6.
            let address = unsafe { ptr::read(ptr::from_ref(storage).cast::<libc::sockaddr_in6>()) };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                std::net::Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                u32::from_be(address.sin6_flowinfo),
                address.sin6_scope_id,
            )))
        }
        _ => invalid_data("invalid UDP source address"),
    }
}

fn gro_size(control: &[u8]) -> io::Result<Option<u16>> {
    let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
    let alignment = mem::size_of::<libc::c_long>();
    let mut offset = 0;
    let mut segment_size = None;
    while offset < control.len() {
        if control.len() - offset < header_len {
            return invalid_data("truncated socket control header");
        }
        // SAFETY: the length check above covers a complete cmsghdr. Use an
        // unaligned read so this parser remains correct even for malformed
        // caller-provided byte slices in tests.
        let header =
            unsafe { ptr::read_unaligned(control[offset..].as_ptr().cast::<libc::cmsghdr>()) };
        let cmsg_len = header.cmsg_len as usize;
        if cmsg_len < header_len || cmsg_len > control.len() - offset {
            return invalid_data("malformed socket control length");
        }
        let data = &control[offset + header_len..offset + cmsg_len];
        if header.cmsg_level == libc::SOL_UDP && header.cmsg_type == UDP_GRO {
            if data.len() != UDP_SEGMENT_DATA_LEN {
                return invalid_data("UDP_GRO control payload is not a u16");
            }
            let size = u16::from_ne_bytes([data[0], data[1]]);
            if size == 0 {
                return invalid_data("UDP_GRO control has a zero segment size");
            }
            if segment_size.replace(size).is_some() {
                return invalid_data("duplicate UDP_GRO control message");
            }
        }
        let aligned = cmsg_len
            .checked_add(alignment - 1)
            .map(|n| n / alignment * alignment);
        let Some(next) = aligned else {
            return invalid_data("overflowing socket control length");
        };
        if next > control.len() {
            // cmsg_len itself can consume the last unpadded message. Any
            // leftover bytes smaller than a header are ABI padding, not data.
            if cmsg_len == control.len() - offset {
                break;
            }
            return invalid_data("malformed socket control padding");
        }
        offset += next;
    }
    Ok(segment_size)
}

fn invalid_data<T>(message: &'static str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
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
        header.msg_iovlen = message.datagrams as _;
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

    fn set_gro_control(control: &mut Control, segment_size: u16) {
        let header_len = unsafe { libc::CMSG_LEN(UDP_SEGMENT_DATA_LEN as _) } as usize;
        // SAFETY: `Control` is cmsghdr-aligned and has CMSG_SPACE(2) bytes.
        unsafe {
            let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
            (*header).cmsg_level = libc::SOL_UDP;
            (*header).cmsg_type = UDP_GRO;
            (*header).cmsg_len = header_len as _;
            ptr::copy_nonoverlapping(
                segment_size.to_ne_bytes().as_ptr(),
                libc::CMSG_DATA(header),
                UDP_SEGMENT_DATA_LEN,
            );
        }
    }

    fn gro_control_with_payload(payload: &[u8]) -> (Control, usize) {
        assert!(payload.len() <= 3);
        let mut control = Control::ZERO;
        let control_len = unsafe { libc::CMSG_SPACE(payload.len() as _) } as usize;
        let header_len = unsafe { libc::CMSG_LEN(payload.len() as _) } as usize;
        // SAFETY: `Control` is cmsghdr-aligned and the test payload fits in its
        // CMSG_SPACE(2) allocation on every supported Linux ABI.
        unsafe {
            let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
            (*header).cmsg_level = libc::SOL_UDP;
            (*header).cmsg_type = UDP_GRO;
            (*header).cmsg_len = header_len as _;
            ptr::copy_nonoverlapping(payload.as_ptr(), libc::CMSG_DATA(header), payload.len());
        }
        (control, control_len)
    }

    fn set_tail_message(
        batch: &mut ReceiveBatch,
        tail: usize,
        packet: &[u8],
        segment_size: Option<u16>,
    ) {
        let index = MAX_BATCH - GRO_TAIL_SLOTS + tail;
        batch.gro_packets[tail][..packet.len()].copy_from_slice(packet);
        let address = sockaddr_in(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234 + tail as u16));
        // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in.
        unsafe {
            ptr::write(
                ptr::addr_of_mut!(batch.names[index]).cast::<libc::sockaddr_in>(),
                address,
            );
        }
        batch.headers[index].msg_len = packet.len() as _;
        batch.headers[index].msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_in>() as _;
        batch.headers[index].msg_hdr.msg_flags = 0;
        batch.headers[index].msg_hdr.msg_controllen = 0;
        if let Some(segment_size) = segment_size {
            set_gro_control(&mut batch.controls[index], segment_size);
            batch.headers[index].msg_hdr.msg_controllen = UDP_SEGMENT_CONTROL_SPACE as _;
        }
    }

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
    async fn recvmmsg_loopback_preserves_order_sources_and_zero_length_packets() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packets = [b"one".as_slice(), b"", b"three"];
        assert_eq!(
            send(&sender, receiver.local_addr().unwrap(), &packets).unwrap(),
            3
        );

        let mut batch = ReceiveBatch::with_gro(false);
        assert_eq!(batch.recv(&receiver).unwrap(), packets.len());
        for (index, expected) in packets.into_iter().enumerate() {
            let (packet, source) = batch.datagram(index).unwrap();
            assert_eq!(packet, expected);
            assert_eq!(source, sender.local_addr().unwrap());
        }
    }

    #[test]
    fn udp_gro_enablement_is_best_effort_and_independent_from_gso() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let socket = UdpSocket::from_std(socket).unwrap();
        // This intentionally does not inspect UDP_SEGMENT. A kernel may expose
        // GRO and GSO independently, and either outcome is valid here.
        let _ = try_enable_udp_gro(&socket);
        disable_udp_gro(&socket);
    }

    #[test]
    fn split_two_gro_tail_messages_preserves_order_and_smaller_tail() {
        let mut batch = ReceiveBatch::with_gro(true);
        set_tail_message(&mut batch, 0, b"aaabbbcc", Some(3));
        set_tail_message(&mut batch, 1, b"ddddx", Some(4));
        batch.split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 2).unwrap();
        let got: Vec<_> = (0..batch.len())
            .map(|index| batch.datagram(index).unwrap().0.to_vec())
            .collect();
        assert_eq!(
            got,
            vec![
                b"aaa".to_vec(),
                b"bbb".to_vec(),
                b"cc".to_vec(),
                b"dddd".to_vec(),
                b"x".to_vec()
            ]
        );
        assert_eq!(batch.datagram(0).unwrap().1.port(), 1234);
        assert_eq!(batch.datagram(3).unwrap().1.port(), 1235);
    }

    #[test]
    fn missing_gro_control_is_one_logical_datagram() {
        let mut batch = ReceiveBatch::with_gro(true);
        set_tail_message(&mut batch, 0, b"not-split", None);
        batch.split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 1).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.datagram(0).unwrap().0, b"not-split");
    }

    #[test]
    fn gro_control_requires_exactly_one_nonzero_native_endian_u16() {
        for payload in [&[][..], &[7][..], &[7, 0, 0][..], &[0, 0][..]] {
            let (control, control_len) = gro_control_with_payload(payload);
            assert_eq!(
                gro_size(&control.as_bytes()[..control_len])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }

        let expected = 0x1234u16;
        let (control, control_len) = gro_control_with_payload(&expected.to_ne_bytes());
        assert_eq!(
            gro_size(&control.as_bytes()[..control_len]).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn failed_later_gro_message_keeps_the_entire_batch_undispatchable() {
        let mut batch = ReceiveBatch::with_gro(true);
        set_tail_message(&mut batch, 0, b"first", None);
        set_tail_message(&mut batch, 1, b"second", None);
        batch.names[MAX_BATCH - 1] = unsafe { mem::zeroed() };

        assert_eq!(
            batch
                .split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, GRO_TAIL_SLOTS)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(batch.len(), 0);
        assert!(batch.datagram(0).is_none());
        assert!(batch.datagram(1).is_none());
    }

    #[test]
    fn malformed_control_truncation_invalid_source_oversize_and_overflow_are_rejected() {
        assert_eq!(
            gro_size(&[0]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut malformed = Control::ZERO;
        // SAFETY: `malformed` is cmsghdr-aligned storage. Its deliberately
        // impossible cmsg_len must be rejected before any payload is read.
        let malformed_len = mem::size_of::<Control>() + 1;
        unsafe {
            (*malformed.as_mut_ptr().cast::<libc::cmsghdr>()).cmsg_len = malformed_len as _;
        }
        assert_eq!(
            gro_size(malformed.as_bytes()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut batch = ReceiveBatch::with_gro(true);
        set_tail_message(&mut batch, 0, b"abc", None);
        batch.headers[MAX_BATCH - GRO_TAIL_SLOTS].msg_hdr.msg_flags = libc::MSG_CTRUNC;
        assert_eq!(
            batch
                .split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut batch = ReceiveBatch::with_gro(true);
        set_tail_message(&mut batch, 0, b"abc", None);
        batch.names[MAX_BATCH - GRO_TAIL_SLOTS] = unsafe { mem::zeroed() };
        assert_eq!(
            batch
                .split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut batch = ReceiveBatch::with_gro(true);
        let oversized = vec![0; LOGICAL_PACKET_CAPACITY + 1];
        set_tail_message(&mut batch, 0, &oversized, None);
        assert_eq!(
            batch
                .split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut batch = ReceiveBatch::with_gro(true);
        let too_many_segments = vec![0; MAX_BATCH + 1];
        set_tail_message(&mut batch, 0, &too_many_segments, Some(1));
        assert_eq!(
            batch
                .split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn receive_batch_reuse_clears_old_lengths_sources_and_packet_bytes() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut batch = ReceiveBatch::with_gro(false);
        assert_eq!(
            send(
                &sender,
                receiver.local_addr().unwrap(),
                &[b"first".as_slice(), b"second".as_slice()]
            )
            .unwrap(),
            2
        );
        assert_eq!(batch.recv(&receiver).unwrap(), 2);
        assert_eq!(
            send(&sender, receiver.local_addr().unwrap(), &[b"x"]).unwrap(),
            1
        );
        assert_eq!(batch.recv(&receiver).unwrap(), 1);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.datagram(0).unwrap().0, b"x");
        assert!(batch.datagram(1).is_none());
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

    #[tokio::test]
    async fn gso_loopback_gro_receive_splits_equal_segments_and_smaller_tail() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut batch = ReceiveBatch::new(&receiver);
        if !batch.gro_enabled {
            // UDP_GRO is not available on this kernel/socket. The send-side
            // test above separately covers the case where UDP_SEGMENT exists.
            return;
        }
        if let Err(error) = probe_gso(&sender) {
            match error.raw_os_error() {
                Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP) => return,
                _ => panic!("UDP_SEGMENT capability probe failed: {error}"),
            }
        }
        let packets = [
            vec![1; 1_200],
            vec![2; 1_200],
            vec![3; 1_200],
            vec![4; 1_000],
        ];
        assert_eq!(
            send_gso(&sender, receiver.local_addr().unwrap(), &packets).unwrap(),
            packets.len()
        );
        assert_eq!(batch.recv(&receiver).unwrap(), packets.len());
        for (index, expected) in packets.iter().enumerate() {
            assert_eq!(batch.datagram(index).unwrap().0, expected);
        }
    }
}
