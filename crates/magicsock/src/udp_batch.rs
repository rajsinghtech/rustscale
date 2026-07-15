//! Linux `sendmmsg`/`recvmmsg` support for direct WireGuard UDP batches.

#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

/// Matches the TUN batch cap. Keeping these arrays on the stack avoids a
/// header allocation for each WireGuard microburst.
pub(crate) const MAX_BATCH: usize = 128;
const MAX_GSO_SEGMENTS: usize = 64;
/// Upstream's invalid WireGuard tail. It is sender-only metadata: receivers
/// must not infer provenance from this forgeable one-byte payload.
const NEVER_GSO_EQUAL_TAIL_SENTINEL: &[u8] = &[0x07];
/// Match upstream's threshold: below this, the workaround uses plain
/// `sendmmsg` rather than paying for a sentinel packet.
const SENTINEL_TAIL_BATCH_THRESHOLD: usize = 8;
const MAX_IPV4_PAYLOAD: usize = 65_507;
const MAX_IPV6_PAYLOAD: usize = 65_527;
/// Direct WireGuard, disco, and Geneve packets normally fit comfortably in
/// this pooled fast-path buffer.
pub(crate) const LOGICAL_PACKET_CAPACITY: usize = 2_048;
/// Matches WireGuard's accepted maximum and the scalar receiver's storage.
/// Each plain recvmmsg slot uses a small pooled head plus this reusable tail,
/// so an infrequent jumbo cannot truncate or discard the following packets.
const KERNEL_PACKET_CAPACITY: usize = 65_536;
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
type KernelPacket = [u8];
/// Total fixed receive storage. 128 boxes are always installed in recvmmsg
/// scratch, leaving exactly 384 independently reserved detachable buffers.
/// This is exactly 1 MiB of pooled fast-path payload storage; separate
/// per-slot kernel scratch is never detached into queued ciphertexts.
pub(crate) const RECEIVE_BUFFER_POOL_CAPACITY: usize = 512;
const RECEIVE_BUFFER_POOL_FREE_CAPACITY: usize = RECEIVE_BUFFER_POOL_CAPACITY;
const RECEIVE_BUFFER_POOL_DETACHABLE_CAPACITY: usize = RECEIVE_BUFFER_POOL_CAPACITY - MAX_BATCH;
const GRO_SNAPSHOT_INTERVAL: u64 = 256;

/// A fixed receive buffer detached from a `ReceiveBatch`.
///
/// The synchronous recycler is deliberately bounded and `try_send` is used
/// from Drop: returning a ciphertext never waits for the receive task or a
/// mutex. A full recycler is an invariant violation, never a recoverable
/// packet/buffer loss path.
pub(crate) struct PooledPacket {
    packet: Option<Box<Packet>>,
    len: usize,
    recycler: Arc<RecyclerState>,
}

impl PooledPacket {
    fn new(packet: Box<Packet>, len: usize, recycler: Arc<RecyclerState>) -> Self {
        Self {
            packet: Some(packet),
            len,
            recycler,
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.packet.as_ref().expect("pooled packet exists")[..self.len]
    }
}

impl Drop for PooledPacket {
    fn drop(&mut self) {
        let Some(packet) = self.packet.take() else {
            return;
        };
        match self.recycler.sender.try_send(packet) {
            Ok(()) => {
                self.recycler.free.fetch_add(1, Ordering::Relaxed);
                self.recycler.recycled.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                // The receive task has shut down; releasing this box is the
                // correct lifecycle outcome.
            }
            Err(TrySendError::Full(_)) => {
                self.recycler
                    .recycle_overflow
                    .fetch_add(1, Ordering::Relaxed);
                panic!("bounded receive recycler overflowed");
            }
        }
    }
}

/// Shared drop-side state for every detached packet. A pooled ciphertext
/// clones this one Arc, rather than a sender plus several counter Arcs.
struct RecyclerState {
    sender: SyncSender<Box<Packet>>,
    free: AtomicUsize,
    recycled: AtomicU64,
    recycle_overflow: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct ReceiveBufferPoolSnapshot {
    pub(crate) capacity: usize,
    pub(crate) free: usize,
    pub(crate) inventory: usize,
    pub(crate) detached: u64,
    pub(crate) recycled: u64,
    pub(crate) unavailable: u64,
    pub(crate) recycle_overflow: u64,
}

struct ReceiveBufferPool {
    recycler: Arc<RecyclerState>,
    available: Receiver<Box<Packet>>,
    /// Counts only buffers that may be detached. The 128 scratch boxes are
    /// permanently installed in `ReceiveBatch` and are not inventory permits.
    inventory: Arc<Semaphore>,
    detached: AtomicU64,
    unavailable: AtomicU64,
}

impl ReceiveBufferPool {
    fn new() -> Self {
        let (sender, available) = mpsc::sync_channel(RECEIVE_BUFFER_POOL_FREE_CAPACITY);
        for _ in 0..RECEIVE_BUFFER_POOL_CAPACITY {
            sender
                .send(Box::new([0; LOGICAL_PACKET_CAPACITY]))
                .expect("new receive recycler is connected and has capacity");
        }
        Self {
            recycler: Arc::new(RecyclerState {
                sender,
                free: AtomicUsize::new(RECEIVE_BUFFER_POOL_CAPACITY),
                recycled: AtomicU64::new(0),
                recycle_overflow: AtomicU64::new(0),
            }),
            available,
            inventory: Arc::new(Semaphore::new(RECEIVE_BUFFER_POOL_DETACHABLE_CAPACITY)),
            detached: AtomicU64::new(0),
            unavailable: AtomicU64::new(0),
        }
    }

    fn take_scratch(&self) -> Box<Packet> {
        let packet = self
            .available
            .recv()
            .expect("new receive pool contains its 128 scratch buffers");
        self.recycler.free.fetch_sub(1, Ordering::Relaxed);
        packet
    }

    fn replace_and_detach(&self, slot: &mut Box<Packet>, len: usize) -> PooledPacket {
        let replacement = match self.available.try_recv() {
            Ok(packet) => {
                self.recycler.free.fetch_sub(1, Ordering::Relaxed);
                packet
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                self.unavailable.fetch_add(1, Ordering::Relaxed);
                panic!("receive buffer pool exhausted despite inventory reservation");
            }
        };
        let packet = std::mem::replace(slot, replacement);
        self.detached.fetch_add(1, Ordering::Relaxed);
        PooledPacket::new(packet, len, self.recycler.clone())
    }

    fn inventory(&self) -> Arc<Semaphore> {
        self.inventory.clone()
    }

    #[cfg(test)]
    fn snapshot(&self) -> ReceiveBufferPoolSnapshot {
        ReceiveBufferPoolSnapshot {
            capacity: RECEIVE_BUFFER_POOL_CAPACITY,
            free: self.recycler.free.load(Ordering::Relaxed),
            inventory: self.inventory.available_permits(),
            detached: self.detached.load(Ordering::Relaxed),
            recycled: self.recycler.recycled.load(Ordering::Relaxed),
            unavailable: self.unavailable.load(Ordering::Relaxed),
            recycle_overflow: self.recycler.recycle_overflow.load(Ordering::Relaxed),
        }
    }
}

/// Receive-side GRO diagnostics. These are deliberately process-local and
/// relaxed: they are canary evidence, not a public metrics surface.
struct GroStats {
    enable_success: AtomicU64,
    enable_unavailable: AtomicU64,
    rxq_enable_success: AtomicU64,
    rxq_enable_unavailable: AtomicU64,
    kernel_messages: AtomicU64,
    logical_datagrams: AtomicU64,
    coalesced_messages: AtomicU64,
    parse_failures: AtomicU64,
    permanent_fallbacks: AtomicU64,
    dropped_batches: AtomicU64,
    dropped_kernel_messages: AtomicU64,
    drop_logged: AtomicBool,
    rxq_overflow_delta: AtomicU64,
    rxq_overflow_logged: AtomicBool,
    next_snapshot_kernel_messages: AtomicU64,
}

static GRO_STATS: GroStats = GroStats {
    enable_success: AtomicU64::new(0),
    enable_unavailable: AtomicU64::new(0),
    rxq_enable_success: AtomicU64::new(0),
    rxq_enable_unavailable: AtomicU64::new(0),
    kernel_messages: AtomicU64::new(0),
    logical_datagrams: AtomicU64::new(0),
    coalesced_messages: AtomicU64::new(0),
    parse_failures: AtomicU64::new(0),
    permanent_fallbacks: AtomicU64::new(0),
    dropped_batches: AtomicU64::new(0),
    dropped_kernel_messages: AtomicU64::new(0),
    drop_logged: AtomicBool::new(false),
    rxq_overflow_delta: AtomicU64::new(0),
    rxq_overflow_logged: AtomicBool::new(false),
    next_snapshot_kernel_messages: AtomicU64::new(GRO_SNAPSHOT_INTERVAL),
};

#[derive(Clone, Copy)]
struct GroStatsSnapshot {
    enable_success: u64,
    enable_unavailable: u64,
    rxq_enable_success: u64,
    rxq_enable_unavailable: u64,
    kernel_messages: u64,
    logical_datagrams: u64,
    coalesced_messages: u64,
    parse_failures: u64,
    permanent_fallbacks: u64,
    dropped_batches: u64,
    dropped_kernel_messages: u64,
    rxq_overflow_delta: u64,
}

impl GroStats {
    fn snapshot(&self) -> GroStatsSnapshot {
        GroStatsSnapshot {
            enable_success: self.enable_success.load(Ordering::Relaxed),
            enable_unavailable: self.enable_unavailable.load(Ordering::Relaxed),
            rxq_enable_success: self.rxq_enable_success.load(Ordering::Relaxed),
            rxq_enable_unavailable: self.rxq_enable_unavailable.load(Ordering::Relaxed),
            kernel_messages: self.kernel_messages.load(Ordering::Relaxed),
            logical_datagrams: self.logical_datagrams.load(Ordering::Relaxed),
            coalesced_messages: self.coalesced_messages.load(Ordering::Relaxed),
            parse_failures: self.parse_failures.load(Ordering::Relaxed),
            permanent_fallbacks: self.permanent_fallbacks.load(Ordering::Relaxed),
            dropped_batches: self.dropped_batches.load(Ordering::Relaxed),
            dropped_kernel_messages: self.dropped_kernel_messages.load(Ordering::Relaxed),
            rxq_overflow_delta: self.rxq_overflow_delta.load(Ordering::Relaxed),
        }
    }

    fn emit_snapshot(&self, event: &str) {
        let snapshot = self.snapshot();
        eprintln!(
            "rustscale: udp_gro_stats event={event} enable_success={} enable_unavailable={} rxq_enable_success={} rxq_enable_unavailable={} kernel_messages={} logical_datagrams={} coalesced_messages={} parse_failures={} permanent_fallbacks={} dropped_batches={} dropped_kernel_messages={} rxq_overflow_delta={}",
            snapshot.enable_success,
            snapshot.enable_unavailable,
            snapshot.rxq_enable_success,
            snapshot.rxq_enable_unavailable,
            snapshot.kernel_messages,
            snapshot.logical_datagrams,
            snapshot.coalesced_messages,
            snapshot.parse_failures,
            snapshot.permanent_fallbacks,
            snapshot.dropped_batches,
            snapshot.dropped_kernel_messages,
            snapshot.rxq_overflow_delta,
        );
    }

    fn add_kernel_messages(&self, received: usize) -> u64 {
        let received = received as u64;
        self.kernel_messages
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(received))
            })
            .expect("AtomicU64 fetch_update closure always returns Some")
            .saturating_add(received)
    }

    /// Emit at 256, 512, 1024, ... kernel messages. Setting the threshold to
    /// zero after u64 saturation permanently retires this bounded log stream.
    fn note_kernel_messages(&self, total: u64) {
        loop {
            let next = self.next_snapshot_kernel_messages.load(Ordering::Relaxed);
            if !snapshot_threshold_is_due(total, next) {
                return;
            }
            let following = next_snapshot_threshold(next);
            if self
                .next_snapshot_kernel_messages
                .compare_exchange_weak(next, following, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.emit_snapshot("periodic");
                return;
            }
        }
    }

    fn emit_rxq_overflow(&self, delta: u32) {
        debug_assert_ne!(delta, 0);
        let snapshot = self.snapshot();
        eprintln!(
            "rustscale: udp_gro_stats event=rxq_overflow_delta delta={delta} kernel_messages={} logical_datagrams={} parse_failures={} permanent_fallbacks={} rxq_overflow_delta={}",
            snapshot.kernel_messages,
            snapshot.logical_datagrams,
            snapshot.parse_failures,
            snapshot.permanent_fallbacks,
            snapshot.rxq_overflow_delta,
        );
    }

    /// Count every rejected kernel batch but emit only the first diagnostic;
    /// hostile traffic cannot turn validation failures into an unbounded log.
    fn note_dropped_batch(&self, kernel_messages: usize, reason: &io::Error) {
        self.dropped_batches.fetch_add(1, Ordering::Relaxed);
        self.dropped_kernel_messages
            .fetch_add(kernel_messages as u64, Ordering::Relaxed);
        if self
            .drop_logged
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            eprintln!(
                "rustscale: Linux UDP batch dropped kernel_messages={kernel_messages}: {reason}"
            );
            self.emit_snapshot("batch_drop");
        }
    }
}

fn next_snapshot_threshold(threshold: u64) -> u64 {
    threshold.checked_mul(2).unwrap_or(0)
}

fn snapshot_threshold_is_due(total: u64, threshold: u64) -> bool {
    threshold != 0 && total >= threshold
}

fn rxq_overflow_delta(previous: u32, current: u32) -> u32 {
    current.wrapping_sub(previous)
}

/// Claim the process-wide one-shot loss event. Zero deltas do not arm the
/// latch, so an absent event in a complete process log proves no observed RXQ
/// loss while still avoiding a synchronous log on every later loss report.
fn claim_rxq_overflow_event(delta: u32, logged: &AtomicBool) -> bool {
    delta != 0
        && logged
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

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
    /// Original caller datagrams represented by this kernel message. The
    /// optional sentinel is excluded from sender progress/netlog accounting;
    /// receivers cannot infer that provenance and account it physically.
    datagrams: usize,
    segment_size: Option<u16>,
    append_sentinel: bool,
}

impl PlannedMessage {
    const EMPTY: Self = Self {
        first: 0,
        datagrams: 0,
        segment_size: None,
        append_sentinel: false,
    };

    fn wire_bytes<T: AsRef<[u8]>>(&self, datagrams: &[T]) -> usize {
        datagrams[self.first..self.first + self.datagrams]
            .iter()
            .map(|datagram| datagram.as_ref().len())
            .sum::<usize>()
            + usize::from(self.append_sentinel) * NEVER_GSO_EQUAL_TAIL_SENTINEL.len()
    }
}

/// Returns whether this socket supports per-message UDP GSO control data.
/// A successful zero-value read is only a capability probe; it does not set a
/// socket-wide segment size.
pub(crate) fn supports_gso(socket: &UdpSocket) -> bool {
    match probe_gso(socket) {
        Ok(()) => true,
        Err(error) => {
            log_unsupported_capability("UDP_SEGMENT", &error);
            false
        }
    }
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
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of_val(&segment_size) {
        return invalid_data("UDP_SEGMENT capability probe returned an unexpected value size");
    }
    if segment_size != 0 {
        return invalid_data("UDP_SEGMENT socket-wide default is unexpectedly nonzero");
    }
    Ok(())
}

/// Best-effort UDP GRO enablement. Receive and send offloads are independent
/// kernel capabilities, so this deliberately does not consult the GSO probe.
fn try_enable_udp_gro(socket: &UdpSocket) -> bool {
    match set_udp_gro(socket, true) {
        Ok(()) => {
            GRO_STATS.enable_success.fetch_add(1, Ordering::Relaxed);
            eprintln!("rustscale: Linux UDP GRO receive enabled");
            GRO_STATS.emit_snapshot("gro_enabled");
            true
        }
        Err(error) => {
            GRO_STATS.enable_unavailable.fetch_add(1, Ordering::Relaxed);
            eprintln!("rustscale: Linux UDP GRO receive unavailable: {error}");
            GRO_STATS.emit_snapshot("gro_unavailable");
            false
        }
    }
}

fn set_udp_gro(socket: &UdpSocket, enabled: bool) -> io::Result<()> {
    let value = libc::c_int::from(enabled);
    // SAFETY: `value` is valid storage for this integer socket option and the
    // socket stays valid throughout the synchronous syscall.
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

fn enable_rxq_overflow(socket: &UdpSocket) -> io::Result<()> {
    let value = libc::c_int::from(true);
    // SAFETY: `value` is valid storage for this integer socket option and the
    // socket stays valid throughout the synchronous syscall.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            ptr::from_ref(&value).cast(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        GRO_STATS.rxq_enable_success.fetch_add(1, Ordering::Relaxed);
        GRO_STATS.emit_snapshot("rxq_enabled");
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        GRO_STATS
            .rxq_enable_unavailable
            .fetch_add(1, Ordering::Relaxed);
        eprintln!("rustscale: SO_RXQ_OVFL unavailable: {error}");
        GRO_STATS.emit_snapshot("rxq_unavailable");
        Err(error)
    }
}

fn log_unsupported_capability(capability: &str, error: &io::Error) {
    eprintln!("rustscale: Linux {capability} unavailable: {error}");
}

/// True when `recvmmsg` cannot be used by this process: either the kernel
/// lacks it, or a seccomp/LSM policy rejects the syscall. Ordinary socket
/// failures remain terminal receive-task errors.
pub(crate) fn recvmmsg_is_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS | libc::EPERM | libc::EACCES)
    )
}

/// True when batched transmit is unambiguously unavailable to this process.
/// `EPERM`/`EACCES` are deliberately excluded because outbound firewall rules
/// can report them; those remain ordinary lost-UDP results rather than
/// permanently changing the socket mode.
pub(crate) fn sendmmsg_is_unsupported(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP))
}

fn plan<T: AsRef<[u8]>>(
    addr: SocketAddr,
    datagrams: &[T],
    never_gso_equal_tail: bool,
) -> ([PlannedMessage; MAX_BATCH], usize) {
    let mut max_payload = if addr.is_ipv4() {
        MAX_IPV4_PAYLOAD
    } else {
        MAX_IPV6_PAYLOAD
    };
    let mut max_datagrams = MAX_GSO_SEGMENTS;
    if never_gso_equal_tail {
        // Reserve both one segment and one byte for a possible sentinel.
        max_datagrams -= 1;
        max_payload -= NEVER_GSO_EQUAL_TAIL_SENTINEL.len();
    }
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
            && count < max_datagrams
            && !has_smaller_tail
            && gso_eligible
        {
            let next_len = datagrams[first + count].as_ref().len();
            let sentinel_can_be_smaller =
                !never_gso_equal_tail || next_len > NEVER_GSO_EQUAL_TAIL_SENTINEL.len();
            if next_len == 0
                || next_len > segment_len
                || total + next_len > max_payload
                || !sentinel_can_be_smaller
            {
                break;
            }
            total += next_len;
            count += 1;
            has_smaller_tail = next_len < segment_len;
        }
        let segment_size = (count > 1 && gso_eligible).then_some(segment_len as u16);
        messages[message_count] = PlannedMessage {
            first,
            datagrams: count,
            segment_size,
            append_sentinel: never_gso_equal_tail && segment_size.is_some() && !has_smaller_tail,
        };
        message_count += 1;
        first += count;
    }
    (messages, message_count)
}

const UDP_SEGMENT_DATA_LEN: usize = mem::size_of::<u16>();
const UDP_GRO_DATA_LEN: usize = mem::size_of::<libc::c_int>();
const RXQ_OVFL_DATA_LEN: usize = mem::size_of::<u32>();
// `CMSG_SPACE` includes the trailing alignment padding required by the ABI.
const UDP_SEGMENT_CONTROL_SPACE: usize =
    unsafe { libc::CMSG_SPACE(UDP_SEGMENT_DATA_LEN as _) as usize };
const RECEIVE_CONTROL_SPACE: usize = unsafe {
    libc::CMSG_SPACE(UDP_GRO_DATA_LEN as _) as usize
        + libc::CMSG_SPACE(RXQ_OVFL_DATA_LEN as _) as usize
};
const CONTROL_SPACE: usize = if UDP_SEGMENT_CONTROL_SPACE > RECEIVE_CONTROL_SPACE {
    UDP_SEGMENT_CONTROL_SPACE
} else {
    RECEIVE_CONTROL_SPACE
};
const CONTROL_WORDS: usize = CONTROL_SPACE.div_ceil(mem::size_of::<usize>());

/// Aligned ancillary storage. Receive slots reserve independently aligned room
/// for both the Linux `int` UDP_GRO payload and the `u32` SO_RXQ_OVFL payload.
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
const _: () = assert!(mem::size_of::<Control>() >= CONTROL_SPACE);

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
/// The storage is allocated once when the task starts. Plain mode submits all
/// 128 logical slots. Each slot writes into a 2 KiB pooled head and a bounded
/// 64 KiB kernel tail; ordinary packets remain zero-copy detachable while a
/// jumbo is retained in its reusable kernel scratch and handled sequentially.
/// GRO mode submits two 64 KiB tail slots and splits them into the same
/// logical head buffers.
pub(crate) struct ReceiveBatch {
    gro_enabled: bool,
    /// SO_RXQ_OVFL remains active after GRO falls back. Plain slot preparation
    /// must therefore continue providing ancillary storage until the socket
    /// is closed, or the kernel can report MSG_CTRUNC and lose a burst.
    rxq_overflow_enabled: bool,
    /// Boxed fixed slots keep the kernel target stable even while an ordinary
    /// direct packet is detached for the consumer. `detach_datagram` replaces
    /// a slot before the next syscall and refreshes its iovec.
    #[allow(clippy::vec_box)]
    packets: Vec<Box<Packet>>,
    pool: ReceiveBufferPool,
    /// One bounded kernel tail per plain slot. This is intentionally scratch,
    /// not detached ownership: it avoids 512 jumbo-sized pooled buffers while
    /// allowing every valid scalar-sized UDP payload to be received intact.
    #[allow(clippy::vec_box)]
    kernel_packets: Vec<Box<KernelPacket>>,
    /// True when a published logical packet is backed by its kernel scratch
    /// rather than a pooled fast-path head. Such a batch stays sequential.
    kernel_backed: Vec<bool>,
    /// Present only while GRO is active. Dropping this after a permanent
    /// fallback immediately releases the two 64 KiB tail buffers; no syscall
    /// retains their pointers after it returns.
    gro_packets: Option<Vec<Vec<u8>>>,
    /// Two iovecs per plain slot (fast head + kernel tail); GRO uses only the
    /// first iovec in each of its two tail slots.
    iovecs: Vec<libc::iovec>,
    names: Vec<libc::sockaddr_storage>,
    controls: Vec<Control>,
    headers: Vec<libc::mmsghdr>,
    lengths: Vec<usize>,
    sources: Vec<Option<SocketAddr>>,
    rxq_overflows: Option<u32>,
    last_gro_payload_len: Option<usize>,
    count: usize,
}

// `ReceiveBatch` is moved only into its single Tokio receive task. The raw
// pointers in `mmsghdr`/`iovec` are recreated before every syscall and point
// exclusively at storage owned by the same batch; the kernel retains none of
// them after `recvmmsg` returns. It is therefore safe to move this task, but
// not to share a batch between tasks.
unsafe impl Send for ReceiveBatch {}

impl ReceiveBatch {
    /// `disable_gro` is read once by the task owner, so packet processing never
    /// consults the environment.
    pub(crate) fn new(socket: &UdpSocket, disable_gro: bool) -> Self {
        let gro_enabled = !disable_gro && try_enable_udp_gro(socket);
        if disable_gro {
            eprintln!("rustscale: Linux UDP GRO receive disabled by RUSTSCALE_DISABLE_UDP_GRO");
        }
        // The GRO path remains guarded by setup failure handling and its
        // receive-time circuit breaker. Queue-overflow accounting is only
        // requested when GRO is active.
        let rxq_overflow_enabled = gro_enabled && enable_rxq_overflow(socket).is_ok();
        eprintln!(
            "rustscale: Linux UDP receive mode=batch gro={} rxq_overflow={}",
            if gro_enabled { "enabled" } else { "plain" },
            if rxq_overflow_enabled {
                "enabled"
            } else {
                "disabled"
            },
        );
        Self::with_gro_and_rxq(gro_enabled, rxq_overflow_enabled)
    }

    #[cfg(test)]
    fn with_gro(gro_enabled: bool) -> Self {
        Self::with_gro_and_rxq(gro_enabled, gro_enabled)
    }

    fn with_gro_and_rxq(gro_enabled: bool, rxq_overflow_enabled: bool) -> Self {
        let pool = ReceiveBufferPool::new();
        // These vectors never change length, so all pointer targets remain
        // stable for every recvmmsg call made by this batch.
        Self {
            gro_enabled,
            rxq_overflow_enabled,
            packets: (0..MAX_BATCH).map(|_| pool.take_scratch()).collect(),
            pool,
            kernel_packets: (0..MAX_BATCH)
                .map(|_| vec![0; KERNEL_PACKET_CAPACITY].into_boxed_slice())
                .collect(),
            kernel_backed: vec![false; MAX_BATCH],
            gro_packets: gro_enabled.then(|| vec![vec![0; GRO_PACKET_CAPACITY]; GRO_TAIL_SLOTS]),
            iovecs: vec![
                libc::iovec {
                    iov_base: ptr::null_mut(),
                    iov_len: 0,
                };
                MAX_BATCH * 2
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
            rxq_overflows: None,
            last_gro_payload_len: None,
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
        let data = if self.kernel_backed[index] {
            &self.kernel_packets[index][..len]
        } else {
            &self.packets[index][..len]
        };
        Some((data, source))
    }

    /// Metadata for a published logical datagram without borrowing packet
    /// storage. This is used to identify source runs before awaiting receive
    /// credits and before detaching any scratch slot.
    pub(crate) fn datagram_meta(&self, index: usize) -> Option<(usize, SocketAddr)> {
        if index >= self.count {
            return None;
        }
        Some((
            *self.lengths.get(index)?,
            self.sources.get(index).copied().flatten()?,
        ))
    }

    /// Detach one published logical datagram into stable owned storage.
    ///
    /// Credits are acquired by the caller before this operation, so a pool
    /// miss is an invariant failure rather than an allocation fallback. GRO
    /// logical segments were copied into these fixed slots during splitting;
    /// plain recvmmsg packets are transferred without copying.
    pub(crate) fn detach_datagram(&mut self, index: usize) -> Option<(PooledPacket, SocketAddr)> {
        if index >= self.count {
            return None;
        }
        // Jumbo packets deliberately stay on the established sequential path;
        // they cannot consume a small pooled handoff slot.
        if self.kernel_backed[index] {
            return None;
        }
        let len = *self.lengths.get(index)?;
        let source = self.sources.get(index).copied().flatten()?;
        let packet = self.pool.replace_and_detach(&mut self.packets[index], len);
        self.refresh_iovec(index);
        Some((packet, source))
    }

    /// Clone the detached-buffer inventory semaphore before awaiting its
    /// permits. This avoids borrowing `ReceiveBatch` across backpressure.
    pub(crate) fn pool_inventory(&self) -> Arc<Semaphore> {
        self.pool.inventory()
    }

    fn refresh_iovec(&mut self, index: usize) {
        self.iovecs[index * 2] = libc::iovec {
            iov_base: self.packets[index].as_mut_ptr().cast(),
            iov_len: LOGICAL_PACKET_CAPACITY,
        };
    }

    #[cfg(test)]
    pub(crate) fn pool_snapshot(&self) -> ReceiveBufferPoolSnapshot {
        self.pool.snapshot()
    }

    #[cfg(test)]
    pub(crate) fn iovec_base(&self, index: usize) -> *mut libc::c_void {
        self.iovecs[index * 2].iov_base
    }

    /// Receive one nonblocking kernel batch. `WouldBlock` is returned without
    /// modifying readiness state, for Tokio's `async_io` to retry correctly.
    pub(crate) fn recv(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        self.lengths.fill(0);
        self.sources.fill(None);
        self.kernel_backed.fill(false);
        self.count = 0;
        self.last_gro_payload_len = None;

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

        let received =
            match raw_recvmmsg(socket.as_raw_fd(), &mut self.headers[first..first + slots]) {
                Ok(received) => received,
                Err(error) if self.gro_enabled && recvmmsg_is_unsupported(&error) => {
                    self.disable_gro(socket, "recvmmsg is unavailable")?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
        if received == 0 {
            return Ok(0);
        }
        if self.gro_enabled {
            let kernel_messages = GRO_STATS.add_kernel_messages(received);
            if let Err(error) = self.split_gro_tail(first, received) {
                GRO_STATS.parse_failures.fetch_add(1, Ordering::Relaxed);
                GRO_STATS.note_dropped_batch(received, &error);
                let reason = error.to_string();
                self.disable_gro(socket, &reason)?;
                // The failed syscall is unpublished. A bounded number of
                // already-queued coalesced skbs can still drain after the
                // socket option changes, but subsequent reads use plain mode.
                return Ok(0);
            }
            GRO_STATS
                .logical_datagrams
                .fetch_add(self.count as u64, Ordering::Relaxed);
            // Split accounting is complete before a periodic snapshot makes
            // this batch observable to benchmark artifacts.
            GRO_STATS.note_kernel_messages(kernel_messages);
        } else if let Err(error) = self.finish_plain(received) {
            GRO_STATS.note_dropped_batch(received, &error);
            return Err(error);
        }
        Ok(self.len())
    }

    fn prepare_slot(&mut self, index: usize) {
        self.names[index] = unsafe { mem::zeroed() };
        self.controls[index] = Control::ZERO;
        let (data, capacity) = if self.gro_enabled {
            let tail = index - (MAX_BATCH - GRO_TAIL_SLOTS);
            (
                &mut self
                    .gro_packets
                    .as_mut()
                    .expect("GRO tail storage exists while GRO is enabled")[tail][..],
                GRO_PACKET_CAPACITY,
            )
        } else {
            (&mut self.packets[index][..], LOGICAL_PACKET_CAPACITY)
        };
        let first_iovec = index * 2;
        self.iovecs[first_iovec] = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: capacity,
        };
        if !self.gro_enabled {
            self.iovecs[first_iovec + 1] = libc::iovec {
                iov_base: self.kernel_packets[index][LOGICAL_PACKET_CAPACITY..]
                    .as_mut_ptr()
                    .cast(),
                iov_len: KERNEL_PACKET_CAPACITY - LOGICAL_PACKET_CAPACITY,
            };
        }
        // SAFETY: a zeroed msghdr is valid before its pointer and length fields
        // below are initialized. Resetting it also resets kernel-written flags,
        // name lengths, control lengths, and mmsghdr.msg_len every syscall.
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_name = ptr::addr_of_mut!(self.names[index]).cast();
        hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        hdr.msg_iov = ptr::addr_of_mut!(self.iovecs[first_iovec]);
        hdr.msg_iovlen = if self.gro_enabled { 1 } else { 2 };
        if self.gro_enabled || self.rxq_overflow_enabled {
            hdr.msg_control = self.controls[index].as_mut_ptr();
            hdr.msg_controllen = RECEIVE_CONTROL_SPACE as _;
        }
        self.headers[index] = libc::mmsghdr {
            msg_hdr: hdr,
            msg_len: 0,
        };
    }

    fn finish_plain(&mut self, received: usize) -> io::Result<()> {
        self.count = 0;
        self.kernel_backed.fill(false);
        for index in 0..received {
            self.validate_message(index, KERNEL_PACKET_CAPACITY)?;
            let control_len = normalize_control_len(self.headers[index].msg_hdr.msg_controllen)?;
            if control_len > RECEIVE_CONTROL_SPACE {
                return invalid_data("kernel returned oversized ancillary data");
            }
            let parsed = parse_control(&self.controls[index].as_bytes()[..control_len])?;
            if parsed.gro_size.is_some() {
                return invalid_data("plain UDP receive returned unexpected UDP_GRO control");
            }
            if let Some(rxq) = parsed.rxq_overflow {
                self.record_rxq_overflow(rxq);
            }
            let length = self.headers[index].msg_len as usize;
            if length > LOGICAL_PACKET_CAPACITY {
                self.kernel_packets[index][..LOGICAL_PACKET_CAPACITY]
                    .copy_from_slice(&self.packets[index][..]);
                self.kernel_backed[index] = true;
            }
            self.lengths[index] = length;
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
        self.kernel_backed.fill(false);
        let mut output = 0;
        for index in first..first + received {
            self.validate_message(index, GRO_PACKET_CAPACITY)?;
            let length = self.headers[index].msg_len as usize;
            let source = socket_addr(&self.names[index], self.headers[index].msg_hdr.msg_namelen)?;
            let control_len = normalize_control_len(self.headers[index].msg_hdr.msg_controllen)?;
            if control_len > RECEIVE_CONTROL_SPACE {
                return invalid_data("kernel returned oversized ancillary data");
            }
            let parsed = parse_control(&self.controls[index].as_bytes()[..control_len])?;
            if let Some(rxq) = parsed.rxq_overflow {
                self.record_rxq_overflow(rxq);
            }
            if let Some(payload_len) = parsed.gro_payload_len {
                self.last_gro_payload_len = Some(payload_len);
            }
            let segments = match parsed.gro_size {
                Some(size) => validate_gro_segments(length, size)?,
                None => 1,
            };
            if output + segments > MAX_BATCH {
                return invalid_data("splitting UDP GRO packet would overflow batch");
            }
            if parsed.gro_size.is_some() {
                GRO_STATS.coalesced_messages.fetch_add(1, Ordering::Relaxed);
            }
            let mut start = 0;
            for _ in 0..segments {
                let end = parsed
                    .gro_size
                    .map_or(length, |size| (start + usize::from(size)).min(length));
                let logical_len = end - start;
                let input = &self
                    .gro_packets
                    .as_ref()
                    .expect("GRO tail storage exists while GRO is enabled")[index - first]
                    [start..end];
                if logical_len > LOGICAL_PACKET_CAPACITY {
                    self.kernel_packets[output][..logical_len].copy_from_slice(input);
                    self.kernel_backed[output] = true;
                } else {
                    self.packets[output][..logical_len].copy_from_slice(input);
                }
                self.lengths[output] = logical_len;
                self.sources[output] = Some(source);
                output += 1;
                start = end;
            }
        }
        self.count = output;
        Ok(())
    }

    fn record_rxq_overflow(&mut self, current: u32) {
        let previous = self.rxq_overflows.unwrap_or(0);
        let delta = rxq_overflow_delta(previous, current);
        GRO_STATS
            .rxq_overflow_delta
            .fetch_add(u64::from(delta), Ordering::Relaxed);
        self.rxq_overflows = Some(current);
        if claim_rxq_overflow_event(delta, &GRO_STATS.rxq_overflow_logged) {
            GRO_STATS.emit_rxq_overflow(delta);
        }
    }

    fn disable_gro(&mut self, socket: &UdpSocket, reason: &str) -> io::Result<()> {
        debug_assert!(self.gro_enabled);
        GRO_STATS
            .permanent_fallbacks
            .fetch_add(1, Ordering::Relaxed);
        self.finish_disabling_gro(set_udp_gro(socket, false), reason)
    }

    fn finish_disabling_gro(&mut self, result: io::Result<()>, reason: &str) -> io::Result<()> {
        match result {
            Ok(()) => {
                self.gro_enabled = false;
                self.gro_packets = None;
                self.count = 0;
                eprintln!("rustscale: Linux UDP GRO receive permanently disabled: {reason}");
                GRO_STATS.emit_snapshot("gro_permanent_fallback");
                Ok(())
            }
            Err(error) => {
                eprintln!(
                    "rustscale: Linux UDP GRO disable failed after {reason}; receive task will stop: {error}"
                );
                GRO_STATS.emit_snapshot("gro_disable_failed");
                Err(io::Error::new(
                    error.kind(),
                    format!("cannot disable UDP_GRO before plain receive fallback: {error}"),
                ))
            }
        }
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
        // SAFETY: Control is contiguous initialized storage. Callers slice it
        // to the kernel-reported control length before parsing.
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast(), mem::size_of::<Self>()) }
    }
}

fn raw_recvmmsg(fd: libc::c_int, headers: &mut [libc::mmsghdr]) -> io::Result<usize> {
    // SAFETY: `headers` points at initialized mmsghdr/iovec/name storage that
    // lives until this syscall returns. The socket is nonblocking
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

#[derive(Debug, Default)]
struct ParsedControl {
    gro_size: Option<u16>,
    gro_payload_len: Option<usize>,
    rxq_overflow: Option<u32>,
}

/// Parse Linux ancillary data without relying on the CMSG iterator macros.
/// The reported `cmsg_len` is authoritative; messages can arrive in either
/// order and unrelated well-formed messages are ignored.
fn parse_control(control: &[u8]) -> io::Result<ParsedControl> {
    let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
    let alignment = mem::size_of::<usize>();
    let mut offset = 0;
    let mut saw_message = false;
    let mut parsed = ParsedControl::default();

    while offset < control.len() {
        let remaining = control.len() - offset;
        if remaining < header_len {
            // This is the ABI's terminal CMSG alignment padding. The storage
            // was zeroed before the syscall, so nonzero short tails indicate a
            // malformed cmsg chain rather than stale bytes.
            if !saw_message || control[offset..].iter().any(|&byte| byte != 0) {
                return invalid_data("malformed socket control padding");
            }
            break;
        }
        // SAFETY: `remaining >= header_len` covers the complete cmsghdr. The
        // unaligned read keeps fabricated test slices safe too.
        let header =
            unsafe { ptr::read_unaligned(control[offset..].as_ptr().cast::<libc::cmsghdr>()) };
        let cmsg_len = header.cmsg_len as usize;
        if cmsg_len < header_len || cmsg_len > remaining {
            return invalid_data("malformed socket control length");
        }
        let data = &control[offset + header_len..offset + cmsg_len];
        saw_message = true;
        if header.cmsg_level == libc::SOL_UDP && header.cmsg_type == UDP_GRO {
            if parsed.gro_size.is_some() {
                return invalid_data("duplicate UDP_GRO control message");
            }
            parsed.gro_size = Some(parse_gro_size(data)?);
            parsed.gro_payload_len = Some(data.len());
        } else if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SO_RXQ_OVFL {
            if parsed.rxq_overflow.is_some() {
                return invalid_data("duplicate SO_RXQ_OVFL control message");
            }
            if data.len() != RXQ_OVFL_DATA_LEN {
                return invalid_data("SO_RXQ_OVFL control payload is not exactly a u32");
            }
            let bytes: [u8; RXQ_OVFL_DATA_LEN] =
                data.try_into().expect("fixed-size ancillary slice");
            parsed.rxq_overflow = Some(u32::from_ne_bytes(bytes));
        }

        let next = cmsg_len
            .checked_add(alignment - 1)
            .and_then(|length| length.checked_div(alignment))
            .and_then(|words| words.checked_mul(alignment))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "overflowing socket control length",
                )
            })?;
        if next > remaining {
            // The final cmsg may consume precisely the non-padded tail.
            if cmsg_len == remaining {
                break;
            }
            return invalid_data("malformed socket control padding");
        }
        offset += next;
    }
    Ok(parsed)
}

fn validate_gro_segments(length: usize, segment_size: u16) -> io::Result<usize> {
    if length == 0 {
        return invalid_data("UDP_GRO control accompanied an empty payload");
    }
    let segments = length.div_ceil(usize::from(segment_size));
    if segments > MAX_GSO_SEGMENTS {
        return invalid_data("UDP_GRO control exceeds the Linux segment limit");
    }
    Ok(segments)
}

fn parse_gro_size(data: &[u8]) -> io::Result<u16> {
    let value = if data.len() == UDP_GRO_DATA_LEN {
        let bytes: [u8; UDP_GRO_DATA_LEN] = data.try_into().expect("fixed-size ancillary slice");
        let value = libc::c_int::from_ne_bytes(bytes);
        u16::try_from(value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP_GRO control is not a positive u16-sized integer",
            )
        })?
    } else if data.len() == UDP_SEGMENT_DATA_LEN {
        u16::from_ne_bytes(data.try_into().expect("exact two-byte ancillary slice"))
    } else {
        return invalid_data("UDP_GRO control payload is neither exact native int nor exact u16");
    };
    if value == 0 {
        return invalid_data("UDP_GRO control has a zero segment size");
    }
    Ok(value)
}

fn invalid_data<T>(message: &'static str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn normalize_control_len<T: TryInto<usize>>(value: T) -> io::Result<usize> {
    match value.try_into() {
        Ok(value) => Ok(value),
        Err(_) => invalid_data("kernel returned unrepresentable ancillary data length"),
    }
}

/// Successful GSO send progress. `datagrams` excludes mitigation sentinels;
/// `wire_bytes` includes them for physical socket accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SendOutcome {
    pub(crate) datagrams: usize,
    pub(crate) wire_bytes: usize,
}

/// Send an ordered batch with per-message UDP_SEGMENT control data.
///
/// The successful prefix is returned in original datagram units, not planned
/// kernel-message units. When the equal-tail mitigation is live, batches below
/// the upstream threshold conservatively use plain `sendmmsg`.
pub(crate) fn send_gso<T: AsRef<[u8]>>(
    socket: &UdpSocket,
    addr: SocketAddr,
    datagrams: &[T],
    never_gso_equal_tail: bool,
) -> io::Result<SendOutcome> {
    if datagrams.is_empty() || datagrams.len() > MAX_BATCH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sendmmsg batch must contain 1..=128 datagrams",
        ));
    }

    if never_gso_equal_tail && datagrams.len() < SENTINEL_TAIL_BATCH_THRESHOLD {
        return send(socket, addr, datagrams).map(|sent| SendOutcome {
            datagrams: sent,
            wire_bytes: datagrams[..sent]
                .iter()
                .map(|datagram| datagram.as_ref().len())
                .sum(),
        });
    }

    let (messages, message_count) = plan(addr, datagrams, never_gso_equal_tail);
    let sockaddr = SockAddr::from_socket_addr(addr);
    let (name, name_len) = sockaddr.as_ptr_len();
    let mut iovecs = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; MAX_BATCH * 2];
    let mut controls = [Control::ZERO; MAX_BATCH];
    // SAFETY: zeroed `msghdr` is valid; fields below initialize each used one.
    let mut empty_hdr: libc::msghdr = unsafe { mem::zeroed() };
    empty_hdr.msg_name = name.cast_mut().cast();
    empty_hdr.msg_namelen = name_len;
    let mut headers = [libc::mmsghdr {
        msg_hdr: empty_hdr,
        msg_len: 0,
    }; MAX_BATCH];

    let mut iovec_count = 0;
    for (index, message) in messages[..message_count].iter().enumerate() {
        let first_iovec = iovec_count;
        for datagram in &datagrams[message.first..message.first + message.datagrams] {
            let data = datagram.as_ref();
            iovecs[iovec_count] = libc::iovec {
                iov_base: data.as_ptr().cast_mut().cast(),
                iov_len: data.len(),
            };
            iovec_count += 1;
        }
        if message.append_sentinel {
            iovecs[iovec_count] = libc::iovec {
                iov_base: NEVER_GSO_EQUAL_TAIL_SENTINEL.as_ptr().cast_mut().cast(),
                iov_len: NEVER_GSO_EQUAL_TAIL_SENTINEL.len(),
            };
            iovec_count += 1;
        }
        let header = &mut headers[index].msg_hdr;
        header.msg_iov = ptr::addr_of_mut!(iovecs[first_iovec]);
        header.msg_iovlen = (message.datagrams + usize::from(message.append_sentinel)) as _;
        if let Some(segment_size) = message.segment_size {
            set_segment_control(&mut controls[index], segment_size);
            header.msg_control = controls[index].as_mut_ptr();
            header.msg_controllen = UDP_SEGMENT_CONTROL_SPACE as _;
        }
    }

    // SAFETY: all mmsghdr/iovec/control pointers refer to initialized stack
    // storage that remains live through the syscall; packet and static
    // sentinel bytes are read-only despite iovec's C mut pointer type, and are
    // neither modified nor retained by the kernel.
    let sent = unsafe {
        libc::sendmmsg(
            socket.as_raw_fd(),
            headers.as_mut_ptr(),
            message_count as libc::c_uint,
            SENDMMSG_FLAGS,
        )
    };
    match sent.cmp(&0) {
        std::cmp::Ordering::Greater => {
            let sent_messages = &messages[..sent as usize];
            Ok(SendOutcome {
                datagrams: sent_messages.iter().map(|message| message.datagrams).sum(),
                wire_bytes: sent_messages
                    .iter()
                    .map(|message| message.wire_bytes(datagrams))
                    .sum(),
            })
        }
        std::cmp::Ordering::Equal => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        std::cmp::Ordering::Less => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PoolInventoryReservation, WgCiphertext, WgDatagram, WgReceiveBatch,
        WG_RECEIVE_PACKET_CAPACITY,
    };
    use rustscale_key::NodePrivate;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::sync::{OwnedSemaphorePermit, Semaphore};

    fn append_control(
        control: &mut Control,
        offset: usize,
        level: libc::c_int,
        kind: libc::c_int,
        payload: &[u8],
    ) -> usize {
        let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
        let message_len = unsafe { libc::CMSG_LEN(payload.len() as _) } as usize;
        let space = unsafe { libc::CMSG_SPACE(payload.len() as _) } as usize;
        assert!(offset + space <= mem::size_of::<Control>());
        // SAFETY: offset is CMSG_SPACE aligned, the control allocation is
        // cmsghdr aligned, and the payload fits in the reserved message.
        unsafe {
            let header = control
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<libc::cmsghdr>();
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = message_len as _;
            ptr::copy_nonoverlapping(
                payload.as_ptr(),
                header.cast::<u8>().add(header_len),
                payload.len(),
            );
        }
        offset + space
    }

    fn set_tail_message(batch: &mut ReceiveBatch, tail: usize, packet: &[u8], control_len: usize) {
        let index = MAX_BATCH - GRO_TAIL_SLOTS + tail;
        batch
            .gro_packets
            .as_mut()
            .expect("GRO tail storage exists for a GRO test")[tail][..packet.len()]
            .copy_from_slice(packet);
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
        batch.headers[index].msg_hdr.msg_controllen = control_len as _;
    }

    fn set_plain_message(batch: &mut ReceiveBatch, index: usize, packet: &[u8], port: u16) {
        assert!(packet.len() <= KERNEL_PACKET_CAPACITY);
        let head = packet.len().min(LOGICAL_PACKET_CAPACITY);
        batch.packets[index][..head].copy_from_slice(&packet[..head]);
        if packet.len() > head {
            batch.kernel_packets[index][head..packet.len()].copy_from_slice(&packet[head..]);
        }
        let address = sockaddr_in(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
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
    }

    fn pooled_publication_parts(
        batch: &mut ReceiveBatch,
        credits: &Arc<Semaphore>,
        peer: &rustscale_key::NodePublic,
        count: usize,
    ) -> (
        Vec<WgDatagram>,
        OwnedSemaphorePermit,
        Arc<PoolInventoryReservation>,
    ) {
        let channel_permit = credits
            .clone()
            .try_acquire_many_owned(count.try_into().unwrap())
            .expect("test channel has credits");
        let pool_permit = batch
            .pool_inventory()
            .try_acquire_many_owned(count.try_into().unwrap())
            .expect("test pool inventory has detached buffers");
        let pool_reservation = Arc::new(PoolInventoryReservation {
            _permit: pool_permit,
        });
        let datagrams = (0..count)
            .map(|index| {
                let (packet, _) = batch.detach_datagram(index).unwrap();
                WgDatagram {
                    peer: peer.clone(),
                    data: WgCiphertext::from_pooled(packet, pool_reservation.clone()),
                }
            })
            .collect();
        (datagrams, channel_permit, pool_reservation)
    }

    fn pooled_receive_batch(
        batch: &mut ReceiveBatch,
        credits: &Arc<Semaphore>,
        peer: &rustscale_key::NodePublic,
        count: usize,
    ) -> WgReceiveBatch {
        let (datagrams, channel_permit, pool_reservation) =
            pooled_publication_parts(batch, credits, peer, count);
        WgReceiveBatch::new_pooled(datagrams, channel_permit, pool_reservation)
    }

    #[test]
    fn gro_snapshot_thresholds_are_logarithmic_and_saturating() {
        assert!(!snapshot_threshold_is_due(255, GRO_SNAPSHOT_INTERVAL));
        assert!(snapshot_threshold_is_due(256, GRO_SNAPSHOT_INTERVAL));
        assert_eq!(next_snapshot_threshold(256), 512);
        assert_eq!(next_snapshot_threshold(u64::MAX / 2 + 1), 0);
        assert!(!snapshot_threshold_is_due(u64::MAX, 0));

        let mut threshold = GRO_SNAPSHOT_INTERVAL;
        let mut emissions = 0;
        while threshold != 0 {
            emissions += 1;
            threshold = next_snapshot_threshold(threshold);
        }
        // One event per power of two means a full u64 lifetime remains
        // logarithmically bounded, rather than stopping after a fixed budget.
        assert!(emissions <= 64);
        assert!(emissions > 1);
    }

    #[test]
    fn rxq_overflow_event_decision_is_positive_only_and_wraps() {
        let logged = AtomicBool::new(false);
        assert_eq!(rxq_overflow_delta(7, 7), 0);
        assert!(!claim_rxq_overflow_event(0, &logged));
        assert!(!logged.load(Ordering::Relaxed));
        assert_eq!(rxq_overflow_delta(u32::MAX, 1), 2);
        assert!(claim_rxq_overflow_event(
            rxq_overflow_delta(u32::MAX, 1),
            &logged
        ));
        assert!(logged.load(Ordering::Relaxed));
        assert!(!claim_rxq_overflow_event(1, &logged));
    }

    #[test]
    fn mmsg_seccomp_rejections_fall_back_but_socket_failures_do_not() {
        for errno in [libc::ENOSYS, libc::EPERM, libc::EACCES] {
            assert!(recvmmsg_is_unsupported(&io::Error::from_raw_os_error(
                errno
            )));
        }
        for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
            assert!(sendmmsg_is_unsupported(&io::Error::from_raw_os_error(
                errno
            )));
        }
        assert!(!recvmmsg_is_unsupported(&io::Error::from_raw_os_error(
            libc::EOPNOTSUPP
        )));
        for errno in [libc::EBADF, libc::ECONNREFUSED, libc::EIO, libc::EINVAL] {
            let error = io::Error::from_raw_os_error(errno);
            assert!(!recvmmsg_is_unsupported(&error));
            assert!(!sendmmsg_is_unsupported(&error));
        }
        for errno in [libc::EPERM, libc::EACCES] {
            assert!(!sendmmsg_is_unsupported(&io::Error::from_raw_os_error(
                errno
            )));
        }
    }

    fn packets(lengths: &[usize]) -> Vec<Vec<u8>> {
        lengths.iter().map(|&len| vec![0; len]).collect()
    }

    fn planned_with_mitigation(
        lengths: &[usize],
        addr: SocketAddr,
        never_gso_equal_tail: bool,
    ) -> Vec<PlannedMessage> {
        let packets = packets(lengths);
        let (messages, count) = plan(addr, &packets, never_gso_equal_tail);
        messages[..count].to_vec()
    }

    fn planned(lengths: &[usize], addr: SocketAddr) -> Vec<PlannedMessage> {
        planned_with_mitigation(lengths, addr, false)
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
        let sender_one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        sender_one.send_to(b"one", receiver_addr).await.unwrap();
        sender_two.send_to(b"", receiver_addr).await.unwrap();
        sender_one.send_to(b"three", receiver_addr).await.unwrap();

        let expected = [
            (b"one".as_slice(), sender_one.local_addr().unwrap()),
            (b"", sender_two.local_addr().unwrap()),
            (b"three", sender_one.local_addr().unwrap()),
        ];
        let mut batch = ReceiveBatch::new(&receiver, true);
        assert_eq!(batch.recv(&receiver).unwrap(), expected.len());
        for (index, (expected_packet, expected_source)) in expected.into_iter().enumerate() {
            let (packet, source) = batch.datagram(index).unwrap();
            assert_eq!(packet, expected_packet);
            assert_eq!(source, expected_source);
        }
    }

    #[tokio::test]
    async fn plain_recvmmsg_keeps_8k_9k_packets_and_neighbors_intact() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let eight_k = vec![8; 8 * 1024];
        let nine_k = vec![9; 9 * 1024];
        for packet in [
            b"before".as_slice(),
            eight_k.as_slice(),
            nine_k.as_slice(),
            b"after",
        ] {
            sender.send_to(packet, receiver_addr).await.unwrap();
        }

        let mut batch = ReceiveBatch::new(&receiver, true);
        assert_eq!(batch.recv(&receiver).unwrap(), 4);
        assert_eq!(batch.datagram(0).unwrap().0, b"before");
        assert_eq!(batch.datagram(1).unwrap().0, eight_k);
        assert_eq!(batch.datagram(2).unwrap().0, nine_k);
        assert_eq!(batch.datagram(3).unwrap().0, b"after");
        assert_eq!(&batch.kernel_backed[..4], [false, true, true, false]);
        assert!(batch.detach_datagram(1).is_none());
    }

    #[tokio::test]
    async fn plain_recvmmsg_isolates_a_hostile_jumbo_without_dropping_neighbors() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let jumbo = vec![0xA5; 65_507];
        for packet in [b"before".as_slice(), jumbo.as_slice(), b"after"] {
            sender.send_to(packet, receiver_addr).await.unwrap();
        }

        let mut batch = ReceiveBatch::new(&receiver, true);
        assert_eq!(batch.recv(&receiver).unwrap(), 3);
        assert_eq!(batch.datagram(0).unwrap().0, b"before");
        assert_eq!(batch.datagram(1).unwrap().0, jumbo);
        assert_eq!(batch.datagram(2).unwrap().0, b"after");
        assert!(batch.kernel_backed[1]);
    }

    #[test]
    fn plain_receive_preserves_one_byte_values_across_mixed_sources_and_order() {
        let mut batch = ReceiveBatch::with_gro(false);
        set_plain_message(&mut batch, 0, b"\x07", 1234);
        set_plain_message(&mut batch, 1, b"ordinary", 4321);
        set_plain_message(&mut batch, 2, b"\x07", 1234);
        batch.finish_plain(3).unwrap();

        let received: Vec<_> = (0..batch.len())
            .map(|index| {
                let (data, source) = batch.datagram(index).unwrap();
                (data.to_vec(), source.port())
            })
            .collect();
        assert_eq!(
            received,
            [
                (b"\x07".to_vec(), 1234),
                (b"ordinary".to_vec(), 4321),
                (b"\x07".to_vec(), 1234),
            ]
        );
    }

    #[test]
    fn plain_recvmmsg_truncation_is_rejected_atomically() {
        let mut batch = ReceiveBatch::with_gro(false);
        set_plain_message(&mut batch, 0, b"first", 1234);
        set_plain_message(&mut batch, 1, b"second", 1235);
        batch.headers[1].msg_hdr.msg_flags = libc::MSG_TRUNC;

        assert_eq!(
            batch.finish_plain(2).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(batch.len(), 0);
        assert!(batch.datagram(0).is_none());
        assert!(batch.datagram(1).is_none());
    }

    #[test]
    fn detach_replaces_iovec_and_returns_fixed_storage() {
        let mut batch = ReceiveBatch::with_gro(false);
        assert_eq!(
            batch.pool_snapshot(),
            ReceiveBufferPoolSnapshot {
                capacity: RECEIVE_BUFFER_POOL_CAPACITY,
                free: RECEIVE_BUFFER_POOL_CAPACITY - MAX_BATCH,
                inventory: RECEIVE_BUFFER_POOL_DETACHABLE_CAPACITY,
                detached: 0,
                recycled: 0,
                unavailable: 0,
                recycle_overflow: 0,
            }
        );
        batch.prepare_slot(0);
        set_plain_message(&mut batch, 0, b"detached", 1234);
        batch.finish_plain(1).unwrap();
        let old_iovec = batch.iovec_base(0);
        let (packet, source) = batch.detach_datagram(0).expect("published packet detaches");
        assert_eq!(packet.as_slice(), b"detached");
        assert_eq!(source, "127.0.0.1:1234".parse().unwrap());
        assert_ne!(batch.iovec_base(0), old_iovec);
        assert_eq!(
            batch.iovec_base(0),
            batch.packets[0].as_mut_ptr().cast::<libc::c_void>()
        );
        assert_eq!(
            batch.pool_snapshot().free,
            RECEIVE_BUFFER_POOL_CAPACITY - MAX_BATCH - 1
        );
        drop(packet);
        let snapshot = batch.pool_snapshot();
        assert_eq!(snapshot.free, RECEIVE_BUFFER_POOL_CAPACITY - MAX_BATCH);
        assert_eq!(snapshot.inventory, RECEIVE_BUFFER_POOL_DETACHABLE_CAPACITY);
        assert_eq!(snapshot.detached, 1);
        assert_eq!(snapshot.recycled, 1);
        assert_eq!(snapshot.unavailable, 0);
        assert_eq!(snapshot.recycle_overflow, 0);
    }

    #[test]
    fn repeated_plain_detaches_reuse_the_bounded_pool() {
        let mut batch = ReceiveBatch::with_gro(false);
        for burst in 0..4 {
            for index in 0..MAX_BATCH {
                set_plain_message(
                    &mut batch,
                    index,
                    &[burst as u8, index as u8],
                    2000 + index as u16,
                );
            }
            batch.finish_plain(MAX_BATCH).unwrap();
            let packets = (0..MAX_BATCH)
                .map(|index| batch.detach_datagram(index).expect("bounded replacement"))
                .collect::<Vec<_>>();
            for (index, (packet, _)) in packets.iter().enumerate() {
                assert_eq!(packet.as_slice(), &[burst as u8, index as u8]);
            }
            drop(packets);
            let snapshot = batch.pool_snapshot();
            assert_eq!(snapshot.free, RECEIVE_BUFFER_POOL_CAPACITY - MAX_BATCH);
            assert_eq!(snapshot.detached, ((burst + 1) * MAX_BATCH) as u64);
            assert_eq!(snapshot.recycled, ((burst + 1) * MAX_BATCH) as u64);
            assert_eq!(
                snapshot.unavailable, 0,
                "ordinary direct bursts never allocate/fallback"
            );
            assert_eq!(snapshot.recycle_overflow, 0);
        }
    }

    #[test]
    fn consumed_pooled_batch_releases_channel_credits_but_not_pool_inventory() {
        let mut batch = ReceiveBatch::with_gro(false);
        let peer = NodePrivate::generate().public();
        for index in 0..3 {
            set_plain_message(&mut batch, index, &[index as u8], 3000 + index as u16);
        }
        batch.finish_plain(3).unwrap();

        let credits = Arc::new(Semaphore::new(WG_RECEIVE_PACKET_CAPACITY));
        let receive = pooled_receive_batch(&mut batch, &credits, &peer, 3);
        let mut extracted = receive.into_datagrams();
        let last = extracted.pop().unwrap();
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);
        assert_eq!(batch.pool_inventory().available_permits(), 381);
        drop(extracted);
        assert_eq!(batch.pool_inventory().available_permits(), 381);
        drop(last);
        assert_eq!(batch.pool_inventory().available_permits(), 384);

        let snapshot = batch.pool_snapshot();
        assert_eq!(snapshot.free, RECEIVE_BUFFER_POOL_CAPACITY - MAX_BATCH);
        assert_eq!(snapshot.detached, 3);
        assert_eq!(snapshot.recycled, 3);
        assert_eq!(snapshot.unavailable, 0);
        assert_eq!(snapshot.recycle_overflow, 0);
    }

    #[test]
    fn dropped_queued_pooled_batch_returns_channel_and_pool_reservations() {
        let mut batch = ReceiveBatch::with_gro(false);
        set_plain_message(&mut batch, 0, b"queued", 3000);
        batch.finish_plain(1).unwrap();
        let credits = Arc::new(Semaphore::new(WG_RECEIVE_PACKET_CAPACITY));
        let peer = NodePrivate::generate().public();
        let queued = pooled_receive_batch(&mut batch, &credits, &peer, 1);
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY - 1);
        assert_eq!(batch.pool_inventory().available_permits(), 383);
        drop(queued);
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);
        assert_eq!(batch.pool_inventory().available_permits(), 384);
        let snapshot = batch.pool_snapshot();
        assert_eq!(snapshot.free, RECEIVE_BUFFER_POOL_CAPACITY - MAX_BATCH);
        assert_eq!(snapshot.unavailable, 0);
        assert_eq!(snapshot.recycle_overflow, 0);
    }

    #[tokio::test]
    async fn cancelled_and_closed_pooled_publication_return_both_reservations() {
        let mut batch = ReceiveBatch::with_gro(false);
        let peer = NodePrivate::generate().public();
        let credits = Arc::new(Semaphore::new(WG_RECEIVE_PACKET_CAPACITY));
        set_plain_message(&mut batch, 0, b"cancelled", 3000);
        batch.finish_plain(1).unwrap();

        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(WgReceiveBatch::from_datagrams_for_test(Vec::new()))
            .await
            .unwrap();
        let (datagrams, channel_permit, pool_reservation) =
            pooled_publication_parts(&mut batch, &credits, &peer, 1);
        let cancelled_sender = sender.clone();
        let cancelled = tokio::spawn(async move {
            crate::publish_reserved_wg_batch(
                &cancelled_sender,
                datagrams,
                channel_permit,
                pool_reservation,
            )
            .await;
        });
        tokio::task::yield_now().await;
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY - 1);
        assert_eq!(batch.pool_inventory().available_permits(), 383);
        cancelled.abort();
        let _ = cancelled.await;
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);
        assert_eq!(batch.pool_inventory().available_permits(), 384);
        drop(receiver.recv().await);

        set_plain_message(&mut batch, 0, b"closed", 3001);
        batch.finish_plain(1).unwrap();
        let (closed_sender, closed_receiver) = tokio::sync::mpsc::channel(1);
        drop(closed_receiver);
        let (datagrams, channel_permit, pool_reservation) =
            pooled_publication_parts(&mut batch, &credits, &peer, 1);
        crate::publish_reserved_wg_batch(
            &closed_sender,
            datagrams,
            channel_permit,
            pool_reservation,
        )
        .await;
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);
        assert_eq!(batch.pool_inventory().available_permits(), 384);
        assert_eq!(batch.pool_snapshot().unavailable, 0);
    }

    #[tokio::test]
    async fn retained_pooled_packets_fill_384_inventory_then_wait_without_pool_miss() {
        let mut batch = ReceiveBatch::with_gro(false);
        let peer = NodePrivate::generate().public();
        let credits = Arc::new(Semaphore::new(WG_RECEIVE_PACKET_CAPACITY));
        let mut retained = Vec::new();
        for burst in 0..3 {
            for index in 0..MAX_BATCH {
                set_plain_message(
                    &mut batch,
                    index,
                    &[burst as u8, index as u8],
                    4000 + index as u16,
                );
            }
            batch.finish_plain(MAX_BATCH).unwrap();
            retained.push(
                pooled_receive_batch(&mut batch, &credits, &peer, MAX_BATCH).into_datagrams(),
            );
        }
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);
        assert_eq!(batch.pool_inventory().available_permits(), 0);
        assert_eq!(batch.pool_snapshot().unavailable, 0);

        let inventory = batch.pool_inventory();
        let waiting =
            tokio::spawn(async move { PoolInventoryReservation::acquire(inventory, 1).await });
        tokio::task::yield_now().await;
        assert!(
            !waiting.is_finished(),
            "inventory waits before detachment can panic"
        );

        drop(retained.remove(0));
        let reservation = tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .expect("returned pooled buffers wake inventory waiter")
            .expect("waiter task completes")
            .expect("inventory remains open");
        assert_eq!(batch.pool_snapshot().unavailable, 0);
        drop(reservation);
        drop(retained);
        assert_eq!(batch.pool_inventory().available_permits(), 384);
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
                append_sentinel: false,
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
                    append_sentinel: false,
                },
                PlannedMessage {
                    first: 3,
                    datagrams: 1,
                    segment_size: None,
                    append_sentinel: false,
                },
            ]
        );
    }

    #[test]
    fn planner_matches_never_gso_equal_tail_packet_vectors() {
        let addr = "127.0.0.1:1".parse().unwrap();

        let one = planned_with_mitigation(&[32], addr, true);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].segment_size, None);
        assert!(!one[0].append_sentinel);

        let equal = planned_with_mitigation(&[32, 32], addr, true);
        assert_eq!(equal.len(), 1);
        assert_eq!(equal[0].datagrams, 2);
        assert_eq!(equal[0].segment_size, Some(32));
        assert!(equal[0].append_sentinel);
        assert_eq!(equal[0].wire_bytes(&packets(&[32, 32])), 65);

        let smaller_tail = planned_with_mitigation(&[32, 32, 24], addr, true);
        assert_eq!(smaller_tail.len(), 1);
        assert_eq!(smaller_tail[0].datagrams, 3);
        assert!(!smaller_tail[0].append_sentinel);

        let one_byte_tail = planned_with_mitigation(&[32, 1], addr, true);
        assert_eq!(one_byte_tail.len(), 2);
        assert!(one_byte_tail
            .iter()
            .all(|message| message.segment_size.is_none() && !message.append_sentinel));

        let mixed = planned_with_mitigation(&[32, 32, 24, 32], addr, true);
        assert_eq!(mixed.len(), 2);
        assert_eq!(mixed[0].datagrams, 3);
        assert!(!mixed[0].append_sentinel);
        assert_eq!(mixed[1].datagrams, 1);
        assert!(!mixed[1].append_sentinel);

        let larger_boundary = planned_with_mitigation(&[32, 32, 40], addr, true);
        assert_eq!(larger_boundary.len(), 2);
        assert_eq!(larger_boundary[0].datagrams, 2);
        assert!(larger_boundary[0].append_sentinel);
        assert_eq!(larger_boundary[1].datagrams, 1);
        assert!(!larger_boundary[1].append_sentinel);

        let boundary = planned_with_mitigation(&vec![32; MAX_GSO_SEGMENTS], addr, true);
        assert_eq!(boundary.len(), 2);
        assert_eq!(boundary[0].datagrams, MAX_GSO_SEGMENTS - 1);
        assert!(boundary[0].append_sentinel);
        assert_eq!(boundary[1].datagrams, 1);
        assert!(!boundary[1].append_sentinel);
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
    fn gro_parser_accepts_linux_native_int_and_exact_u16_without_prefix_parsing() {
        let size = 0x1234i32;
        assert_eq!(parse_gro_size(&size.to_ne_bytes()).unwrap(), size as u16);
        assert_eq!(parse_gro_size(&0x5678u16.to_ne_bytes()).unwrap(), 0x5678);
        // This fixture models a big-endian Linux int. Reading its first u16
        // would produce zero, while native c_int decoding preserves 0x1234.
        let big_endian_int = [0, 0, 0x12, 0x34];
        assert_eq!(i32::from_be_bytes(big_endian_int), 0x1234);
        assert_ne!(
            u16::from_be_bytes([big_endian_int[0], big_endian_int[1]]),
            0x1234
        );
        assert_eq!(
            parse_gro_size(&0i32.to_ne_bytes()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            parse_gro_size(&[1]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            parse_gro_size(&(-1i32).to_ne_bytes()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            parse_gro_size(&65_536i32.to_ne_bytes()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn control_parser_handles_both_orders_unknown_messages_duplicates_and_short_payloads() {
        let gro = 1200i32.to_ne_bytes();
        let overflow = 17u32.to_ne_bytes();
        for reverse in [false, true] {
            let mut control = Control::ZERO;
            let mut len = 0;
            if reverse {
                len = append_control(
                    &mut control,
                    len,
                    libc::SOL_SOCKET,
                    libc::SO_RXQ_OVFL,
                    &overflow,
                );
                len = append_control(&mut control, len, libc::SOL_UDP, UDP_GRO, &gro);
            } else {
                len = append_control(&mut control, len, libc::SOL_UDP, UDP_GRO, &gro);
                len = append_control(
                    &mut control,
                    len,
                    libc::SOL_SOCKET,
                    libc::SO_RXQ_OVFL,
                    &overflow,
                );
            }
            let parsed = parse_control(&control.as_bytes()[..len]).unwrap();
            assert_eq!(parsed.gro_size, Some(1200));
            assert_eq!(parsed.rxq_overflow, Some(17));
            assert_eq!(parsed.gro_payload_len, Some(mem::size_of::<libc::c_int>()));
        }

        let mut unknown = Control::ZERO;
        let len = append_control(
            &mut unknown,
            0,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMP,
            &[1, 2, 3, 4],
        );
        let parsed = parse_control(&unknown.as_bytes()[..len]).unwrap();
        assert_eq!(parsed.gro_size, None);

        let mut duplicate = Control::ZERO;
        let len = append_control(&mut duplicate, 0, libc::SOL_UDP, UDP_GRO, &gro);
        let len = append_control(&mut duplicate, len, libc::SOL_UDP, UDP_GRO, &gro);
        assert_eq!(
            parse_control(&duplicate.as_bytes()[..len])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut short = Control::ZERO;
        let len = append_control(&mut short, 0, libc::SOL_UDP, UDP_GRO, &[1]);
        assert_eq!(
            parse_control(&short.as_bytes()[..len]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut oversized_gro = Control::ZERO;
        let len = append_control(&mut oversized_gro, 0, libc::SOL_UDP, UDP_GRO, &[0; 5]);
        assert_eq!(
            parse_control(&oversized_gro.as_bytes()[..len])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut duplicate_rxq = Control::ZERO;
        let len = append_control(
            &mut duplicate_rxq,
            0,
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            &overflow,
        );
        let len = append_control(
            &mut duplicate_rxq,
            len,
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            &overflow,
        );
        assert_eq!(
            parse_control(&duplicate_rxq.as_bytes()[..len])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut oversized_rxq = Control::ZERO;
        let len = append_control(
            &mut oversized_rxq,
            0,
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            &[0; 5],
        );
        assert_eq!(
            parse_control(&oversized_rxq.as_bytes()[..len])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            parse_control(&[0]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut malformed = Control::ZERO;
        // SAFETY: the intentionally oversized length is read by the parser
        // before it can access a payload.
        unsafe {
            (*malformed.as_mut_ptr().cast::<libc::cmsghdr>()).cmsg_len =
                (mem::size_of::<Control>() + 1) as _;
        }
        assert_eq!(
            parse_control(malformed.as_bytes()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn split_two_gro_tails_preserves_order_smaller_tail_and_rxq_wrap() {
        let mut batch = ReceiveBatch::with_gro(true);
        let gro_three = 3i32.to_ne_bytes();
        let gro_four = 4i32.to_ne_bytes();
        let mut first_len = append_control(
            &mut batch.controls[MAX_BATCH - GRO_TAIL_SLOTS],
            0,
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            &u32::MAX.to_ne_bytes(),
        );
        first_len = append_control(
            &mut batch.controls[MAX_BATCH - GRO_TAIL_SLOTS],
            first_len,
            libc::SOL_UDP,
            UDP_GRO,
            &gro_three,
        );
        let mut second_len = append_control(
            &mut batch.controls[MAX_BATCH - 1],
            0,
            libc::SOL_UDP,
            UDP_GRO,
            &gro_four,
        );
        second_len = append_control(
            &mut batch.controls[MAX_BATCH - 1],
            second_len,
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            &1u32.to_ne_bytes(),
        );
        set_tail_message(&mut batch, 0, b"aaabbbcc", first_len);
        set_tail_message(&mut batch, 1, b"ddddx", second_len);
        let before = GRO_STATS.rxq_overflow_delta.load(Ordering::Relaxed);
        batch.split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 2).unwrap();
        let packets: Vec<_> = (0..batch.len())
            .map(|index| batch.datagram(index).unwrap().0.to_vec())
            .collect();
        assert_eq!(
            packets,
            vec![
                b"aaa".to_vec(),
                b"bbb".to_vec(),
                b"cc".to_vec(),
                b"dddd".to_vec(),
                b"x".to_vec(),
            ]
        );
        assert_eq!(batch.datagram(0).unwrap().1.port(), 1234);
        assert_eq!(batch.datagram(3).unwrap().1.port(), 1235);
        assert_eq!(
            GRO_STATS.rxq_overflow_delta.load(Ordering::Relaxed) - before,
            u64::from(u32::MAX) + 2
        );
    }

    #[test]
    fn gro_receive_preserves_standalone_and_smaller_tail_07_with_source_order() {
        let mut batch = ReceiveBatch::with_gro(true);
        set_tail_message(&mut batch, 0, b"\x07", 0);
        let control_len = append_control(
            &mut batch.controls[MAX_BATCH - 1],
            0,
            libc::SOL_UDP,
            UDP_GRO,
            &2i32.to_ne_bytes(),
        );
        set_tail_message(&mut batch, 1, b"aabb\x07", control_len);

        batch.split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 2).unwrap();
        let received: Vec<_> = (0..batch.len())
            .map(|index| {
                let (data, source) = batch.datagram(index).unwrap();
                (data.to_vec(), source.port())
            })
            .collect();
        assert_eq!(
            received,
            [
                (b"\x07".to_vec(), 1234),
                (b"aa".to_vec(), 1235),
                (b"bb".to_vec(), 1235),
                (b"\x07".to_vec(), 1235),
            ]
        );
    }

    #[test]
    fn plain_receive_after_gro_fallback_accepts_rxq_control_and_accounts_from_zero() {
        let mut batch = ReceiveBatch::with_gro(true);
        batch.finish_disabling_gro(Ok(()), "test fallback").unwrap();
        assert!(!batch.gro_enabled);
        batch.prepare_slot(0);
        assert!(!batch.headers[0].msg_hdr.msg_control.is_null());
        assert_eq!(
            normalize_control_len(batch.headers[0].msg_hdr.msg_controllen).unwrap(),
            RECEIVE_CONTROL_SPACE
        );
        set_plain_message(&mut batch, 0, b"plain", 1234);
        let control_len = append_control(
            &mut batch.controls[0],
            0,
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            &9u32.to_ne_bytes(),
        );
        batch.headers[0].msg_hdr.msg_controllen = control_len as _;
        let before = GRO_STATS.rxq_overflow_delta.load(Ordering::Relaxed);
        batch.finish_plain(1).unwrap();
        assert_eq!(batch.datagram(0).unwrap().0, b"plain");
        assert_eq!(batch.rxq_overflows, Some(9));
        assert_eq!(
            GRO_STATS.rxq_overflow_delta.load(Ordering::Relaxed) - before,
            9
        );
    }

    #[test]
    fn disabled_and_fallback_modes_do_not_retain_gro_tail_storage() {
        let disabled = ReceiveBatch::with_gro(false);
        assert!(disabled.gro_packets.is_none());

        let mut fallback = ReceiveBatch::with_gro(true);
        assert_eq!(
            fallback.gro_packets.as_ref().map(Vec::len),
            Some(GRO_TAIL_SLOTS)
        );
        fallback
            .finish_disabling_gro(Ok(()), "test fallback")
            .unwrap();
        assert!(!fallback.gro_enabled);
        assert!(fallback.gro_packets.is_none());
    }

    #[test]
    fn gro_segment_metadata_requires_payload_and_stays_within_kernel_limit() {
        assert_eq!(
            validate_gro_segments(0, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(validate_gro_segments(64, 1).unwrap(), 64);
        assert_eq!(
            validate_gro_segments(65, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(validate_gro_segments(65_507, u16::MAX).unwrap(), 1);
    }

    #[test]
    fn gro_split_rejects_truncation_invalid_source_and_logical_overflow() {
        let mut truncated = ReceiveBatch::with_gro(true);
        set_tail_message(&mut truncated, 0, b"abc", 0);
        truncated.headers[MAX_BATCH - GRO_TAIL_SLOTS]
            .msg_hdr
            .msg_flags = libc::MSG_CTRUNC;
        assert_eq!(
            truncated
                .split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut bad_source = ReceiveBatch::with_gro(true);
        set_tail_message(&mut bad_source, 0, b"abc", 0);
        bad_source.names[MAX_BATCH - GRO_TAIL_SLOTS] = unsafe { mem::zeroed() };
        assert_eq!(
            bad_source
                .split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut overflow = ReceiveBatch::with_gro(true);
        let gro_one = 1i32.to_ne_bytes();
        let control_len = append_control(
            &mut overflow.controls[MAX_BATCH - GRO_TAIL_SLOTS],
            0,
            libc::SOL_UDP,
            UDP_GRO,
            &gro_one,
        );
        set_tail_message(&mut overflow, 0, &[0; MAX_BATCH + 1], control_len);
        assert_eq!(
            overflow
                .split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn gro_tail_reuse_resets_kernel_written_state_and_control_storage() {
        let mut batch = ReceiveBatch::with_gro(true);
        let index = MAX_BATCH - GRO_TAIL_SLOTS;
        batch.headers[index].msg_len = 99;
        batch.headers[index].msg_hdr.msg_flags = libc::MSG_TRUNC;
        batch.headers[index].msg_hdr.msg_controllen = 1;
        batch.controls[index].0.fill(usize::MAX);
        batch.names[index] = unsafe { mem::zeroed() };
        batch.names[index].ss_family = libc::AF_INET as _;
        batch.sources[index] = Some("127.0.0.1:1234".parse().unwrap());

        batch.prepare_slot(index);

        assert_eq!(batch.headers[index].msg_len, 0);
        assert_eq!(batch.headers[index].msg_hdr.msg_flags, 0);
        assert_eq!(
            normalize_control_len(batch.headers[index].msg_hdr.msg_controllen).unwrap(),
            RECEIVE_CONTROL_SPACE
        );
        assert_eq!(batch.names[index].ss_family, 0);
        assert!(batch.controls[index]
            .as_bytes()
            .iter()
            .all(|&byte| byte == 0));
        // `recv` clears publication state before preparing the next syscall.
        batch.sources.fill(None);
        assert_eq!(batch.sources[index], None);
    }

    #[tokio::test]
    async fn gro_circuit_breaker_switches_to_plain_recvmmsg_after_bad_batch() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut batch = ReceiveBatch::with_gro(true);
        set_tail_message(&mut batch, 0, b"bad", 1);
        assert_eq!(
            batch
                .split_gro_tail(MAX_BATCH - GRO_TAIL_SLOTS, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        batch
            .disable_gro(&receiver, "test malformed control")
            .unwrap();
        assert!(!batch.gro_enabled);
        sender
            .send_to(b"plain", receiver.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(batch.recv(&receiver).unwrap(), 1);
        assert_eq!(batch.datagram(0).unwrap().0, b"plain");
    }

    #[tokio::test]
    async fn gro_receiver_keeps_jumbo_packets_without_circuit_breaking() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut batch = ReceiveBatch::new(&receiver, false);
        if !batch.gro_enabled {
            return;
        }
        let jumbo = vec![0; 9 * 1024];
        sender
            .send_to(&jumbo, receiver.local_addr().unwrap())
            .await
            .unwrap();
        receiver.readable().await.unwrap();
        assert_eq!(batch.recv(&receiver).unwrap(), 1);
        assert_eq!(batch.datagram(0).unwrap().0, jumbo);
        assert!(batch.kernel_backed[0]);
        assert!(batch.gro_enabled);
    }

    #[test]
    fn gro_disable_failure_keeps_plain_receive_ineligible() {
        let mut batch = ReceiveBatch::with_gro(true);
        let error = io::Error::from_raw_os_error(libc::EBADF);
        assert!(batch
            .finish_disabling_gro(Err(error), "test failure")
            .is_err());
        assert!(
            batch.gro_enabled,
            "a failed disable must not permit a plain read"
        );
    }

    #[tokio::test]
    async fn disabled_gro_keeps_plain_recvmmsg_active() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut batch = ReceiveBatch::new(&receiver, true);
        assert!(!batch.gro_enabled);
        sender
            .send_to(b"plain", receiver.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(batch.recv(&receiver).unwrap(), 1);
        assert_eq!(batch.datagram(0).unwrap().0, b"plain");
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
                    segment_size: None,
                    append_sentinel: false,
                },
                PlannedMessage {
                    first: 1,
                    datagrams: 1,
                    segment_size: None,
                    append_sentinel: false,
                },
                PlannedMessage {
                    first: 2,
                    datagrams: 2,
                    segment_size: Some(1200),
                    append_sentinel: false,
                },
                PlannedMessage {
                    first: 4,
                    datagrams: 1,
                    segment_size: None,
                    append_sentinel: false,
                },
                PlannedMessage {
                    first: 5,
                    datagrams: 1,
                    segment_size: None,
                    append_sentinel: false,
                },
                PlannedMessage {
                    first: 6,
                    datagrams: 1,
                    segment_size: None,
                    append_sentinel: false,
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
                normalize_control_len((*header).cmsg_len).unwrap(),
                normalize_control_len(libc::CMSG_LEN(UDP_SEGMENT_DATA_LEN as _)).unwrap()
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
                Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP) => {
                    log_unsupported_capability("UDP_SEGMENT", &error);
                    return;
                }
                _ => panic!("UDP_SEGMENT capability probe failed: {error}"),
            }
        }
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packets = [b"one".as_slice(), b"two", b"three", b"four"];
        assert_eq!(
            send_gso(&sender, receiver.local_addr().unwrap(), &packets, false,)
                .unwrap()
                .datagrams,
            packets.len()
        );
        let mut buf = [0; 16];
        for expected in packets {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], expected);
        }
    }

    #[tokio::test]
    async fn equal_tail_mitigation_preserves_vectors_and_reports_physical_bytes() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if probe_gso(&sender).is_err() {
            return;
        }
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut buf = [0; 64];

        // The small-batch fallback cannot attach provenance to a one-byte
        // value, so a real standalone 0x07 datagram remains byte-exact.
        let standalone = [b"\x07".as_slice()];
        let outcome = send_gso(&sender, receiver_addr, &standalone, true).unwrap();
        assert_eq!(
            outcome,
            SendOutcome {
                datagrams: 1,
                wire_bytes: 1,
            }
        );
        let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"\x07");

        // Upstream avoids GSO below eight packets rather than paying for a
        // sentinel. Two equal WireGuard-sized payloads remain byte-exact.
        let small = [vec![1; 32], vec![2; 32]];
        let outcome = send_gso(&sender, receiver_addr, &small, true).unwrap();
        assert_eq!(
            outcome,
            SendOutcome {
                datagrams: 2,
                wire_bytes: 64,
            }
        );
        for expected in &small {
            let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], expected);
        }

        // At the threshold an all-equal GSO message gains exactly one smaller
        // invalid-WireGuard tail; every original payload remains unchanged.
        let equal: Vec<_> = (0..SENTINEL_TAIL_BATCH_THRESHOLD)
            .map(|value| vec![value as u8; 32])
            .collect();
        let outcome = send_gso(&sender, receiver_addr, &equal, true).unwrap();
        assert_eq!(outcome.datagrams, equal.len());
        assert_eq!(outcome.wire_bytes, equal.len() * 32 + 1);
        for expected in &equal {
            let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], expected);
        }
        let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], NEVER_GSO_EQUAL_TAIL_SENTINEL);
    }

    #[tokio::test]
    async fn gso_to_gro_loopback_uses_production_parser_when_both_capabilities_exist() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut batch = ReceiveBatch::new(&receiver, false);
        if !batch.gro_enabled {
            // The receiver recorded the explicit capability result during
            // construction; generic Linux CI may not expose UDP_GRO.
            eprintln!("rustscale: GSO-to-GRO loopback skipped: UDP_GRO unavailable");
            return;
        }
        if let Err(error) = probe_gso(&sender) {
            match error.raw_os_error() {
                Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP) => {
                    log_unsupported_capability("UDP_SEGMENT", &error);
                    return;
                }
                _ => panic!("UDP_SEGMENT capability probe failed: {error}"),
            }
        }
        let packets = [vec![1; 1200], vec![2; 1200], vec![3; 1200], vec![4; 1000]];
        assert_eq!(
            send_gso(&sender, receiver.local_addr().unwrap(), &packets, false,)
                .unwrap()
                .datagrams,
            packets.len()
        );
        receiver.readable().await.unwrap();
        assert_eq!(batch.recv(&receiver).unwrap(), packets.len());
        for (index, expected) in packets.iter().enumerate() {
            assert_eq!(batch.datagram(index).unwrap().0, expected);
        }
        assert_eq!(
            batch.last_gro_payload_len,
            Some(mem::size_of::<libc::c_int>())
        );
    }

    #[tokio::test]
    async fn gro_two_tail_layout_preserves_uncoalesced_burst_order() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut batch = ReceiveBatch::new(&receiver, false);
        if !batch.gro_enabled {
            eprintln!("rustscale: uncoalesced GRO loopback skipped: UDP_GRO unavailable");
            return;
        }
        // Each next datagram is larger than the preceding established segment
        // size. UDP GRO can finish with only a smaller tail, so this prevents
        // these 64 packets from merging and requires 32 two-tail recv cycles.
        let packets: Vec<_> = (0u8..64)
            .map(|index| vec![index; usize::from(index) + 1])
            .collect();
        assert!(packets
            .iter()
            .all(|packet| packet.len() <= LOGICAL_PACKET_CAPACITY));
        for packet in &packets {
            sender
                .send_to(packet, receiver.local_addr().unwrap())
                .await
                .unwrap();
        }
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut received = Vec::new();
            while received.len() < packets.len() {
                receiver.readable().await.unwrap();
                let count = batch.recv(&receiver).unwrap();
                for index in 0..count {
                    received.push(batch.datagram(index).unwrap().0.to_vec());
                }
            }
            received
        })
        .await
        .expect("uncoalesced burst was not fully delivered within two seconds");
        assert_eq!(received, packets);
    }
}
