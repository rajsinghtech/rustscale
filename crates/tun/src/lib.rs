//! Platform TUN device abstraction for rustscale.
//!
//! Provides an async [`Tun`] trait and a concrete [`TunDevice`] that wraps the
//! OS-level TUN interface:
//! - **macOS**: `utun` via `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` +
//!   `CTLIOCGINFO` for `com.apple.net.utun_control`, with the 4-byte address-family
//!   header stripped/prepended on read/write (matching Go's `wireguard-go/tun`).
//! - **Linux**: `/dev/net/tun` with `TUNSETIFF` (`IFF_TUN | IFF_NO_PI`), using
//!   VNET headers and receive-side GSO splitting when supported by the kernel.
//!
//! The public API deals in **plain IP packets** — the macOS AF header and the
//! Linux packet-info byte are never exposed to callers. See [`strip_af_header`]
//! and [`prepend_af_header`] for the framing primitives, which are unit-tested
//! independently of any real device.
//!
//! # Why hand-rolled instead of the `tun` crate?
//!
//! We need exact control over the macOS utun 4-byte AF framing (the `tun` crate
//! on crates.io exposes a sync or Linux-centric API and varies by version), a
//! tokio `AsyncFd`-friendly async surface, and plain-packet semantics with no
//! platform framing leaking. Hand-rolling against `libc` + `tokio::io::AsyncFd`
//! is the most faithful port of `wireguard-go/tun/tun_darwin.go` and keeps the
//! boundary clean. This crate is the only one in the workspace that permits
//! `unsafe` (raw syscalls require it); all other crates keep
//! `unsafe_code = "forbid"`.

use std::io;

use async_trait::async_trait;

#[cfg(target_os = "macos")]
#[path = "darwin.rs"]
mod darwin;
#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod linux;
mod mock;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod offload;

#[cfg(target_os = "macos")]
pub use darwin::TunDevice;
#[cfg(target_os = "linux")]
pub use linux::TunDevice;
pub use mock::MockTun;

/// Reusable TCP receive coalescer for userspace IP stacks.
///
/// Valid, contiguous TCPv4/TCPv6 segments are combined into ordinary IP
/// packets with complete checksums. Malformed, checksum-invalid, non-TCP, and
/// incompatible packets remain scalar and retain their input order. Unlike
/// Linux TUN write-side GRO, the output carries no virtio header or partial
/// checksum metadata and can be injected directly into a userspace stack.
pub struct TcpGroCoalescer {
    state: offload::TcpGroState,
    output: Vec<Vec<u8>>,
    max_segments: usize,
}

impl Default for TcpGroCoalescer {
    fn default() -> Self {
        Self {
            state: offload::TcpGroState::default(),
            output: Vec::new(),
            max_segments: usize::MAX,
        }
    }
}

impl TcpGroCoalescer {
    /// Construct an empty coalescer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Limit the number of original TCP segments represented by one output
    /// packet. A bound of one leaves valid input segments scalar.
    pub fn set_max_segments(&mut self, max_segments: usize) {
        assert!(max_segments > 0, "TCP GRO segment bound must be non-zero");
        self.max_segments = max_segments;
    }

    /// Coalesce compatible TCP segments in place while retaining planner
    /// allocations for the next batch.
    pub fn coalesce(&mut self, packets: &mut Vec<Vec<u8>>) {
        offload::coalesce_tcp_packets_bounded(
            &mut self.state,
            packets,
            &mut self.output,
            self.max_segments,
        );
    }

    /// Coalesce while returning fragment allocations that no longer own an
    /// output packet. Embedded stacks can feed these buffers back into their
    /// WireGuard plaintext scratch instead of freeing them per segment.
    pub fn coalesce_recycling(&mut self, packets: &mut Vec<Vec<u8>>, recycled: &mut Vec<Vec<u8>>) {
        offload::coalesce_tcp_packets_bounded_recycling(
            &mut self.state,
            packets,
            &mut self.output,
            self.max_segments,
            recycled,
        );
    }
}

/// Reusable storage for packets returned by [`Tun::read_batch`].
///
/// A successful read may contain up to [`Self::MAX_PACKETS`] packets. Calling
/// [`Self::clear`] drops the logical packet count while retaining all backing
/// allocations for the next read.
pub struct TunPacketBatch {
    packets: Vec<Vec<u8>>,
    len: usize,
}

impl TunPacketBatch {
    /// Maximum number of packets one TUN read may return.
    pub const MAX_PACKETS: usize = 128;

    /// Construct an empty batch with no packet allocations.
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
            len: 0,
        }
    }
    /// Remove all logically present packets while retaining their allocations.
    pub fn clear(&mut self) {
        self.len = 0;
    }
    /// Packets produced by the most recent successful read, in read order.
    pub fn packets(&self) -> &[Vec<u8>] {
        &self.packets[..self.len]
    }
    /// Append one packet, primarily for in-memory [`Tun`] implementations.
    ///
    /// Returns `InvalidData` when the batch has reached [`Self::MAX_PACKETS`].
    pub fn push_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let index = self.len;
        let out = self.packet_mut(index)?;
        out.clear();
        out.extend_from_slice(packet);
        self.len += 1;
        Ok(())
    }
    pub(crate) fn packet_mut(&mut self, index: usize) -> io::Result<&mut Vec<u8>> {
        if index >= Self::MAX_PACKETS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many TUN packets",
            ));
        }
        while self.packets.len() <= index {
            self.packets.push(Vec::new());
        }
        Ok(&mut self.packets[index])
    }
    pub(crate) fn set_len(&mut self, len: usize) {
        self.len = len;
    }
}

impl Default for TunPacketBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from TUN device operations.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid tun name: {0}")]
    InvalidName(String),
    #[error("tun device creation failed during {operation}: {source}")]
    CreateIo {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("tun device creation failed: {0}")]
    Create(String),
}

/// An async TUN device that reads and writes plain IP packets.
///
/// Implementations strip/prepend platform-specific framing internally so callers
/// only ever see raw IPv4/IPv6 packets. `TunDevice` is the real OS-backed
/// implementation; [`MockTun`] is an in-memory implementation for tests.
#[async_trait]
pub trait Tun: Send + Sync {
    /// Read one or more raw IP packets into reusable batch storage.
    ///
    /// Implementations retain the allocation where possible. On success,
    /// [`TunPacketBatch::packets`] contains one or more IPv4 or IPv6 packets;
    /// platform framing is never exposed.
    async fn read_batch(&self, batch: &mut TunPacketBatch) -> io::Result<()>;

    /// Write one IP packet to the device.
    async fn write_packet(&self, packet: &[u8]) -> io::Result<()>;

    /// Write an ordered batch of owned IP packets to the device.
    ///
    /// This is consume-on-write storage: once this future is polled, an
    /// OS-backed implementation may permanently rewrite selected packet
    /// headers. Those mutations can remain after success, I/O error, or
    /// cancellation; callers must replace or clear packet contents before
    /// reusing them. Callers that need original bytes (for example capture)
    /// must observe them before this boundary. An empty batch is a successful
    /// no-op.
    ///
    /// The default deliberately retains the scalar contract: it attempts every
    /// packet in order and returns the first error only after attempting the
    /// remainder of the batch.
    async fn write_batch(&self, packets: &mut [Vec<u8>]) -> io::Result<()> {
        let mut first_error = None;
        for packet in packets {
            if let Err(error) = self.write_packet(packet).await {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// The OS-assigned interface name (e.g. `utun4`).
    fn name(&self) -> &str;

    /// The device MTU in bytes.
    fn mtu(&self) -> usize;
}

/// Configuration for creating a [`TunDevice`].
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Interface name hint. On macOS use `"utun"` for automatic selection or
    /// `"utunN"` (e.g. `"utun9"`) for a specific unit. On Linux any interface
    /// name ≤ 15 bytes.
    pub name: String,
    /// Desired MTU. Linux applies this to the created interface; Tailscale's
    /// tailnet MTU is 1280.
    pub mtu: usize,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            // "utun" on macOS auto-selects a unit; Linux users should override.
            #[cfg(target_os = "macos")]
            name: "utun".to_string(),
            #[cfg(not(target_os = "macos"))]
            name: "tun0".to_string(),
            mtu: 1280,
        }
    }
}

impl TunConfig {
    /// Build a config with the given name hint and the default tailnet MTU.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mtu: 1280,
        }
    }
}

/// Create a real OS-backed [`TunDevice`] from a [`TunConfig`].
///
/// On macOS this opens a `utun` control socket (requires root). On Linux this
/// opens `/dev/net/tun` (requires the `tun` module and appropriate permissions).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn create(config: &TunConfig) -> Result<TunDevice, TunError> {
    TunDevice::create(config)
}

/// Clear `packet` and retain enough capacity for a read of `read_len` bytes.
///
/// Clearing first is important: [`Vec::reserve`] guarantees capacity relative
/// to the current length, so after this call `packet.capacity() >= read_len`
/// regardless of its previous length and capacity.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub(crate) fn prepare_read_buffer(packet: &mut Vec<u8>, read_len: usize) {
    packet.clear();
    packet.reserve(read_len);
}

// ---------------------------------------------------------------------------
// Address-family framing primitives (macOS utun)
// ---------------------------------------------------------------------------

/// macOS address families used in the utun 4-byte packet header.
#[cfg(unix)]
pub const AF_INET: u8 = libc::AF_INET as u8;
/// IPv6 address family for the utun 4-byte packet header.
#[cfg(unix)]
pub const AF_INET6: u8 = libc::AF_INET6 as u8;

/// Length of the utun 4-byte address-family header prepended to every packet.
pub const AF_HEADER_LEN: usize = 4;

/// Given a raw utun read (4-byte AF header + IP packet), return the plain IP
/// packet bytes. Returns `None` if the frame is too short or the AF byte is
/// neither `AF_INET` nor `AF_INET6`.
#[cfg(unix)]
pub fn strip_af_header(raw: &[u8]) -> Option<&[u8]> {
    if raw.len() < AF_HEADER_LEN {
        return None;
    }
    let af = raw[3];
    if af != AF_INET && af != AF_INET6 {
        return None;
    }
    Some(&raw[AF_HEADER_LEN..])
}

/// Prepend the utun 4-byte AF header to `packet`, writing into `out`. The AF
/// byte is derived from the IP version nibble of `packet[0]`. Returns an error
/// if the packet is empty or has an unknown IP version.
#[cfg(unix)]
pub fn prepend_af_header(packet: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    if packet.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty packet"));
    }
    let af = match packet[0] >> 4 {
        4 => AF_INET,
        6 => AF_INET6,
        v => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown IP version {v}"),
            ));
        }
    };
    out.clear();
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    out.push(af);
    out.extend_from_slice(packet);
    Ok(())
}

#[cfg(test)]
mod tests;
