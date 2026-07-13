//! Linux `/dev/net/tun` TUN device implementation.
//!
//! Opens `/dev/net/tun`, sets the interface up with `TUNSETIFF`
//! (`IFF_TUN | IFF_NO_PI`), and reads/writes **plain IP packets** (no
//! packet-info header, since `IFF_NO_PI` suppresses it).
//!
//! Requires the `tun` kernel module and appropriate permissions (root or
//! `CAP_NET_ADMIN`). This code is compiled only on `target_os = "linux"`; it is
//! not exercised on the macOS dev machine but is kept CI-friendly.

use std::io;
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

use crate::{offload, prepare_read_buffer, Tun, TunConfig, TunError, TunPacketBatch};

/// Linux interface-name field size (`IFNAMSIZ`).
const IFNAMSIZ: usize = 16;
const IFF_VNET_HDR: libc::c_short = 0x4000;
const TUN_F_CSUM: libc::c_int = 0x01;
const TUN_F_TSO4: libc::c_int = 0x02;
const TUN_F_TSO6: libc::c_int = 0x04;
const VNET_READ_LEN: usize = offload::VIRTIO_NET_HDR_LEN + 65_535;

/// The `ifreq` union. `ifmap` is the largest Linux member on 64-bit targets;
/// three `c_ulong`s provide its size and alignment without relying on a
/// platform-specific libc `ifmap` definition.
#[repr(C)]
union IfreqData {
    flags: libc::c_short,
    mtu: libc::c_int,
    addr: libc::sockaddr,
    ifmap: [libc::c_ulong; 3],
}

/// Linux `struct ifreq`, including its complete data union.
///
/// ioctl handlers may copy or access the whole ABI object, even when a
/// particular operation uses only one union member.
#[repr(C)]
struct Ifreq {
    name: [libc::c_char; IFNAMSIZ],
    data: IfreqData,
}

/// A real Linux `tun` device backed by a tokio `AsyncFd`.
pub struct TunDevice {
    afd: AsyncFd<OwnedFd>,
    name: String,
    mtu: usize,
    vnet_hdr: bool,
    raw_frame: Mutex<Vec<u8>>,
    write_op: Mutex<WriteScratch>,
}

/// State that must remain exclusively owned while a VNET batch is planned,
/// header-accounted, and written. The raw iovecs only borrow packets for the
/// duration of one syscall and are rebuilt immediately before that syscall.
#[derive(Default)]
struct WriteScratch {
    gro: offload::TcpGroState,
}

/// Guarantees logical GRO state is released even when an async write is
/// cancelled while waiting for descriptor readiness.
struct ActiveWritePlan<'a> {
    scratch: &'a mut WriteScratch,
}

impl ActiveWritePlan<'_> {
    fn gro(&mut self) -> &mut offload::TcpGroState {
        &mut self.scratch.gro
    }
}

impl Drop for ActiveWritePlan<'_> {
    fn drop(&mut self) {
        self.scratch.gro.reset();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteRetry {
    Immediate,
    WaitWritable,
    Terminal,
}

enum OutputWriteError {
    Readiness(io::Error),
    Frame(io::Error),
}

#[derive(Default)]
struct WritePlanErrors {
    first: Option<io::Error>,
}

enum WritePlanStep {
    Continue,
    Stop(io::Error),
}

impl WritePlanErrors {
    fn record(&mut self, error: OutputWriteError) -> WritePlanStep {
        match error {
            OutputWriteError::Readiness(error) => WritePlanStep::Stop(error),
            OutputWriteError::Frame(error) => {
                let terminal = terminal_write_error(&error);
                if self.first.is_none() {
                    self.first = Some(error);
                }
                if terminal {
                    WritePlanStep::Stop(self.first.take().expect("first frame error"))
                } else {
                    WritePlanStep::Continue
                }
            }
        }
    }

    fn finish(self) -> io::Result<()> {
        self.first.map_or(Ok(()), Err)
    }
}

fn classify_write_error(error: &io::Error) -> WriteRetry {
    if error.raw_os_error() == Some(libc::EINTR) {
        WriteRetry::Immediate
    } else if error.kind() == io::ErrorKind::WouldBlock {
        WriteRetry::WaitWritable
    } else {
        WriteRetry::Terminal
    }
}

impl TunDevice {
    /// Create a tun device. `config.name` is the requested interface name (≤ 15
    /// bytes). Requires root or `CAP_NET_ADMIN`.
    pub fn create(config: &TunConfig) -> Result<Self, TunError> {
        let mtu = read_buffer_len(config.mtu)
            .map_err(|e| TunError::Create(format!("invalid MTU {}: {e}", config.mtu)))?;

        let (owned, name, vnet_hdr) = match open_configured_tun(&config.name, true) {
            Ok((fd, name)) => (fd, name, true),
            Err(e) if is_unsupported(&e) => {
                let (fd, name) = open_configured_tun(&config.name, false)?;
                (fd, name, false)
            }
            Err(e) => return Err(e),
        };
        // A TUN device defaults to MTU 1500. Set the kernel interface MTU before
        // using `config.mtu` as the read buffer bound, so reads cannot truncate
        // packets admitted by the interface.
        set_interface_mtu(&name, mtu)
            .map_err(|e| TunError::Create(format!("set MTU {mtu} on interface {name}: {e}")))?;
        let afd = AsyncFd::new(owned)
            .map_err(|e| TunError::Create(format!("AsyncFd registration: {e}")))?;

        Ok(Self {
            afd,
            name,
            mtu,
            vnet_hdr,
            raw_frame: Mutex::new(Vec::new()),
            write_op: Mutex::new(WriteScratch::default()),
        })
    }
}

fn open_configured_tun(requested: &str, vnet_hdr: bool) -> Result<(OwnedFd, String), TunError> {
    let path = std::ffi::CString::new("/dev/net/tun").expect("static path");
    // SAFETY: opening a well-known device path; no memory-safety preconditions.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(create_io("open /dev/net/tun", io::Error::last_os_error()));
    }

    // SAFETY: `fd` is a freshly opened, owned descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let name = set_tun_iff(owned.as_raw_fd(), requested, vnet_hdr)?;
    if vnet_hdr {
        set_tun_offload(owned.as_raw_fd())?;
    }
    Ok((owned, name))
}

#[async_trait]
impl Tun for TunDevice {
    async fn read_batch(&self, batch: &mut TunPacketBatch) -> io::Result<()> {
        if self.vnet_hdr {
            return self.read_vnet_batch(batch).await;
        }
        batch.clear();
        let read_len = read_buffer_len(self.mtu)?;
        let packet = batch.packet_mut(0)?;
        // Keep the vector valid if this future is cancelled while waiting, or
        // if readiness proves stale and we retry below.
        prepare_read_buffer(packet, read_len);
        loop {
            let mut guard = self.afd.readable().await?;
            match guard.try_io(|afd| {
                let fd = afd.get_ref().as_raw_fd();
                let spare = &mut packet.spare_capacity_mut()[..read_len];
                // SAFETY: `spare` names exactly the vector's uninitialized
                // capacity used for this read. `read` initializes at most
                // `read_len` bytes; only the successful nonzero result is
                // exposed with set_len.
                let n = unsafe {
                    libc::read(fd, spare.as_mut_ptr().cast::<libc::c_void>(), spare.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "tun device closed",
                        ));
                    }
                    // SAFETY: the successful read above initialized exactly
                    // `n` bytes in `packet`'s spare capacity.
                    unsafe { packet.set_len(n) };
                    batch.set_len(1);
                    return Ok(());
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        if self.vnet_hdr {
            return self.write_vnet_packet(packet).await;
        }

        loop {
            let mut guard = self.afd.writable().await?;
            match guard.try_io(|afd| {
                let fd = afd.get_ref().as_raw_fd();
                // SAFETY: write the caller's packet bytes via the raw fd.
                let n = unsafe {
                    libc::write(fd, packet.as_ptr().cast::<libc::c_void>(), packet.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return validate_packet_write(result, packet.len()),
                Err(_would_block) => {}
            }
        }
    }

    async fn write_batch(&self, packets: &mut [Vec<u8>]) -> io::Result<()> {
        if packets.is_empty() {
            return Ok(());
        }
        if !self.vnet_hdr {
            let mut first_error = None;
            for packet in packets {
                if let Err(error) = self.write_packet(packet).await {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
            return first_error.map_or(Ok(()), Err);
        }

        let mut scratch = self.write_op.lock().await;
        let mut plan = ActiveWritePlan {
            scratch: &mut scratch,
        };
        plan.gro().plan(packets);
        self.write_vnet_plan(packets, plan.gro()).await
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

impl TunDevice {
    /// Write one plain IP packet using the Linux VNET framing contract.
    ///
    /// The virtio header is deliberately stack allocated: every inbound packet
    /// is non-GSO and needs neither checksum work nor any other metadata.
    async fn write_vnet_packet(&self, packet: &[u8]) -> io::Result<()> {
        let header = [0_u8; offload::VIRTIO_NET_HDR_LEN];
        let expected = vnet_write_len(packet.len())?;

        loop {
            let mut guard = self.afd.writable().await?;
            match guard.try_io(|afd| {
                let iovecs = vnet_write_iovecs(&header, packet);
                // SAFETY: both iovecs reference live immutable buffers for
                // this call, and their count matches the array length.
                let n = unsafe {
                    libc::writev(
                        afd.get_ref().as_raw_fd(),
                        iovecs.as_ptr(),
                        iovecs.len() as libc::c_int,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return validate_vnet_write(result, expected),
                Err(_would_block) => {}
            }
        }
    }

    async fn write_vnet_plan(
        &self,
        packets: &[Vec<u8>],
        gro: &offload::TcpGroState,
    ) -> io::Result<()> {
        let mut errors = WritePlanErrors::default();
        for output in gro.outputs() {
            if let Err(error) = self.write_gro_output(output, packets).await {
                if let WritePlanStep::Stop(error) = errors.record(error) {
                    return Err(error);
                }
            }
        }
        errors.finish()
    }

    async fn write_gro_output(
        &self,
        output: &offload::GroOutput,
        packets: &[Vec<u8>],
    ) -> Result<(), OutputWriteError> {
        loop {
            let mut guard = self
                .afd
                .writable()
                .await
                .map_err(OutputWriteError::Readiness)?;
            match guard.try_io(|afd| loop {
                // The iovecs are created inside the readiness closure and
                // never survive an await or cancellation point.
                let mut iovecs: [MaybeUninit<libc::iovec>; offload::MAX_GRO_IOVECS] =
                    std::array::from_fn(|_| MaybeUninit::uninit());
                let (iovecs, expected) = gro_write_iovecs(&mut iovecs, output, packets)?;
                // SAFETY: `iovecs` was just built from live packet and header
                // storage held by the caller's write-operation mutex. The
                // kernel reads it only for this syscall.
                let n = unsafe {
                    libc::writev(
                        afd.get_ref().as_raw_fd(),
                        iovecs.as_ptr(),
                        iovecs.len() as libc::c_int,
                    )
                };
                if n >= 0 {
                    return Ok((n as usize, expected));
                }
                let error = io::Error::last_os_error();
                match classify_write_error(&error) {
                    WriteRetry::Immediate => continue,
                    WriteRetry::WaitWritable | WriteRetry::Terminal => return Err(error),
                }
            }) {
                Ok(Ok((written, expected))) => {
                    return validate_vnet_write(Ok(written), expected)
                        .map_err(OutputWriteError::Frame)
                }
                Ok(Err(error)) => return Err(OutputWriteError::Frame(error)),
                Err(_would_block) => {}
            }
        }
    }

    async fn read_vnet_batch(&self, batch: &mut TunPacketBatch) -> io::Result<()> {
        batch.clear();
        let mut raw = self.raw_frame.lock().await;
        prepare_read_buffer(&mut raw, VNET_READ_LEN);
        loop {
            let mut guard = self.afd.readable().await?;
            match guard.try_io(|afd| {
                let spare = &mut raw.spare_capacity_mut()[..VNET_READ_LEN];
                // SAFETY: the spare capacity is the exact destination of this read.
                let n = unsafe {
                    libc::read(
                        afd.get_ref().as_raw_fd(),
                        spare.as_mut_ptr().cast(),
                        spare.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tun device closed",
                    ))
                }
                Ok(Ok(n)) => {
                    unsafe { raw.set_len(n) };
                    return offload::split_virtio(&raw, batch);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
            }
        }
    }
}

/// Descriptor failures cannot make progress by polling a later frame.
fn terminal_write_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EBADF) | Some(libc::EBADFD))
}

/// Return the allocation size for one TUN packet read.
fn read_buffer_len(mtu: usize) -> io::Result<usize> {
    if mtu == 0 || mtu > libc::c_int::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN MTU must fit in a positive C int",
        ));
    }
    Ok(mtu)
}

/// Set the kernel MTU of an interface created by this device.
fn set_interface_mtu(ifname: &str, mtu: usize) -> io::Result<()> {
    let mut ifr = interface_mtu_request(ifname, mtu)?;

    // SAFETY: creating an AF_INET datagram socket has no memory-safety preconditions.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened, owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // SAFETY: SIOCSIFMTU expects an ifreq with the interface name and MTU union member.
    let rc = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCSIFMTU as _,
            std::ptr::addr_of_mut!(ifr),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Build the `SIOCSIFMTU` request after validating values representable by it.
fn interface_mtu_request(ifname: &str, mtu: usize) -> io::Result<Ifreq> {
    let mut ifr = Ifreq {
        name: [0; IFNAMSIZ],
        data: IfreqData {
            mtu: read_buffer_len(mtu)? as libc::c_int,
        },
    };
    copy_ifname(&mut ifr.name, ifname)?;
    Ok(ifr)
}

fn copy_ifname(dst: &mut [libc::c_char; IFNAMSIZ], name: &str) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() >= IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name exceeds IFNAMSIZ",
        ));
    }
    for (i, b) in bytes.iter().enumerate() {
        dst[i] = *b as libc::c_char;
    }
    Ok(())
}

/// Validate that a TUN write accepted precisely one complete packet.
fn validate_packet_write(result: io::Result<usize>, packet_len: usize) -> io::Result<()> {
    let written = result?;
    if written == packet_len {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::WriteZero,
        format!("short TUN packet write: wrote {written} of {packet_len} bytes"),
    ))
}

/// Return the total VNET frame length, rejecting values that `writev` cannot
/// report as a positive `ssize_t` result.
fn vnet_write_len(packet_len: usize) -> io::Result<usize> {
    let total = offload::VIRTIO_NET_HDR_LEN
        .checked_add(packet_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "VNET frame length overflow"))?;
    if total > libc::ssize_t::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VNET frame length exceeds ssize_t",
        ));
    }
    Ok(total)
}

/// Build the exact two-vector Linux VNET frame without copying `packet`.
fn vnet_write_iovecs(
    header: &[u8; offload::VIRTIO_NET_HDR_LEN],
    packet: &[u8],
) -> [libc::iovec; 2] {
    [
        libc::iovec {
            iov_base: header.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: packet.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: packet.len(),
        },
    ]
}

/// Materialize one platform-neutral GRO output as Linux iovecs. The plan
/// contains indexes and ranges rather than borrows, so all pointer work stays
/// at this syscall boundary. Only the returned initialized prefix is exposed.
fn gro_write_iovecs<'a>(
    iovecs: &'a mut [MaybeUninit<libc::iovec>],
    output: &offload::GroOutput,
    packets: &[Vec<u8>],
) -> io::Result<(&'a [libc::iovec], usize)> {
    let count = output.iovec_count();
    if count > offload::MAX_GRO_IOVECS || count > iovecs.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many VNET iovecs",
        ));
    }
    if count > libc::c_int::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iov count exceeds C int",
        ));
    }
    let head = packets.get(output.head).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "GRO head packet index out of bounds",
        )
    })?;
    let mut total = vnet_write_len(head.len())?;
    // Validate every fragment and total before initializing any caller slot.
    for fragment in &output.fragments {
        let packet = packets.get(fragment.packet).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "GRO fragment packet index out of bounds",
            )
        })?;
        let bytes = packet.get(fragment.start..fragment.end).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "GRO fragment range out of bounds",
            )
        })?;
        total = total.checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "VNET frame length overflow")
        })?;
        if total > libc::ssize_t::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VNET frame length exceeds ssize_t",
            ));
        }
    }
    iovecs[0].write(libc::iovec {
        iov_base: output.header.as_ptr().cast_mut().cast(),
        iov_len: output.header.len(),
    });
    iovecs[1].write(libc::iovec {
        iov_base: head.as_ptr().cast_mut().cast(),
        iov_len: head.len(),
    });
    for (index, fragment) in output.fragments.iter().enumerate() {
        let bytes = &packets[fragment.packet][fragment.start..fragment.end];
        iovecs[index + 2].write(libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        });
    }
    // SAFETY: the count and every index written above are bounded by
    // `iovecs.len()`, and all slots in this prefix were initialized.
    let iovecs = unsafe { std::slice::from_raw_parts(iovecs.as_ptr().cast(), count) };
    Ok((iovecs, total))
}

/// Validate that a VNET write consumed both its header and its packet.
fn validate_vnet_write(result: io::Result<usize>, expected: usize) -> io::Result<()> {
    let written = result?;
    if written == expected {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::WriteZero,
        format!("short VNET TUN write: wrote {written} of {expected} bytes"),
    ))
}

/// Issue `TUNSETIFF` on `fd` with `IFF_TUN | IFF_NO_PI` and return the
/// kernel-assigned interface name.
fn set_tun_iff(fd: RawFd, requested: &str, vnet_hdr: bool) -> Result<String, TunError> {
    let mut ifr = tun_iff_request(requested, vnet_hdr)?;

    // SAFETY: TUNSETIFF on an ifreq pointer is the documented use.
    let rc = unsafe { libc::ioctl(fd, libc::TUNSETIFF, std::ptr::addr_of_mut!(ifr)) };
    if rc < 0 {
        return Err(create_io("TUNSETIFF", io::Error::last_os_error()));
    }

    // Read back the (possibly kernel-assigned) name.
    let name_end = ifr.name.iter().position(|&c| c == 0).unwrap_or(IFNAMSIZ);
    let name = std::str::from_utf8(
        &ifr.name[..name_end]
            .iter()
            .map(|&c| c as u8)
            .collect::<Vec<_>>(),
    )
    .map_err(|e| TunError::Create(format!("ifname utf8: {e}")))?
    .to_owned();

    // Nonblocking + close-on-exec (already CLOEXEC from open, but be explicit).
    // SAFETY: fcntl on a valid fd.
    unsafe {
        if libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) < 0 {
            return Err(create_io("fcntl O_NONBLOCK", io::Error::last_os_error()));
        }
    }

    Ok(name)
}

fn tun_iff_request(requested: &str, vnet_hdr: bool) -> Result<Ifreq, TunError> {
    let mut ifr = Ifreq {
        name: [0; IFNAMSIZ],
        data: IfreqData {
            flags: ((libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short)
                | if vnet_hdr { IFF_VNET_HDR } else { 0 },
        },
    };
    if copy_ifname(&mut ifr.name, requested).is_err() {
        return Err(TunError::InvalidName(requested.into()));
    }
    Ok(ifr)
}

fn set_tun_offload(fd: RawFd) -> Result<(), TunError> {
    let flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
    // SAFETY: TUNSETOFFLOAD expects an integer flag value, not a pointer.
    if unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD, flags) } < 0 {
        return Err(create_io("TUNSETOFFLOAD", io::Error::last_os_error()));
    }
    Ok(())
}
fn create_io(operation: &'static str, source: io::Error) -> TunError {
    TunError::CreateIo { operation, source }
}

/// Only capability negotiation ioctls may trigger a clean-descriptor fallback.
fn is_unsupported(error: &TunError) -> bool {
    let TunError::CreateIo { operation, source } = error else {
        return false;
    };
    if !matches!(*operation, "TUNSETIFF" | "TUNSETOFFLOAD") {
        return false;
    }
    matches!(
        source.raw_os_error(),
        Some(libc::EINVAL | libc::EOPNOTSUPP | libc::ENOTTY)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn ifreq_matches_linux_abi_size_and_union_offset() {
        let expected_union_size = if cfg!(target_pointer_width = "64") {
            24
        } else {
            16
        };
        let expected_ifreq_size = if cfg!(target_pointer_width = "64") {
            40
        } else {
            32
        };

        assert_eq!(size_of::<IfreqData>(), expected_union_size);
        assert_eq!(offset_of!(Ifreq, data), IFNAMSIZ);
        assert_eq!(size_of::<Ifreq>(), expected_ifreq_size);
    }

    #[test]
    fn read_buffer_uses_configured_mtu() {
        assert_eq!(read_buffer_len(1280).unwrap(), 1280);
        assert_eq!(read_buffer_len(9000).unwrap(), 9000);
    }

    #[test]
    fn read_buffer_rejects_zero_mtu() {
        let error = read_buffer_len(0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn read_buffer_rejects_mtu_that_cannot_be_applied() {
        let error = read_buffer_len(libc::c_int::MAX as usize + 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn interface_mtu_request_uses_the_validated_mtu() {
        let request = interface_mtu_request("tun0", 1280).unwrap();
        // SAFETY: this request initialized the `mtu` union member.
        assert_eq!(unsafe { request.data.mtu }, 1280);
        assert_eq!(
            &request.name[..4],
            &[
                b't' as libc::c_char,
                b'u' as libc::c_char,
                b'n' as libc::c_char,
                b'0' as libc::c_char
            ]
        );
    }

    #[test]
    fn tun_iff_request_encodes_name_and_flags() {
        let request = tun_iff_request("tun0", false).unwrap();
        assert_eq!(
            &request.name[..5],
            &[
                b't' as libc::c_char,
                b'u' as libc::c_char,
                b'n' as libc::c_char,
                b'0' as libc::c_char,
                0,
            ]
        );
        // SAFETY: this request initialized the `flags` union member.
        assert_eq!(
            unsafe { request.data.flags },
            (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short
        );
    }

    #[test]
    fn vnet_request_and_offload_constants_match_linux_uapi() {
        let request = tun_iff_request("tun0", true).unwrap();
        // SAFETY: this request initialized the flags union member.
        assert_eq!(
            unsafe { request.data.flags },
            (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short | 0x4000
        );
        assert_eq!(TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6, 0x07);
        assert_eq!(libc::TUNSETOFFLOAD as u64, 0x4004_54d0);
        assert_eq!(VNET_READ_LEN, offload::VIRTIO_NET_HDR_LEN + 65_535);
    }

    #[test]
    fn fallback_is_limited_to_vnet_ioctl_capability_errnos() {
        for errno in [libc::EINVAL, libc::EOPNOTSUPP, libc::ENOTTY] {
            assert!(is_unsupported(&create_io(
                "TUNSETIFF",
                io::Error::from_raw_os_error(errno)
            )));
            assert!(is_unsupported(&create_io(
                "TUNSETOFFLOAD",
                io::Error::from_raw_os_error(errno)
            )));
        }
        for operation in ["open /dev/net/tun", "fcntl O_NONBLOCK", "set MTU"] {
            assert!(!is_unsupported(&create_io(
                operation,
                io::Error::from_raw_os_error(libc::EINVAL)
            )));
        }
        for errno in [libc::EPERM, libc::ENOENT, libc::EIO] {
            assert!(!is_unsupported(&create_io(
                "TUNSETIFF",
                io::Error::from_raw_os_error(errno)
            )));
        }
        assert!(!is_unsupported(&TunError::InvalidName("bad".into())));
        assert!(!is_unsupported(&TunError::Create(
            "arbitrary EINVAL text".into()
        )));
    }

    #[test]
    fn full_packet_write_succeeds() {
        validate_packet_write(Ok(1280), 1280).unwrap();
    }

    #[test]
    fn short_packet_write_is_an_error() {
        let error = validate_packet_write(Ok(1279), 1280).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn syscall_error_is_preserved_by_write_path() {
        let error =
            validate_packet_write(Err(io::Error::other("TUN write failed")), 1280).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "TUN write failed");
    }

    #[test]
    fn vnet_write_uses_a_zeroed_ten_byte_header_and_two_iovecs() {
        let header = [0_u8; offload::VIRTIO_NET_HDR_LEN];
        let packet = [0x45, 0, 0, 20];
        let iovecs = vnet_write_iovecs(&header, &packet);

        assert_eq!(header, [0; 10]);
        assert_eq!(iovecs.len(), 2);
        assert_eq!(iovecs[0].iov_base, header.as_ptr().cast_mut().cast());
        assert_eq!(iovecs[0].iov_len, offload::VIRTIO_NET_HDR_LEN);
        assert_eq!(iovecs[1].iov_base, packet.as_ptr().cast_mut().cast());
        assert_eq!(iovecs[1].iov_len, packet.len());
    }

    #[test]
    fn full_vnet_write_requires_header_and_packet() {
        let expected = vnet_write_len(1280).unwrap();
        assert_eq!(expected, 1290);
        validate_vnet_write(Ok(expected), expected).unwrap();
    }

    #[test]
    fn short_vnet_write_is_an_error() {
        let expected = vnet_write_len(1280).unwrap();
        let error = validate_vnet_write(Ok(expected - 1), expected).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn vnet_syscall_error_is_preserved() {
        let error = validate_vnet_write(Err(io::Error::other("writev failed")), 1290).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "writev failed");
    }

    #[test]
    fn vnet_write_rejects_overflow_and_unreportable_lengths() {
        assert_eq!(
            vnet_write_len(usize::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            vnet_write_len(libc::ssize_t::MAX as usize)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn gro_iovec_materialization_checks_ranges_and_limits() {
        let packets = vec![vec![0x45, 0, 0, 20], vec![1, 2, 3, 4]];
        let output = offload::GroOutput {
            header: [0; offload::VIRTIO_NET_HDR_LEN],
            head: 0,
            fragments: vec![offload::PayloadFragment {
                packet: 1,
                start: 1,
                end: 3,
            }],
        };
        let mut iovecs: [MaybeUninit<libc::iovec>; offload::MAX_GRO_IOVECS] =
            std::array::from_fn(|_| MaybeUninit::uninit());
        {
            let (prefix, total) = gro_write_iovecs(&mut iovecs, &output, &packets).unwrap();
            assert_eq!(prefix.len(), 3);
            assert_eq!(total, offload::VIRTIO_NET_HDR_LEN + 4 + 2);
            assert_eq!(prefix[0].iov_len, offload::VIRTIO_NET_HDR_LEN);
        }

        let bad_range = offload::GroOutput {
            fragments: vec![offload::PayloadFragment {
                packet: 1,
                start: 3,
                end: 5,
            }],
            ..output.clone()
        };
        assert!(gro_write_iovecs(&mut iovecs, &bad_range, &packets).is_err());

        let exactly_max = offload::GroOutput {
            fragments: vec![
                offload::PayloadFragment {
                    packet: 1,
                    start: 0,
                    end: 1,
                };
                offload::MAX_GRO_IOVECS - 2
            ],
            ..output.clone()
        };
        {
            let (prefix, _) = gro_write_iovecs(&mut iovecs, &exactly_max, &packets).unwrap();
            assert_eq!(prefix.len(), offload::MAX_GRO_IOVECS);
        }

        let too_many = offload::GroOutput {
            fragments: vec![
                offload::PayloadFragment {
                    packet: 1,
                    start: 0,
                    end: 1,
                };
                offload::MAX_GRO_IOVECS - 1
            ],
            ..output
        };
        assert!(gro_write_iovecs(&mut iovecs, &too_many, &packets).is_err());
    }

    #[test]
    fn bad_descriptor_errors_are_terminal() {
        for errno in [libc::EBADF, libc::EBADFD] {
            assert!(terminal_write_error(&io::Error::from_raw_os_error(errno)));
        }
        assert!(!terminal_write_error(&io::Error::from_raw_os_error(
            libc::EAGAIN
        )));
    }

    #[test]
    fn syscall_retry_classification_handles_eintr_and_eagain() {
        assert_eq!(
            classify_write_error(&io::Error::from_raw_os_error(libc::EINTR)),
            WriteRetry::Immediate
        );
        assert_eq!(
            classify_write_error(&io::Error::from_raw_os_error(libc::EAGAIN)),
            WriteRetry::WaitWritable
        );
        assert_eq!(
            classify_write_error(&io::Error::from_raw_os_error(libc::EBADF)),
            WriteRetry::Terminal
        );
    }

    #[test]
    fn active_plan_drop_resets_state_for_reuse() {
        let mut packets = vec![vec![0x45, 0, 0, 20]];
        let mut scratch = WriteScratch::default();
        {
            let mut plan = ActiveWritePlan {
                scratch: &mut scratch,
            };
            plan.gro().plan(&mut packets);
            assert_eq!(plan.gro().outputs().len(), 1);
        }
        assert!(scratch.gro.outputs().is_empty());
        scratch.gro.plan(&mut packets);
        assert_eq!(scratch.gro.outputs().len(), 1);
    }

    #[test]
    fn write_plan_error_policy_is_terminal_only_when_required() {
        let mut errors = WritePlanErrors::default();
        assert!(matches!(
            errors.record(OutputWriteError::Frame(io::Error::other("first"))),
            WritePlanStep::Continue
        ));
        assert!(matches!(
            errors.record(OutputWriteError::Frame(io::Error::other("later"))),
            WritePlanStep::Continue
        ));
        assert_eq!(errors.finish().unwrap_err().to_string(), "first");

        let mut errors = WritePlanErrors::default();
        match errors.record(OutputWriteError::Readiness(io::Error::other("poller"))) {
            WritePlanStep::Stop(error) => assert_eq!(error.to_string(), "poller"),
            WritePlanStep::Continue => panic!("readiness failure must stop"),
        }

        for errno in [libc::EBADF, libc::EBADFD] {
            let mut errors = WritePlanErrors::default();
            assert!(matches!(
                errors.record(OutputWriteError::Frame(io::Error::other("first"))),
                WritePlanStep::Continue
            ));
            match errors.record(OutputWriteError::Frame(io::Error::from_raw_os_error(errno))) {
                WritePlanStep::Stop(error) => assert_eq!(error.to_string(), "first"),
                WritePlanStep::Continue => panic!("bad descriptor must stop"),
            }
        }
    }
}
