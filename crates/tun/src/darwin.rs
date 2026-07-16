//! macOS `utun` TUN device implementation.
//!
//! Ports the approach from `wireguard-go/tun/tun_darwin.go`: open a
//! `PF_SYSTEM` / `SYSPROTO_CONTROL` socket, look up the
//! `com.apple.net.utun_control` kernel controller via `CTLIOCGINFO`, `connect`
//! a `sockaddr_ctl` to bind a utun unit, then read/write IP packets with a
//! 4-byte address-family header prepended by the kernel.
//!
//! Requires root (utun creation is privileged).

use std::ffi::CStr;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;

use crate::{prepare_read_buffer, Tun, TunConfig, TunError, TunPacketBatch, AF_HEADER_LEN};

/// Largest IP packet accepted by the utun framing API.
const MAX_IP_PACKET_LEN: usize = 65_535;
/// Maximum utun frame: a maximum IP packet plus its 4-byte AF header.
///
/// Unlike Linux, this implementation does not apply `TunConfig::mtu` to the
/// kernel interface, so that configuration is not a safe syscall read bound.
const MAX_READ: usize = MAX_IP_PACKET_LEN + AF_HEADER_LEN;

/// The kernel-control name for utun devices.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

/// A real macOS `utun` TUN device backed by a tokio `AsyncFd`.
pub struct TunDevice {
    afd: AsyncFd<OwnedFd>,
    name: String,
    mtu: usize,
}

impl TunDevice {
    /// Create a utun device. `config.name` is `"utun"` (auto-select a unit) or
    /// `"utunN"` for a specific unit index. Requires root.
    pub fn create(config: &TunConfig) -> Result<Self, TunError> {
        require_runtime()?;
        // Parse the requested unit index. "utun" -> auto (-1, becomes unit 0).
        let unit: i32 = if config.name == "utun" {
            -1
        } else {
            let rest = config
                .name
                .strip_prefix("utun")
                .ok_or_else(|| TunError::InvalidName(config.name.clone()))?;
            rest.parse::<i32>()
                .map_err(|_| TunError::InvalidName(config.name.clone()))?
        };

        let fd = open_utun(unit)?;
        // Take ownership so the fd is closed on drop / deregistration.
        // SAFETY: `fd` is a freshly opened, owned file descriptor that nothing
        // else holds. `from_raw_fd` takes sole ownership.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let afd = register_async_fd(owned, AsyncFd::new)?;

        let name = interface_name(&afd)?;

        Ok(Self {
            afd,
            name,
            mtu: config.mtu,
        })
    }
}

/// The registration boundary is kept separate from privileged utun setup so
/// tests can exercise it with an ordinary pipe rather than opening a device.
fn register_async_fd<F>(owned: OwnedFd, register: F) -> Result<AsyncFd<OwnedFd>, TunError>
where
    F: FnOnce(OwnedFd) -> io::Result<AsyncFd<OwnedFd>>,
{
    require_runtime()?;
    register(owned).map_err(|e| TunError::Create(format!("AsyncFd registration: {e}")))
}

fn require_runtime() -> Result<(), TunError> {
    tokio::runtime::Handle::try_current()
        .map(|_| ())
        .map_err(|_| {
            TunError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN creation requires an entered Tokio runtime",
            ))
        })
}

#[async_trait]
impl Tun for TunDevice {
    async fn read_batch(&self, batch: &mut TunPacketBatch) -> io::Result<()> {
        batch.clear();
        let packet = batch.packet_mut(0)?;
        // utun does not receive a configured MTU here; retain one maximum-size
        // frame allocation rather than risking truncation based on `self.mtu`.
        let read_len = MAX_READ;
        // The vector remains valid and empty on cancellation, a stale
        // readiness retry, EOF, or syscall error.
        prepare_read_buffer(packet, read_len);
        loop {
            let mut guard = self.afd.readable().await?;
            match guard.try_io(|afd| {
                let fd = afd.get_ref().as_raw_fd();
                let spare = &mut packet.spare_capacity_mut()[..read_len];
                // SAFETY: `spare` is precisely the vector's uninitialized
                // capacity used for this read. A successful read initializes
                // exactly the result count, which is the only count later
                // passed to set_len.
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
                            "utun device closed",
                        ));
                    }
                    // SAFETY: the successful read above initialized exactly
                    // `n` bytes in `packet`'s spare capacity.
                    unsafe { packet.set_len(n) };
                    strip_packet_in_place(packet)?;
                    batch.set_len(1);
                    return Ok(());
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let mut framed = Vec::with_capacity(AF_HEADER_LEN + packet.len());
        crate::prepend_af_header(packet, &mut framed)?;

        loop {
            let mut guard = self.afd.writable().await?;
            match guard.try_io(|afd| {
                let fd = afd.get_ref().as_raw_fd();
                // SAFETY: writing from `framed`'s buffer through the raw fd.
                let n = unsafe {
                    libc::write(fd, framed.as_ptr().cast::<libc::c_void>(), framed.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    if n == framed.len() {
                        return Ok(());
                    }
                    // Partial write: very unlikely for a datagram-style utun
                    // socket, but guard against it anyway.
                    framed.drain(..n);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

/// Open a utun kernel-control socket and connect to unit `unit` (auto-select
/// when negative). Returns the raw fd, nonblocking and close-on-exec.
fn open_utun(unit: i32) -> Result<RawFd, TunError> {
    // socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
    // SAFETY: libc socket() has no memory-safety preconditions.
    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(TunError::Create(format!(
            "socket(PF_SYSTEM): {}",
            io::Error::last_os_error()
        )));
    }

    // Look up the utun kernel controller id via CTLIOCGINFO.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    let name_len = UTUN_CONTROL_NAME.len().min(info.ctl_name.len());
    for (dst, &b) in info.ctl_name[..name_len]
        .iter_mut()
        .zip(&UTUN_CONTROL_NAME[..name_len])
    {
        *dst = b as libc::c_char;
    }
    // SAFETY: CTLIOCGINFO on a ctl_info pointer is the documented use.
    let rc = unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, std::ptr::addr_of_mut!(info)) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(TunError::Create(format!("CTLIOCGINFO: {e}")));
    }

    // Build the sockaddr_ctl and connect.
    let sc_unit: u32 = if unit < 0 { 0 } else { unit as u32 + 1 };
    let sc = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
        sc_family: libc::AF_SYSTEM as libc::c_uchar,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit,
        sc_reserved: [0; 5],
    };

    // SAFETY: connect with a valid sockaddr_ctl pointer + its size.
    let rc = unsafe {
        libc::connect(
            fd,
            std::ptr::addr_of!(sc).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(TunError::Create(format!("connect utun: {e}")));
    }

    set_nonblock_cloexec(fd).map_err(|e| TunError::Create(format!("fcntl: {e}")))?;

    Ok(fd)
}

/// Fetch the kernel-assigned interface name via getsockopt(UTUN_OPT_IFNAME).
fn interface_name(afd: &AsyncFd<OwnedFd>) -> Result<String, TunError> {
    let fd = afd.get_ref().as_raw_fd();
    let mut buf = [0u8; 64];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: getsockopt writes into `buf` (a local array) bounded by `len`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if rc < 0 {
        return Err(TunError::Create(format!(
            "getsockopt(UTUN_OPT_IFNAME): {}",
            io::Error::last_os_error()
        )));
    }
    let cstr = CStr::from_bytes_until_nul(&buf[..len as usize])
        .map_err(|e| TunError::Create(format!("ifname not valid UTF-8/nil: {e}")))?;
    Ok(cstr.to_string_lossy().into_owned())
}

/// Make `fd` nonblocking and close-on-exec.
fn set_nonblock_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl F_SETFL / F_SETFD on a valid fd.
    unsafe {
        if libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Validate a utun frame and remove its 4-byte AF header in place.
fn strip_packet_in_place(packet: &mut Vec<u8>) -> io::Result<()> {
    if packet.len() < AF_HEADER_LEN {
        packet.clear();
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short utun read (no AF header)",
        ));
    }
    let af = packet[3];
    if af != crate::AF_INET && af != crate::AF_INET6 {
        packet.clear();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown address family {af:#x}"),
        ));
    }
    packet.copy_within(AF_HEADER_LEN.., 0);
    packet.truncate(packet.len() - AF_HEADER_LEN);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    #[test]
    fn registration_boundary_without_runtime_returns_an_error() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe returned a newly owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: the other pipe end is not used by this test.
        unsafe { libc::close(fds[1]) };
        let result = std::panic::catch_unwind(|| register_async_fd(owned, AsyncFd::new));
        let error = result
            .expect("must not panic")
            .expect_err("runtime is required");
        assert!(error.to_string().contains("entered Tokio runtime"));
    }

    #[tokio::test]
    async fn registration_boundary_accepts_an_unprivileged_pipe() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe returned a newly owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: the other pipe end is not used by this test.
        unsafe { libc::close(fds[1]) };
        assert!(register_async_fd(owned, AsyncFd::new).is_ok());
    }

    #[test]
    fn strip_packet_compacts_a_valid_frame_in_place() {
        let mut packet = Vec::with_capacity(1284);
        packet.extend_from_slice(&[0, 0, 0, crate::AF_INET, 0x45, 1, 2]);
        let capacity = packet.capacity();

        strip_packet_in_place(&mut packet).unwrap();

        assert_eq!(packet, [0x45, 1, 2]);
        assert_eq!(packet.capacity(), capacity);
    }

    #[test]
    fn strip_packet_rejects_short_and_unknown_frames() {
        let mut short = vec![0, 0, 0];
        let error = strip_packet_in_place(&mut short).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(short.is_empty());

        let mut unknown = vec![0, 0, 0, 99, 0x45];
        let error = strip_packet_in_place(&mut unknown).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(unknown.is_empty());
    }

    #[test]
    fn read_buffer_includes_maximum_ip_packet_and_utun_header() {
        assert_eq!(MAX_READ, MAX_IP_PACKET_LEN + AF_HEADER_LEN);
    }
}
