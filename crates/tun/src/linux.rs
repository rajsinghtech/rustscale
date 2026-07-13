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
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;

use crate::{Tun, TunConfig, TunError};

/// Linux interface-name field size (`IFNAMSIZ`).
const IFNAMSIZ: usize = 16;

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
}

impl TunDevice {
    /// Create a tun device. `config.name` is the requested interface name (≤ 15
    /// bytes). Requires root or `CAP_NET_ADMIN`.
    pub fn create(config: &TunConfig) -> Result<Self, TunError> {
        let mtu = read_buffer_len(config.mtu)
            .map_err(|e| TunError::Create(format!("invalid MTU {}: {e}", config.mtu)))?;

        let path = std::ffi::CString::new("/dev/net/tun").expect("static path");
        // SAFETY: opening a well-known device path; no memory-safety preconditions.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(TunError::Create(format!(
                "open /dev/net/tun: {}",
                io::Error::last_os_error()
            )));
        }

        // SAFETY: `fd` is a freshly opened, owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let name = set_tun_iff(owned.as_raw_fd(), &config.name)?;
        // A TUN device defaults to MTU 1500. Set the kernel interface MTU before
        // using `config.mtu` as the read buffer bound, so reads cannot truncate
        // packets admitted by the interface.
        set_interface_mtu(&name, mtu)
            .map_err(|e| TunError::Create(format!("set MTU {mtu} on interface {name}: {e}")))?;
        let afd = AsyncFd::new(owned)
            .map_err(|e| TunError::Create(format!("AsyncFd registration: {e}")))?;

        Ok(Self { afd, name, mtu })
    }
}

#[async_trait]
impl Tun for TunDevice {
    async fn read_packet(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; read_buffer_len(self.mtu)?];
        loop {
            let mut guard = self.afd.readable().await?;
            match guard.try_io(|afd| {
                let fd = afd.get_ref().as_raw_fd();
                // SAFETY: read into our buffer via the raw fd.
                let n =
                    unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
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
                    buf.truncate(n);
                    return Ok(buf);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
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

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
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

/// Issue `TUNSETIFF` on `fd` with `IFF_TUN | IFF_NO_PI` and return the
/// kernel-assigned interface name.
fn set_tun_iff(fd: RawFd, requested: &str) -> Result<String, TunError> {
    let mut ifr = tun_iff_request(requested)?;

    // SAFETY: TUNSETIFF on an ifreq pointer is the documented use.
    let rc = unsafe { libc::ioctl(fd, libc::TUNSETIFF, std::ptr::addr_of_mut!(ifr)) };
    if rc < 0 {
        return Err(TunError::Create(format!(
            "TUNSETIFF: {}",
            io::Error::last_os_error()
        )));
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
            return Err(TunError::Create(format!(
                "fcntl O_NONBLOCK: {}",
                io::Error::last_os_error()
            )));
        }
    }

    Ok(name)
}

fn tun_iff_request(requested: &str) -> Result<Ifreq, TunError> {
    let mut ifr = Ifreq {
        name: [0; IFNAMSIZ],
        data: IfreqData {
            flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
        },
    };
    if copy_ifname(&mut ifr.name, requested).is_err() {
        return Err(TunError::InvalidName(requested.into()));
    }
    Ok(ifr)
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
        let request = tun_iff_request("tun0").unwrap();
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
}
