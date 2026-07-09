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

/// Maximum IP packet size.
const MAX_READ: usize = 65_535;

/// A `struct ifreq` laid out for the `TUNSETIFF` flags case.
#[repr(C)]
struct IfreqFlags {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
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
        let path = std::ffi::CString::new("/dev/net/tun").expect("static path");
        // SAFETY: opening a well-known device path; no memory-safety preconditions.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(TunError::Create(format!(
                "open /dev/net/tun: {}",
                io::Error::last_os_error()
            )));
        }

        let name = set_tun_iff(fd, &config.name)?;

        // SAFETY: `fd` is a freshly opened, owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let afd = AsyncFd::new(owned)
            .map_err(|e| TunError::Create(format!("AsyncFd registration: {e}")))?;

        Ok(Self {
            afd,
            name,
            mtu: config.mtu,
        })
    }
}

#[async_trait]
impl Tun for TunDevice {
    async fn read_packet(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_READ];
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
            let packet = packet.to_vec();
            match guard.try_io(|afd| {
                let fd = afd.get_ref().as_raw_fd();
                // SAFETY: write the packet buffer through the raw fd.
                let n = unsafe {
                    libc::write(fd, packet.as_ptr().cast::<libc::c_void>(), packet.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    if n == packet.len() {
                        return Ok(());
                    }
                    // Partial write: continue with the remainder on the next ready.
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

/// Issue `TUNSETIFF` on `fd` with `IFF_TUN | IFF_NO_PI` and return the
/// kernel-assigned interface name.
fn set_tun_iff(fd: RawFd, requested: &str) -> Result<String, TunError> {
    let mut ifr = IfreqFlags {
        name: [0; IFNAMSIZ],
        flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
    };
    let bytes = requested.as_bytes();
    if bytes.len() >= IFNAMSIZ {
        return Err(TunError::InvalidName(requested.into()));
    }
    for (i, b) in bytes.iter().enumerate() {
        ifr.name[i] = *b as libc::c_char;
    }

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
