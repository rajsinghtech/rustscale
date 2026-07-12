//! TCP connection information for rustscale.
//!
//! Ports the Go `tailscale.com/net/tcpinfo` package and the
//! `breakTCPConnsDarwin` helper from `ipn/ipnlocal`.
//!
//! On macOS, reads `struct tcp_connection_info` via `getsockopt` with
//! `TCP_CONNECTION_INFO` (option 0x106) and extracts `tcpi_rttcur`
//! (milliseconds). On Linux, reads `struct tcp_info` via `getsockopt` with
//! `TCP_INFO` (option 11) and extracts `tcpi_rtt` (microseconds). On other
//! platforms `rtt` returns `io::ErrorKind::Unsupported`.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

/// Returns the round-trip time for the given TCP stream.
///
/// On macOS reads `tcpi_rttcur` via `getsockopt(TCP_CONNECTION_INFO)`, on
/// Linux reads `tcpi_rtt` via `getsockopt(TCP_INFO)`. On other platforms
/// returns `io::ErrorKind::Unsupported`.
#[cfg(unix)]
pub fn rtt(stream: &TcpStream) -> io::Result<Duration> {
    rtt_impl(stream.as_raw_fd())
}

#[cfg(not(unix))]
pub fn rtt(_stream: &TcpStream) -> io::Result<Duration> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tcpinfo: not supported on this platform",
    ))
}

/// Closes all TCP connections visible in the current process by iterating
/// file descriptors 0..1000 and closing any that are TCP sockets.
///
/// Returns the number of connections closed. On non-macOS platforms this
/// is a no-op that returns `Ok(0)`.
pub fn break_tcp_conns() -> io::Result<usize> {
    break_tcp_conns_impl()
}

// ---------------------------------------------------------------------------
// macOS (Darwin) — getsockopt TCP_CONNECTION_INFO
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const TCP_CONNECTION_INFO: libc::c_int = 0x106;

#[cfg(target_os = "macos")]
fn rtt_impl(fd: RawFd) -> io::Result<Duration> {
    let mut info: TcpConnectionInfo = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<TcpConnectionInfo>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_CONNECTION_INFO,
            (&raw mut info).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Duration::from_millis(u64::from(info.tcpi_rttcur)))
}

#[cfg(target_os = "macos")]
fn break_tcp_conns_impl() -> io::Result<usize> {
    let mut matched = 0usize;
    for fd in 0..1000i32 {
        let mut info: TcpConnectionInfo = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<TcpConnectionInfo>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_CONNECTION_INFO,
                (&raw mut info).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        if ret == 0 {
            matched += 1;
            let rc = unsafe { libc::close(fd) };
            if rc != 0 {
                eprintln!("debug: closed TCP fd {fd}: {}", io::Error::last_os_error());
            } else {
                eprintln!("debug: closed TCP fd {fd}: ok");
            }
        }
    }
    if matched == 0 {
        eprintln!("debug: no TCP connections found");
    }
    Ok(matched)
}

/// `struct tcp_connection_info` from `<netinet/tcp.h>` (macOS).
///
/// Only the first ~52 bytes (through `tcpi_rttcur` at offset 40) are
/// semantically important for RTT extraction; the full struct is declared
/// faithfully to match the kernel ABI.
#[cfg(target_os = "macos")]
#[repr(C)]
struct TcpConnectionInfo {
    tcpi_state: u8,
    tcpi_snd_wscale: u8,
    tcpi_rcv_wscale: u8,
    __pad1: u8,
    tcpi_options: u32,
    tcpi_flags: u32,
    tcpi_rto: u32,
    tcpi_maxseg: u32,
    tcpi_snd_ssthresh: u32,
    tcpi_snd_cwnd: u32,
    tcpi_snd_wnd: u32,
    tcpi_snd_sbbytes: u32,
    tcpi_rcv_wnd: u32,
    tcpi_rttcur: u32,
    tcpi_srtt: u32,
    tcpi_rttvar: u32,
    tcpi_tfo_flags: u32,
    tcpi_txpackets: u64,
    tcpi_txbytes: u64,
    tcpi_txretransmitbytes: u64,
    tcpi_rxpackets: u64,
    tcpi_rxbytes: u64,
    tcpi_rxoutoforderbytes: u64,
    tcpi_txretransmitpackets: u64,
}

// ---------------------------------------------------------------------------
// Linux — getsockopt TCP_INFO
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn rtt_impl(fd: RawFd) -> io::Result<Duration> {
    let mut info: TcpInfo = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<TcpInfo>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&raw mut info).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Duration::from_micros(u64::from(info.rtt)))
}

/// `struct tcp_info` from `<linux/tcp.h>`.
///
/// Only the first ~68 bytes (through `rtt` at offset 68) are needed.
#[cfg(target_os = "linux")]
#[repr(C)]
struct TcpInfo {
    state: u8,
    ca_state: u8,
    retransmits: u8,
    probes: u8,
    backoff: u8,
    options: u8,
    wscale: u8,
    __pad: u8,
    rto: u32,
    ato: u32,
    snd_mss: u32,
    rcv_mss: u32,
    unacked: u32,
    sacked: u32,
    lost: u32,
    retrans: u32,
    fackets: u32,
    last_data_sent: u32,
    last_ack_sent: u32,
    last_data_recv: u32,
    last_ack_recv: u32,
    pmtu: u32,
    rcv_ssthresh: u32,
    rtt: u32,
    rttvar: u32,
    snd_ssthresh: u32,
    snd_cwnd: u32,
}

// ---------------------------------------------------------------------------
// Unsupported platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[cfg(unix)]
fn rtt_impl(_fd: RawFd) -> io::Result<Duration> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tcpinfo: not supported on this platform",
    ))
}

#[cfg(not(target_os = "macos"))]
fn break_tcp_conns_impl() -> io::Result<usize> {
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_localhost() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let _accepted = listener.accept().unwrap();
        let _d = rtt(&stream).expect("rtt should succeed on macOS");
    }
}
