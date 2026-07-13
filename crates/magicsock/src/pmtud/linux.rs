//! Linux PMTUD via IP_MTU_DISCOVER / IP_PMTUDISC_DO.
//! Mirrors Go's peermtu_linux.go.
//!
//! IPPROTO_IP + IP_MTU_DISCOVER = IP_PMTUDISC_DO (enable) / IP_PMTUDISC_DONT (disable)
//! IPPROTO_IPV6 + IPV6_MTU_DISCOVER = same values

#![allow(unsafe_code)]

use std::io;
use std::os::unix::io::RawFd;

use crate::pmtud::platform::{conn_control, ip_proto};

/// Return the socket option name for the given network.
fn dont_frag_opt(network: &str) -> i32 {
    if network == "udp4" {
        libc::IP_MTU_DISCOVER
    } else {
        libc::IPV6_MTU_DISCOVER
    }
}

/// Enable/disable DF on a UDP socket for the given network (udp4/udp6).
pub(crate) fn set_dont_fragment(fd: RawFd, network: &str, enable: bool) -> Result<(), SetDfError> {
    let opt_arg: libc::c_int = if enable {
        libc::IP_PMTUDISC_DO
    } else {
        libc::IP_PMTUDISC_DONT
    };
    let proto = ip_proto(network);
    let opt = dont_frag_opt(network);
    let mut err: Option<io::Error> = None;
    conn_control(fd, &mut |fd| {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                proto,
                opt,
                std::ptr::addr_of!(opt_arg).cast::<libc::c_void>(),
                std::mem::size_of_val(&opt_arg) as libc::socklen_t,
            )
        };
        if ret != 0 {
            err = Some(io::Error::last_os_error());
        }
    })
    .map_err(|_| SetDfError::Unsupported)?;
    if let Some(e) = err {
        return Err(SetDfError::Io(e));
    }
    Ok(())
}

/// Query the DF bit state on a socket. Returns `true` if DF is set.
pub(crate) fn get_dont_fragment(fd: RawFd, network: &str) -> Result<bool, SetDfError> {
    let proto = ip_proto(network);
    let opt = dont_frag_opt(network);
    let mut val: libc::c_int = 0;
    let mut err: Option<io::Error> = None;
    conn_control(fd, &mut |fd| {
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                proto,
                opt,
                std::ptr::addr_of_mut!(val).cast::<libc::c_void>(),
                std::ptr::addr_of_mut!(len),
            )
        };
        if ret != 0 {
            err = Some(io::Error::last_os_error());
        }
    })
    .map_err(|_| SetDfError::Unsupported)?;
    if let Some(e) = err {
        return Err(SetDfError::Io(e));
    }
    Ok(val == libc::IP_PMTUDISC_DO)
}

/// Error from set/get dont-fragment operations.
#[derive(Debug, thiserror::Error)]
pub enum SetDfError {
    #[error("unsupported connection type")]
    Unsupported,
    #[error("setsockopt failed: {0}")]
    Io(#[from] io::Error),
}
