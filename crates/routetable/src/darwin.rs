//! macOS route table fetch via PF_ROUTE sysctl.
//!
//! Ports the sysctl + message iteration logic from Go's
//! `golang.org/x/net/route` (`FetchRIB`/`ParseRIB`) and
//! `routetable_bsd.go`'s `Get` function.
//!
//! Uses `sysctl` with MIB `[CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP2, 0]` to
//! fetch the routing information base, then iterates over the
//! `rt_msghdr2` records (type `RTM_GET2`) and their trailing sockaddrs.

#![allow(clippy::cast_ptr_alignment, clippy::borrow_as_ptr, clippy::ptr_as_ptr)]

use std::io;

use crate::parser::{parse_route_entry, DARWIN_CONFIG};
use crate::RouteEntry;

/// `NET_RT_DUMP2` — not in the `libc` crate on macOS; value from XNU
/// `<net/route.h>`.
const NET_RT_DUMP2: libc::c_int = 7;

/// Verify at compile time that the `rt_msghdr2` struct size matches our
/// hardcoded constant. If this fails, the parser's `RT_MSGHDR2_SIZE` needs
/// updating.
const _: () = {
    // On macOS, libc::rt_msghdr2 is available. We can't use it on non-macOS,
    // but this module is only compiled on macOS.
    assert!(
        std::mem::size_of::<libc::rt_msghdr2>() == 92,
        "rt_msghdr2 size mismatch — update RT_MSGHDR2_SIZE in parser.rs"
    );
};

/// Fetch the routing information base via sysctl.
fn fetch_rib() -> io::Result<Vec<u8>> {
    // MIB: [CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP2, 0]
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, NET_RT_DUMP2, 0];

    // First call: get the required buffer size.
    let mut needed: libc::size_t = 0;
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    if needed == 0 {
        return Ok(Vec::new());
    }

    // Second call: fetch the data.
    let mut buf = vec![0u8; needed];
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(needed);
    Ok(buf)
}

/// Resolve an interface index to a name via `if_indextoname`.
fn iface_name(index: u32) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut buf = [0i8; libc::IF_NAMESIZE];
    let ret = unsafe { libc::if_indextoname(index as libc::c_uint, buf.as_mut_ptr()) };
    if ret.is_null() {
        return None;
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(ret) };
    c_str.to_str().ok().map(str::to_string)
}

/// Fetch route entries from the system route table, limited to at most `max`
/// results.
pub(crate) fn get_route_table(max: usize) -> io::Result<Vec<RouteEntry>> {
    let rib = fetch_rib()?;

    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + 4 <= rib.len() {
        // Each message starts with rtm_msglen (u16, native endian).
        let msg_len = u16::from_ne_bytes([rib[offset], rib[offset + 1]]) as usize;
        if msg_len == 0 || offset + msg_len > rib.len() {
            break;
        }
        let msg = &rib[offset..offset + msg_len];
        if let Some(entry) = parse_route_entry(msg, DARWIN_CONFIG, iface_name)? {
            entries.push(entry);
            if entries.len() >= max {
                break;
            }
        }
        offset += msg_len;
    }

    Ok(entries)
}
