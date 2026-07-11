//! Platform-specific interface metadata: index, MTU, flags, hardware MAC.
//!
//! Uses libc `getifaddrs` + `ioctl` to gather data not exposed by the
//! `if_addrs` crate. Falls back to defaults (index 0, MTU 0, flags 0, no
//! MAC) on platforms where the syscalls are unavailable or fail.

#![allow(
    clippy::cast_ptr_alignment,
    clippy::borrow_as_ptr,
    clippy::ptr_as_ptr
)]

use std::collections::HashMap;

/// Extended interface details not available from `if_addrs`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct InterfaceDetails {
    pub index: u32,
    pub mtu: u32,
    pub flags: u32,
    pub hw_addr: Option<[u8; 6]>,
}

/// Gather extended interface metadata for all interfaces on the system.
pub(crate) fn gather_interface_details() -> HashMap<String, InterfaceDetails> {
    gather_interface_details_impl()
}

/// On macOS, `SIOCGIFMTU` is not exposed by the `libc` crate. We read
/// the MTU from `ifa_data` (points to `struct if_data`) where `ifi_mtu`
/// is at byte offset 8 (after 8 `u_char` fields).
#[cfg(target_os = "macos")]
const IF_DATA_MTU_OFFSET: usize = 8;

#[cfg(target_os = "macos")]
fn gather_interface_details_impl() -> HashMap<String, InterfaceDetails> {
    use std::ffi::CStr;

    let mut result: HashMap<String, InterfaceDetails> = HashMap::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(std::ptr::addr_of_mut!(ifap)) != 0 {
            return result;
        }

        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            let name_ptr = ifa.ifa_name;
            if name_ptr.is_null() {
                cur = ifa.ifa_next;
                continue;
            }
            let name = if let Ok(s) = CStr::from_ptr(name_ptr).to_str() {
                s.to_string()
            } else {
                cur = ifa.ifa_next;
                continue;
            };

            let entry = result
                .entry(name.clone())
                .or_insert_with(|| InterfaceDetails {
                    flags: ifa.ifa_flags,
                    ..Default::default()
                });

            if ifa.ifa_flags != 0 {
                entry.flags = ifa.ifa_flags;
            }

            if !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                if u32::from(sa.sa_family) == libc::AF_LINK as u32 {
                    let sdl = &*(ifa.ifa_addr as *const libc::sockaddr_dl);
                    entry.index = u32::from(sdl.sdl_index);
                    let alen = sdl.sdl_alen as usize;
                    if alen == 6 {
                        let nlen = sdl.sdl_nlen as usize;
                        if nlen + 6 <= sdl.sdl_data.len() {
                            let mut mac = [0u8; 6];
                            let data_ptr = sdl.sdl_data.as_ptr().cast::<u8>();
                            std::ptr::copy_nonoverlapping(
                                data_ptr.add(nlen),
                                mac.as_mut_ptr(),
                                6,
                            );
                            entry.hw_addr = Some(mac);
                        }
                    }
                }
            }

            if entry.mtu == 0 && !ifa.ifa_data.is_null() {
                let mtu_ptr = (ifa.ifa_data as *const u8)
                    .add(IF_DATA_MTU_OFFSET)
                    .cast::<u32>();
                entry.mtu = *mtu_ptr;
            }

            if entry.index == 0 {
                if let Ok(cname) = std::ffi::CString::new(name.as_str()) {
                    let idx = libc::if_nametoindex(cname.as_ptr());
                    if idx != 0 {
                        entry.index = idx;
                    }
                }
            }

            cur = ifa.ifa_next;
        }

        libc::freeifaddrs(ifap);
    }

    result
}

#[cfg(target_os = "linux")]
fn gather_interface_details_impl() -> HashMap<String, InterfaceDetails> {
    use std::ffi::CStr;
    use std::mem;

    let mut result: HashMap<String, InterfaceDetails> = HashMap::new();

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let have_fd = fd >= 0;

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(std::ptr::addr_of_mut!(ifap)) != 0 {
            if have_fd {
                libc::close(fd);
            }
            return result;
        }

        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            let name_ptr = ifa.ifa_name;
            if name_ptr.is_null() {
                cur = ifa.ifa_next;
                continue;
            }
            let name = if let Ok(s) = CStr::from_ptr(name_ptr).to_str() {
                s.to_string()
            } else {
                cur = ifa.ifa_next;
                continue;
            };

            let entry = result
                .entry(name.clone())
                .or_insert_with(|| InterfaceDetails {
                    flags: ifa.ifa_flags,
                    ..Default::default()
                });

            if ifa.ifa_flags != 0 {
                entry.flags = ifa.ifa_flags;
            }

            if !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                if u32::from(sa.sa_family) == libc::AF_PACKET as u32 {
                    let sll = &*(ifa.ifa_addr as *const libc::sockaddr_ll);
                    entry.index = sll.sll_ifindex as u32;
                    let halen = sll.sll_halen as usize;
                    if halen == 6 {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&sll.sll_addr[..6]);
                        entry.hw_addr = Some(mac);
                    }
                }
            }

            if entry.mtu == 0 && have_fd {
                let mut ifr: libc::ifreq = mem::zeroed();
                let name_bytes = name.as_bytes();
                let copy_len = name_bytes.len().min(ifr.ifr_name.len() - 1);
                for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
                    ifr.ifr_name[i] = b as libc::c_char;
                }
                if libc::ioctl(fd, libc::SIOCGIFMTU, &mut ifr as *mut libc::ifreq) == 0 {
                    entry.mtu = ifr.ifr_ifru.ifru_mtu as u32;
                }
            }

            if entry.index == 0 {
                if let Ok(cname) = std::ffi::CString::new(name.as_str()) {
                    let idx = libc::if_nametoindex(cname.as_ptr());
                    if idx != 0 {
                        entry.index = idx;
                    }
                }
            }

            cur = ifa.ifa_next;
        }

        libc::freeifaddrs(ifap);
    }

    if have_fd {
        unsafe {
            libc::close(fd);
        }
    }

    result
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn gather_interface_details_impl() -> HashMap<String, InterfaceDetails> {
    HashMap::new()
}
