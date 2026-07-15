//! Linux port scanning via `/proc/net/tcp{,6}` and `/proc/net/udp{,6}`.
//!
//! The `/proc/net/tcp` file format (one entry per line after the header):
//! ```text
//!   sl  local_address rem_address   st tx_queue rx_queue ...
//!    0: 0100007F:1F90 00000000:0000 0A ...
//! ```
//! - `local_address`: hex `AABBCCDD:PPPP` — IPv4 in little-endian, port in hex.
//!   `0100007F` = 127.0.0.1, `1F90` = 8080.
//! - `st`: hex state. `0A` = LISTEN (TCP).
//! - For UDP, listening = remote address all zeros.
//!
//! IPv6 (`/proc/net/tcp6`): 32 hex chars for the address (four 32-bit
//! little-endian groups).

use crate::Port;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// TCP LISTEN state in /proc/net/tcp.
const TCP_LISTEN: u8 = 10;

/// Parse a `/proc/net/tcp` or `/proc/net/udp` line into
/// `(local_ip, local_port, state, inode)`.
///
/// Returns `None` for the header line or malformed entries.
fn parse_proc_line(line: &str) -> Option<(IpAddr, u16, u8, u64)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("sl") {
        return None;
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let local = parts[1];
    let state = u8::from_str_radix(parts[3], 16).ok()?;
    let inode: u64 = parts[9].parse().ok()?;

    let (ip, port) = parse_hex_addr(local)?;
    Some((ip, port, state, inode))
}

/// Parse a `/proc/net/tcp6` or `/proc/net/udp6` line (32-char hex address).
fn parse_proc6_line(line: &str) -> Option<(IpAddr, u16, u8, u64)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("sl") {
        return None;
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let local = parts[1];
    let state = u8::from_str_radix(parts[3], 16).ok()?;
    let inode: u64 = parts[9].parse().ok()?;

    let (ip, port) = parse_hex6_addr(local)?;
    Some((ip, port, state, inode))
}

/// Parse `AABBCCDD:PPPP` (IPv4 little-endian + hex port).
fn parse_hex_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = s.split_once(':')?;
    if addr.len() != 8 {
        return None;
    }
    let bytes = hex_decode(addr)?;
    let ip = Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]);
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((IpAddr::V4(ip), port))
}

/// Parse 32-char hex IPv6 address + `:PPPP` port.
///
/// `/proc/net/tcp6` stores IPv6 as four 32-bit little-endian groups.
fn parse_hex6_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = s.split_once(':')?;
    if addr.len() != 32 {
        return None;
    }
    let bytes = hex_decode(addr)?;
    let mut ipv6 = [0u8; 16];
    for i in 0..4 {
        let base = i * 4;
        ipv6[base] = bytes[base + 3];
        ipv6[base + 1] = bytes[base + 2];
        ipv6[base + 2] = bytes[base + 1];
        ipv6[base + 3] = bytes[base];
    }
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((IpAddr::V6(Ipv6Addr::from(ipv6)), port))
}

fn is_localhost(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Scan `/proc/net/{tcp,tcp6,udp,udp6}` for listening ports, then walk
/// `/proc/*/fd/` to resolve process names.
// Keep the same async API as the other platform implementations and callers.
#[allow(clippy::unused_async)]
pub async fn scan_ports(include_localhost: bool) -> Vec<Port> {
    let mut raw: Vec<(String, u16, u64)> = Vec::new();

    for (path, proto, is_v6) in [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp", true),
    ] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let parsed = if is_v6 {
                    parse_proc6_line(line)
                } else {
                    parse_proc_line(line)
                };
                let Some((ip, port, state, inode)) = parsed else {
                    continue;
                };

                if proto == "tcp" {
                    if state != TCP_LISTEN {
                        continue;
                    }
                } else if inode == 0 {
                    continue;
                }

                if !include_localhost && is_localhost(ip) {
                    continue;
                }

                raw.push((proto.to_string(), port, inode));
            }
        }
    }

    let inodes: Vec<u64> = raw.iter().map(|(_, _, inode)| *inode).collect();
    let pid_map = resolve_pids(&inodes);

    raw.into_iter()
        .map(|(proto, port, inode)| {
            let (process, pid) = pid_map.get(&inode).cloned().unwrap_or_default();
            Port {
                proto,
                port,
                process,
                pid,
            }
        })
        .collect()
}

/// Walk `/proc/*/fd/` to build `inode -> (process_name, pid)` map.
fn resolve_pids(inodes: &[u64]) -> HashMap<u64, (String, u32)> {
    let mut map: HashMap<u64, (String, u32)> = HashMap::new();
    let inode_set: std::collections::HashSet<u64> = inodes.iter().copied().collect();
    if inode_set.is_empty() {
        return map;
    }

    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                let link_str = link.to_string_lossy().to_string();
                if let Some(stripped) = link_str
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                {
                    if let Ok(inode) = stripped.parse::<u64>() {
                        if inode_set.contains(&inode) && !map.contains_key(&inode) {
                            let cmdline_path = format!("/proc/{pid}/cmdline");
                            let process = fs::read(&cmdline_path)
                                .ok()
                                .and_then(|raw| {
                                    let null_pos = raw.iter().position(|&b| b == 0)?;
                                    Some(String::from_utf8_lossy(&raw[..null_pos]).to_string())
                                })
                                .unwrap_or_default();
                            map.insert(inode, (process, pid));
                        }
                    }
                }
            }
        }
    }

    map
}

/// Minimal hex decoder (avoids pulling in a hex crate dependency).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in bytes.chunks(2) {
        out.push(hex_byte(chunk[0])? * 16 + hex_byte(chunk[1])?);
    }
    Some(out)
}

fn hex_byte(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_addr_v4() {
        let (ip, port) = parse_hex_addr("0100007F:1F90").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_hex_addr_zero() {
        let (ip, port) = parse_hex_addr("00000000:0050").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_hex6_addr_loopback() {
        let (ip, port) = parse_hex6_addr("00000000000000000000000001000000:0035").unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_proc6_line_listen() {
        let line = "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        let (ip, port, state, inode) = parse_proc6_line(line).unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(port, 8080);
        assert_eq!(state, TCP_LISTEN);
        assert_eq!(inode, 12345);
    }

    #[test]
    fn test_parse_proc_line_header() {
        assert!(parse_proc_line("  sl  local_address rem_address   st").is_none());
    }

    #[test]
    fn test_parse_proc_line_listen() {
        let line = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        let (ip, port, state, inode) = parse_proc_line(line).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(port, 8080);
        assert_eq!(state, TCP_LISTEN);
        assert_eq!(inode, 12345);
    }

    #[test]
    fn test_parse_proc_line_non_listen() {
        let line = "   1: 0100007F:1F90 0200007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 100 0 0 10 0";
        let (_ip, _port, state, _inode) = parse_proc_line(line).unwrap();
        assert_ne!(state, TCP_LISTEN);
    }

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_localhost(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_localhost(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(
            hex_decode("0100007F").unwrap(),
            vec![0x01, 0x00, 0x00, 0x7F]
        );
        assert_eq!(hex_decode("1F90").unwrap(), vec![0x1F, 0x90]);
        assert!(hex_decode("XYZ").is_none());
    }

    #[test]
    fn test_parse_proc_content_filters_localhost() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 100 0 0 10 0\n";
        let mut found = Vec::new();
        for line in content.lines() {
            if let Some((ip, port, state, _)) = parse_proc_line(line) {
                if state == TCP_LISTEN && !is_localhost(ip) {
                    found.push(port);
                }
            }
        }
        assert_eq!(found, vec![80]);
    }

    #[test]
    fn test_parse_proc_content_includes_localhost() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n";
        let mut found = Vec::new();
        for line in content.lines() {
            if let Some((ip, port, state, _)) = parse_proc_line(line) {
                if state == TCP_LISTEN && is_localhost(ip) {
                    found.push(port);
                }
            }
        }
        assert_eq!(found, vec![8080]);
    }
}
