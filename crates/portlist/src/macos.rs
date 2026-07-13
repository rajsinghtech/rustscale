//! macOS port scanning via `netstat` (port discovery) and `lsof` (process names).
//!
//! `netstat -na` is ~100x faster than `lsof`, so we use it for the initial
//! port scan. `lsof` is only spawned for process-name resolution on
//! newly-detected ports.
//!
//! On macOS sandbox (App Store), `lsof` may fail silently — we cache the
//! failure and skip process-name fetching thereafter.

use crate::Port;
use std::collections::HashMap;
use tokio::process::Command;

/// Cached process-name lookup: `(proto, port) -> (process, pid)`.
type PidCache = HashMap<(String, u16), (String, u32)>;

/// Whether `lsof` has failed (sandbox) — skip process-name fetching if so.
static LSOF_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Parse `netstat -na` output to extract listening TCP/UDP ports.
///
/// Example TCP lines:
/// ```text
/// tcp4       0      0  127.0.0.1.8080         *.*                    LISTEN
/// tcp6       0      0  ::1.8080               *.*                    LISTEN
/// ```
/// Example UDP lines:
/// ```text
/// udp4       0      0  *.53                   *.*
/// udp6       0      0  ::.53                  *.*
/// ```
fn parse_netstat_line(line: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let proto = parts[0];
    let local = parts[3];

    // TCP: check for LISTEN state (parts[5] or parts[6]).
    if proto.starts_with("tcp") {
        let state_idx = if parts.len() > 6 { 6 } else { 5 };
        if parts.get(state_idx).copied() != Some("LISTEN") {
            return None;
        }
    } else if !proto.starts_with("udp") {
        return None;
    }

    let (is_v6, proto_name) = if proto.starts_with("tcp4") {
        (false, "tcp")
    } else if proto.starts_with("tcp6") {
        (true, "tcp")
    } else if proto.starts_with("udp4") {
        (false, "udp")
    } else if proto.starts_with("udp6") {
        (true, "udp")
    } else {
        return None;
    };

    // Local address format: "IP.port" (e.g. "127.0.0.1.8080" or "*.53" or "::1.8080")
    let port = parse_netstat_addr_port(local, is_v6)?;
    Some((proto_name.to_string(), port))
}

/// Extract the port from a netstat local address like "127.0.0.1.8080" or "*.53".
fn parse_netstat_addr_port(addr: &str, is_v6: bool) -> Option<u16> {
    // IPv6 addresses contain colons, e.g. "::1.8080" — the port is after the
    // last dot.
    // IPv4: "A.B.C.D.port" — port is after the last dot.
    // Wildcard: "*.port"
    if is_v6 {
        // For IPv6, the format is "addr.port" where addr contains colons.
        // Split on the last dot.
        let last_dot = addr.rfind('.')?;
        let port_str = &addr[last_dot + 1..];
        port_str.parse::<u16>().ok()
    } else {
        let last_dot = addr.rfind('.')?;
        let port_str = &addr[last_dot + 1..];
        port_str.parse::<u16>().ok()
    }
}

/// Scan listening ports via `netstat -na`, then resolve process names via
/// `lsof` for newly-detected ports.
pub async fn scan_ports(include_localhost: bool) -> Vec<Port> {
    let output = match Command::new("netstat").arg("-na").output().await {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ports: Vec<(String, u16)> = Vec::new();

    for line in stdout.lines() {
        if let Some((proto, port)) = parse_netstat_line(line) {
            // Filter localhost if not included.
            if !include_localhost {
                let local = line.split_whitespace().nth(3).unwrap_or("");
                if local.starts_with("127.") || local.starts_with("::1.") {
                    continue;
                }
            }
            ports.push((proto, port));
        }
    }

    // Deduplicate by (proto, port).
    ports.sort();
    ports.dedup();

    // Resolve process names via lsof (skip if previously failed).
    let pid_map = if LSOF_FAILED.load(std::sync::atomic::Ordering::Relaxed) {
        HashMap::new()
    } else {
        resolve_pids_lsof(&ports).await
    };

    ports
        .into_iter()
        .map(|(proto, port)| {
            let (process, pid) = pid_map
                .get(&(proto.clone(), port))
                .cloned()
                .unwrap_or_default();
            Port {
                proto,
                port,
                process,
                pid,
            }
        })
        .collect()
}

/// Run `lsof -F -n -P -i4 -i6` and build `(proto, port) -> (process, pid)`.
async fn resolve_pids_lsof(ports: &[(String, u16)]) -> PidCache {
    if ports.is_empty() {
        return HashMap::new();
    }

    let Ok(output) = Command::new("lsof")
        .args(["-F", "n", "-P", "-O", "-S2", "-T", "-i4", "-i6"])
        .output()
        .await
    else {
        LSOF_FAILED.store(true, std::sync::atomic::Ordering::Relaxed);
        return HashMap::new();
    };

    if !output.status.success() {
        LSOF_FAILED.store(true, std::sync::atomic::Ordering::Relaxed);
        return HashMap::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_lsof_output(&stdout)
}

/// Parse `lsof -F` field-based output.
///
/// Fields: `p`=PID, `c`=command, `P`=protocol, `n`=address.
fn parse_lsof_output(stdout: &str) -> PidCache {
    let mut map: PidCache = HashMap::new();
    let mut current_pid: u32 = 0;
    let mut current_cmd: String = String::new();
    let mut current_proto: String = String::new();

    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let (field, value) = line.split_at(1);
        match field {
            "p" => {
                current_pid = value.parse().unwrap_or(0);
            }
            "c" => {
                current_cmd = value.to_string();
            }
            "P" => {
                current_proto = value.to_lowercase();
            }
            "n" => {
                // Address: "IP:port" for TCP, "IP->IP:port" for UDP.
                // Extract the local port.
                if let Some(port) = extract_lsof_port(value, &current_proto) {
                    let proto = if current_proto.starts_with("tcp") {
                        "tcp"
                    } else {
                        "udp"
                    };
                    map.entry((proto.to_string(), port))
                        .or_insert((current_cmd.clone(), current_pid));
                }
                // Reset for next entry.
                current_proto.clear();
            }
            _ => {}
        }
    }

    map
}

/// Extract the local port from an lsof address field.
fn extract_lsof_port(addr: &str, proto: &str) -> Option<u16> {
    // TCP: "127.0.0.1:8080" or "[::1]:8080"
    // UDP: "127.0.0.1:53" or "*:*"
    if addr.contains("->") {
        // Connected socket — skip (we only want listening).
        return None;
    }

    if proto.starts_with("tcp") || proto.starts_with("udp") {
        let port = addr.rsplit(':').next()?;
        if port == "*" {
            return None;
        }
        port.parse::<u16>().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_netstat_tcp_listen() {
        let line = "tcp4       0      0  127.0.0.1.8080         *.*                    LISTEN";
        let (proto, port) = parse_netstat_line(line).unwrap();
        assert_eq!(proto, "tcp");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_netstat_tcp6_listen() {
        let line = "tcp6       0      0  ::1.8080               *.*                    LISTEN";
        let (proto, port) = parse_netstat_line(line).unwrap();
        assert_eq!(proto, "tcp");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_netstat_udp() {
        let line = "udp4       0      0  *.53                   *.*";
        let (proto, port) = parse_netstat_line(line).unwrap();
        assert_eq!(proto, "udp");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_netstat_non_listen_tcp() {
        let line = "tcp4       0      0  127.0.0.1.8080         10.0.0.1.443           ESTABLISHED";
        assert!(parse_netstat_line(line).is_none());
    }

    #[test]
    fn test_parse_netstat_addr_port_wildcard() {
        assert_eq!(parse_netstat_addr_port("*.53", false), Some(53));
    }

    #[test]
    fn test_parse_netstat_addr_port_ipv4() {
        assert_eq!(parse_netstat_addr_port("127.0.0.1.8080", false), Some(8080));
    }

    #[test]
    fn test_parse_netstat_addr_port_ipv6() {
        assert_eq!(parse_netstat_addr_port("::1.8080", true), Some(8080));
    }

    #[test]
    fn test_extract_lsof_port_tcp() {
        assert_eq!(extract_lsof_port("127.0.0.1:8080", "tcp"), Some(8080));
    }

    #[test]
    fn test_extract_lsof_port_connected() {
        assert!(extract_lsof_port("127.0.0.1:8080->10.0.0.1:443", "tcp").is_none());
    }

    #[test]
    fn test_extract_lsof_port_wildcard() {
        assert!(extract_lsof_port("*:*", "tcp").is_none());
    }

    #[test]
    fn test_parse_lsof_output() {
        let output = "p1234\nctestproc\nPtcp4\nn127.0.0.1:8080\np5678\ncnother\nPudp4\nn*:53\n";
        let map = parse_lsof_output(output);
        assert_eq!(
            map.get(&("tcp".to_string(), 8080)),
            Some(&("testproc".to_string(), 1234))
        );
        assert_eq!(
            map.get(&("udp".to_string(), 53)),
            Some(&("nother".to_string(), 5678))
        );
    }
}
