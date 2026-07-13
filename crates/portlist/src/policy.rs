//! Service policy: decides which ports are "interesting" enough to report
//! in `Hostinfo.Services`.
//!
//! Mirrors Go's `portlist` filter logic:
//! - peerAPI services (`peerapi4`, `peerapi6`, `peerapi-dns-proxy`) are always
//!   interesting.
//! - Non-TCP services are dropped (UDP ports are not reported to control).
//! - On non-Windows: all TCP ports are kept.
//! - On Windows: only specific well-known ports are reported.

/// Returns `true` if a service with the given protocol and port should be
/// included in `Hostinfo.Services`.
pub fn is_interesting_service(proto: &str, port: u16) -> bool {
    if proto == "peerapi4" || proto == "peerapi6" || proto == "peerapi-dns-proxy" {
        return true;
    }
    if proto != "tcp" {
        return false;
    }
    if cfg!(target_os = "windows") {
        const INTERESTING_WINDOWS_PORTS: &[u16] =
            &[22, 80, 443, 3389, 5900, 32400, 8000, 8080, 8443, 8888];
        return INTERESTING_WINDOWS_PORTS.contains(&port);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peerapi_always_interesting() {
        assert!(is_interesting_service("peerapi4", 12345));
        assert!(is_interesting_service("peerapi6", 12345));
        assert!(is_interesting_service("peerapi-dns-proxy", 12345));
    }

    #[test]
    fn test_udp_dropped() {
        assert!(!is_interesting_service("udp", 53));
        assert!(!is_interesting_service("udp", 8080));
    }

    #[test]
    fn test_tcp_non_windows() {
        if !cfg!(target_os = "windows") {
            assert!(is_interesting_service("tcp", 22));
            assert!(is_interesting_service("tcp", 8080));
            assert!(is_interesting_service("tcp", 9999));
        }
    }
}
