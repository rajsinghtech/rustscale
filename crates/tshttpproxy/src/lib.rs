#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
use std::process::Command;
use std::{
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::Instant,
};
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum TsHttpProxyError {
    #[error("failed to parse proxy URL: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("platform proxy detection failed: {0}")]
    PlatformDetection(String),

    #[error("proxy IO: {0}")]
    Io(#[from] std::io::Error),

    #[error("proxy CONNECT failed: {0}")]
    ConnectFailed(String),
}

mod connect;
pub use connect::http_connect;

static NO_PROXY_UNTIL: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
static SELF_PROXY_ADDRS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

fn no_proxy_until_lock() -> &'static Mutex<Option<Instant>> {
    NO_PROXY_UNTIL.get_or_init(|| Mutex::new(None))
}

fn self_proxy_addrs_lock() -> &'static Mutex<Vec<String>> {
    SELF_PROXY_ADDRS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn invalidate_cache() {
    *no_proxy_until_lock().lock().unwrap() = None;
}

pub fn set_self_proxy(addrs: &[String]) {
    let mut self_addrs = self_proxy_addrs_lock().lock().unwrap();
    self_addrs.clear();
    for addr in addrs {
        self_addrs.push(normalize_host_port(addr));
    }
}

fn normalize_host_port(addr: &str) -> String {
    let addr = addr.strip_prefix("http://").unwrap_or(addr);
    let addr = addr.strip_prefix("https://").unwrap_or(addr);
    let (host, port) = match split_host_port(addr) {
        Some(hp) => hp,
        None => return addr.to_string(),
    };
    match host {
        "127.0.0.1" | "::1" => format!("localhost:{}", port),
        _ if host.starts_with("127.0.0.") && cfg!(target_os = "linux") => {
            format!("localhost:{}", port)
        }
        _ => addr.to_string(),
    }
}

fn split_host_port(s: &str) -> Option<(&str, u16)> {
    let s = s.trim_start_matches('[');
    if let Some(bracket_end) = s.find(']') {
        let host = s[..bracket_end].trim();
        let rest = s[bracket_end + 1..].trim();
        if let Some(port_str) = rest.strip_prefix(':') {
            let port: u16 = port_str.parse().ok()?;
            Some((host, port))
        } else {
            None
        }
    } else if let Some(idx) = s.rfind(':') {
        let host = s[..idx].trim();
        let port_str = s[idx + 1..].trim();
        let port: u16 = port_str.parse().ok()?;
        Some((host, port))
    } else {
        None
    }
}

fn is_self_proxy(proxy_str: &str) -> bool {
    let normalized = normalize_host_port(proxy_str);
    let self_addrs = self_proxy_addrs_lock().lock().unwrap();
    self_addrs.contains(&normalized)
}

fn is_no_proxy(host: &str, port: Option<u16>) -> bool {
    let no_proxy = std::env::var("no_proxy")
        .or_else(|_| std::env::var("NO_PROXY"))
        .unwrap_or_default();
    if no_proxy.is_empty() {
        return false;
    }
    let entries: Vec<&str> = no_proxy
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.is_empty() {
        return false;
    }
    if entries.contains(&"*") {
        return true;
    }
    for entry in &entries {
        if match_no_proxy_entry(entry, host, port) {
            return true;
        }
    }
    false
}

fn match_no_proxy_entry(entry: &str, host: &str, port: Option<u16>) -> bool {
    if entry == "*" {
        return true;
    }
    let (entry_host, entry_port) = parse_no_proxy_entry(entry);
    if let Some(ep) = entry_port {
        if let Some(p) = port {
            if ep != p {
                return false;
            }
        }
    }
    if entry_host.contains('/') {
        return match_cidr(entry_host, host);
    }
    if entry_host == host {
        return true;
    }
    if let Some(rest) = entry_host.strip_prefix('.') {
        if host == rest || host.ends_with(&format!(".{rest}")) {
            return true;
        }
    } else if host.ends_with(&format!(".{entry_host}")) {
        return true;
    }
    if let Ok(entry_ip) = entry_host.parse::<IpAddr>() {
        if let Ok(host_ip) = host.parse::<IpAddr>() {
            return entry_ip == host_ip;
        }
    }
    false
}

fn parse_no_proxy_entry(entry: &str) -> (&str, Option<u16>) {
    if entry.starts_with('[') {
        if let Some(bracket_end) = entry.find(']') {
            let host = &entry[1..bracket_end];
            let rest = entry[bracket_end + 1..].trim();
            if let Some(port_str) = rest.strip_prefix(':') {
                if let Ok(port) = port_str.parse() {
                    return (host, Some(port));
                }
            }
            return (host, None);
        }
    }
    if entry.contains(':') && !entry.contains("::") {
        if let Some(idx) = entry.rfind(':') {
            if let Ok(port) = entry[idx + 1..].parse::<u16>() {
                return (&entry[..idx], Some(port));
            }
        }
    }
    (entry, None)
}

fn match_cidr(cidr: &str, host: &str) -> bool {
    let (ip_str, bits_str) = match cidr.split_once('/') {
        Some(pair) => pair,
        None => return false,
    };
    let bits: u8 = match bits_str.parse() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let host_ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let cidr_ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match (cidr_ip, host_ip) {
        (IpAddr::V4(cidr_v4), IpAddr::V4(host_v4)) => {
            if bits > 32 {
                return false;
            }
            let mask = if bits == 0 {
                0u32
            } else {
                u32::MAX << (32 - bits)
            };
            let cidr_bits = u32::from(cidr_v4);
            let host_bits = u32::from(host_v4);
            (cidr_bits & mask) == (host_bits & mask)
        }
        (IpAddr::V6(cidr_v6), IpAddr::V6(host_v6)) => {
            if bits > 128 {
                return false;
            }
            let mask = if bits == 0 {
                0u128
            } else {
                u128::MAX << (128 - bits)
            };
            let cidr_bits = u128::from(cidr_v6);
            let host_bits = u128::from(host_v6);
            (cidr_bits & mask) == (host_bits & mask)
        }
        _ => false,
    }
}

pub fn proxy_from_environment(url: &Url) -> Result<Option<Url>, TsHttpProxyError> {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or("");
    let port = url.port();
    let proxy_var = match scheme {
        "https" => std::env::var("https_proxy")
            .or_else(|_| std::env::var("HTTPS_PROXY"))
            .ok(),
        "http" => std::env::var("http_proxy")
            .or_else(|_| std::env::var("HTTP_PROXY"))
            .ok(),
        _ => None,
    };
    if let Some(proxy_str) = proxy_var {
        if proxy_str.is_empty() {
            return Ok(None);
        }
        if is_no_proxy(host, port) {
            return Ok(None);
        }
        if is_self_proxy(&proxy_str) {
            return Ok(None);
        }
        let proxy_url = if proxy_str.contains("://") {
            Url::parse(&proxy_str)?
        } else {
            Url::parse(&format!("http://{proxy_str}"))?
        };
        return Ok(Some(proxy_url));
    }
    platform_sys_proxy(url)
}

pub fn platform_sys_proxy(url: &Url) -> Result<Option<Url>, TsHttpProxyError> {
    {
        let guard = no_proxy_until_lock().lock().unwrap();
        if let Some(deadline) = *guard {
            if Instant::now() < deadline {
                return Ok(None);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        macos_sys_proxy(url)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = url;
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
fn macos_sys_proxy(url: &Url) -> Result<Option<Url>, TsHttpProxyError> {
    let output = Command::new("/usr/sbin/scutil")
        .arg("--proxy")
        .output()
        .map_err(|e| TsHttpProxyError::PlatformDetection(format!("failed to run scutil: {e}")))?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let scheme_upper = url.scheme().to_uppercase();
    let enable_key = format!("{scheme_upper}Enable");
    let proxy_key = format!("{scheme_upper}Proxy");
    let port_key = format!("{scheme_upper}Port");
    let mut enabled = false;
    let mut proxy_host = String::new();
    let mut proxy_port = 0u16;
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with(&enable_key) {
            if let Some(val) = line.split(':').nth(1) {
                enabled = val.trim() == "1";
            }
        } else if line.starts_with(&proxy_key) {
            if let Some(val) = line.split(':').nth(1) {
                proxy_host = val.trim().trim_matches('"').to_string();
            }
        } else if line.starts_with(&port_key) {
            if let Some(val) = line.split(':').nth(1) {
                proxy_port = val.trim().parse().unwrap_or(0);
            }
        }
    }
    if enabled && !proxy_host.is_empty() && proxy_port > 0 {
        Ok(Some(Url::parse(&format!(
            "http://{proxy_host}:{proxy_port}"
        ))?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn test_no_proxy_wildcard() {
        assert!(match_no_proxy_entry("*", "example.com", None));
    }

    #[test]
    fn test_no_proxy_exact_domain() {
        assert!(match_no_proxy_entry("example.com", "example.com", None));
    }

    #[test]
    fn test_no_proxy_exact_not_matching() {
        assert!(!match_no_proxy_entry("example.com", "other.com", None));
    }

    #[test]
    fn test_no_proxy_subdomain() {
        assert!(match_no_proxy_entry("example.com", "sub.example.com", None));
    }

    #[test]
    fn test_no_proxy_dot_prefix_match() {
        assert!(match_no_proxy_entry(".example.com", "example.com", None));
        assert!(match_no_proxy_entry(
            ".example.com",
            "sub.example.com",
            None
        ));
    }

    #[test]
    fn test_no_proxy_dot_prefix_no_match() {
        assert!(!match_no_proxy_entry(".example.com", "other.com", None));
    }

    #[test]
    fn test_no_proxy_ip_exact() {
        assert!(match_no_proxy_entry("192.168.1.1", "192.168.1.1", None));
    }

    #[test]
    fn test_no_proxy_ip_no_match() {
        assert!(!match_no_proxy_entry("192.168.1.1", "192.168.1.2", None));
    }

    #[test]
    fn test_no_proxy_cidr_v4() {
        assert!(match_no_proxy_entry(
            "192.168.1.0/24",
            "192.168.1.100",
            None
        ));
        assert!(!match_no_proxy_entry("192.168.1.0/24", "192.168.2.1", None));
    }

    #[test]
    fn test_no_proxy_cidr_v6() {
        assert!(match_no_proxy_entry("2001:db8::/32", "2001:db8::1", None));
        assert!(!match_no_proxy_entry("2001:db8::/32", "2001:db9::1", None));
    }

    #[test]
    fn test_no_proxy_port_match() {
        assert!(match_no_proxy_entry(
            "127.0.0.1:8080",
            "127.0.0.1",
            Some(8080)
        ));
    }

    #[test]
    fn test_no_proxy_port_no_match() {
        assert!(!match_no_proxy_entry(
            "127.0.0.1:8080",
            "127.0.0.1",
            Some(9090)
        ));
    }

    #[test]
    fn test_no_proxy_ipv6_bracketed() {
        assert!(match_no_proxy_entry("[::1]", "::1", None));
        assert!(match_no_proxy_entry("[::1]:8080", "::1", Some(8080)));
    }

    #[test]
    fn test_no_proxy_empty_port_ignored() {
        assert!(match_no_proxy_entry("127.0.0.1", "127.0.0.1", Some(8080)));
    }

    #[test]
    fn test_no_proxy_subdomain_not_matching() {
        assert!(!match_no_proxy_entry("example.com", "notexample.com", None));
    }

    #[test]
    fn test_is_no_proxy_wildcard() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("no_proxy", "*");
        assert!(is_no_proxy("anything.com", None));
        std::env::remove_var("no_proxy");
    }

    #[test]
    fn test_is_no_proxy_multiple_entries() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("NO_PROXY", "localhost,127.0.0.1,.local");
        assert!(is_no_proxy("localhost", None));
        assert!(is_no_proxy("127.0.0.1", None));
        assert!(is_no_proxy("service.local", None));
        assert!(!is_no_proxy("external.com", None));
        std::env::remove_var("NO_PROXY");
    }

    #[test]
    fn test_is_no_proxy_empty() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("no_proxy", "");
        assert!(!is_no_proxy("example.com", None));
        std::env::remove_var("no_proxy");
    }

    #[test]
    fn test_is_no_proxy_not_set() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("no_proxy");
        std::env::remove_var("NO_PROXY");
        assert!(!is_no_proxy("example.com", None));
    }

    #[test]
    fn test_proxy_from_environment_http() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("http_proxy", "http://proxy.local:8080");
        let url = Url::parse("http://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert_eq!(result.unwrap().as_str(), "http://proxy.local:8080/");
        std::env::remove_var("http_proxy");
    }

    #[test]
    fn test_proxy_from_environment_https() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("https_proxy", "https://proxy.local:8443");
        let url = Url::parse("https://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_some_and(|u| u.as_str() == "https://proxy.local:8443/"));
        std::env::remove_var("https_proxy");
    }

    #[test]
    fn test_proxy_from_environment_uppercase() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("HTTP_PROXY", "http://upproxy:3128");
        let url = Url::parse("http://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert_eq!(result.unwrap().as_str(), "http://upproxy:3128/");
        std::env::remove_var("HTTP_PROXY");
    }

    #[test]
    fn test_proxy_from_environment_no_scheme() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("http_proxy", "10.0.0.1:3128");
        let url = Url::parse("http://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert_eq!(result.unwrap().as_str(), "http://10.0.0.1:3128/");
        std::env::remove_var("http_proxy");
    }

    #[test]
    fn test_proxy_from_environment_no_proxy_bypass() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("http_proxy", "http://proxy:8080");
        std::env::set_var("no_proxy", "example.com");
        let url = Url::parse("http://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_none());
        std::env::remove_var("http_proxy");
        std::env::remove_var("no_proxy");
    }

    #[test]
    fn test_proxy_from_environment_no_proxy_subdomain() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("HTTP_PROXY", "http://proxy:8080");
        std::env::set_var("NO_PROXY", ".internal.corp");
        let url = Url::parse("http://svc.internal.corp").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_none());
        let url2 = Url::parse("http://external.com").unwrap();
        let result2 = proxy_from_environment(&url2).unwrap();
        assert!(result2.is_some());
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("NO_PROXY");
    }

    #[test]
    fn test_proxy_from_environment_no_proxy_with_port() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("http_proxy", "http://proxy:8080");
        std::env::set_var("no_proxy", "127.0.0.1:8080");
        let url = Url::parse("http://127.0.0.1:8080").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_none());
        std::env::remove_var("http_proxy");
        std::env::remove_var("no_proxy");
    }

    #[test]
    fn test_proxy_from_environment_no_proxy_different_port() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("http_proxy", "http://proxy:8080");
        std::env::set_var("no_proxy", "127.0.0.1:9090");
        let url = Url::parse("http://127.0.0.1:8080").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_some());
        std::env::remove_var("http_proxy");
        std::env::remove_var("no_proxy");
    }

    #[test]
    fn test_proxy_from_environment_no_proxy_missing_no_proxy() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("HTTPS_PROXY", "http://proxy:8080");
        std::env::remove_var("no_proxy");
        let url = Url::parse("https://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_some());
        std::env::remove_var("HTTPS_PROXY");
    }

    #[test]
    fn test_proxy_from_environment_scheme_mismatch() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("http_proxy", "http://proxy:8080");
        let url = Url::parse("https://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_none());
        std::env::remove_var("http_proxy");
    }

    #[test]
    fn test_proxy_from_environment_self_proxy() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("http_proxy", "127.0.0.1:1234");
        set_self_proxy(&["127.0.0.1:1234".to_string()]);
        let url = Url::parse("http://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_none());
        set_self_proxy(&[]);
        std::env::remove_var("http_proxy");
    }

    #[test]
    fn test_invalidate_cache() {
        {
            let mut guard = no_proxy_until_lock().lock().unwrap();
            *guard = Some(Instant::now() + std::time::Duration::from_secs(60));
        }
        invalidate_cache();
        let guard = no_proxy_until_lock().lock().unwrap();
        assert!(guard.is_none());
    }

    #[test]
    fn test_set_self_proxy_clears_previous() {
        set_self_proxy(&["127.0.0.1:1234".to_string()]);
        set_self_proxy(&["10.0.0.1:5678".to_string()]);
        let addrs = self_proxy_addrs_lock().lock().unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "10.0.0.1:5678");
    }

    #[test]
    fn test_normalize_host_port_localhost_127001() {
        assert_eq!(normalize_host_port("127.0.0.1:8080"), "localhost:8080");
    }

    #[test]
    fn test_normalize_host_port_ipv6() {
        assert_eq!(normalize_host_port("[::1]:8080"), "localhost:8080");
    }

    #[test]
    fn test_normalize_host_port_regular() {
        assert_eq!(normalize_host_port("proxy.local:3128"), "proxy.local:3128");
    }

    #[test]
    fn test_normalize_host_port_no_port() {
        assert_eq!(normalize_host_port("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn test_normalize_host_port_with_scheme() {
        assert_eq!(
            normalize_host_port("http://127.0.0.1:8080"),
            "localhost:8080"
        );
    }

    #[test]
    fn test_is_no_proxy_uppercase_var() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("NO_PROXY", "internal.com");
        assert!(is_no_proxy("internal.com", None));
        assert!(!is_no_proxy("external.com", None));
        std::env::remove_var("NO_PROXY");
    }

    #[test]
    fn test_match_cidr_v4_invalid_bits() {
        assert!(!match_cidr("10.0.0.0/33", "10.0.0.1"));
    }

    #[test]
    fn test_match_cidr_v6_invalid_bits() {
        assert!(!match_cidr("::/129", "::1"));
    }

    #[test]
    fn test_match_cidr_not_a_cidr() {
        assert!(!match_cidr("not-a-cidr", "10.0.0.1"));
    }

    #[test]
    fn test_match_cidr_v4_against_v6_host() {
        assert!(!match_cidr("10.0.0.0/8", "::1"));
    }

    #[test]
    fn test_proxy_from_environment_no_env_vars() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("http_proxy");
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("https_proxy");
        std::env::remove_var("HTTPS_PROXY");
        // No env vars should fall through to platform_sys_proxy (which returns Ok(None) on non-macOS)
        let url = Url::parse("http://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_proxy_from_environment_empty_var() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("http_proxy", "");
        let url = Url::parse("http://example.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_none());
        std::env::remove_var("http_proxy");
    }

    #[test]
    fn test_proxy_from_environment_no_proxy_wildcard() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("http_proxy", "http://proxy:8080");
        std::env::set_var("no_proxy", "*");
        let url = Url::parse("http://anything.com").unwrap();
        let result = proxy_from_environment(&url).unwrap();
        assert!(result.is_none());
        std::env::remove_var("http_proxy");
        std::env::remove_var("no_proxy");
    }

    #[test]
    fn test_no_proxy_mixed() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("no_proxy", "localhost, 127.0.0.1, .example.com");
        assert!(is_no_proxy("localhost", None));
        assert!(is_no_proxy("127.0.0.1", None));
        assert!(is_no_proxy("foo.example.com", None));
        assert!(!is_no_proxy("example.org", None));
        std::env::remove_var("no_proxy");
    }

    #[test]
    fn test_parse_no_proxy_entry_port() {
        let (host, port) = parse_no_proxy_entry("127.0.0.1:8080");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn test_parse_no_proxy_entry_no_port() {
        let (host, port) = parse_no_proxy_entry("example.com");
        assert_eq!(host, "example.com");
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_no_proxy_entry_ipv6_bracketed() {
        let (host, port) = parse_no_proxy_entry("[::1]:8080");
        assert_eq!(host, "::1");
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn test_parse_no_proxy_entry_ipv6_no_port() {
        let (host, port) = parse_no_proxy_entry("[::1]");
        assert_eq!(host, "::1");
        assert_eq!(port, None);
    }

    #[test]
    fn test_match_no_proxy_entry_ipv6_exact() {
        assert!(match_no_proxy_entry("::1", "::1", None));
    }

    #[test]
    fn test_no_proxy_ipv6_not_matching() {
        assert!(!match_no_proxy_entry("::1", "::2", None));
    }

    #[test]
    fn test_no_proxy_cidr_v4_exact_32() {
        assert!(match_no_proxy_entry("192.168.1.1/32", "192.168.1.1", None));
        assert!(!match_no_proxy_entry("192.168.1.1/32", "192.168.1.2", None));
    }

    #[test]
    fn test_is_self_proxy_true() {
        set_self_proxy(&["127.0.0.1:8080".to_string()]);
        assert!(is_self_proxy("127.0.0.1:8080"));
        assert!(is_self_proxy("http://127.0.0.1:8080"));
        set_self_proxy(&[]);
    }

    #[test]
    fn test_is_self_proxy_false() {
        set_self_proxy(&["127.0.0.1:8080".to_string()]);
        assert!(!is_self_proxy("10.0.0.1:8080"));
        set_self_proxy(&[]);
    }

    #[test]
    fn test_platform_sys_proxy_no_proxy_until() {
        {
            let mut guard = no_proxy_until_lock().lock().unwrap();
            *guard = Some(Instant::now() + std::time::Duration::from_secs(60));
        }
        let url = Url::parse("http://example.com").unwrap();
        let result = platform_sys_proxy(&url).unwrap();
        assert!(result.is_none());
        invalidate_cache();
    }

    #[test]
    fn test_split_host_port_ipv6_bracketed() {
        let (host, port) = split_host_port("[::1]:8080").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_split_host_port_no_port() {
        assert!(split_host_port("10.0.0.1").is_none());
    }

    #[test]
    fn test_split_host_port_standard() {
        let (host, port) = split_host_port("proxy.local:3128").unwrap();
        assert_eq!(host, "proxy.local");
        assert_eq!(port, 3128);
    }
}
