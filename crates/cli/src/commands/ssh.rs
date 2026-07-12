//! `rustscale ssh` — SSH client wrapper.
//!
//! Ports Go's `cmd/tailscale/cli/ssh.go` + `ssh_exec.go`. This is the CLIENT
//! wrapper that execs the system `ssh` binary — NOT the Tailscale SSH server
//! (which lives in `crates/ssh` + `tsnet::listen_ssh` behind the `ssh`
//! feature).
//!
//! What the wrapper does:
//! - Resolves the destination host against the netmap/MagicDNS (status
//!   peers): accepts short hostname, FQDN, or Tailscale IP.
//! - Adds `-o HostName <resolved-ip-or-fqdn>` so OpenSSH connects to the
//!   resolved Tailscale address even if the user typed a short name.
//! - If the target peer advertises Tailscale SSH host keys, writes a
//!   known_hosts file and adds trust options so OpenSSH verifies the
//!   connection against the control-plane-advertised keys.
//! - Passes through remaining args to the system ssh.
//! - Execs the system `ssh` binary (execvp, replacing the process) on Unix.
//!   Windows: prints "not supported".

use std::path::Path;

use rustscale_localclient::LocalClient;
use serde_json::Value;

use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    if args.is_empty() {
        return Err(CliError(
            "usage: rustscale ssh [user@]<host> [args...]".into(),
        ));
    }

    let (user, host, arg_rest) = parse_user_host(&args);

    let lc = LocalClient::new(socket);
    let status = lc.status().await?;

    let peer = resolve_peer(&status, &host);

    let host_for_ssh = match &peer {
        Some(p) => {
            let corp_dns = status
                .get("CurrentTailnet")
                .and_then(|v| v.get("MagicDNSSuffix"))
                .and_then(Value::as_str)
                .is_some();
            if corp_dns {
                p.dns_name.clone()
            } else {
                first_ip(&p.ips)
                    .cloned()
                    .unwrap_or_else(|| p.dns_name.clone())
            }
        }
        None => host.clone(),
    };

    let resolved_addr = peer
        .as_ref()
        .and_then(|p| first_ip(&p.ips).cloned())
        .or_else(|| peer.as_ref().map(|p| p.dns_name.clone()));

    let has_ssh_keys = peer.as_ref().is_some_and(|p| !p.ssh_host_keys.is_empty());

    let known_hosts_file = if has_ssh_keys {
        let peer_for_hosts = peer.as_ref().unwrap();
        let original_alias = if host_for_ssh == host {
            None
        } else {
            Some(host.as_str())
        };
        Some(write_known_hosts(&status, original_alias, peer_for_hosts)?)
    } else {
        None
    };

    let ssh_path = find_ssh()?;

    let argv = build_ssh_argv(
        &ssh_path,
        user.as_deref(),
        &host_for_ssh,
        resolved_addr.as_deref(),
        has_ssh_keys,
        known_hosts_file.as_deref(),
        &arg_rest,
    );

    exec_ssh(&ssh_path, &argv)
}

/// Split the first argument into `(user, host)` and return the remaining args.
/// `user@host` → `(Some("user"), "host")`; `host` → `(None, "host")`.
fn parse_user_host(args: &[String]) -> (Option<String>, String, Vec<String>) {
    let arg = &args[0];
    let rest = args[1..].to_vec();
    match arg.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string(), rest),
        None => (None, arg.clone(), rest),
    }
}

/// Information about a resolved peer, extracted from the status JSON.
struct PeerInfo {
    dns_name: String,
    ips: Vec<String>,
    ssh_host_keys: Vec<String>,
}

/// Resolve a host argument against the status peers. Accepts:
/// - Tailscale IP (exact match against peer TailscaleIPs)
/// - FQDN (case-insensitive, trailing dot trimmed)
/// - Short hostname (first label of DNSName, case-insensitive)
fn resolve_peer(status: &Value, host: &str) -> Option<PeerInfo> {
    if host.is_empty() {
        return None;
    }
    let peers = status.get("Peer")?.as_object()?;
    for (_id, peer) in peers {
        let dns_name = peer
            .get("DNSName")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let ips: Vec<String> = peer
            .get("TailscaleIPs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        if matches_by_ip(&ips, host) || matches_by_name(&dns_name, host) {
            let ssh_host_keys: Vec<String> = peer
                .get("SSH_HostKeys")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .filter(|s| !s.contains(['\n', '\r']))
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            return Some(PeerInfo {
                dns_name,
                ips,
                ssh_host_keys,
            });
        }
    }
    None
}

/// Check if `host` is a Tailscale IP of this peer.
fn matches_by_ip(ips: &[String], host: &str) -> bool {
    ips.iter().any(|ip| ip == host)
}

/// Check if `host` matches the peer's DNSName (FQDN or short name).
fn matches_by_name(dns_name: &str, host: &str) -> bool {
    let dn = dns_name.trim_end_matches('.');
    let h = host.trim_end_matches('.');
    if dn.eq_ignore_ascii_case(h) {
        return true;
    }
    if let Some((base, _)) = dn.split_once('.') {
        return base.eq_ignore_ascii_case(h);
    }
    false
}

/// Return the first IPv4 from the list, or the first IP overall.
fn first_ip(ips: &[String]) -> Option<&String> {
    ips.iter()
        .find(|ip| ip.contains('.') && !ip.contains(':'))
        .or_else(|| ips.first())
}

/// Construct the argv array for the system ssh command.
///
/// This is a pure function for testability — the caller passes the resolved
/// peer info and the function returns the complete argv.
fn build_ssh_argv(
    ssh_path: &str,
    user: Option<&str>,
    host_for_ssh: &str,
    resolved_addr: Option<&str>,
    has_ssh_host_keys: bool,
    known_hosts_file: Option<&str>,
    arg_rest: &[String],
) -> Vec<String> {
    let mut argv = vec![ssh_path.to_string()];

    if let Some(addr) = resolved_addr {
        if addr != host_for_ssh {
            argv.push("-o".into());
            argv.push(format!("HostName {addr}"));
        }
    }

    if has_ssh_host_keys {
        if let Some(khf) = known_hosts_file {
            argv.push("-o".into());
            argv.push(format!("UserKnownHostsFile {khf}"));
            argv.push("-o".into());
            argv.push("UpdateHostKeys no".into());
            argv.push("-o".into());
            argv.push("StrictHostKeyChecking yes".into());
            argv.push("-o".into());
            argv.push("CanonicalizeHostname no".into());
        }
    }

    let target = match user {
        Some(u) => format!("{u}@{host_for_ssh}"),
        None => host_for_ssh.to_string(),
    };
    argv.push(target);

    argv.extend_from_slice(arg_rest);
    argv
}

/// Generate the contents of a known_hosts file from the status peers.
/// Includes entries for DNSName, each Tailscale IP, and optionally the
/// original host alias the user typed (so short-name lookups succeed).
fn gen_known_hosts(status: &Value, original_alias: Option<&str>, target_peer: &PeerInfo) -> String {
    let mut buf = String::new();
    if let Some(peers) = status.get("Peer").and_then(|v| v.as_object()) {
        for (_id, peer) in peers {
            let dns_name = peer
                .get("DNSName")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim_end_matches('.');
            let ips: Vec<String> = peer
                .get("TailscaleIPs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let host_keys: Vec<String> = peer
                .get("SSH_HostKeys")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .filter(|s| !s.contains(['\n', '\r']))
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            let is_target =
                dns_name.eq_ignore_ascii_case(target_peer.dns_name.trim_end_matches('.'));

            for hk in &host_keys {
                use std::fmt::Write;
                if !dns_name.is_empty() {
                    let _ = writeln!(buf, "{dns_name} {hk}");
                }
                for ip in &ips {
                    let _ = writeln!(buf, "{ip} {hk}");
                }
                if is_target {
                    if let Some(alias) = original_alias {
                        if !alias.eq_ignore_ascii_case(dns_name) {
                            let _ = writeln!(buf, "{alias} {hk}");
                        }
                    }
                }
            }
        }
    }
    buf
}

/// Write the known_hosts file to the user's config dir, only if the content
/// changed. Returns the path to the file.
#[cfg(unix)]
fn write_known_hosts(
    status: &Value,
    original_alias: Option<&str>,
    target_peer: &PeerInfo,
) -> Result<String, CliError> {
    let conf_dir =
        config_dir().ok_or_else(|| CliError("cannot determine user config directory".into()))?;
    let ts_dir = conf_dir.join("tailscale");
    std::fs::create_dir_all(&ts_dir)
        .map_err(|e| CliError(format!("failed to create config dir: {e}")))?;

    let kh_path = ts_dir.join("ssh_known_hosts");
    let content = gen_known_hosts(status, original_alias, target_peer);

    if std::fs::read_to_string(&kh_path).is_ok_and(|cur| cur == content) {
        return Ok(kh_path.to_string_lossy().into_owned());
    }

    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&kh_path)
        .and_then(|mut f| f.write_all(content.as_bytes()))
        .map_err(|e| CliError(format!("failed to write known_hosts: {e}")))?;

    Ok(kh_path.to_string_lossy().into_owned())
}

#[cfg(not(unix))]
fn write_known_hosts(
    _status: &Value,
    _original_alias: Option<&str>,
    _target_peer: &PeerInfo,
) -> Result<String, CliError> {
    Err(CliError("ssh is not supported on this platform".into()))
}

/// Return the user's config directory (matches Go's `os.UserConfigDir()`).
#[cfg(unix)]
fn config_dir() -> Option<std::path::PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() && xdg != "." {
            return Some(std::path::PathBuf::from(xdg));
        }
    }
    std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".config"))
}

/// Find the system `ssh` binary in PATH.
fn find_ssh() -> Result<String, CliError> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = std::path::Path::new(dir).join("ssh");
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(CliError("no system 'ssh' command found in PATH".into()))
}

/// Exec the system ssh binary, replacing this process. On success, this
/// function never returns.
#[cfg(unix)]
fn exec_ssh(ssh_path: &str, argv: &[String]) -> Result<(), CliError> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(ssh_path);
    cmd.args(&argv[1..]);
    let err = cmd.exec();
    Err(CliError(format!("exec ssh failed: {err}")))
}

#[cfg(not(unix))]
fn exec_ssh(_ssh_path: &str, _argv: &[String]) -> Result<(), CliError> {
    eprintln!("rustscale ssh is not supported on this platform.");
    Err(CliError("ssh is not supported on this platform".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_status(peers: Vec<Value>) -> Value {
        let mut peer_map = serde_json::Map::new();
        for (i, p) in peers.into_iter().enumerate() {
            peer_map.insert(format!("node{i}"), p);
        }
        json!({
            "BackendState": "Running",
            "CurrentTailnet": {
                "MagicDNSSuffix": "tailnet.ts.net"
            },
            "Peer": peer_map,
        })
    }

    fn make_peer(dns_name: &str, ips: &[&str], ssh_host_keys: &[&str]) -> Value {
        json!({
            "DNSName": dns_name,
            "TailscaleIPs": ips,
            "SSH_HostKeys": ssh_host_keys,
        })
    }

    #[test]
    fn parse_user_host_with_user() {
        let args = vec![
            "alice@myhost".to_string(),
            "-p".to_string(),
            "22".to_string(),
        ];
        let (user, host, rest) = parse_user_host(&args);
        assert_eq!(user, Some("alice".into()));
        assert_eq!(host, "myhost");
        assert_eq!(rest, vec!["-p", "22"]);
    }

    #[test]
    fn parse_user_host_without_user() {
        let args = vec!["myhost".to_string(), "ls".to_string()];
        let (user, host, rest) = parse_user_host(&args);
        assert_eq!(user, None);
        assert_eq!(host, "myhost");
        assert_eq!(rest, vec!["ls"]);
    }

    #[test]
    fn parse_user_host_at_in_host_part() {
        let args = vec!["alice@myhost@weird".to_string()];
        let (user, host, _rest) = parse_user_host(&args);
        assert_eq!(user, Some("alice".into()));
        assert_eq!(host, "myhost@weird");
    }

    #[test]
    fn resolve_peer_by_short_name() {
        let st = make_status(vec![make_peer(
            "myhost.tailnet.ts.net",
            &["100.64.0.5"],
            &[],
        )]);
        let peer = resolve_peer(&st, "myhost").unwrap();
        assert_eq!(peer.dns_name, "myhost.tailnet.ts.net");
        assert_eq!(peer.ips, vec!["100.64.0.5"]);
    }

    #[test]
    fn resolve_peer_by_fqdn() {
        let st = make_status(vec![make_peer(
            "myhost.tailnet.ts.net",
            &["100.64.0.5"],
            &[],
        )]);
        let peer = resolve_peer(&st, "myhost.tailnet.ts.net").unwrap();
        assert_eq!(peer.dns_name, "myhost.tailnet.ts.net");
    }

    #[test]
    fn resolve_peer_by_fqdn_trailing_dot() {
        let st = make_status(vec![make_peer(
            "myhost.tailnet.ts.net",
            &["100.64.0.5"],
            &[],
        )]);
        let peer = resolve_peer(&st, "myhost.tailnet.ts.net.").unwrap();
        assert_eq!(peer.dns_name, "myhost.tailnet.ts.net");
    }

    #[test]
    fn resolve_peer_by_ip() {
        let st = make_status(vec![make_peer(
            "myhost.tailnet.ts.net",
            &["100.64.0.5"],
            &[],
        )]);
        let peer = resolve_peer(&st, "100.64.0.5").unwrap();
        assert_eq!(peer.dns_name, "myhost.tailnet.ts.net");
    }

    #[test]
    fn resolve_peer_case_insensitive() {
        let st = make_status(vec![make_peer(
            "MyHost.tailnet.ts.net",
            &["100.64.0.5"],
            &[],
        )]);
        assert!(resolve_peer(&st, "myhost").is_some());
        assert!(resolve_peer(&st, "MYHOST.TAILNET.TS.NET").is_some());
    }

    #[test]
    fn resolve_peer_not_found() {
        let st = make_status(vec![make_peer(
            "other.tailnet.ts.net",
            &["100.64.0.3"],
            &[],
        )]);
        assert!(resolve_peer(&st, "nonexistent").is_none());
    }

    #[test]
    fn resolve_peer_with_ssh_keys() {
        let st = make_status(vec![make_peer(
            "myhost.tailnet.ts.net",
            &["100.64.0.5"],
            &["ssh-ed25519 AAAA..."],
        )]);
        let peer = resolve_peer(&st, "myhost").unwrap();
        assert_eq!(peer.ssh_host_keys, vec!["ssh-ed25519 AAAA..."]);
    }

    #[test]
    fn resolve_peer_empty_host() {
        let st = make_status(vec![make_peer("host.ts.net", &["100.64.0.1"], &[])]);
        assert!(resolve_peer(&st, "").is_none());
    }

    #[test]
    fn build_argv_basic_no_peer() {
        let argv = build_ssh_argv("/usr/bin/ssh", None, "somehost", None, false, None, &[]);
        assert_eq!(argv, vec!["/usr/bin/ssh", "somehost"]);
    }

    #[test]
    fn build_argv_with_user_no_peer() {
        let argv = build_ssh_argv(
            "/usr/bin/ssh",
            Some("alice"),
            "somehost",
            None,
            false,
            None,
            &[],
        );
        assert_eq!(argv, vec!["/usr/bin/ssh", "alice@somehost"]);
    }

    #[test]
    fn build_argv_resolved_ip() {
        let argv = build_ssh_argv(
            "/usr/bin/ssh",
            None,
            "myhost",
            Some("100.64.0.5"),
            false,
            None,
            &[],
        );
        assert_eq!(
            argv,
            vec!["/usr/bin/ssh", "-o", "HostName 100.64.0.5", "myhost"]
        );
    }

    #[test]
    fn build_argv_resolved_ip_with_user() {
        let argv = build_ssh_argv(
            "/usr/bin/ssh",
            Some("alice"),
            "myhost",
            Some("100.64.0.5"),
            false,
            None,
            &[],
        );
        assert_eq!(
            argv,
            vec!["/usr/bin/ssh", "-o", "HostName 100.64.0.5", "alice@myhost"]
        );
    }

    #[test]
    fn build_argv_with_ssh_host_keys() {
        let argv = build_ssh_argv(
            "/usr/bin/ssh",
            None,
            "myhost.tailnet.ts.net",
            Some("100.64.0.5"),
            true,
            Some("/home/user/.config/tailscale/ssh_known_hosts"),
            &[],
        );
        assert_eq!(
            argv,
            vec![
                "/usr/bin/ssh",
                "-o",
                "HostName 100.64.0.5",
                "-o",
                "UserKnownHostsFile /home/user/.config/tailscale/ssh_known_hosts",
                "-o",
                "UpdateHostKeys no",
                "-o",
                "StrictHostKeyChecking yes",
                "-o",
                "CanonicalizeHostname no",
                "myhost.tailnet.ts.net",
            ]
        );
    }

    #[test]
    fn build_argv_passes_through_args() {
        let extra = vec!["-p".to_string(), "2222".to_string(), "ls".to_string()];
        let argv = build_ssh_argv(
            "/usr/bin/ssh",
            Some("bob"),
            "host",
            None,
            false,
            None,
            &extra,
        );
        assert_eq!(argv, vec!["/usr/bin/ssh", "bob@host", "-p", "2222", "ls"]);
    }

    #[test]
    fn build_argv_no_hostname_when_same_as_host() {
        let argv = build_ssh_argv(
            "/usr/bin/ssh",
            None,
            "100.64.0.5",
            Some("100.64.0.5"),
            false,
            None,
            &[],
        );
        assert_eq!(argv, vec!["/usr/bin/ssh", "100.64.0.5"]);
    }

    #[test]
    fn build_argv_ssh_keys_no_file_omits_options() {
        let argv = build_ssh_argv(
            "/usr/bin/ssh",
            None,
            "host",
            Some("100.64.0.5"),
            true,
            None,
            &[],
        );
        assert_eq!(
            argv,
            vec!["/usr/bin/ssh", "-o", "HostName 100.64.0.5", "host"]
        );
    }

    #[test]
    fn gen_known_hosts_basic() {
        let st = make_status(vec![
            make_peer(
                "host1.tailnet.ts.net",
                &["100.64.0.1"],
                &["ssh-ed25519 AAAA1"],
            ),
            make_peer(
                "host2.tailnet.ts.net",
                &["100.64.0.2"],
                &["ssh-ed25519 AAAA2"],
            ),
        ]);
        let target = PeerInfo {
            dns_name: "host1.tailnet.ts.net".into(),
            ips: vec!["100.64.0.1".into()],
            ssh_host_keys: vec!["ssh-ed25519 AAAA1".into()],
        };
        let content = gen_known_hosts(&st, Some("host1"), &target);
        assert!(content.contains("host1.tailnet.ts.net ssh-ed25519 AAAA1"));
        assert!(content.contains("100.64.0.1 ssh-ed25519 AAAA1"));
        assert!(content.contains("host1 ssh-ed25519 AAAA1"));
        assert!(content.contains("host2.tailnet.ts.net ssh-ed25519 AAAA2"));
        assert!(content.contains("100.64.0.2 ssh-ed25519 AAAA2"));
    }

    #[test]
    fn gen_known_hosts_no_alias_when_same_as_dnsname() {
        let st = make_status(vec![make_peer(
            "host1.tailnet.ts.net",
            &["100.64.0.1"],
            &["ssh-ed25519 AAAA1"],
        )]);
        let target = PeerInfo {
            dns_name: "host1.tailnet.ts.net".into(),
            ips: vec!["100.64.0.1".into()],
            ssh_host_keys: vec!["ssh-ed25519 AAAA1".into()],
        };
        let content = gen_known_hosts(&st, Some("host1.tailnet.ts.net"), &target);
        assert!(content.contains("host1.tailnet.ts.net ssh-ed25519 AAAA1"));
        assert!(
            !content.contains("\nhost1.tailnet.ts.net ssh-ed25519 AAAA1\nhost1.tailnet.ts.net ")
        );
    }

    #[test]
    fn gen_known_hosts_no_keys() {
        let st = make_status(vec![make_peer(
            "host1.tailnet.ts.net",
            &["100.64.0.1"],
            &[],
        )]);
        let target = PeerInfo {
            dns_name: "host1.tailnet.ts.net".into(),
            ips: vec!["100.64.0.1".into()],
            ssh_host_keys: vec![],
        };
        let content = gen_known_hosts(&st, None, &target);
        assert!(content.is_empty());
    }

    #[test]
    fn gen_known_hosts_rejects_newlines_in_keys() {
        let st = make_status(vec![make_peer(
            "host1.tailnet.ts.net",
            &["100.64.0.1"],
            &["ssh-ed25519 AAAA1\nmalicious"],
        )]);
        let target = PeerInfo {
            dns_name: "host1.tailnet.ts.net".into(),
            ips: vec!["100.64.0.1".into()],
            ssh_host_keys: vec![],
        };
        let content = gen_known_hosts(&st, None, &target);
        assert!(content.is_empty());
    }

    #[test]
    fn first_ip_prefers_ipv4() {
        let ips = vec!["fd7a:115c::1".to_string(), "100.64.0.5".to_string()];
        assert_eq!(first_ip(&ips), Some(&"100.64.0.5".to_string()));
    }

    #[test]
    fn first_ip_falls_back_to_ipv6() {
        let ips = vec!["fd7a:115c::1".to_string()];
        assert_eq!(first_ip(&ips), Some(&"fd7a:115c::1".to_string()));
    }

    #[test]
    fn first_ip_empty() {
        let ips: Vec<String> = vec![];
        assert_eq!(first_ip(&ips), None);
    }

    #[test]
    fn matches_by_name_short() {
        assert!(matches_by_name("host.tailnet.ts.net", "host"));
        assert!(matches_by_name("HOST.tailnet.ts.net", "host"));
    }

    #[test]
    fn matches_by_name_fqdn() {
        assert!(matches_by_name(
            "host.tailnet.ts.net",
            "host.tailnet.ts.net"
        ));
        assert!(matches_by_name(
            "host.tailnet.ts.net.",
            "host.tailnet.ts.net"
        ));
    }

    #[test]
    fn matches_by_name_no_match() {
        assert!(!matches_by_name("host.tailnet.ts.net", "other"));
        assert!(!matches_by_name("host.tailnet.ts.net", "host.other.net"));
    }
}
