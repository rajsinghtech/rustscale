//! `rustscale ip` — show Tailscale IP addresses.
//!
//! Ports Go's `cmd/tailscale/cli/ip.go`. Shows self IPs by default, or a
//! specific peer's IPs when a peer argument (IP or hostname) is given.

use std::net::IpAddr;
use std::path::Path;

use rustscale_localclient::LocalClient;
use serde_json::Value;

use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let want4 = has_flag(&args, "4");
    let want6 = has_flag(&args, "6");
    let want1 = has_flag(&args, "1");

    // -1, -4, -6 are mutually exclusive.
    let nflags = [want1, want4, want6].iter().filter(|&&b| b).count();
    if nflags > 1 {
        return Err(CliError(
            "rustscale ip -1, -4, and -6 are mutually exclusive".into(),
        ));
    }

    let (v4, v6) = if want4 || want6 {
        (want4, want6)
    } else {
        (true, true)
    };

    // Positional args: at most one peer.
    let positional: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    if positional.len() > 1 {
        return Err(CliError(
            "too many arguments, expected at most one peer".into(),
        ));
    }

    let client = LocalClient::new(socket);
    let status = client.status().await?;

    let mut ips: Vec<String> = if let Some(peer_arg) = positional.first() {
        // Look up peer by IP or hostname.
        let peer_ips = find_peer_ips(&status, peer_arg);
        if peer_ips.is_empty() {
            return Err(CliError(format!(
                "no peer found with IP or hostname {peer_arg}"
            )));
        }
        peer_ips
    } else {
        // Self IPs.
        status
            .get("TailscaleIPs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };

    if ips.is_empty() {
        let backend_state = status
            .get("BackendState")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        return Err(CliError(format!(
            "no current Tailscale IPs; state: {backend_state}"
        )));
    }

    if want1 {
        ips.truncate(1);
    }

    let mut found = false;
    for ip_str in &ips {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            let is_v4 = ip.is_ipv4();
            let is_v6 = ip.is_ipv6();
            if (is_v4 && v4) || (is_v6 && v6) {
                println!("{ip_str}");
                found = true;
            }
        }
    }

    if !found {
        if want4 {
            return Err(CliError("no Tailscale IPv4 address".into()));
        }
        if want6 {
            return Err(CliError("no Tailscale IPv6 address".into()));
        }
    }

    Ok(())
}

fn has_flag(args: &[String], name: &str) -> bool {
    let dash = format!("-{name}");
    args.iter().any(|a| a == &dash)
}

/// Find a peer's IPs by matching the argument against peer IPs or hostnames.
fn find_peer_ips(status: &Value, arg: &str) -> Vec<String> {
    // Try matching by IP first.
    if let Some(peers) = status.get("Peer").and_then(|v| v.as_object()) {
        for (_key, peer) in peers {
            let peer_ips: Vec<String> = peer
                .get("TailscaleIPs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if peer_ips.iter().any(|ip| ip == arg) {
                return peer_ips;
            }
        }
    }

    // Try matching by hostname (case-insensitive).
    let arg_lower = arg.to_lowercase();
    if let Some(peers) = status.get("Peer").and_then(|v| v.as_object()) {
        for (_key, peer) in peers {
            let hostname = peer
                .get("HostName")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let dns_name = peer
                .get("DNSName")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            if hostname == arg_lower || dns_name == arg_lower {
                return peer
                    .get("TailscaleIPs")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
            }
        }
    }

    // Check self.
    if let Some(self_node) = status.get("Self") {
        let self_ips: Vec<String> = self_node
            .get("TailscaleIPs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if self_ips.iter().any(|ip| ip == arg) {
            return self_ips;
        }
    }

    Vec::new()
}
