//! `rustscale status` — show state of rustscaled and its connections.
//!
//! Ports Go's `cmd/tailscale/cli/status.go`. Renders a peer table with
//! IP, hostname, owner, and connection path. With `--json`, outputs the
//! raw status JSON (passthrough from the daemon).

use std::path::Path;

use rustscale_localclient::LocalClient;
use serde_json::Value;

use crate::flags;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let want_json = json || flags::parse_bool_flag(&args, "json").unwrap_or(false);
    let peers_flag = flags::parse_bool_flag(&args, "peers").unwrap_or(true);
    let active = flags::parse_bool_flag(&args, "active").unwrap_or(false);

    let client = LocalClient::new(socket);
    let status = client.status().await?;

    if want_json {
        let pretty = serde_json::to_string_pretty(&status).map_err(|e| CliError(e.to_string()))?;
        println!("{pretty}");
        return Ok(());
    }

    // Check backend state — print a human-readable description for
    // non-running states, mirroring Go's isRunningOrStarting.
    if let Some(description) = backend_state_description(&status) {
        println!("{description}");
        return Ok(());
    }

    // Print health warnings if present (Go prints these before the table
    // when in Starting/NoState, and after the table otherwise).
    let health: Vec<String> = status
        .get("Health")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let magicdns_suffix = status
        .get("CurrentTailnet")
        .and_then(|v| v.get("MagicDNSSuffix"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    // Build the peer table.
    // Collect all peers (self + peers) into a sorted list.
    let mut entries: Vec<PeerEntry> = Vec::new();

    // Self entry.
    if let Some(self_node) = status.get("Self") {
        entries.push(parse_peer_entry(self_node, magicdns_suffix, true, &status));
    }

    // Peer entries.
    if peers_flag {
        if let Some(peers) = status.get("Peer").and_then(|v| v.as_object()) {
            for (_key, peer) in peers {
                let entry = parse_peer_entry(peer, magicdns_suffix, false, &status);
                if active && !entry.active {
                    continue;
                }
                entries.push(entry);
            }
        }
    }

    // Sort by IP (Go uses ipnstate.SortPeers which sorts by IP).
    entries.sort_by(|a, b| a.first_ip.cmp(&b.first_ip));

    // Render the table.
    for entry in &entries {
        print_peer_entry(entry);
    }

    if !health.is_empty() {
        println!();
        println!("# Health check:");
        for m in &health {
            println!("#     - {m}");
        }
    }

    if let Some(cv) = status.get("ClientVersion") {
        let running_latest = cv
            .get("RunningLatest")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let latest_version = cv
            .get("LatestVersion")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let urgent = cv
            .get("UrgentSecurityUpdate")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if !running_latest && !latest_version.is_empty() {
            println!();
            if urgent {
                println!("** URGENT update available: {latest_version} **");
            } else {
                println!("Update available: {latest_version}");
            }
        }
    }

    Ok(())
}

/// Return the standard user-facing description for a state that cannot yet
/// service tailnet operations. `Running` and `Starting` are usable.
pub(crate) fn backend_state_description(status: &Value) -> Option<String> {
    match status
        .get("BackendState")
        .and_then(Value::as_str)
        .unwrap_or("NoState")
    {
        "Running" | "Starting" => None,
        "Stopped" => Some("Tailscale is stopped.".into()),
        "NeedsLogin" => {
            let auth_url = status
                .get("AuthURL")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if auth_url.is_empty() {
                Some("Logged out.".into())
            } else {
                Some(format!("Logged out.\nLog in at: {auth_url}"))
            }
        }
        "NeedsMachineAuth" => Some("Machine is not yet approved by tailnet admin.".into()),
        other => Some(format!("unexpected state: {other}")),
    }
}

struct PeerEntry {
    first_ip: String,
    hostname: String,
    owner: String,
    relay: String,
    online: bool,
    exit_node: bool,
    exit_node_option: bool,
    active: bool,
}

fn parse_peer_entry(
    node: &Value,
    magicdns_suffix: &str,
    is_self: bool,
    status: &Value,
) -> PeerEntry {
    let ips = node
        .get("TailscaleIPs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let first_ip = ips.first().cloned().unwrap_or_default();

    let dns_name = node
        .get("DNSName")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let hostname = node
        .get("HostName")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    // Display name: strip the MagicDNS suffix if present.
    let display_name = if magicdns_suffix.is_empty() {
        hostname.to_string()
    } else {
        dns_name
            .strip_suffix(&format!(".{magicdns_suffix}"))
            .or_else(|| dns_name.strip_suffix(magicdns_suffix))
            .unwrap_or(dns_name)
            .trim_end_matches('.')
            .to_string()
    };

    // Owner: look up the user profile by UserID.
    let user_id = node.get("UserID").and_then(serde_json::Value::as_i64);
    let owner = if is_self {
        String::from("-")
    } else if let Some(uid) = user_id {
        let user_key = uid.to_string();
        status
            .get("User")
            .and_then(|v| v.get(&user_key))
            .and_then(|v| v.get("LoginName"))
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || uid.to_string(),
                |s| {
                    // Show up to (and including) the @ like Go.
                    match s.find('@') {
                        Some(i) => s[..=i].to_string(),
                        None => s.to_string(),
                    }
                },
            )
    } else {
        String::from("-")
    };

    let relay = node
        .get("Relay")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();

    let online = node
        .get("Online")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let exit_node = node
        .get("ExitNode")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let exit_node_option = node
        .get("ExitNodeOption")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    // rustscale doesn't track Active/TxBytes/RxBytes yet. Consider a peer
    // "active" if it's online and has a relay or direct path.
    let active = online;

    PeerEntry {
        first_ip,
        hostname: display_name,
        owner,
        relay,
        online,
        exit_node,
        exit_node_option,
        active,
    }
}

fn print_peer_entry(entry: &PeerEntry) {
    // Format: IP  hostname  owner  status
    // Mirrors Go's tabwriter output with 2-space padding.
    let ip = if entry.first_ip.is_empty() {
        "?"
    } else {
        &entry.first_ip
    };

    // Build the status column.
    let status_str = if entry.exit_node {
        if entry.online {
            "active; exit node".to_string()
        } else {
            "idle; exit node; offline".to_string()
        }
    } else if entry.exit_node_option {
        if entry.online {
            "active; offers exit node".to_string()
        } else {
            "idle; offers exit node; offline".to_string()
        }
    } else if !entry.online {
        "offline".to_string()
    } else if !entry.relay.is_empty() {
        format!("active; relay \"{}\"", entry.relay)
    } else {
        "active; direct".to_string()
    };

    println!(
        "{ip}\t{host}\t{owner}\t{status}",
        host = entry.hostname,
        owner = entry.owner,
        status = status_str
    );
}
