//! `rustscale exit-node` — list or select exit nodes.
//!
//! Without arguments, lists peers that offer exit-node capability.
//! With `--suggest`, prints the control-suggested exit node.
//! With a node argument, prints a TODO (setting exit nodes via CLI
//! requires PATCH /prefs wiring which is not yet hooked up for
//! exit-node selection).

use std::path::Path;

use rustscale_localclient::LocalClient;
use serde_json::Value;

use crate::flags;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let want_json = json || flags::parse_bool_flag(&args, "json").unwrap_or(false);
    let want_suggest = flags::parse_bool_flag(&args, "suggest").unwrap_or(false);

    let client = LocalClient::new(socket);
    let status = client.status().await?;

    if want_suggest {
        let suggested = status
            .get("SuggestedExitNode")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if want_json {
            println!("{}", serde_json::json!({"suggestedExitNode": suggested}));
        } else if suggested.is_empty() {
            println!("No exit node suggested by control.");
        } else {
            println!("{suggested}");
        }
        return Ok(());
    }

    // List exit-node-capable peers.
    let mut exit_nodes: Vec<(String, String, bool)> = Vec::new();

    if let Some(peers) = status.get("Peer").and_then(|v| v.as_object()) {
        for (_key, peer) in peers {
            let exit_option = peer
                .get("ExitNodeOption")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !exit_option {
                continue;
            }
            let ips = peer
                .get("TailscaleIPs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let ip = ips.first().cloned().unwrap_or_default();
            let hostname = peer
                .get("DNSName")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .trim_end_matches('.')
                .to_string();
            let online = peer
                .get("Online")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            exit_nodes.push((ip, hostname, online));
        }
    }

    exit_nodes.sort_by(|a, b| a.1.cmp(&b.1));

    if want_json {
        let arr: Vec<Value> = exit_nodes
            .iter()
            .map(|(ip, host, online)| {
                serde_json::json!({
                    "ip": ip,
                    "hostname": host,
                    "online": online,
                })
            })
            .collect();
        println!("{}", serde_json::json!(arr));
        return Ok(());
    }

    if exit_nodes.is_empty() {
        println!("No exit nodes available.");
        return Ok(());
    }

    println!("Available exit nodes:");
    for (ip, host, online) in &exit_nodes {
        let status = if *online { "online" } else { "offline" };
        println!("  {ip}\t{host}\t{status}");
    }

    Ok(())
}
