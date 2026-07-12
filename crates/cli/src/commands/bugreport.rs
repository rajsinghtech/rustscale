//! `rustscale bugreport` — print a diagnostic summary for bug reports.
//!
//! Collects version, backend state, health warnings, and peer count
//! into a concise summary suitable for pasting into an issue.

use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::version;
use crate::CliError;

pub async fn run(_args: Vec<String>, socket: &Path, _json: bool) -> Result<(), CliError> {
    let client = LocalClient::new(socket);

    let status = client.status().await;
    let health = client.health().await;

    println!("=== rustscale bug report ===");
    println!("Client version: {}", version::CLIENT_VERSION_LONG);

    match &status {
        Ok(s) => {
            let backend_state = s
                .get("BackendState")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let peer_count = s
                .get("Peer")
                .and_then(serde_json::Value::as_object)
                .map_or(0, serde_json::Map::len);
            let suggested = s
                .get("SuggestedExitNode")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            println!("Backend state: {backend_state}");
            println!("Peer count: {peer_count}");
            if !suggested.is_empty() {
                println!("Suggested exit node: {suggested}");
            }
        }
        Err(e) => {
            println!("Backend state: unavailable ({e})");
        }
    }

    match &health {
        Ok(h) => {
            if let Some(warnings) = h.as_array() {
                if warnings.is_empty() {
                    println!("Health: no warnings");
                } else {
                    println!("Health: {} warning(s)", warnings.len());
                    for w in warnings {
                        let text = w
                            .get("text")
                            .and_then(serde_json::Value::as_str)
                            .or_else(|| w.as_str())
                            .unwrap_or("unknown");
                        println!("  - {text}");
                    }
                }
            } else {
                println!("Health: no warnings");
            }
        }
        Err(e) => {
            println!("Health: unavailable ({e})");
        }
    }

    Ok(())
}
