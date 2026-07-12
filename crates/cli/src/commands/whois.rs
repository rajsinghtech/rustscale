//! `rustscale whois` — show the machine and user associated with a
//! Tailscale IP. Ports Go's `cmd/tailscale/cli/whois.go`.

use std::path::Path;

use rustscale_localclient::LocalClient;
use serde_json::Value;

use crate::flags;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let want_json = json || flags::parse_bool_flag(&args, "json").unwrap_or(false);

    let positional: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    if positional.is_empty() {
        return Err(CliError("missing argument, expected one peer".into()));
    }
    if positional.len() > 1 {
        return Err(CliError(
            "too many arguments, expected at most one peer".into(),
        ));
    }

    let addr = &positional[0];
    let client = LocalClient::new(socket);
    let who = client.whois(addr).await?;

    if want_json {
        let pretty = serde_json::to_string_pretty(&who).map_err(|e| CliError(e.to_string()))?;
        println!("{pretty}");
        return Ok(());
    }

    print_whois(&who);
    Ok(())
}

fn print_whois(who: &Value) {
    // Machine section.
    println!("Machine:");
    if let Some(node) = who.get("Node") {
        let name = node
            .get("Name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let trimmed = name.trim_end_matches('.');
        println!("  Name:\t{trimmed}");
        if let Some(addrs) = node.get("Addresses").and_then(|v| v.as_array()) {
            let addr_strs: Vec<String> = addrs
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            println!("  Addresses:\t{}", addr_strs.join(", "));
        }
    }

    // User section.
    if let Some(profile) = who.get("UserProfile") {
        if !profile.is_null() {
            println!("User:");
            let login = profile
                .get("LoginName")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let id = profile
                .get("ID")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            println!("  Name:\t{login}");
            println!("  ID:\t{id}");
        }
    }
}
