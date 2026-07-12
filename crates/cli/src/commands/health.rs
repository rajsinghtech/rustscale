//! `rustscale health` — print active health warnings from the daemon.

use std::path::Path;

use rustscale_localclient::LocalClient;
use serde_json::Value;

use crate::flags;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let want_json = json || flags::parse_bool_flag(&args, "json").unwrap_or(false);

    let client = LocalClient::new(socket);
    let health = client.health().await?;

    if want_json {
        let pretty = serde_json::to_string_pretty(&health).map_err(|e| CliError(e.to_string()))?;
        println!("{pretty}");
        return Ok(());
    }

    print_health(&health);
    Ok(())
}

fn print_health(health: &Value) {
    if let Some(warnings) = health.as_array() {
        if warnings.is_empty() {
            println!("No health warnings.");
            return;
        }
        for w in warnings {
            let text = w
                .get("text")
                .and_then(serde_json::Value::as_str)
                .or_else(|| w.as_str())
                .unwrap_or("unknown");
            let severity = w
                .get("severity")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            println!("[{severity}] {text}");
        }
    } else {
        println!("No health warnings.");
    }
}
