//! `rustscale version` — print client and (optionally) daemon version.
//!
//! Ports Go's `cmd/tailscale/cli/version.go`. With `--json`, outputs a JSON
//! object with `majorMinor` and `long` version strings. With `--daemon`,
//! also queries the daemon's version from the status endpoint.

use std::path::Path;

use rustscale_localclient::LocalClient;
use serde_json::json;

use crate::flags;
use crate::version;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let want_json = json || flags::parse_bool_flag(&args, "json").unwrap_or(false);
    let want_daemon = flags::parse_bool_flag(&args, "daemon").unwrap_or(false);

    let client_ver_short = version::CLIENT_VERSION;
    let client_ver_long = version::CLIENT_VERSION_LONG;

    let mut daemon_ver: Option<String> = None;

    if want_daemon {
        let client = LocalClient::new(socket);
        match client.status().await {
            Ok(status) => {
                daemon_ver = status
                    .get("Version")
                    .and_then(serde_json::Value::as_str)
                    .map(String::from);
            }
            Err(e) => {
                eprintln!("warning: could not fetch daemon version: {e}");
            }
        }
    }

    if want_json {
        let out = json!({
            "majorMinor": client_ver_short,
            "long": client_ver_long,
            "daemonLong": daemon_ver,
        });
        let pretty = serde_json::to_string_pretty(&out).map_err(|e| CliError(e.to_string()))?;
        println!("{pretty}");
        return Ok(());
    }

    if let Some(dv) = daemon_ver {
        println!("Client: {client_ver_long}");
        println!("Daemon: {dv}");
    } else {
        println!("{client_ver_long}");
    }

    Ok(())
}
