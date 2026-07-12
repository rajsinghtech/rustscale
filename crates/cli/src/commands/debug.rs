//! `rustscale debug` — call daemon debug endpoints.
//!
//! Ports a subset of Go's `cmd/tailscale/cli/debug.go`. Supports
//! `debug status`, `debug ipconfig`, and `debug metrics` sub-commands.

use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::flags;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let want_json = json || flags::parse_bool_flag(&args, "json").unwrap_or(false);

    // The first positional arg selects the debug action.
    let action = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map_or("status", String::as_str);

    let client = LocalClient::new(socket);
    let result = client.debug(action).await?;

    if want_json {
        let pretty = serde_json::to_string_pretty(&result).map_err(|e| CliError(e.to_string()))?;
        println!("{pretty}");
    } else {
        println!("{result}");
    }
    Ok(())
}
