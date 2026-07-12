//! `rustscale ping` — ping a peer.
//!
//! Ports Go's `cmd/tailscale/cli/ping.go`. The daemon's ping endpoint
//! currently returns 501 (magicsock doesn't expose a standalone disco-ping
//! API yet). This CLI surfaces the 501 as "not yet supported by rustscaled".

use std::path::Path;

use rustscale_localclient::LocalClient;
use rustscale_localclient::LocalClientError;

use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let positional: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    if positional.is_empty() {
        return Err(CliError("usage: rustscale ping <ip>".into()));
    }
    let ip = &positional[0];

    let client = LocalClient::new(socket);
    match client.ping(ip, "disco").await {
        Ok(result) => {
            let pretty =
                serde_json::to_string_pretty(&result).map_err(|e| CliError(e.to_string()))?;
            println!("{pretty}");
            Ok(())
        }
        Err(LocalClientError::HttpStatus { status: 501, .. }) => Err(CliError(
            "ping: not yet supported by rustscaled (magicsock disco-ping API pending)".into(),
        )),
        Err(e) => Err(CliError::from(e)),
    }
}
