//! `rustscale metrics` — print current metric values in Prometheus text
//! format. Ports Go's `cmd/tailscale/cli/metrics.go` (the `print` subcommand).

use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::CliError;

pub async fn run(_args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let client = LocalClient::new(socket);
    let metrics = client.metrics().await?;
    print!("{metrics}");
    Ok(())
}
