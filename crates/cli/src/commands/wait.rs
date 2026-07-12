//! `rustscale wait` — wait for the backend to reach Running state.
//!
//! Ports Go's `cmd/tailscale/cli/wait.go`. Polls the daemon status every
//! second and returns once `BackendState == "Running"`. Exits 1 on timeout.
//!
//! Unlike the Go version, this does not verify that a Tailscale IP is
//! assigned to a host network interface (TUN interface check). The
//! userspace netstack mode used by rustscale doesn't create a host
//! interface, so we only wait for the Running state.

use std::path::Path;
use std::time::Duration;

use rustscale_localclient::LocalClient;

use crate::flags;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, _json: bool) -> Result<(), CliError> {
    let timeout_secs = flags::parse_str_flag(&args, "timeout")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);

    let client = LocalClient::new(socket);
    let poll = Duration::from_secs(1);
    let deadline = if timeout_secs > 0 {
        Some(tokio::time::Instant::now() + Duration::from_secs(timeout_secs))
    } else {
        None
    };

    loop {
        if let Ok(status) = client.status().await {
            let state = status
                .get("BackendState")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("NoState");
            if state == "Running" {
                return Ok(());
            }
        }
        // Daemon not reachable or not running yet; keep retrying.

        if let Some(dl) = deadline {
            if tokio::time::Instant::now() >= dl {
                return Err(CliError(format!("wait: timed out after {timeout_secs}s")));
            }
        }

        tokio::time::sleep(poll).await;
    }
}
