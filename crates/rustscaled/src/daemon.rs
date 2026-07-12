//! Daemon `run` subcommand: bring up a tsnet Server, start the safesocket
//! listener for CLI IPC, and wait for SIGINT/SIGTERM.

use std::path::{Path, PathBuf};

use rustscale_tsnet::{Server, TunModeConfig};

/// Default state directory if `--statedir` is not specified.
const DEFAULT_STATE_DIR: &str = "/var/lib/rustscale";

/// Primary safesocket path (requires root or appropriate permissions).
const PRIMARY_SOCKET_PATH: &str = "/var/run/rustscaled.sock";

/// Run the daemon: bring up a tsnet Server, start the safesocket listener,
/// and wait for SIGINT/SIGTERM. On shutdown, calls `server.close()` for
/// clean teardown.
///
/// The auth key is read from the `TS_AUTHKEY` environment variable.
pub async fn run(
    statedir: Option<PathBuf>,
    hostname: Option<String>,
    tun: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_key =
        std::env::var("TS_AUTHKEY").map_err(|_| "TS_AUTHKEY environment variable is required")?;

    let state_dir = statedir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let hostname = hostname.unwrap_or_else(|| "rustscale".to_string());

    let mut server = Server::builder()
        .hostname(&hostname)
        .auth_key(&auth_key)
        .state_dir(&state_dir)
        .build()?;

    if tun {
        let config = TunModeConfig {
            apply_routes: true,
            ..Default::default()
        };
        Box::pin(server.up_tun(config)).await?;
        eprintln!("rustscaled: TUN mode up (hostname={hostname})");
    } else {
        Box::pin(server.up()).await?;
        eprintln!("rustscaled: up (hostname={hostname})");
    }

    let status = server.status();
    let ips: Vec<String> = status
        .tailscale_ips
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    eprintln!("rustscaled: tailscale IPs: {}", ips.join(", "));

    let _socket_task = start_safesocket_listener(&state_dir);

    wait_for_shutdown().await;

    eprintln!("rustscaled: shutting down...");
    server.close().await;

    Ok(())
}

/// Bind the safesocket listener for CLI IPC. Tries `/var/run/rustscaled.sock`
/// first, falling back to `<state_dir>/rustscaled.sock` if the primary path
/// is not writable.
///
/// Connections are accepted and dropped — a TODO placeholder for the
/// LocalAPI implementation in a later phase.
#[cfg(unix)]
fn start_safesocket_listener(state_dir: &Path) -> Option<tokio::task::JoinHandle<()>> {
    let primary = PathBuf::from(PRIMARY_SOCKET_PATH);
    let fallback = state_dir.join("rustscaled.sock");

    let (listener, path) = match rustscale_safesocket::listen(&primary) {
        Ok(l) => (l, primary),
        Err(e) => {
            eprintln!(
                "rustscaled: could not bind {}: {e}; falling back to {}",
                primary.display(),
                fallback.display()
            );
            match rustscale_safesocket::listen(&fallback) {
                Ok(l) => (l, fallback),
                Err(e2) => {
                    eprintln!("rustscaled: could not bind {}: {e2}", fallback.display());
                    return None;
                }
            }
        }
    };

    eprintln!("rustscaled: safesocket listening at {}", path.display());

    let _ = listener.set_nonblocking(true);
    let listener = tokio::net::UnixListener::from_std(listener).ok()?;

    Some(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((_stream, _addr)) => {
                    // TODO: LocalAPI (a later phase)
                }
                Err(e) => {
                    eprintln!("rustscaled: safesocket accept error: {e}");
                    break;
                }
            }
        }
    }))
}

#[cfg(not(unix))]
fn start_safesocket_listener(_state_dir: &Path) -> Option<()> {
    None
}

/// Wait for SIGINT or SIGTERM.
#[cfg(unix)]
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
