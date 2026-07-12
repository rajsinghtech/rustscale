use std::path::{Path, PathBuf};

use rustscale_tsnet::localapi::DaemonCommand;
use rustscale_tsnet::{Server, TunModeConfig};

const DEFAULT_STATE_DIR: &str = "/var/lib/rustscale";
const PRIMARY_SOCKET_PATH: &str = "/var/run/rustscaled.sock";

pub async fn run(
    statedir: Option<PathBuf>,
    hostname: Option<String>,
    tun: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_key = std::env::var("TS_AUTHKEY").ok();
    let state_dir = statedir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let hostname = hostname.unwrap_or_else(|| "rustscale".to_string());
    let socket_path = determine_socket_path(&state_dir);

    if let Some(key) = auth_key {
        run_with_auth_key(&key, &state_dir, &hostname, &socket_path, tun).await
    } else {
        run_interactive(&state_dir, &hostname, &socket_path, tun).await
    }
}

async fn run_with_auth_key(
    auth_key: &str,
    state_dir: &Path,
    hostname: &str,
    socket_path: &Path,
    tun: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut server = Server::builder()
        .hostname(hostname)
        .auth_key(auth_key)
        .state_dir(state_dir)
        .localapi_path(socket_path)
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

    print_status(&server, socket_path);
    wait_for_shutdown().await;
    eprintln!("rustscaled: shutting down...");
    server.close().await;
    Ok(())
}

async fn run_interactive(
    state_dir: &Path,
    hostname: &str,
    socket_path: &Path,
    tun: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut server = Server::builder()
        .hostname(hostname)
        .state_dir(state_dir)
        .localapi_path(socket_path)
        .build()?;

    let mut command_rx = server.start_localapi_only().await?;
    eprintln!("rustscaled: waiting for login (no TS_AUTHKEY set; use 'rustscale up' or 'rustscale login')");

    while let Some(cmd) = command_rx.recv().await {
        match cmd {
            DaemonCommand::Start { auth_key } => {
                if let Some(key) = auth_key {
                    server.set_auth_key(key);
                }
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
                print_status(&server, socket_path);
                break;
            }
            DaemonCommand::LoginInteractive => {
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
                print_status(&server, socket_path);
                break;
            }
            DaemonCommand::Logout => {
                eprintln!("rustscaled: logout requested");
            }
        }
    }

    wait_for_shutdown().await;
    eprintln!("rustscaled: shutting down...");
    server.close().await;
    Ok(())
}

fn print_status(server: &Server, socket_path: &Path) {
    let status = server.status();
    let ips: Vec<String> = status
        .tailscale_ips
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    if !ips.is_empty() {
        eprintln!("rustscaled: tailscale IPs: {}", ips.join(", "));
    }
    if server.localapi_path().is_some() {
        eprintln!(
            "rustscaled: LocalAPI listening at {}",
            socket_path.display()
        );
    }
}

fn determine_socket_path(state_dir: &Path) -> PathBuf {
    let primary = PathBuf::from(PRIMARY_SOCKET_PATH);
    let fallback = state_dir.join("rustscaled.sock");

    match rustscale_safesocket::listen(&primary) {
        Ok(listener) => {
            drop(listener);
            let _ = std::fs::remove_file(&primary);
            primary
        }
        Err(_) => fallback,
    }
}

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
