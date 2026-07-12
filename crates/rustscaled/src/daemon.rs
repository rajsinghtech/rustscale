use std::path::{Path, PathBuf};

use rustscale_tsnet::localapi::DaemonCommand;
use rustscale_tsnet::{Server, TunModeConfig};

#[cfg(unix)]
const DEFAULT_STATE_DIR: &str = "/var/lib/rustscale";
#[cfg(windows)]
const DEFAULT_STATE_DIR: &str = "C:\\ProgramData\\Rustscale";

pub async fn run(
    statedir: Option<PathBuf>,
    hostname: Option<String>,
    tun: bool,
    socket_override: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_key = std::env::var("TS_AUTHKEY").ok();
    let state_dir = statedir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let hostname = hostname.unwrap_or_else(|| "rustscale".to_string());
    let socket_path = socket_override.unwrap_or_else(|| determine_socket_path(&state_dir));

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

    // Wait for either shutdown or logout.
    let logout_trigger = server.logout_trigger();
    tokio::select! {
        () = wait_for_shutdown_signal() => {}
        () = async {
            if let Some(ref trigger) = logout_trigger {
                trigger.notified().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            eprintln!("rustscaled: logout requested");
            server.logout().await?;
            eprintln!("rustscaled: logged out, state cleared → NeedsLogin");
        }
    }

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

    // Phase 1: wait for Start/LoginInteractive to bring the server up.
    let mut is_up = false;
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
                is_up = true;
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
                is_up = true;
                break;
            }
            DaemonCommand::Logout => {
                eprintln!("rustscaled: logout requested (server not up yet)");
            }
        }
    }

    if !is_up {
        return Ok(());
    }

    // Phase 2: server is up — wait for shutdown or logout.
    let logout_trigger = server.logout_trigger();
    tokio::select! {
        () = wait_for_shutdown_signal() => {}
        () = async {
            if let Some(ref trigger) = logout_trigger {
                trigger.notified().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            eprintln!("rustscaled: logout requested");
            server.logout().await?;
            eprintln!("rustscaled: logged out, state cleared → NeedsLogin");
        }
    }

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
    let primary = rustscale_safesocket::default_socket_path();

    // On Windows, the named pipe path is always the same — no fallback.
    #[cfg(windows)]
    {
        let _ = state_dir;
        primary
    }

    // On Unix, try the primary path first, then fall back to the state dir.
    #[cfg(unix)]
    {
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

/// Signal-wait future usable in `tokio::select!`.
#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    wait_for_shutdown().await;
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
