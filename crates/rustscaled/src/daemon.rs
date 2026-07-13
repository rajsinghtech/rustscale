use std::path::{Path, PathBuf};

use rustscale_conffile::Config;
use rustscale_tsnet::localapi::DaemonCommand;
use rustscale_tsnet::{Server, TunModeConfig};

#[cfg(target_os = "macos")]
const DEFAULT_STATE_DIR: &str = "/var/db/rustscale";
#[cfg(all(unix, not(target_os = "macos")))]
const DEFAULT_STATE_DIR: &str = "/var/lib/rustscale";
#[cfg(windows)]
const DEFAULT_STATE_DIR: &str = "C:\\ProgramData\\Rustscale";

pub async fn run(
    statedir: Option<PathBuf>,
    hostname: Option<String>,
    tun: bool,
    socket_override: Option<PathBuf>,
    port: Option<u16>,
    socks5_server: Option<String>,
    http_proxy_server: Option<String>,
    config_path: Option<PathBuf>,
    cleanup: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_key = std::env::var("TS_AUTHKEY").ok();
    let state_dir = statedir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let socket_path = socket_override.unwrap_or_else(|| determine_socket_path(&state_dir));

    // --cleanup: remove old state files and exit.
    if cleanup {
        eprintln!("rustscaled: cleaning up state in {}", state_dir.display());
        cleanup_state(&state_dir)?;
        return Ok(());
    }

    // --socks5-server: not yet wired into the daemon bootstrap.
    // TODO: spawn SOCKS5 listener via tsnet::socks5 when the server is up.
    if let Some(ref addr) = socks5_server {
        eprintln!("rustscaled: --socks5-server {addr} (TODO: not yet wired)");
    }

    // --http-proxy-server: set as environment variable for outbound proxies.
    // TODO: wire into magicsock/controlclient HTTP clients directly.
    if let Some(ref addr) = http_proxy_server {
        eprintln!("rustscaled: --http-proxy-server {addr} (TODO: not yet wired)");
    }

    // Load declarative config file if --config was provided.
    let config = if let Some(ref cp) = config_path {
        match Config::load(cp.to_str().unwrap_or("")) {
            Ok(c) => {
                eprintln!("rustscaled: config loaded from {}", cp.display());
                Some(c)
            }
            Err(e) => {
                eprintln!("rustscaled: config load failed: {e}");
                return Err(e.into());
            }
        }
    } else {
        None
    };

    // Resolve hostname: CLI --hostname takes priority, then config file, then default.
    let hostname = hostname
        .or_else(|| config.as_ref().and_then(|c| c.parsed.Hostname.clone()))
        .unwrap_or_else(|| "rustscale".to_string());

    // Resolve auth key: TS_AUTHKEY env, then config file.
    let auth_key = auth_key.or_else(|| config.as_ref().and_then(|c| c.parsed.AuthKey.clone()));

    if let Some(key) = auth_key {
        run_with_auth_key(
            &key,
            &state_dir,
            &hostname,
            &socket_path,
            tun,
            port,
            config_path,
            config,
        )
        .await
    } else {
        run_interactive(
            &state_dir,
            &hostname,
            &socket_path,
            tun,
            port,
            config_path,
            config,
        )
        .await
    }
}

async fn run_with_auth_key(
    auth_key: &str,
    state_dir: &Path,
    hostname: &str,
    socket_path: &Path,
    tun: bool,
    port: Option<u16>,
    config_path: Option<PathBuf>,
    config: Option<Config>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = Server::builder()
        .hostname(hostname)
        .auth_key(auth_key)
        .state_dir(state_dir)
        .localapi_path(socket_path);

    // Apply config-file fields to the builder.
    if let Some(ref cfg) = config {
        if let Some(ref url) = cfg.parsed.ServerURL {
            if !url.is_empty() {
                builder = builder.control_url(url);
            }
        }
        if !cfg.parsed.AdvertiseRoutes.is_empty() {
            builder = builder.advertise_routes(cfg.parsed.AdvertiseRoutes.clone());
        }
        if let Some(true) = cfg.parsed.AcceptRoutes.as_bool() {
            builder = builder.accept_routes(true);
        }
    }
    if let Some(ref cp) = config_path {
        builder = builder.config_path(cp);
    }
    if let Some(p) = port {
        builder = builder.port(p);
    }

    // Apply config prefs to the on-disk prefs so up() picks them up.
    if let Some(ref cfg) = config {
        apply_config_prefs_to_disk(cfg, state_dir)?;
    }

    let mut server = builder.build()?;

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
    let config_path_clone = config_path.clone();
    tokio::select! {
        () = wait_for_shutdown_signal(config_path_clone.as_ref()) => {}
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
    port: Option<u16>,
    config_path: Option<PathBuf>,
    config: Option<Config>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = Server::builder()
        .hostname(hostname)
        .state_dir(state_dir)
        .localapi_path(socket_path);

    // Apply config-file fields to the builder.
    if let Some(ref cfg) = config {
        if let Some(ref url) = cfg.parsed.ServerURL {
            if !url.is_empty() {
                builder = builder.control_url(url);
            }
        }
        if !cfg.parsed.AdvertiseRoutes.is_empty() {
            builder = builder.advertise_routes(cfg.parsed.AdvertiseRoutes.clone());
        }
        if let Some(true) = cfg.parsed.AcceptRoutes.as_bool() {
            builder = builder.accept_routes(true);
        }
    }
    if let Some(ref cp) = config_path {
        builder = builder.config_path(cp);
    }
    if let Some(p) = port {
        builder = builder.port(p);
    }

    // Apply config prefs to the on-disk prefs so up() picks them up.
    if let Some(ref cfg) = config {
        apply_config_prefs_to_disk(cfg, state_dir)?;
    }

    let mut server = builder.build()?;

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
            DaemonCommand::Shutdown => {
                eprintln!("rustscaled: shutdown requested (server not up yet)");
                return Ok(());
            }
            DaemonCommand::ReloadConfig => {
                eprintln!("rustscaled: reload-config requested (server not up yet)");
            }
        }
    }

    if !is_up {
        return Ok(());
    }

    // Phase 2: server is up — wait for shutdown, logout, or LocalAPI shutdown.
    let logout_trigger = server.logout_trigger();
    let config_path_clone = config_path.clone();
    tokio::select! {
        () = wait_for_shutdown_signal(config_path_clone.as_ref()) => {}
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
        Some(cmd) = command_rx.recv() => {
            match cmd {
                DaemonCommand::Shutdown => {
                    eprintln!("rustscaled: shutdown requested via LocalAPI");
                }
                DaemonCommand::ReloadConfig => {
                    if let Some(ref cp) = config_path {
                        eprintln!("rustscaled: reload-config via LocalAPI from {}", cp.display());
                        if let Err(e) = server.reload_config(cp.to_str().unwrap_or("")).await {
                            eprintln!("rustscaled: config reload failed: {e}");
                        }
                    }
                }
                _ => {}
            }
        }
    }

    eprintln!("rustscaled: shutting down...");
    server.close().await;
    Ok(())
}

/// Apply config-file prefs to the on-disk prefs file so that `Server::up()`
/// picks them up via `load_prefs()`. This handles fields that don't have
/// direct `ServerBuilder` equivalents (e.g. `ShieldsUp`, `CorpDNS`,
/// `ExitNodeID`, `RunSSH`, etc.). Fields with builder methods are applied
/// separately in the caller.
fn apply_config_prefs_to_disk(
    config: &Config,
    state_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let masked = config.parsed.to_prefs();
    if masked.is_empty() {
        return Ok(());
    }
    let mut prefs = rustscale_ipn::Prefs::load(state_dir).unwrap_or_default();
    masked.apply_to(&mut prefs);
    prefs.save(state_dir)?;
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

/// Remove stale state files (socket, lock files) from the state directory.
/// Mirrors Go's `cleanupState()` in `cmd/tailscaled/tailscaled.go`.
fn cleanup_state(state_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Remove the LocalAPI socket file if it exists.
    let socket = state_dir.join("rustscaled.sock");
    if socket.exists() {
        std::fs::remove_file(&socket)?;
        eprintln!("rustscaled: removed {}", socket.display());
    }

    // Remove the primary socket path if it exists.
    #[cfg(unix)]
    {
        let primary = rustscale_safesocket::default_socket_path();
        if primary.exists() {
            let _ = std::fs::remove_file(&primary);
            eprintln!("rustscaled: removed {}", primary.display());
        }
    }

    eprintln!("rustscaled: cleanup complete");
    Ok(())
}

fn determine_socket_path(state_dir: &Path) -> PathBuf {
    let primary = rustscale_safesocket::default_socket_path();

    // On Windows, the named pipe path is always the same — no fallback.
    #[cfg(windows)]
    {
        let _ = state_dir;
        primary
    }

    // On Unix, probe whether the primary socket's parent directory is
    // writable by creating a throwaway temp file. We deliberately do NOT
    // bind the real socket here: the daemon binds it later, and binding as a
    // probe is racy (another process could grab the path between probe and
    // real bind) and noisy (a panic during `drop` would leave a stale socket
    // file on disk). If the parent is missing or not writable, fall back to a
    // socket inside the state directory.
    #[cfg(unix)]
    {
        let fallback = state_dir.join("rustscaled.sock");

        let writable = primary.parent().is_some_and(|dir| {
            let probe = dir.join(format!(".rustscaled.probe.{}", std::process::id()));
            let result = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&probe);
            let _ = std::fs::remove_file(&probe);
            result.is_ok()
        });

        if writable {
            primary
        } else {
            fallback
        }
    }
}

#[cfg(unix)]
async fn wait_for_shutdown(config_path: Option<&PathBuf>) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sighup = signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => {
                if let Some(cp) = config_path {
                    eprintln!("rustscaled: SIGHUP received, reloading config from {}", cp.display());
                    // The server reference is not available here; the reload
                    // is handled via the LocalAPI POST /reload-config endpoint.
                    // In practice, the daemon's caller can wire a reload
                    // callback. For now, log and continue.
                    eprintln!("rustscaled: use 'POST /localapi/v0/reload-config' for live reload");
                } else {
                    eprintln!("rustscaled: SIGHUP received (no config file set, ignoring)");
                }
            }
        }
    }
}

/// Signal-wait future usable in `tokio::select!`.
#[cfg(unix)]
async fn wait_for_shutdown_signal(config_path: Option<&PathBuf>) {
    wait_for_shutdown(config_path).await;
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal(_config_path: Option<&PathBuf>) {
    let _ = tokio::signal::ctrl_c().await;
}
