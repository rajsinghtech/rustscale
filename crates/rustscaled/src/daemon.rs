use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use rustscale_conffile::Config;
use rustscale_logpolicy::{Policy, DEFAULT_COLLECTION};
use rustscale_logtail::{LogTail, LogtailLogger};
use rustscale_tsnet::localapi::DaemonCommand;
use rustscale_tsnet::{PreferencePolicy, PreferencePolicySubscription, Server, TunModeConfig};

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
    no_logs_no_support: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_key = std::env::var("TS_AUTHKEY").ok();
    let state_dir = statedir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let socket_path = socket_override.unwrap_or_else(|| determine_socket_path(&state_dir));

    // --cleanup: remove old state files and exit.
    if cleanup {
        log::info!("rustscaled: cleaning up state in {}", state_dir.display());
        cleanup_state(&state_dir)?;
        return Ok(());
    }

    // --socks5-server: not yet wired into the daemon bootstrap.
    // TODO: spawn SOCKS5 listener via tsnet::socks5 when the server is up.
    if let Some(ref addr) = socks5_server {
        log::debug!("rustscaled: --socks5-server {addr} (TODO: not yet wired)");
    }

    // --http-proxy-server: set as environment variable for outbound proxies.
    // TODO: wire into magicsock/controlclient HTTP clients directly.
    if let Some(ref addr) = http_proxy_server {
        log::debug!("rustscaled: --http-proxy-server {addr} (TODO: not yet wired)");
    }

    // Load declarative config file if --config was provided.
    let config = if let Some(ref cp) = config_path {
        match Config::load(cp.to_str().unwrap_or("")) {
            Ok(c) => {
                log::info!("rustscaled: config loaded from {}", cp.display());
                Some(c)
            }
            Err(e) => {
                log::warn!("rustscaled: config load failed: {e}");
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

    let system_policy = Arc::new(InstallUpdatesPolicy::new()?);

    // Apply config preferences before constructing log policy so a persisted
    // NoLogsNoSupport preference takes effect from the first upload task. Then
    // enforce managed preferences over the resulting candidate.
    if let Some(ref cfg) = config {
        apply_config_prefs_to_disk(cfg, &state_dir)?;
    }
    apply_system_policy_prefs_to_disk(&state_dir, &system_policy)?;

    // Go creates logpolicy before its local backend. Keep that order here so
    // the private ID used by upload is the same persisted ID tsnet exposes as
    // Hostinfo.BackendLogID.
    let policy = Policy::new(DEFAULT_COLLECTION, &state_dir)?;
    let prefs = rustscale_ipn::Prefs::load(&state_dir).unwrap_or_default();
    policy.set_enabled(!no_logs_no_support && !prefs.NoLogsNoSupport);
    let logtail = policy.logtail().clone();
    if log::set_boxed_logger(Box::new(LogtailLogger::new(
        logtail.clone(),
        log::LevelFilter::Info,
    )))
    .is_ok()
    {
        log::set_max_level(log::LevelFilter::Info);
    }
    let upload = policy.start_upload()?;

    let result = if let Some(key) = auth_key {
        run_with_auth_key(
            &key,
            &state_dir,
            &hostname,
            &socket_path,
            tun,
            port,
            config_path,
            config,
            logtail,
            system_policy,
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
            logtail,
            system_policy,
        )
        .await
    };

    // Logtail is deliberately shut down after the server so final daemon
    // shutdown messages can still be flushed.
    policy.logtail().flush();
    upload.shutdown().await;
    result
}

trait LogoutRunner {
    type Error: std::fmt::Display;

    fn attempt_logout(
        &mut self,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}

impl LogoutRunner for Server {
    type Error = rustscale_tsnet::TsnetError;

    async fn attempt_logout(&mut self) -> Result<(), Self::Error> {
        Server::logout(self).await
    }
}

/// Retry a retained logout phase with bounded exponential backoff. Each
/// attempt is cancellation-safe because Server transfers transaction ownership
/// before awaiting; shutdown stops daemon retries and Drop continues ownership.
async fn retry_logout_until_shutdown<R, S>(
    runner: &mut R,
    mut shutdown: std::pin::Pin<&mut S>,
) -> bool
where
    R: LogoutRunner,
    S: std::future::Future<Output = ()> + ?Sized,
{
    let mut delay = std::time::Duration::from_millis(25);
    loop {
        let result = tokio::select! {
            result = runner.attempt_logout() => Some(result),
            () = shutdown.as_mut() => None,
        };
        match result {
            Some(Ok(())) => return true,
            Some(Err(error)) => {
                log::warn!("rustscaled: logout incomplete; retrying: {error}");
            }
            None => return false,
        }
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = shutdown.as_mut() => return false,
        }
        delay = (delay * 2).min(std::time::Duration::from_secs(5));
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
    logtail: LogTail,
    system_policy: Arc<InstallUpdatesPolicy>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = Server::builder()
        .hostname(hostname)
        .auth_key(auth_key)
        .state_dir(state_dir)
        .localapi_path(socket_path)
        .logtail(logtail)
        .preference_policy(system_policy);

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

    let mut server = builder.build()?;

    if tun {
        let config = TunModeConfig {
            apply_routes: true,
            ..Default::default()
        };
        Box::pin(server.up_tun(config)).await?;
        log::info!("rustscaled: TUN mode up (hostname={hostname})");
    } else {
        Box::pin(server.up()).await?;
        log::info!("rustscaled: up (hostname={hostname})");
    }

    print_status(&server, socket_path);

    // Wait for either shutdown or logout. A transient register/disk/cleanup
    // failure resumes the retained transaction rather than falling through to
    // close and silently abandoning its remaining phases.
    let logout_trigger = server.logout_trigger();
    let config_path_clone = config_path.clone();
    let mut shutdown = Box::pin(wait_for_shutdown_signal(config_path_clone.as_ref()));
    let logout_requested = tokio::select! {
        () = shutdown.as_mut() => false,
        () = async {
            if let Some(ref trigger) = logout_trigger {
                trigger.notified().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => true,
    };
    if logout_requested {
        log::info!("rustscaled: logout requested");
        if !retry_logout_until_shutdown(&mut server, shutdown.as_mut()).await {
            server.fail_pending_logout_requests("daemon shutdown interrupted logout completion");
            log::info!("rustscaled: shutdown interrupted logout; Drop retained its transaction");
            return Ok(());
        }
        server.complete_pending_logout_requests();
        log::info!("rustscaled: logged out, state cleared → NeedsLogin");
    }

    log::info!("rustscaled: shutting down...");
    server.close().await?;
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
    logtail: LogTail,
    system_policy: Arc<InstallUpdatesPolicy>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = Server::builder()
        .hostname(hostname)
        .state_dir(state_dir)
        .localapi_path(socket_path)
        .logtail(logtail)
        .preference_policy(system_policy);

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

    let mut server = builder.build()?;

    let mut command_rx = server.start_localapi_only().await?;
    log::info!("rustscaled: waiting for login (no TS_AUTHKEY set; use 'rustscale up' or 'rustscale login')");

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
                    log::info!("rustscaled: TUN mode up (hostname={hostname})");
                } else {
                    Box::pin(server.up()).await?;
                    log::info!("rustscaled: up (hostname={hostname})");
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
                    log::info!("rustscaled: TUN mode up (hostname={hostname})");
                } else {
                    Box::pin(server.up()).await?;
                    log::info!("rustscaled: up (hostname={hostname})");
                }
                print_status(&server, socket_path);
                is_up = true;
                break;
            }
            DaemonCommand::Logout => {
                log::info!("rustscaled: logout requested (server not up yet)");
                server.fail_pending_logout_requests("server is not logged in");
            }
            DaemonCommand::Shutdown => {
                log::debug!("rustscaled: shutdown requested (server not up yet)");
                return Ok(());
            }
            DaemonCommand::ReloadConfig => {
                log::debug!("rustscaled: reload-config requested (server not up yet)");
            }
            DaemonCommand::SwitchProfile(id) => {
                log::info!("rustscaled: switching to profile {id}");
                if let Err(e) = server.switch_profile(&id).await {
                    log::warn!("rustscaled: profile switch failed: {e}");
                } else {
                    log::info!("rustscaled: up (hostname={hostname})");
                    print_status(&server, socket_path);
                    is_up = true;
                    break;
                }
            }
        }
    }

    if !is_up {
        return Ok(());
    }

    // Phase 2: server is up — wait for shutdown, logout, or LocalAPI
    // commands. This is a loop so that `SwitchProfile` and `ReloadConfig`
    // can be handled without exiting: after the teardown+restart the
    // daemon continues to wait for the next event.
    let logout_trigger = server.logout_trigger();
    let config_path_clone = config_path.clone();
    let mut shutdown = Box::pin(wait_for_shutdown_signal(config_path_clone.as_ref()));
    loop {
        tokio::select! {
            () = shutdown.as_mut() => break,
            () = async {
                if let Some(ref trigger) = logout_trigger {
                    trigger.notified().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                log::info!("rustscaled: logout requested");
                if !retry_logout_until_shutdown(&mut server, shutdown.as_mut()).await {
                    server.fail_pending_logout_requests(
                        "daemon shutdown interrupted logout completion",
                    );
                    log::info!(
                        "rustscaled: shutdown interrupted logout; Drop retained its transaction"
                    );
                    return Ok(());
                }
                server.complete_pending_logout_requests();
                log::info!("rustscaled: logged out, state cleared → NeedsLogin");
                break;
            }
            Some(cmd) = command_rx.recv() => {
                match cmd {
                    DaemonCommand::Shutdown => {
                        log::debug!("rustscaled: shutdown requested via LocalAPI");
                        break;
                    }
                    DaemonCommand::Logout => {
                        log::info!("rustscaled: logout requested via LocalAPI command");
                        if !retry_logout_until_shutdown(&mut server, shutdown.as_mut()).await {
                            server.fail_pending_logout_requests(
                                "daemon shutdown interrupted logout completion",
                            );
                            return Ok(());
                        }
                        server.complete_pending_logout_requests();
                        log::info!("rustscaled: logged out, state cleared → NeedsLogin");
                        break;
                    }
                    DaemonCommand::ReloadConfig => {
                        if let Some(ref cp) = config_path {
                            log::debug!("rustscaled: reload-config via LocalAPI from {}", cp.display());
                            if let Err(e) = server.reload_config(cp.to_str().unwrap_or("")).await {
                                log::warn!("rustscaled: config reload failed: {e}");
                            }
                        }
                    }
                    DaemonCommand::SwitchProfile(id) => {
                        log::info!("rustscaled: switching to profile {id}");
                        if let Err(e) = server.switch_profile(&id).await {
                            log::warn!("rustscaled: profile switch failed: {e}");
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    log::info!("rustscaled: shutting down...");
    server.close().await?;
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

struct InstallUpdatesPolicy {
    engine: rustscale_syspolicy::PolicyEngine,
}

impl InstallUpdatesPolicy {
    fn new() -> Result<Self, rustscale_syspolicy::PolicyError> {
        Ok(Self {
            engine: rustscale_syspolicy::default_engine(rustscale_syspolicy::PolicyScope::Device)?,
        })
    }
}

struct InstallUpdatesSubscription {
    _registration: rustscale_syspolicy::CallbackRegistration,
}

impl PreferencePolicySubscription for InstallUpdatesSubscription {}

impl PreferencePolicy for InstallUpdatesPolicy {
    fn reconcile(&self, prefs: &mut rustscale_ipn::Prefs) -> Result<bool, String> {
        use rustscale_syspolicy::{PolicyKey, PreferenceOption};

        let option = self
            .engine
            .get_preference_option(PolicyKey::ApplyUpdates, PreferenceOption::UserDecides)
            .map_err(|error| error.to_string())?;
        if option == PreferenceOption::UserDecides {
            return Ok(false);
        }
        let desired = option.should_enable(prefs.AutoUpdate.unwrap_or(false));
        if prefs.AutoUpdate == Some(desired) {
            return Ok(false);
        }
        prefs.AutoUpdate = Some(desired);
        Ok(true)
    }

    fn generation(&self) -> u64 {
        self.engine.snapshot().generation()
    }

    fn allows_update(&self, lower_precedence_choice: bool) -> Result<bool, String> {
        use rustscale_syspolicy::{PolicyKey, PreferenceOption};

        self.engine
            .get_preference_option(PolicyKey::ApplyUpdates, PreferenceOption::UserDecides)
            .map(|option| option.should_enable(lower_precedence_choice))
            .map_err(|error| error.to_string())
    }

    fn subscribe(
        &self,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Box<dyn PreferencePolicySubscription> {
        let registration = self.engine.register_change_callback(move |change| {
            if change.has_changed(rustscale_syspolicy::PolicyKey::ApplyUpdates) {
                callback();
            }
        });
        Box::new(InstallUpdatesSubscription {
            _registration: registration,
        })
    }
}

fn apply_system_policy_prefs_to_disk(
    state_dir: &Path,
    policy: &InstallUpdatesPolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut prefs = rustscale_ipn::Prefs::load(state_dir)?;
    if policy
        .reconcile(&mut prefs)
        .map_err(std::io::Error::other)?
    {
        prefs.save(state_dir)?;
    }
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
        log::debug!("rustscaled: tailscale IPs: {}", ips.join(", "));
    }
    if server.localapi_path().is_some() {
        log::info!(
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
        log::debug!("rustscaled: removed {}", socket.display());
    }

    // Remove the primary socket path if it exists.
    #[cfg(unix)]
    {
        let primary = rustscale_safesocket::default_socket_path();
        if primary.exists() {
            let _ = std::fs::remove_file(&primary);
            log::debug!("rustscaled: removed {}", primary.display());
        }
    }

    log::info!("rustscaled: cleanup complete");
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
                    log::info!("rustscaled: SIGHUP received, reloading config from {}", cp.display());
                    // The server reference is not available here; the reload
                    // is handled via the LocalAPI POST /reload-config endpoint.
                    // In practice, the daemon's caller can wire a reload
                    // callback. For now, log and continue.
                    log::debug!("rustscaled: use 'POST /localapi/v0/reload-config' for live reload");
                } else {
                    log::info!("rustscaled: SIGHUP received (no config file set, ignoring)");
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

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::{Duration, Instant},
    };

    use rustscale_syspolicy::{
        MemoryProvider, PolicyEngine, PolicyErrorKind, PolicyKey, PolicyScope, RawValue,
    };
    use rustscale_tsnet::PreferencePolicy;

    use super::{retry_logout_until_shutdown, InstallUpdatesPolicy, LogoutRunner};

    struct TransientLogout {
        remaining_failures: usize,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl LogoutRunner for TransientLogout {
        type Error = std::io::Error;

        async fn attempt_logout(&mut self) -> Result<(), Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.remaining_failures > 0 {
                self.remaining_failures -= 1;
                Err(std::io::Error::other("injected transient logout failure"))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn daemon_retries_transient_logout_until_durable_success() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut logout = TransientLogout {
            remaining_failures: 2,
            calls: Arc::clone(&calls),
        };
        let mut shutdown = Box::pin(std::future::pending::<()>());
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            retry_logout_until_shutdown(&mut logout, shutdown.as_mut()),
        )
        .await
        .expect("logout retries exceeded their bounded backoff"));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn install_updates_policy_forces_existing_preference() {
        let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
        engine
            .add_provider(
                "test",
                PolicyScope::Device,
                Arc::new(MemoryProvider::from_values(BTreeMap::from([(
                    PolicyKey::ApplyUpdates,
                    RawValue::String("always".into()),
                )]))),
            )
            .unwrap();
        let policy = InstallUpdatesPolicy { engine };
        let mut prefs = rustscale_ipn::Prefs {
            AutoUpdate: Some(false),
            ..Default::default()
        };
        assert!(policy.reconcile(&mut prefs).unwrap());
        assert_eq!(prefs.AutoUpdate, Some(true));
    }

    #[test]
    fn managed_never_denies_hostinfo_update_even_when_lower_precedence_allows() {
        let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
        engine
            .add_provider(
                "managed",
                PolicyScope::Device,
                Arc::new(MemoryProvider::from_values(BTreeMap::from([(
                    PolicyKey::ApplyUpdates,
                    RawValue::String("never".into()),
                )]))),
            )
            .unwrap();
        let policy = InstallUpdatesPolicy { engine };
        assert!(!policy.allows_update(true).unwrap());

        let undecided = InstallUpdatesPolicy {
            engine: PolicyEngine::well_known(PolicyScope::Device).unwrap(),
        };
        assert!(undecided.allows_update(true).unwrap());
        assert!(!undecided.allows_update(false).unwrap());
    }

    #[test]
    fn invalid_install_updates_uses_upstream_default_but_keeps_diagnostic() {
        let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
        engine
            .add_provider(
                "test",
                PolicyScope::Device,
                Arc::new(MemoryProvider::from_values(BTreeMap::from([(
                    PolicyKey::ApplyUpdates,
                    RawValue::String("sometimes".into()),
                )]))),
            )
            .unwrap();
        let policy = InstallUpdatesPolicy { engine };
        let mut prefs = rustscale_ipn::Prefs::default();
        assert!(!policy.reconcile(&mut prefs).unwrap());
        assert_eq!(prefs.AutoUpdate, None);
        assert_eq!(
            policy
                .engine
                .snapshot()
                .item(PolicyKey::ApplyUpdates)
                .unwrap()
                .error
                .as_ref()
                .unwrap()
                .kind,
            PolicyErrorKind::Parse
        );
    }

    #[test]
    fn provider_change_notifies_live_reconciler_asynchronously() {
        let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
        let provider = Arc::new(MemoryProvider::new());
        engine
            .add_provider("test", PolicyScope::Device, provider.clone())
            .unwrap();
        let policy = InstallUpdatesPolicy { engine };
        let notified = Arc::new(AtomicBool::new(false));
        let notified_by_callback = notified.clone();
        let _subscription = policy.subscribe(Arc::new(move || {
            notified_by_callback.store(true, Ordering::SeqCst);
        }));

        provider.set(PolicyKey::ApplyUpdates, RawValue::String("never".into()));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !notified.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(notified.load(Ordering::SeqCst));
        let mut prefs = rustscale_ipn::Prefs {
            AutoUpdate: Some(true),
            ..Default::default()
        };
        assert!(policy.reconcile(&mut prefs).unwrap());
        assert_eq!(prefs.AutoUpdate, Some(false));
    }
}
