use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use rustscale_conffile::Config;
use rustscale_logpolicy::{Policy, DEFAULT_COLLECTION};
use rustscale_logtail::{LogTail, LogtailLogger};
use rustscale_tsnet::localapi::DaemonCommand;
use rustscale_tsnet::{
    PreferencePolicy, PreferencePolicySubscription, Server, TsnetError, TunModeConfig,
};

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

trait CloseRunner {
    type Error: std::fmt::Display;

    fn attempt_close(
        &mut self,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}

impl CloseRunner for Server {
    type Error = TsnetError;

    async fn attempt_close(&mut self) -> Result<(), Self::Error> {
        Server::close(self).await
    }
}

/// Server cleanup deliberately retains uncertain ownership for retry. Give
/// daemon shutdown a bounded retry window so transient port-mapper or task
/// cleanup uncertainty does not turn an otherwise successful service stop
/// into a permanent failure.
async fn retry_close<R: CloseRunner>(runner: &mut R) -> Result<(), R::Error> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut delay = std::time::Duration::from_millis(25);
    loop {
        match runner.attempt_close().await {
            Ok(()) => return Ok(()),
            Err(error) if tokio::time::Instant::now() < deadline => {
                log::warn!("rustscaled: shutdown cleanup incomplete; retrying: {error}");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_millis(500));
            }
            Err(error) => return Err(error),
        }
    }
}

const UNCONFIRMED_EXTERNAL_PORTMAP_RELEASE: &str = "server cleanup is busy or failed; retry close: magicsock cleanup: portmapper cleanup incomplete: protocol error: portmapper cleanup remains uncertain";

fn is_only_unconfirmed_external_portmap_release(error: &TsnetError) -> bool {
    matches!(error, TsnetError::ShutdownIncomplete(detail) if detail == UNCONFIRMED_EXTERNAL_PORTMAP_RELEASE)
}

async fn close_server(server: &mut Server) -> Result<(), TsnetError> {
    match retry_close(server).await {
        Ok(()) => Ok(()),
        Err(error) if is_only_unconfirmed_external_portmap_release(&error) => {
            // NAT-PMP/PCP/UPnP deletion has no reliable acknowledgement on
            // every router. After bounded retries all local tasks and send
            // ownership are already closed; an external lease can only age
            // out. Do not make systemd treat that sole uncertainty as a crash.
            log::warn!(
                "rustscaled: shutdown complete with unconfirmed external port mapping release"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
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
    close_server(&mut server).await?;
    Ok(())
}

async fn bring_up_until_shutdown<S>(
    server: &mut Server,
    tun: bool,
    mut shutdown: std::pin::Pin<&mut S>,
) -> Result<bool, TsnetError>
where
    S: std::future::Future<Output = ()> + ?Sized,
{
    let startup = async {
        if tun {
            let config = TunModeConfig {
                apply_routes: true,
                ..Default::default()
            };
            Box::pin(server.up_tun(config)).await.map(|_| ())
        } else {
            Box::pin(server.up()).await.map(|_| ())
        }
    };
    tokio::select! {
        result = startup => result.map(|()| true),
        () = shutdown.as_mut() => Ok(false),
    }
}

enum BringUpEvent {
    Running,
    Command(Option<DaemonCommand>),
    Shutdown,
}

/// Poll one startup generation while retaining the sole mutable `Server`
/// owner in this task. Returning `Command` drops the in-flight `up*` future,
/// which transfers partial bootstrap/startup ownership to tsnet's rollback
/// supervisors. The next `up*` joins those supervisors before bootstrapping.
async fn bring_up_until_event<S>(
    server: &mut Server,
    tun: bool,
    command_rx: &mut tokio::sync::mpsc::UnboundedReceiver<DaemonCommand>,
    mut shutdown: std::pin::Pin<&mut S>,
) -> Result<BringUpEvent, TsnetError>
where
    S: std::future::Future<Output = ()> + ?Sized,
{
    let startup = async {
        if tun {
            let config = TunModeConfig {
                apply_routes: true,
                ..Default::default()
            };
            Box::pin(server.up_tun(config)).await.map(|_| ())
        } else {
            Box::pin(server.up()).await.map(|_| ())
        }
    };
    tokio::select! {
        result = startup => result.map(|()| BringUpEvent::Running),
        command = command_rx.recv() => Ok(BringUpEvent::Command(command)),
        () = shutdown.as_mut() => Ok(BringUpEvent::Shutdown),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginLoopOutcome {
    Running,
    Shutdown,
    CommandsClosed,
}

/// Admit pre-login lifecycle commands and let the newest Start or interactive
/// login supersede an older pending startup. Each supersession drops exactly
/// one borrowed startup future; `Server` itself never leaves this owner.
async fn drive_login_until_running<S>(
    server: &mut Server,
    command_rx: &mut tokio::sync::mpsc::UnboundedReceiver<DaemonCommand>,
    tun: bool,
    config_path: Option<&PathBuf>,
    mut shutdown: std::pin::Pin<&mut S>,
) -> Result<LoginLoopOutcome, TsnetError>
where
    S: std::future::Future<Output = ()> + ?Sized,
{
    let mut pending_command = None;
    loop {
        let command = if let Some(command) = pending_command.take() {
            Some(command)
        } else {
            tokio::select! {
                command = command_rx.recv() => command,
                () = shutdown.as_mut() => return Ok(LoginLoopOutcome::Shutdown),
            }
        };
        let Some(command) = command else {
            return Ok(LoginLoopOutcome::CommandsClosed);
        };

        match command {
            DaemonCommand::Start { auth_key } => {
                // StartOptions.AuthKey is an intent for this generation, not
                // sticky daemon configuration. Clearing on None also prevents
                // a cancelled auth-key generation from winning a later
                // interactive/no-auth request.
                server.clear_auth_key();
                if let Some(key) = auth_key {
                    server.set_auth_key(key);
                }
            }
            DaemonCommand::LoginInteractive => {
                server.clear_auth_key();
            }
            DaemonCommand::Logout => {
                server.fail_pending_logout_requests("server is not logged in");
                continue;
            }
            DaemonCommand::Shutdown => return Ok(LoginLoopOutcome::Shutdown),
            DaemonCommand::ReloadConfig => {
                if let Some(path) = config_path {
                    if let Err(error) = server.reload_config(path.to_str().unwrap_or("")).await {
                        log::warn!("rustscaled: config reload failed: {error}");
                    }
                }
                continue;
            }
            DaemonCommand::SwitchProfile(id) => {
                if let Err(error) = server.switch_profile(&id).await {
                    log::warn!("rustscaled: profile switch failed: {error}");
                    continue;
                }
                return Ok(LoginLoopOutcome::Running);
            }
        }

        match bring_up_until_event(server, tun, command_rx, shutdown.as_mut()).await? {
            BringUpEvent::Running => return Ok(LoginLoopOutcome::Running),
            BringUpEvent::Command(command) => pending_command = command,
            BringUpEvent::Shutdown => return Ok(LoginLoopOutcome::Shutdown),
        }
    }
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
    // Install signal handling before any potentially long startup. A status
    // watcher can observe Running before all startup resources commit, so an
    // immediate service stop must cancel through Server's rollback owner
    // rather than terminating the process mid-bootstrap.
    let config_path_clone = config_path.clone();
    let mut shutdown = Box::pin(wait_for_shutdown_signal(config_path_clone.as_ref()));

    // Resume an installed node without requiring another `rustscale up` after
    // every service restart. Fresh/default and explicitly logged-out profiles
    // remain in NeedsLogin with LocalAPI available.
    let persisted_prefs = rustscale_ipn::Prefs::load(state_dir).unwrap_or_default();
    let mut is_up = false;
    if should_resume_persisted_node(&persisted_prefs) {
        if !bring_up_until_shutdown(&mut server, tun, shutdown.as_mut()).await? {
            log::info!("rustscaled: shutdown interrupted persisted-node restore");
            close_server(&mut server).await?;
            return Ok(());
        }
        if tun {
            log::info!("rustscaled: restored TUN mode (hostname={hostname})");
        } else {
            log::info!("rustscaled: restored node (hostname={hostname})");
        }
        print_status(&server, socket_path);
        is_up = true;
    }

    // Phase 1: wait for Start/LoginInteractive to bring a fresh or logged-out
    // profile up. A newer lifecycle intent cancels and supersedes an admitted
    // startup without moving the sole mutable Server into a detached task.
    if !is_up {
        match drive_login_until_running(
            &mut server,
            &mut command_rx,
            tun,
            config_path.as_ref(),
            shutdown.as_mut(),
        )
        .await?
        {
            LoginLoopOutcome::Running => {
                if tun {
                    log::info!("rustscaled: TUN mode up (hostname={hostname})");
                } else {
                    log::info!("rustscaled: up (hostname={hostname})");
                }
                print_status(&server, socket_path);
                is_up = true;
            }
            LoginLoopOutcome::Shutdown => {
                log::info!("rustscaled: shutdown while waiting for login");
                close_server(&mut server).await?;
                return Ok(());
            }
            LoginLoopOutcome::CommandsClosed => {}
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
    close_server(&mut server).await?;
    Ok(())
}

fn should_resume_persisted_node(prefs: &rustscale_ipn::Prefs) -> bool {
    prefs.WantRunning && !prefs.LoggedOut
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
    if rustscale_safesocket::remove_socket_file(&socket)? {
        log::debug!("rustscaled: removed {}", socket.display());
    }

    // Remove the primary socket path only if it is still a socket. A path in
    // a caller-controlled directory may have been replaced after shutdown.
    #[cfg(unix)]
    {
        let primary = rustscale_safesocket::default_socket_path();
        if rustscale_safesocket::remove_socket_file(&primary)? {
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

    use super::{
        drive_login_until_running, is_only_unconfirmed_external_portmap_release, retry_close,
        retry_logout_until_shutdown, should_resume_persisted_node, CloseRunner,
        InstallUpdatesPolicy, LoginLoopOutcome, LogoutRunner, UNCONFIRMED_EXTERNAL_PORTMAP_RELEASE,
    };

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_key_start_supersedes_abandoned_no_auth_generation() {
        let mut control = rustscale_testcontrol::Server::new();
        control.set_require_auth(true);
        control.start().await.unwrap();

        let state_dir = tempfile::tempdir().unwrap();
        let socket = state_dir.path().join("supersede.sock");
        let mut server = rustscale_tsnet::Server::builder()
            .hostname("start-supersession")
            .control_url(control.base_url())
            .state_dir(state_dir.path())
            .localapi_path(&socket)
            .disable_portmapping(true)
            .build()
            .unwrap();
        let mut commands = server.start_localapi_only().await.unwrap();
        let client = rustscale_localclient::LocalClient::new(&socket);
        let mut shutdown = Box::pin(std::future::pending::<()>());

        let requests = async {
            client
                .start(&rustscale_ipn::StartOptions::default())
                .await
                .expect("admit no-auth Start");
            let stale_auth_url = control
                .await_auth_url(Duration::from_secs(5))
                .await
                .expect("no-auth generation did not reach interactive auth");

            // Leave the interactive URL abandoned. The newer auth-key intent
            // must cancel that generation and reach Running without it.
            control.set_require_auth(false);
            client
                .start(&rustscale_ipn::StartOptions {
                    AuthKey: "tskey-test-superseding-secret".into(),
                    ..Default::default()
                })
                .await
                .expect("admit auth-key Start");
            stale_auth_url
        };
        let drive =
            drive_login_until_running(&mut server, &mut commands, false, None, shutdown.as_mut());
        let (outcome, stale_auth_url) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(drive, requests)
        })
        .await
        .expect("auth-key supersession timed out");

        assert_eq!(outcome.unwrap(), LoginLoopOutcome::Running);
        assert!(server.status().up);
        assert_eq!(
            server.ipn_status().await.unwrap().BackendState,
            "Running",
            "abandoned interactive generation became authoritative"
        );
        assert_eq!(control.register_auth_presence(), [false, true]);
        assert!(
            !stale_auth_url.is_empty(),
            "test did not retain the abandoned generation's intent"
        );
        server.close().await.unwrap();
    }

    struct TransientClose {
        remaining_failures: usize,
        calls: usize,
    }

    impl CloseRunner for TransientClose {
        type Error = std::io::Error;

        async fn attempt_close(&mut self) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.remaining_failures > 0 {
                self.remaining_failures -= 1;
                Err(std::io::Error::other("injected cleanup uncertainty"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn daemon_accepts_only_exact_external_portmap_release_uncertainty() {
        let accepted = rustscale_tsnet::TsnetError::ShutdownIncomplete(
            UNCONFIRMED_EXTERNAL_PORTMAP_RELEASE.into(),
        );
        assert!(is_only_unconfirmed_external_portmap_release(&accepted));
        let rejected =
            rustscale_tsnet::TsnetError::ShutdownIncomplete("router cleanup incomplete".into());
        assert!(!is_only_unconfirmed_external_portmap_release(&rejected));
    }

    #[tokio::test]
    async fn daemon_retries_retained_close_ownership() {
        let mut close = TransientClose {
            remaining_failures: 2,
            calls: 0,
        };
        retry_close(&mut close).await.unwrap();
        assert_eq!(close.calls, 3);
    }

    #[test]
    fn daemon_resumes_only_wanted_non_logged_out_profiles() {
        let mut prefs = rustscale_ipn::Prefs::default();
        assert!(!should_resume_persisted_node(&prefs));

        prefs.WantRunning = true;
        assert!(should_resume_persisted_node(&prefs));

        prefs.LoggedOut = true;
        assert!(!should_resume_persisted_node(&prefs));
    }

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
