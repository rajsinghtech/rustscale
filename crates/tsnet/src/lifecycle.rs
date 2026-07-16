#[cfg(test)]
mod startup_rollback_tests;

#[allow(clippy::wildcard_imports)]
use super::*;
use zeroize::{Zeroize, Zeroizing};

/// One-attempt auth material. It cannot be cloned and its formatting is always
/// redacted; dropping it zeroizes the allocation.
pub(crate) struct TransientAuthKey(Zeroizing<String>);

impl TransientAuthKey {
    fn new(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }

    fn take(&mut self) -> String {
        std::mem::take(&mut *self.0)
    }

    #[cfg(all(test, feature = "identity-federation"))]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for TransientAuthKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransientAuthKey(<redacted>)")
    }
}

pub(crate) fn take_initial_register_auth(
    auth: &mut Option<TransientAuthKey>,
) -> Option<rustscale_tailcfg::RegisterResponseAuth> {
    let mut secret = auth.take()?;
    if secret.0.is_empty() {
        return None;
    }
    Some(rustscale_tailcfg::RegisterResponseAuth {
        AuthKey: secret.take(),
    })
}

pub(crate) fn clear_register_auth(request: &mut RegisterRequest) {
    if let Some(auth) = request.Auth.as_mut() {
        auth.AuthKey.zeroize();
    }
    request.Auth = None;
}

#[derive(Clone)]
enum StartupDeliveryEvent {
    Backend(rustscale_ipn::State),
    Profile(Box<(rustscale_ipn::LoginProfile, rustscale_ipn::Prefs, bool)>),
}

struct StartupDeliveryState {
    active: bool,
    draining: bool,
    queue: std::collections::VecDeque<StartupDeliveryEvent>,
}

struct StartupDelivery {
    host: rustscale_ipnext::Host,
    state: std::sync::Mutex<StartupDeliveryState>,
}

impl StartupDelivery {
    fn new(host: rustscale_ipnext::Host) -> Self {
        Self {
            host,
            state: std::sync::Mutex::new(StartupDeliveryState {
                active: false,
                draining: false,
                queue: std::collections::VecDeque::new(),
            }),
        }
    }

    fn enqueue(&self, event: StartupDeliveryEvent) {
        let should_drain = {
            let mut state = self.state.lock().unwrap();
            state.queue.push_back(event);
            if !state.active || state.draining {
                false
            } else {
                state.draining = true;
                true
            }
        };
        if should_drain {
            self.drain();
        }
    }

    fn activate(&self, initial: Vec<StartupDeliveryEvent>) {
        let should_drain = {
            let mut state = self.state.lock().unwrap();
            for event in initial.into_iter().rev() {
                state.queue.push_front(event);
            }
            state.active = true;
            if state.draining {
                false
            } else {
                state.draining = true;
                true
            }
        };
        if should_drain {
            self.drain();
        }
    }

    fn drain(&self) {
        loop {
            let event = {
                let mut state = self.state.lock().unwrap();
                if let Some(event) = state.queue.pop_front() {
                    event
                } else {
                    state.draining = false;
                    return;
                }
            };
            match event {
                StartupDeliveryEvent::Backend(state) => {
                    let _ = self.host.publish_backend_state(state);
                }
                StartupDeliveryEvent::Profile(snapshot) => {
                    let (profile, prefs, same_node) = *snapshot;
                    let _ = self.host.publish_profile_state(profile, prefs, same_node);
                }
            }
        }
    }
}

const ROLLBACK_CLEANUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Transfer rollback ownership off the ambient Tokio runtime. Futures can be
/// dropped while a runtime is being destroyed (or with no runtime entered at
/// all); a dedicated owner must still join tasks and remove OS state.
fn spawn_rollback_cleanup<F>(name: &'static str, cleanup: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Err(error) = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    log::error!("tsnet: failed to build {name} runtime: {error}");
                    return;
                }
            };
            if runtime
                .block_on(
                    async move { tokio::time::timeout(ROLLBACK_CLEANUP_DEADLINE, cleanup).await },
                )
                .is_err()
            {
                log::error!(
                    "tsnet: {name} exceeded its bounded cleanup deadline; revoked resources leaked"
                );
            }
        })
    {
        log::error!("tsnet: failed to spawn {name}: {error}");
    }
}

struct BootstrapRollback {
    supervisor: Arc<BootstrapSupervisor>,
    watchdog: Watchdog,
    map_tasks: Option<Arc<MapSessionTasks>>,
    netlog: Option<Arc<rustscale_netlog::Logger>>,
    magicsock: Option<Arc<Magicsock>>,
    armed: bool,
}

impl BootstrapRollback {
    fn new(supervisor: Arc<BootstrapSupervisor>, watchdog: Watchdog) -> Self {
        Self {
            supervisor,
            watchdog,
            map_tasks: None,
            netlog: None,
            magicsock: None,
            armed: true,
        }
    }

    fn set_map_task(&mut self, map_task: JoinHandle<()>) {
        self.map_tasks = Some(MapSessionTasks::new(map_task));
    }

    fn commit(mut self) -> (Arc<MapSessionTasks>, Option<Arc<rustscale_netlog::Logger>>) {
        self.armed = false;
        let map_tasks = self
            .map_tasks
            .take()
            .expect("bootstrap map task ownership missing");
        (map_tasks, self.netlog.take())
    }
}

impl Drop for BootstrapRollback {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let map_tasks = self.map_tasks.take();
        if let Some(tasks) = map_tasks.as_ref() {
            tasks.begin_shutdown();
        }
        let netlog = self.netlog.take();
        let magicsock = self.magicsock.take();
        if let Some(logger) = netlog.as_ref() {
            logger.request_stop();
        }
        let watchdog = self.watchdog.clone();
        watchdog.stop();
        let completion = self.supervisor.begin_cleanup();
        spawn_rollback_cleanup("rustscale-bootstrap-rollback", async move {
            let _completion = completion;
            watchdog.stop_and_wait().await;
            if let Some(tasks) = map_tasks {
                tasks.join().await;
            }
            if let Some(logger) = netlog {
                let _ = logger.stop().await;
            }
            if let Some(magicsock) = magicsock {
                let _ = shutdown_magicsock(&magicsock).await;
            }
        });
    }
}

const COMPONENT_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(test)]
const ROUTER_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(not(test))]
const ROUTER_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const ROUTER_CLEANUP_WORKERS: usize = 2;
const ROUTER_CLEANUP_QUEUE_CAPACITY: usize = 16;

struct RouterCleanupAttempt {
    result: std::sync::Mutex<Option<Result<(), String>>>,
    changed: tokio::sync::Notify,
}

struct RouterCleanupJob {
    router: SharedRouter,
    attempt: Arc<RouterCleanupAttempt>,
}

struct RouterCleanupScheduler {
    sender: std::sync::mpsc::SyncSender<RouterCleanupJob>,
    attempts: std::sync::Mutex<std::collections::HashMap<usize, Arc<RouterCleanupAttempt>>>,
}

impl RouterCleanupScheduler {
    fn global() -> &'static Self {
        static SCHEDULER: std::sync::OnceLock<RouterCleanupScheduler> = std::sync::OnceLock::new();
        SCHEDULER.get_or_init(|| {
            let (sender, receiver) =
                std::sync::mpsc::sync_channel::<RouterCleanupJob>(ROUTER_CLEANUP_QUEUE_CAPACITY);
            let receiver = Arc::new(std::sync::Mutex::new(receiver));
            for worker in 0..ROUTER_CLEANUP_WORKERS {
                let receiver = Arc::clone(&receiver);
                std::thread::Builder::new()
                    .name(format!("rustscale-router-close-{worker}"))
                    .spawn(move || loop {
                        let job = match receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv()
                        {
                            Ok(job) => job,
                            Err(_) => return,
                        };
                        let result = cleanup_router_owner_blocking(&job.router)
                            .map_err(|error| error.to_string());
                        *job.attempt
                            .result
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
                        job.attempt.changed.notify_waiters();
                    })
                    .expect("spawn bounded router cleanup worker");
            }
            Self {
                sender,
                attempts: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        })
    }

    fn attempt(&self, router: &SharedRouter) -> Result<Arc<RouterCleanupAttempt>, TsnetError> {
        let key = Arc::as_ptr(router) as usize;
        let mut attempts = self
            .attempts
            .lock()
            .map_err(|_| TsnetError::Builder("router cleanup attempt lock poisoned".into()))?;
        if let Some(attempt) = attempts.get(&key) {
            return Ok(Arc::clone(attempt));
        }
        let attempt = Arc::new(RouterCleanupAttempt {
            result: std::sync::Mutex::new(None),
            changed: tokio::sync::Notify::new(),
        });
        attempts.insert(key, Arc::clone(&attempt));
        if let Err(error) = self.sender.try_send(RouterCleanupJob {
            router: Arc::clone(router),
            attempt: Arc::clone(&attempt),
        }) {
            attempts.remove(&key);
            return Err(TsnetError::ShutdownIncomplete(format!(
                "router cleanup worker queue unavailable: {error}"
            )));
        }
        Ok(attempt)
    }

    fn forget(&self, key: usize, attempt: &Arc<RouterCleanupAttempt>) {
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if attempts
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, attempt))
        {
            attempts.remove(&key);
        }
    }
}

async fn wait_router_cleanup(router: &SharedRouter) -> Result<(), TsnetError> {
    let scheduler = RouterCleanupScheduler::global();
    let key = Arc::as_ptr(router) as usize;
    let attempt = scheduler.attempt(router)?;
    let wait = async {
        loop {
            let changed = attempt.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(result) = attempt
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                return result;
            }
            changed.await;
        }
    };
    match tokio::time::timeout(ROUTER_CLEANUP_TIMEOUT, wait).await {
        Ok(result) => {
            scheduler.forget(key, &attempt);
            result.map_err(|error| TsnetError::Builder(format!("route cleanup failed: {error}")))
        }
        Err(_) => Err(TsnetError::ShutdownIncomplete(
            "route cleanup exceeded its bounded worker deadline".into(),
        )),
    }
}

async fn shutdown_magicsock(magicsock: &Magicsock) -> Result<(), String> {
    let portmapper = magicsock
        .shutdown_portmapper(COMPONENT_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| format!("portmapper cleanup incomplete: {error}"));
    let runtime = magicsock
        .shutdown(COMPONENT_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| format!("magicsock cleanup incomplete: {error}"));
    portmapper.and(runtime)
}

struct PrestartedMagicsockRollback {
    supervisor: Arc<BootstrapSupervisor>,
    magicsock: Option<Arc<Magicsock>>,
}

impl PrestartedMagicsockRollback {
    fn new(supervisor: Arc<BootstrapSupervisor>, magicsock: Arc<Magicsock>) -> Self {
        Self {
            supervisor,
            magicsock: Some(magicsock),
        }
    }

    fn commit(&mut self) -> Arc<Magicsock> {
        self.magicsock
            .take()
            .expect("pre-started Magicsock missing")
    }
}

impl Drop for PrestartedMagicsockRollback {
    fn drop(&mut self) {
        let Some(magicsock) = self.magicsock.take() else {
            return;
        };
        let completion = self.supervisor.begin_cleanup();
        spawn_rollback_cleanup("rustscale-prestarted-rollback", async move {
            let _completion = completion;
            if let Err(error) = shutdown_magicsock(&magicsock).await {
                log::warn!("tsnet: pre-started magicsock rollback: {error}");
            }
        });
    }
}

struct StartupRollback {
    armed: bool,
    supervisor: Arc<BootstrapSupervisor>,
    cancel: Arc<CancelToken>,
    watchdog: Watchdog,
    tasks: Vec<JoinHandle<()>>,
    map_tasks: Arc<MapSessionTasks>,
    audit_logger: Option<Arc<rustscale_auditlog::Logger>>,
    netlog: Option<Arc<rustscale_netlog::Logger>>,
    monitor: Option<rustscale_netmon::MonitorHandle>,
    magicsock: Option<Arc<Magicsock>>,
    router: Option<SharedRouter>,
    localapi: Option<localapi::LocalApiHandle>,
    localapi_start: Option<tokio::sync::oneshot::Sender<()>>,
    localapi_handoff: Option<localapi::LocalApiPathHandoff>,
    localapi_generation_handoff: Option<localapi::LocalApiGenerationHandoff>,
    serve: Option<Arc<serve::ServeRunner>>,
    localapi_socket: Option<PathBuf>,
    os_dns_configurator: Option<Box<dyn OsConfigurator + Send>>,
    hostinfo_hooks: Vec<hostinfo::HostinfoHookHandle>,
}

impl StartupRollback {
    fn new(
        supervisor: Arc<BootstrapSupervisor>,
        cancel: Arc<CancelToken>,
        watchdog: Watchdog,
        map_tasks: Arc<MapSessionTasks>,
        netlog: Option<Arc<rustscale_netlog::Logger>>,
    ) -> Self {
        Self {
            armed: true,
            supervisor,
            cancel,
            watchdog,
            tasks: Vec::new(),
            map_tasks,
            audit_logger: None,
            netlog,
            monitor: None,
            magicsock: None,
            router: None,
            localapi: None,
            localapi_start: None,
            localapi_handoff: None,
            localapi_generation_handoff: None,
            serve: None,
            localapi_socket: None,
            os_dns_configurator: None,
            hostinfo_hooks: Vec::new(),
        }
    }

    fn track(&mut self, task: JoinHandle<()>) {
        self.tasks.push(task);
    }

    fn take_monitor(&mut self) -> Option<rustscale_netmon::MonitorHandle> {
        self.monitor.take()
    }

    fn take_localapi(&mut self) -> Option<localapi::LocalApiHandle> {
        self.localapi.take()
    }

    /// Activate and commit a prepared LocalAPI path transaction. This method
    /// contains no await point: once the old path becomes irreversible, the
    /// replacement and all startup resources transfer to RunningState in the
    /// same poll.
    fn commit_localapi_handoff(&mut self) -> Result<(), TsnetError> {
        let Some(start) = self.localapi_start.take() else {
            if let Some(handoff) = self.localapi_generation_handoff.take() {
                handoff.commit();
            }
            return Ok(());
        };
        // This is the final synchronous commit section. Acceptance may begin
        // on the private pathname, then one rename publishes the replacement;
        // no advertised-path operation occurs during preparation.
        start.send(()).map_err(|()| {
            TsnetError::Builder("LocalAPI replacement stopped before activation".into())
        })?;
        let handoff = self
            .localapi_handoff
            .as_mut()
            .expect("LocalAPI activation missing path handoff");
        let handle = self
            .localapi
            .as_mut()
            .expect("LocalAPI activation missing listener handle");
        handoff
            .commit(handle)
            .map_err(|error| TsnetError::Builder(format!("publishing LocalAPI: {error}")))?;
        self.localapi_handoff.take();
        self.localapi_generation_handoff
            .take()
            .expect("LocalAPI activation missing mutation handoff")
            .commit();
        Ok(())
    }

    fn take_serve(&mut self) -> Option<Arc<serve::ServeRunner>> {
        self.serve.take()
    }

    fn take_os_dns_configurator(&mut self) -> Option<Box<dyn OsConfigurator + Send>> {
        self.os_dns_configurator.take()
    }

    fn take_hostinfo_hooks(&mut self) -> Vec<hostinfo::HostinfoHookHandle> {
        std::mem::take(&mut self.hostinfo_hooks)
    }

    fn commit_tasks(&mut self) -> Vec<JoinHandle<()>> {
        self.armed = false;
        std::mem::take(&mut self.tasks)
    }
}

impl Drop for StartupRollback {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.cancel.cancel();
        self.watchdog.stop();
        self.map_tasks.begin_shutdown();
        let map_tasks = Arc::clone(&self.map_tasks);
        let tasks = std::mem::take(&mut self.tasks);
        let router = self.router.take();
        // Neither prepared transaction has touched the advertised pathname.
        // Dropping the generation handoff re-admits the old listener before
        // the private replacement is stopped asynchronously.
        let had_localapi_handoff = self.localapi_handoff.is_some();
        drop(self.localapi_generation_handoff.take());
        drop(self.localapi_handoff.take());
        self.localapi_start.take();
        let localapi_socket = self.localapi_socket.take();
        if !had_localapi_handoff {
            if let Some(path) = localapi_socket.as_ref() {
                let _ = std::fs::remove_file(path);
            }
        }
        let mut configurator = self.os_dns_configurator.take();
        let audit_logger = self.audit_logger.take();
        let netlog = self.netlog.take();
        let monitor = self.monitor.take();
        let magicsock = self.magicsock.take();
        let localapi = self.localapi.take();
        let serve = self.serve.take();
        if let Some(logger) = audit_logger.as_ref() {
            logger.request_stop();
        }
        if let Some(logger) = netlog.as_ref() {
            logger.request_stop();
        }
        let watchdog = self.watchdog.clone();
        let completion = self.supervisor.begin_cleanup();
        spawn_rollback_cleanup("rustscale-startup-rollback", async move {
            let _completion = completion;
            if let Some(localapi) = localapi {
                // A prepared handoff still owns only its private staging
                // pathname, so ordinary shutdown removes exactly that.
                localapi.shutdown().await;
            }
            // A rolled-back handoff never changed the old advertised
            // generation, while a non-handoff path was removed above.
            drop(localapi_socket);
            if let Some(serve) = serve {
                serve.stop().await;
            }
            drain_generation_tasks(tasks).await;
            map_tasks.join().await;
            if let Some(mut monitor) = monitor {
                monitor.shutdown_and_wait().await;
            }
            // Every route-mutating owner is now joined. Router teardown is
            // deliberately last so no map/local/link callback can reinstall.
            if let Some(router) = router {
                let _ = Server::cleanup_or_supervise(router).await;
            }
            if let Some(configurator) = configurator.as_mut() {
                let _ = configurator.close();
            }
            if let Some(magicsock) = magicsock {
                if let Err(error) = shutdown_magicsock(&magicsock).await {
                    log::warn!("tsnet: startup rollback magicsock shutdown: {error}");
                }
            }
            watchdog.stop_and_wait().await;
            if let Some(logger) = netlog {
                if let Err(error) = logger.stop().await {
                    log::warn!("tsnet: startup rollback netlog shutdown: {error}");
                }
            }
            if let Some(logger) = audit_logger {
                logger
                    .flush_and_stop(std::time::Duration::from_secs(5))
                    .await;
            }
        });
    }
}

async fn drain_generation_tasks(tasks: Vec<JoinHandle<()>>) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    while tasks.iter().any(|task| !task.is_finished()) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    for task in &tasks {
        if !task.is_finished() {
            task.abort();
        }
    }
    for task in tasks {
        let _ = task.await;
    }
}

async fn quiesce_pre_started(pre_started: &mut PreStartedLocalApi) {
    if let Some(handle) = pre_started.handle.take() {
        let path = handle.socket_path.clone();
        handle.shutdown().await;
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::remove_file(&pre_started.socket_path);
}

async fn cleanup_pre_started(mut pre_started: PreStartedLocalApi, remove_advertised_path: bool) {
    if remove_advertised_path {
        quiesce_pre_started(&mut pre_started).await;
    } else if let Some(handle) = pre_started.handle.take() {
        // A committed handoff has moved the replacement listener onto this
        // path, so retiring the old listener must not unlink its successor.
        handle.shutdown_preserving_path().await;
    }
    if let Some(magicsock) = pre_started.magicsock.take() {
        if let Err(error) = shutdown_magicsock(&magicsock).await {
            log::warn!("tsnet: pre-login magicsock shutdown: {error}");
        }
    }
}

async fn shutdown_extension_host(
    host: rustscale_ipnext::ExtensionHost,
) -> Result<(), rustscale_ipnext::ExtensionHost> {
    #[cfg(test)]
    const DEADLINE: std::time::Duration = std::time::Duration::from_millis(100);
    #[cfg(not(test))]
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

    // Stop publication admission first. The drain owns its blocking waiter, so
    // timing out this API wait is cancellation-safe. Keep the host for a later
    // close retry if the drain or the owned shutdown worker remains busy.
    if tokio::time::timeout(DEADLINE, host.stop_publications_and_wait())
        .await
        .is_err()
    {
        log::warn!("tsnet: extension publication drain exceeded shutdown deadline");
    }

    let retry_deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        match host.shutdown().await {
            Ok(()) => return Ok(()),
            Err(error) if error.lifecycle_error().is_none() => {
                for failure in error.failures {
                    log::warn!(
                        "tsnet: extension {:?} shutdown failed (retained for retry): {}",
                        failure.name,
                        failure.source
                    );
                }
                return Err(host);
            }
            Err(error) => {
                log::warn!("tsnet: extension shutdown still busy: {error}");
                if tokio::time::Instant::now() >= retry_deadline {
                    return Err(host);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn quiesce_running_state(inner: &mut RunningState, preserve_localapi: bool) {
    inner.cancel.cancel();
    inner.health_watchdog.stop();
    for abort in inner
        .task_aborts
        .lock()
        .expect("server task abort lock poisoned")
        .iter()
    {
        abort.abort();
    }
    inner
        .ssh_callbacks
        .latch_key_revoked(&inner.node_key.public());
    inner.map_tasks.begin_shutdown();
    inner.extension_subscription.take();
    inner.hostinfo_hooks.clear();
    let loopback_controls = inner
        .loopback_controls
        .lock()
        .expect("loopback registry lock poisoned")
        .drain(..)
        .collect::<Vec<_>>();
    let in_memory_clients = inner
        .in_memory_clients
        .lock()
        .expect("in-memory registry lock poisoned")
        .drain(..)
        .collect::<Vec<_>>();
    for control in &loopback_controls {
        control.invalidate();
    }
    for control in &in_memory_clients {
        control.invalidate();
    }
    if let Some(path) = inner.localapi_socket.take() {
        let _ = std::fs::remove_file(path);
    }
    crate::capture::clear(&inner.capture);
    if let Ok(mut handles) = inner.capture_handles.lock() {
        handles.clear();
    }
    inner.magicsock.set_connection_counter(None);
    inner.audit_logger.request_stop();

    if !preserve_localapi {
        if let Some(localapi) = inner.localapi_handle.take() {
            localapi.shutdown().await;
        }
    }
    if let Some(serve) = inner.serve.take() {
        serve.stop().await;
    }
    for control in loopback_controls {
        control.shutdown().await;
    }
    for control in in_memory_clients {
        control.shutdown().await;
    }

    let tasks = {
        let mut tasks = inner.tasks.lock().await;
        tasks.drain(..).collect::<Vec<_>>()
    };
    drain_generation_tasks(tasks).await;
    inner.map_tasks.join().await;
    // LocalAPI cancellation does not cancel an admitted Tailnet Lock init.
    // Join the retained flight before durable identity or route ownership can
    // be rotated or released.
    inner.tailnet_lock.join_init_flight().await;
    inner
        .task_aborts
        .lock()
        .expect("server task abort lock poisoned")
        .clear();
    if let Some(mut monitor) = inner.monitor.take() {
        monitor.shutdown_and_wait().await;
    }
}

async fn finish_running_state(mut inner: RunningState) -> Result<(), (RunningState, String)> {
    // Extension shutdown has succeeded, so dependencies owned by the router,
    // DNS configurator, and magicsock can now be released.
    if let Some(router) = inner.router.take() {
        if let Err(error) = Server::cleanup_or_supervise(router).await {
            log::warn!("tsnet: retaining route cleanup owner: {error}");
            return Err((inner, format!("route cleanup: {error}")));
        }
    }
    if let Some(configurator) = inner.os_dns_configurator.as_mut() {
        if let Err(error) = configurator.close() {
            log::warn!("tsnet: OS DNS cleanup failed (non-fatal): {error}");
        }
    }
    inner.os_dns_configurator.take();
    if let Err(error) = shutdown_magicsock(&inner.magicsock).await {
        log::warn!("tsnet: retaining running cleanup owner: {error}");
        return Err((inner, format!("magicsock cleanup: {error}")));
    }
    inner.health_watchdog.stop_and_wait().await;

    if let Some(netlog) = inner.netlog.take() {
        if let Err(error) = netlog.stop().await {
            log::warn!("tsnet: netlog shutdown failed (non-fatal): {error}");
        }
    }
    inner
        .audit_logger
        .flush_and_stop(std::time::Duration::from_secs(5))
        .await;
    Ok(())
}

fn lifecycle_cleanup_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rustscale-lifecycle-cleanup")
            .enable_all()
            .build()
            .expect("build lifecycle cleanup supervisor runtime")
    })
}

async fn cleanup_server_state(mut owner: CleanupOwner) -> Result<(), (CleanupOwner, String)> {
    // This owner closes only its own router below. Unrelated retained TUN
    // owners gate future startup globally, but must not make a userspace
    // server's close/logout spuriously consume their retry budget.
    if let Some(inner) = owner.inner.as_mut() {
        quiesce_running_state(inner, false).await;
    }
    if let Some(pre_started) = owner.pre_started.as_mut() {
        // Stop external admission, but retain its magicsock until extensions
        // have released every dependency successfully.
        quiesce_pre_started(pre_started).await;
    }

    if let Some(host) = owner.extension_host.take() {
        if let Err(host) = shutdown_extension_host(host).await {
            owner.extension_host = Some(host);
            return Err((owner, "extension shutdown remains incomplete".into()));
        }
    }

    if let Some(inner) = owner.inner.take() {
        if let Err((inner, reason)) = finish_running_state(inner).await {
            owner.inner = Some(inner);
            return Err((owner, reason));
        }
    }
    if let Some(pre_started) = owner.pre_started.take() {
        cleanup_pre_started(pre_started, true).await;
    }
    Ok(())
}

async fn logout_running_transaction(
    mut transaction: LogoutTransaction,
) -> Result<(), (TsnetError, LogoutTransaction)> {
    loop {
        match transaction.phase {
            LogoutPhase::Quiesce => {
                let inner = transaction
                    .owner
                    .inner
                    .as_mut()
                    .expect("logout missing running state");
                if let Err(error) = inner
                    .audit_logger
                    .enqueue(rustscale_tailcfg::AuditNodeDisconnect, "logout")
                {
                    log::warn!("tsnet: failed to persist audit log (non-fatal): {error}");
                }

                // Revoke every runtime writer and join it before any durable
                // logout phase can replace identity, cache, or preferences.
                transaction.drive.disable().await;
                quiesce_running_state(inner, true).await;
                transaction.drive.disable().await;
                transaction.phase = LogoutPhase::ControlLogout;
            }
            LogoutPhase::ControlLogout => {
                let inner = transaction
                    .owner
                    .inner
                    .as_ref()
                    .expect("logout control phase missing running state");
                let cc = ControlClient::new(
                    transaction.control_url.clone(),
                    inner.machine_key.clone(),
                    inner.server_pub_key.clone(),
                    PROTOCOL_VERSION,
                );
                let request = RegisterRequest {
                    Version: CAPABILITY_VERSION,
                    NodeKey: inner.node_key.public(),
                    Expiry: Some(
                        chrono::DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&chrono::Utc),
                    ),
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: transaction.hostname.clone(),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                if let Err(error) = cc.register(&request).await {
                    return Err((TsnetError::Register(error), transaction));
                }
                transaction.phase = LogoutPhase::RotateIdentity;
            }
            LogoutPhase::RotateIdentity => {
                if let Some(scope) = transaction.state_scope.as_ref() {
                    let path = scope.dir.join("tsnet-state.json");
                    let persisted = match PersistedState::load(&path) {
                        Ok(state) => state,
                        Err(error) => return Err((TsnetError::State(error), transaction)),
                    };
                    transaction
                        .tailnet_identity
                        .clone_from(&persisted.tailnet_identity);
                    let rotated = persisted.rotated_for_logout();
                    #[cfg(test)]
                    if transaction.state_save_failures > 0 {
                        transaction.state_save_failures -= 1;
                        return Err((
                            TsnetError::State(crate::StateError::Io(std::io::Error::other(
                                "injected logout state save failure",
                            ))),
                            transaction,
                        ));
                    }
                    if let Err(error) = rotated.save(&path) {
                        return Err((TsnetError::State(error), transaction));
                    }
                }
                transaction.phase = LogoutPhase::ClearCache;
            }
            LogoutPhase::ClearCache => {
                if let Some(scope) = transaction.state_scope.as_ref() {
                    // Identity rotation has committed, so no old-key cache may
                    // survive even if preference persistence needs a retry.
                    NetMapCache::new_scoped(scope, &transaction.tailnet_identity).clear();
                }
                transaction.phase = LogoutPhase::SavePrefs;
            }
            LogoutPhase::SavePrefs => {
                transaction.prefs.LoggedOut = true;
                transaction.prefs.WantRunning = false;
                if let Some(dir) = transaction.state_dir.as_ref() {
                    if let Err(error) = transaction.prefs.save(dir) {
                        return Err((TsnetError::Io(error), transaction));
                    }
                }
                transaction.phase = LogoutPhase::PublishLoggedOut;
            }
            LogoutPhase::PublishLoggedOut => {
                let inner = transaction
                    .owner
                    .inner
                    .as_ref()
                    .expect("logout publish phase missing running state");
                let backend = &inner.ipn_backend;
                backend.set_logged_out(true);
                backend.set_blocked(true);
                backend.update_inputs(|inputs| {
                    inputs.want_running = false;
                    inputs.has_node_key = false;
                    inputs.auth_cant_continue = true;
                    inputs.netmap_present = false;
                });
                backend.bus().send(rustscale_ipn::Notify {
                    State: Some(rustscale_ipn::State::NeedsLogin),
                    Prefs: Some(serde_json::to_value(&transaction.prefs).unwrap_or_default()),
                    ..Default::default()
                });
                // Durable identity, cache, and preference state now agree.
                // Unblock LocalAPI before final listener/component cleanup so
                // its truthful 204 can drain through the listener being closed.
                transaction.completion.complete(Ok(()));
                transaction.phase = LogoutPhase::Cleanup;
            }
            LogoutPhase::Cleanup => {
                let owner = std::mem::replace(&mut transaction.owner, CleanupOwner::empty());
                return match cleanup_server_state(owner).await {
                    Ok(()) => Ok(()),
                    Err((owner, reason)) => {
                        transaction.owner = owner;
                        Err((
                            TsnetError::ShutdownIncomplete(format!(
                                "logout cleanup requires retry: {reason}"
                            )),
                            transaction,
                        ))
                    }
                };
            }
        }
    }
}

/// Nonblocking node lookup view used by the netlog aggregation task.
struct TsnetNetlogNodeSource {
    self_node: Option<Node>,
    peers: Arc<RwLock<Vec<Node>>>,
}

impl rustscale_netlog::NodeSource for TsnetNetlogNodeSource {
    fn self_node(&self) -> Option<rustscale_netlogtype::Node> {
        self.self_node.as_ref().map(netlog_node)
    }

    fn node_by_addr(&self, addr: IpAddr) -> Option<rustscale_netlogtype::Node> {
        if let Some(node) = self
            .self_node
            .as_ref()
            .filter(|node| node_has_addr(node, addr))
        {
            return Some(netlog_node(node));
        }
        // NodeSource is synchronous by design. Avoid blocking a runtime worker
        // if a map update briefly owns the peer list.
        self.peers
            .try_read()
            .ok()?
            .iter()
            .find(|node| node_has_addr(node, addr))
            .map(netlog_node)
    }
}

fn node_has_addr(node: &Node, addr: IpAddr) -> bool {
    node.Addresses.iter().any(|prefix| {
        prefix
            .split_once('/')
            .map_or(prefix.as_str(), |(ip, _)| ip)
            .parse::<IpAddr>()
            .is_ok_and(|node_addr| node_addr == addr)
    })
}

fn netlog_node(node: &Node) -> rustscale_netlogtype::Node {
    rustscale_netlogtype::Node {
        node_id: node.StableID.clone(),
        name: node.Name.trim_end_matches('.').to_string(),
        addresses: node
            .Addresses
            .iter()
            .filter_map(|prefix| {
                prefix
                    .split_once('/')
                    .map_or(prefix.as_str(), |(ip, _)| ip)
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| ip.to_string())
            })
            .collect(),
        os: node
            .Hostinfo
            .as_ref()
            .map(|hostinfo| hostinfo.OS.clone())
            .unwrap_or_default(),
        tags: node.Tags.clone(),
        ..Default::default()
    }
}

fn cleanup_router_owner_blocking(router: &SharedRouter) -> Result<(), TsnetError> {
    let mut managed = router
        .lock()
        .map_err(|_| TsnetError::Builder("router cleanup lock poisoned".into()))?;
    managed
        .router
        .close()
        .map_err(|error| TsnetError::Builder(format!("route cleanup failed: {error}")))?;
    managed.security_block_attempted = false;
    managed.security_block_verified = false;
    managed.security_block_reasons = 0;
    if managed.exit_node {
        rustscale_netns::release_physical_underlay_bypass(&managed.tun_name);
        managed.exit_node = false;
    }
    Ok(())
}

impl Server {
    fn router_cleanup_supervisor() -> &'static std::sync::Mutex<Vec<SharedRouter>> {
        static SUPERVISOR: std::sync::OnceLock<std::sync::Mutex<Vec<SharedRouter>>> =
            std::sync::OnceLock::new();
        SUPERVISOR.get_or_init(|| std::sync::Mutex::new(Vec::new()))
    }

    fn router_cleanup_gate() -> &'static tokio::sync::Mutex<()> {
        static GATE: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        GATE.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn supervise_router_cleanup(router: SharedRouter) {
        match Self::router_cleanup_supervisor().lock() {
            Ok(mut supervisor) => supervisor.push(router),
            Err(poisoned) => poisoned.into_inner().push(router),
        }
    }

    pub(crate) async fn cleanup_or_supervise(router: SharedRouter) -> Result<(), TsnetError> {
        let _gate = Self::router_cleanup_gate().lock().await;
        match wait_router_cleanup(&router).await {
            Ok(()) => Ok(()),
            Err(error) => {
                Self::supervise_router_cleanup(router);
                Err(error)
            }
        }
    }

    async fn retry_pending_router_cleanup() -> Result<(), TsnetError> {
        // Serialize draining with enqueue so successful restart admission can
        // never race a newly retained owner.
        let _gate = Self::router_cleanup_gate().lock().await;
        let pending = {
            let mut supervisor = Self::router_cleanup_supervisor()
                .lock()
                .map_err(|_| TsnetError::Builder("router cleanup supervisor poisoned".into()))?;
            std::mem::take(&mut *supervisor)
        };
        let mut retained = Vec::new();
        let mut errors = Vec::new();
        for router in pending {
            if let Err(error) = wait_router_cleanup(&router).await {
                errors.push(error.to_string());
                retained.push(router);
            }
        }
        if !retained.is_empty() {
            Self::router_cleanup_supervisor()
                .lock()
                .map_err(|_| TsnetError::Builder("router cleanup supervisor poisoned".into()))?
                .extend(retained);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(TsnetError::Builder(format!(
                "pending route cleanup blocks restart: {}",
                errors.join("; ")
            )))
        }
    }

    /// Bring the server online in userspace netstack mode (tsnet listen/dial).
    ///
    /// This is the classic tsnet embedding path: an in-process smoltcp netstack
    /// backs `listen`/`dial`. For a full-client TUN device instead, use
    /// [`Server::up_tun`].
    #[allow(clippy::large_futures)]
    ///
    /// **Idempotent**: calling `up()` on an already-running server returns
    /// `Ok(ServerStatus)` immediately without re-starting. Mirrors Go's
    /// `sync.Once`-guarded `Start()`.
    ///
    /// Returns the current [`ServerStatus`] after startup (or the existing
    /// status if already up). Mirrors Go's `Up()` which returns
    /// `(*ipnstate.Status, error)`.
    #[allow(clippy::large_futures)]
    pub async fn up(&mut self) -> Result<ServerStatus, TsnetError> {
        self.shutdown_supervisor.wait().await;
        self.startup_supervisor.wait().await;
        if self.inner.is_some() {
            return Ok(self.status());
        }
        Self::retry_pending_router_cleanup().await?;
        self.ensure_extension_host().await?;

        ensure_ring_provider();
        let state = self.load_or_create_state()?;
        let initial_auth = self.initial_registration_auth(&state).await?;

        let b = self.bootstrap(state, initial_auth).await?;
        let mut rollback = StartupRollback::new(
            Arc::clone(&self.startup_supervisor),
            b.cancel.clone(),
            b.health_watchdog.clone(),
            Arc::clone(&b.map_tasks),
            b.netlog.clone(),
        );
        rollback.magicsock = Some(Arc::clone(&b.magicsock));
        let (localapi_mutation_fence, localapi_mutation_generation) =
            if let Some(pre_started) = self.pre_started.as_ref() {
                let fence = Arc::clone(&pre_started.mutation_fence);
                let handoff = fence
                    .advance(pre_started.mutation_generation)
                    .await
                    .map_err(TsnetError::Builder)?;
                let generation = handoff.replacement();
                rollback.localapi_generation_handoff = Some(handoff);
                (fence, generation)
            } else {
                let fence = localapi::LocalApiMutationFence::new();
                let generation = fence.generation();
                (fence, generation)
            };
        // Advance the old listener's mutation gate before this snapshot. An
        // accepted stale handler either completed first or now gets conflict.
        let prefs = Arc::new(RwLock::new(self.load_prefs().unwrap_or_default()));
        let profile_mutations = Arc::new(tokio::sync::Mutex::new(()));
        let exit_node_selection = Arc::new(RwLock::new(ExitNodeSelection::from_prefs(
            &*prefs.read().await,
        )));
        let audit_logger = Self::start_audit_logger(
            self.config.state_dir.clone(),
            self.config.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
        )
        .await;
        rollback.audit_logger = Some(audit_logger.clone());

        rollback.monitor = spawn_link_monitor(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.udp_port,
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            b.health.clone(),
            None,
        )
        .await;

        // Userspace netstack bound to our tailnet IPv4.
        let netstack = Arc::new(Netstack::new(b.our_v4, DEFAULT_MTU)?);

        // Periodic endpoint update (Bug 4): pushes a non-streaming
        // MapRequest with OmitPeers=true every 5 minutes so the control
        // server always has fresh endpoint data.
        let periodic_ep = spawn_periodic_endpoint_updates(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            self.config.peer_relay_server,
        );
        rollback.track(periodic_ep);

        let capture = crate::capture::new_slot();

        // Netstack data-plane pump: netstack <-> WG <-> magicsock.
        let pump = tokio::spawn(run_netstack_pump(
            b.magicsock.clone(),
            b.wg_recv,
            netstack.clone(),
            b.wg_tunnels.clone(),
            b.route_table.clone(),
            b.filter.clone(),
            b.packet_drops.clone(),
            b.cancel.clone(),
            capture.clone(),
            b.peer_map.clone(),
        ));
        rollback.track(pump);

        // Map-stream update task (peer/route deltas).
        let suggested_exit_node: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
        let client_updater = Arc::new(std::sync::Mutex::new(
            rustscale_clientupdate::ClientUpdater::new(env!("CARGO_PKG_VERSION")),
        ));
        let key_rotation_ctx = KeyRotationCtx {
            control_url: b.control_url.clone(),
            machine_key: b.machine_key.clone(),
            server_pub_key: b.server_pub_key.clone(),
            hostname: self.config.hostname.clone(),
            ephemeral: self.config.ephemeral,
            advertise_routes: b.advertise_routes.clone(),
            peer_relay_server: self.config.peer_relay_server,
            disco_key: b.disco_key.clone(),
            capability_version: CAPABILITY_VERSION,
            protocol_version: PROTOCOL_VERSION,
            shields_up: prefs.read().await.ShieldsUp,
        };
        b.tailnet_lock
            .attach_peer_authority(crate::map_update::PeerAuthorityRuntime::new(
                b.exit_map_gate.clone(),
                b.peer_map.clone(),
                self.drive.clone(),
                b.magicsock.clone(),
                b.filter.clone(),
                b.peers.clone(),
                b.wg_tunnels.clone(),
                b.resolver.clone(),
                prefs.clone(),
                b.route_table.clone(),
                None,
                b.tailscale_ips.clone(),
                b.control_url.clone(),
                self.config.accept_routes,
            ))
            .map_err(|error| TsnetError::TailnetLock(error.to_string()))?;
        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.raw_peers.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            b.exit_map_gate.clone(),
            None,
            prefs.clone(),
            exit_node_selection.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.named_filters.clone(),
            self.drive.clone(),
            b.peer_map.clone(),
            b.tailscale_ips.clone(),
            b.control_url.clone(),
            self.config.accept_routes,
            b.advertise_routes.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.user_profiles.clone(),
            b.ssh_policy.clone(),
            b.cancel.clone(),
            b.health.clone(),
            b.health_watchdog.clone(),
            b.state_scope.clone(),
            b.node_key.public(),
            b.control_knobs.clone(),
            b.key_expired.clone(),
            b.ipn_backend.clone(),
            Some(key_rotation_ctx),
            b.map_session.clone(),
            Arc::clone(&b.map_tasks),
            b.c2n_router.clone(),
            b.ssh_callbacks.clone(),
            suggested_exit_node.clone(),
            client_updater.clone(),
            b.tailnet_lock.clone(),
            b.domain.clone(),
            b.peer_snapshot_fresh,
        );
        rollback.track(map_update);

        // MagicDNS responder: best-effort UDP server at 100.100.100.100:53.
        // Binding to :53 typically requires root and the MagicDNS VIP to be
        // assigned to an interface; failure is non-fatal (dial still resolves
        // via the shared resolver). The responder serves A/AAAA/PTR for peer
        // hostnames, handles split-DNS routes, ExtraRecords, .onion NXDOMAIN,
        // 4via6 synthesis, and forwards the rest upstream (with TCP fallback
        // and DoH support).
        let dns_cfg_snapshot = b.dns_config.read().await.clone();
        let forwarder = Arc::new(Forwarder::from_dns_config(dns_cfg_snapshot.as_ref()));
        let responder = DnsResponder::with_forwarder(
            b.resolver.clone(),
            SocketAddr::new(IpAddr::V4(MAGICDNS_VIP), 53),
            forwarder,
        );
        match responder.spawn().await {
            Ok(handle) => {
                rollback.track(handle);
            }
            Err(e) => log::warn!(
                "tsnet: MagicDNS responder not started ({e}); dial still resolves via netmap"
            ),
        }

        // Serve/Funnel runner (netstack mode only).
        let serve = Some(Arc::new(serve::ServeRunner::new(
            netstack.clone(),
            b.peers.clone(),
            b.user_profiles.clone(),
            b.our_fqdn.clone(),
            b.magicsock.self_cap_map_arc(),
        )));
        rollback.serve.clone_from(&serve);

        // Taildrop file manager (shared between PeerAPI receive handler
        // and LocalAPI endpoints). Created from the state directory; if
        // no state dir, taildrop is disabled.
        let taildrop = Arc::new(taildrop::TaildropManager::new(
            self.config.state_dir.as_deref(),
            Some(b.ipn_backend.clone()),
        ));

        // PeerAPI server (netstack mode): listens on a deterministic port on
        // the node's tailnet IP, serving DoH DNS + debug endpoints to peers.
        let offering_exit_node = self.config.advertise_exit_node;
        let (peerapi_tasks, peerapi_port) = peerapi::spawn_peerapi_netstack(
            netstack.clone(),
            b.peers.clone(),
            b.user_profiles.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.tailscale_ips.clone(),
            offering_exit_node,
            Some(taildrop.clone()),
            Some(b.sockstats.clone()),
            b.filter.clone(),
            self.drive.clone(),
            b.peer_map.clone(),
        )
        .await;
        for task in peerapi_tasks {
            rollback.track(task);
        }

        // Advertise peerapi4/peerapi6 services to the control plane so peers
        // can discover our PeerAPI port.
        if let Some(port) = peerapi_port {
            let has_v6 = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
            let services =
                peerapi::peerapi_services(Some(port), if has_v6 { Some(port) } else { None });
            if !services.is_empty() {
                let cc_ep = ControlClient::new(
                    &b.control_url,
                    b.machine_key.clone(),
                    b.server_pub_key.clone(),
                    PROTOCOL_VERSION,
                );
                let node_pub = b.node_key.public();
                let disco_pub = b.disco_key.public();
                let svc_req = MapRequest {
                    Version: CAPABILITY_VERSION,
                    KeepAlive: false,
                    NodeKey: node_pub,
                    DiscoKey: disco_pub,
                    Stream: false,
                    OmitPeers: true,
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: b.hostname.clone(),
                        RoutableIPs: b.advertise_routes.clone(),
                        Services: services,
                        PeerRelay: self.config.peer_relay_server,
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                match cc_ep.send_map_request(&svc_req).await {
                    Ok(()) => log::info!("tsnet: peerapi services advertised (port {port})"),
                    Err(e) => {
                        log::warn!("tsnet: peerapi service advertisement failed (non-fatal): {e}");
                    }
                }
            }
        }

        // Portlist: shared state for the background port-scanning task and
        // the hostinfo hook. The hook adds portlist services to
        // Hostinfo.Services; the background task polls every N seconds and
        // updates the shared list. Mirrors Go's portlist EventBus extension.
        let portlist_ports: Arc<std::sync::Mutex<Vec<rustscale_portlist::Port>>> =
            Arc::new(std::sync::Mutex::new(vec![]));
        let proxy_mapper = Arc::new(rustscale_proxymap::Mapper::new());

        // Register a hostinfo hook that adds portlist + peerapi services to
        // Hostinfo.Services before it is sent to control.
        let pl_ports_hook = portlist_ports.clone();
        let hp_port = peerapi_port;
        let has_v6_hook = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
        rollback
            .hostinfo_hooks
            .push(hostinfo::register_hostinfo_hook(move |hi| {
                let mut services = Vec::new();
                if let Some(port) = hp_port {
                    if port > 0 {
                        services.push(rustscale_tailcfg::Service {
                            Proto: "peerapi4".into(),
                            Port: port,
                            Description: String::new(),
                        });
                        if has_v6_hook {
                            services.push(rustscale_tailcfg::Service {
                                Proto: "peerapi6".into(),
                                Port: port,
                                Description: String::new(),
                            });
                        }
                    }
                }
                if let Ok(ports) = pl_ports_hook.lock() {
                    services.extend(rustscale_portlist::to_services(&ports));
                }
                if !services.is_empty() {
                    hi.Services = services;
                }
            }));

        // Spawn the portlist poller background task.
        let pl_ports_task = portlist_ports.clone();
        let pl_cancel = b.cancel.clone();
        let pl_interval = rustscale_portlist::Poller::new(false).interval();
        let portlist_task = tokio::spawn(async move {
            let mut poller = rustscale_portlist::Poller::new(false);
            loop {
                if pl_cancel.is_cancelled() {
                    break;
                }
                let (ports, changed) = poller.poll().await;
                if changed {
                    if let Ok(mut guard) = pl_ports_task.lock() {
                        *guard = ports;
                    }
                }
                tokio::time::sleep(pl_interval).await;
            }
        });
        rollback.track(portlist_task);

        // Periodic Hostinfo refresh (every 10 min, dedup by content hash).
        let hostinfo_loop = spawn_hostinfo_update_loop(
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.home_derp,
            b.peers.clone(),
            b.route_table.clone(),
            serve.clone(),
            b.overrides.clone(),
            self.config.state_dir.clone(),
            b.backend_log_id.clone(),
            b.ssh_host_keys.clone(),
            self.config.posture_checking,
            self.config.preference_policy.clone(),
        );
        rollback.track(hostinfo_loop);

        // LocalAPI Unix-domain-socket server (optional, default OFF).
        let localapi_socket = if self.config.localapi {
            let path = self.config.localapi_path.clone().unwrap_or_else(|| {
                let dir = self
                    .config
                    .state_dir
                    .clone()
                    .unwrap_or_else(|| std::env::temp_dir().join("rustscale"));
                localapi::default_socket_path(&dir)
            });
            let state = localapi::LocalApiState {
                mutation_fence: Arc::clone(&localapi_mutation_fence),
                mutation_generation: localapi_mutation_generation,
                peers: b.peers.clone(),
                user_profiles: b.user_profiles.clone(),
                health: b.health.clone(),
                dns_config: b.dns_config.clone(),
                packet_drops: b.packet_drops.clone(),
                capture: capture.clone(),
                metrics: localapi::default_metric_registry(),
                prefs: prefs.clone(),
                operator_access: std::sync::Mutex::default(),
                posture_checking: b.posture_checking.clone(),
                profile_mutations: profile_mutations.clone(),
                exit_node_selection: exit_node_selection.clone(),
                tailscale_ips: b.tailscale_ips.clone(),
                our_fqdn: b.our_fqdn.clone(),
                hostname: self.config.hostname.clone(),
                magicsock: b.magicsock.clone(),
                tun_mode: false,
                routecheck: Some(b.routecheck.clone()),
                home_derp: b.home_derp,
                ipn_backend: b.ipn_backend.clone(),
                derp_map: b.derp_map.clone(),
                command_tx: self
                    .pre_started
                    .as_ref()
                    .and_then(|ps| ps.command_tx.clone()),
                state_dir: self.config.state_dir.clone(),
                auth_url: Arc::new(std::sync::Mutex::new(None)),
                login_trigger: self
                    .pre_started
                    .as_ref()
                    .map(|ps| ps.login_trigger.clone())
                    .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
                serve_config: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| serve::ServeConfig::load(d).ok())
                        .unwrap_or_default(),
                )),
                serve_runner: serve.clone(),
                profiles: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                        .unwrap_or_default(),
                )),
                current_profile: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                        .flatten(),
                )),
                cert_params: self
                    .config
                    .state_dir
                    .clone()
                    .map(|dir| localapi::CertParams {
                        state_dir: dir,
                        control_url: self.config.control_url.clone(),
                        machine_key: b.machine_key.clone(),
                        server_pub_key: b.server_pub_key.clone(),
                        node_key: b.node_key.clone(),
                        capability_version: CAPABILITY_VERSION,
                        protocol_version: PROTOCOL_VERSION,
                    }),
                control_params: Some(localapi::ControlParams {
                    control_url: self.config.control_url.clone(),
                    machine_key: b.machine_key.clone(),
                    server_pub_key: b.server_pub_key.clone(),
                    node_key: b.node_key.clone(),
                    capability_version: CAPABILITY_VERSION,
                    protocol_version: PROTOCOL_VERSION,
                }),
                taildrop: Some(taildrop.clone()),
                drive: self.drive.clone(),
                peer_map: b.peer_map.clone(),
                tailnet_lock: Some(b.tailnet_lock.clone()),
                netstack: Some(netstack.clone()),
                filter: std::sync::OnceLock::new(),
                route_table: Some(b.route_table.clone()),
                exit_map_gate: b.exit_map_gate.clone(),
                router: None,
                logout_trigger: Arc::clone(&self.logout_trigger),
                logout_completion: Arc::clone(&self.logout_completion),
                suggested_exit_node: suggested_exit_node.clone(),
                config_path: self.config.config_path.clone(),
                client_updater: client_updater.clone(),
                audit_logger: Some(audit_logger.clone()),
                preference_policy: self.config.preference_policy.clone(),
                policy_subscription: std::sync::Mutex::new(None),
            };
            // Publish the live filter so `PATCH /prefs` can toggle
            // shields-up mode without a full rebuild.
            let _ = state.filter.set(b.filter.clone());
            let state = Arc::new(state);
            localapi::activate_preference_policy(&state)
                .await
                .map_err(TsnetError::Builder)?;
            let replacing_prestarted = self
                .pre_started
                .as_ref()
                .and_then(|pre_started| pre_started.handle.as_ref())
                .is_some();
            let handle = if replacing_prestarted {
                localapi::spawn_localapi_paused(state, path.clone()).map(
                    |(handle, start, handoff)| {
                        rollback.localapi_start = Some(start);
                        rollback.localapi_handoff = Some(handoff);
                        handle
                    },
                )
            } else {
                localapi::spawn_localapi(state, path.clone())
            };
            if let Some(handle) = handle {
                let socket_path = if replacing_prestarted {
                    path.clone()
                } else {
                    handle.socket_path.clone()
                };
                rollback.localapi = Some(handle);
                log::info!("tsnet: LocalAPI prepared at {}", path.display());
                Some(socket_path)
            } else {
                // A failed transactional bind leaves the old needs-login
                // listener advertised and owned by self.pre_started. Fail the
                // startup rather than later retiring that reachable listener.
                if replacing_prestarted {
                    return Err(TsnetError::Builder(format!(
                        "failed to prepare LocalAPI replacement at {}",
                        path.display()
                    )));
                }
                log::warn!(
                    "tsnet: LocalAPI failed to bind socket at {}",
                    path.display()
                );
                None
            }
        } else {
            None
        };
        rollback.localapi_socket.clone_from(&localapi_socket);

        // A persisted selection retries only while it is unresolved. Once it
        // resolves, later map rebuilds retain the route-table owner.
        {
            let _map_commit = b.peer_map.gate.write().await;
            let peers = b.peers.read().await;
            let mut selection = exit_node_selection.write().await;
            let mut routes = b.route_table.write().await;
            selection.retry_transactional(&peers, &mut routes, |_| Ok::<(), TsnetError>(()))?;
        }
        let extension_subscription = self
            .start_extensions_with(b.ipn_backend.clone(), prefs.clone())
            .await?;
        #[cfg(test)]
        if let Some((entered, release, fail)) = self.startup_localapi_test_hook.clone() {
            entered.wait().await;
            release.wait().await;
            if fail {
                return Err(TsnetError::Builder(
                    "injected failure after extension startup".into(),
                ));
            }
        }
        rollback.commit_localapi_handoff()?;
        let retire_prestarted = self.pre_started.is_some();
        let tasks = rollback.commit_tasks();
        let task_aborts = tasks.iter().map(JoinHandle::abort_handle).collect();

        let startup_backend = b.ipn_backend.clone();
        let running = RunningState {
            tailscale_ips: b.tailscale_ips,
            magicsock: b.magicsock,
            netlog: b.netlog,
            data_plane: DataPlane::Netstack(netstack),
            peers: b.peers,
            peer_map: b.peer_map,
            routecheck: b.routecheck,
            route_table: b.route_table,
            filter: b.filter,
            exit_map_gate: b.exit_map_gate,
            router: None,
            cancel: b.cancel,
            tasks: Mutex::new(tasks),
            map_tasks: b.map_tasks,
            task_aborts: std::sync::Mutex::new(task_aborts),
            loopback_controls: std::sync::Mutex::new(Vec::new()),
            in_memory_clients: std::sync::Mutex::new(Vec::new()),
            packet_drops: b.packet_drops,
            capture,
            capture_handles: std::sync::Mutex::new(vec![]),
            resolver: b.resolver,
            our_fqdn: b.our_fqdn,
            domain: b.domain.clone(),
            dns_config: b.dns_config,
            user_profiles: b.user_profiles,
            ssh_policy: b.ssh_policy,
            ssh_host_keys: b.ssh_host_keys,
            ssh_callbacks: b.ssh_callbacks,
            monitor: rollback.take_monitor(),
            machine_key: b.machine_key,
            server_pub_key: b.server_pub_key,
            node_key: b.node_key,
            serve: rollback.take_serve(),
            health: b.health,
            health_watchdog: b.health_watchdog,
            c2n_router: b.c2n_router,
            posture_checking: b.posture_checking,
            control_knobs: b.control_knobs,
            peerapi_port,
            overrides: b.overrides,
            localapi_socket,
            localapi_handle: rollback.take_localapi(),
            key_expired: b.key_expired,
            os_dns_configurator: None,
            ipn_backend: b.ipn_backend,
            logout_trigger: Arc::clone(&self.logout_trigger),
            logout_completion: Arc::clone(&self.logout_completion),
            fallback_tcp_handlers: Arc::new(std::sync::Mutex::new(vec![])),
            fallback_next_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            prefs: prefs.clone(),
            profile_mutations,
            localapi_mutation_fence,
            localapi_mutation_generation,
            exit_node_selection: exit_node_selection.clone(),
            proxy_mapper,
            portlist_ports,
            client_updater: client_updater.clone(),
            audit_logger,
            tailnet_lock: b.tailnet_lock.clone(),
            hostinfo_hooks: rollback.take_hostinfo_hooks(),
            extension_subscription,
        };

        self.inner = Some(running);
        // Publish Running only after the complete runtime generation is owned
        // by `self.inner`; cancellation before this point retains Starting.
        startup_backend.set_blocked(false);
        if retire_prestarted {
            self.retire_prestarted_after_handoff();
        }
        Ok(self.status())
    }

    /// Bring the server online in **TUN mode**: route plaintext IP packets
    /// between a real OS TUN device and the WireGuard/magicsock data plane,
    /// instead of an in-process netstack.
    ///
    /// `listen`/`dial` are unavailable in TUN mode. Creating the TUN device
    /// requires root on both macOS (`utun`) and Linux (`/dev/net/tun`). If
    /// `config.apply_routes` is true, the interface is brought up and tailnet
    /// routes are added via `ifconfig`/`route` (macOS) or `ip` (Linux) — also
    /// requiring root.
    #[allow(clippy::large_futures)]
    pub async fn up_tun(&mut self, config: TunModeConfig) -> Result<ServerStatus, TsnetError> {
        self.shutdown_supervisor.wait().await;
        self.startup_supervisor.wait().await;
        if self.inner.is_some() {
            return Ok(self.status());
        }
        Self::retry_pending_router_cleanup().await?;
        self.ensure_extension_host().await?;

        ensure_ring_provider();
        let state = self.load_or_create_state()?;
        let initial_auth = self.initial_registration_auth(&state).await?;

        let b = self.bootstrap(state, initial_auth).await?;
        let mut rollback = StartupRollback::new(
            Arc::clone(&self.startup_supervisor),
            b.cancel.clone(),
            b.health_watchdog.clone(),
            Arc::clone(&b.map_tasks),
            b.netlog.clone(),
        );
        rollback.magicsock = Some(Arc::clone(&b.magicsock));
        let (localapi_mutation_fence, localapi_mutation_generation) =
            if let Some(pre_started) = self.pre_started.as_ref() {
                let fence = Arc::clone(&pre_started.mutation_fence);
                let handoff = fence
                    .advance(pre_started.mutation_generation)
                    .await
                    .map_err(TsnetError::Builder)?;
                let generation = handoff.replacement();
                rollback.localapi_generation_handoff = Some(handoff);
                (fence, generation)
            } else {
                let fence = localapi::LocalApiMutationFence::new();
                let generation = fence.generation();
                (fence, generation)
            };
        // Advance the old listener's mutation gate before this snapshot. An
        // accepted stale handler either completed first or now gets conflict.
        let prefs = Arc::new(RwLock::new(self.load_prefs().unwrap_or_default()));
        let profile_mutations = Arc::new(tokio::sync::Mutex::new(()));
        let exit_node_selection = Arc::new(RwLock::new(ExitNodeSelection::from_prefs(
            &*prefs.read().await,
        )));
        let audit_logger = Self::start_audit_logger(
            self.config.state_dir.clone(),
            self.config.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
        )
        .await;
        rollback.audit_logger = Some(audit_logger.clone());

        // Serialize startup selection with the same mutation domain used once
        // the map task starts.
        let exit_map_guard = b.exit_map_gate.lock().await;
        // Resolve and apply the exit node selection from TunModeConfig, if
        // set. This sets the in-process RouteTable's exit node so the data
        // pump routes non-tailnet traffic to the exit peer. OS-level
        // default-route overrides are installed after the TUN is created.
        if let Some(ref exit) = config.exit_node {
            let _map_commit = b.peer_map.gate.write().await;
            let peers = b.peers.read().await;
            let peer_key = resolve_exit_node(&peers, exit)?;
            drop(peers);
            exit_node_selection.write().await.clear_pending();
            b.route_table.write().await.set_exit_node(peer_key);
            let mut live_prefs = prefs.write().await;
            set_exit_node_pref(&mut live_prefs, exit);
            if let Some(ref dir) = self.config.state_dir {
                live_prefs.save(dir).map_err(|error| {
                    TsnetError::Builder(format!("persist startup exit selection: {error}"))
                })?;
            }
        }

        // Resolve persisted exit intent before the TUN can carry ordinary
        // traffic. If the peer is absent, retry installs capture/no-connect
        // defaults and never exposes the physical default route.
        {
            let peers = b.peers.read().await;
            let mut routes = b.route_table.write().await;
            exit_node_selection.write().await.retry(&peers, &mut routes);
        }
        drop(exit_map_guard);

        // Real TUN device (macOS/Linux only; on other platforms
        // `create_tun_device` returns an error and `?` propagates it).
        let exit_node_allow_lan_access = prefs.read().await.ExitNodeAllowLANAccess;
        let (tun, router) = create_tun_device(
            &config,
            &b,
            self.config.accept_routes,
            exit_node_allow_lan_access,
            self.config.state_dir.as_deref(),
        )
        .await?;
        // Transfer OS-route ownership before the next cancellable await.
        rollback.router.clone_from(&router);

        let monitor = spawn_link_monitor(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.udp_port,
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            b.health.clone(),
            router.as_ref().map(|router| LinkRouteSync {
                exit_map_gate: b.exit_map_gate.clone(),
                router: router.clone(),
                route_table: b.route_table.clone(),
                tailscale_ips: b.tailscale_ips.clone(),
                prefs: prefs.clone(),
            }),
        )
        .await;
        rollback.monitor = monitor;

        let capture = crate::capture::new_slot();

        // TUN data-plane pump: TUN <-> WG <-> magicsock.
        let pump = tokio::spawn(run_tun_pump(
            b.magicsock.clone(),
            b.wg_recv,
            tun.clone(),
            b.wg_tunnels.clone(),
            b.route_table.clone(),
            b.filter.clone(),
            b.packet_drops.clone(),
            b.cancel.clone(),
            capture.clone(),
            b.peer_map.clone(),
        ));
        rollback.track(pump);

        // Periodic endpoint update (Bug 4).
        let periodic_ep = spawn_periodic_endpoint_updates(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            self.config.peer_relay_server,
        );
        rollback.track(periodic_ep);

        let suggested_exit_node: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
        let client_updater = Arc::new(std::sync::Mutex::new(
            rustscale_clientupdate::ClientUpdater::new(env!("CARGO_PKG_VERSION")),
        ));
        let key_rotation_ctx = KeyRotationCtx {
            control_url: b.control_url.clone(),
            machine_key: b.machine_key.clone(),
            server_pub_key: b.server_pub_key.clone(),
            hostname: self.config.hostname.clone(),
            ephemeral: self.config.ephemeral,
            advertise_routes: b.advertise_routes.clone(),
            peer_relay_server: self.config.peer_relay_server,
            disco_key: b.disco_key.clone(),
            capability_version: CAPABILITY_VERSION,
            protocol_version: PROTOCOL_VERSION,
            shields_up: prefs.read().await.ShieldsUp,
        };
        b.tailnet_lock
            .attach_peer_authority(crate::map_update::PeerAuthorityRuntime::new(
                b.exit_map_gate.clone(),
                b.peer_map.clone(),
                self.drive.clone(),
                b.magicsock.clone(),
                b.filter.clone(),
                b.peers.clone(),
                b.wg_tunnels.clone(),
                b.resolver.clone(),
                prefs.clone(),
                b.route_table.clone(),
                router.clone(),
                b.tailscale_ips.clone(),
                b.control_url.clone(),
                self.config.accept_routes,
            ))
            .map_err(|error| TsnetError::TailnetLock(error.to_string()))?;
        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.raw_peers.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            b.exit_map_gate.clone(),
            router.clone(),
            prefs.clone(),
            exit_node_selection.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.named_filters.clone(),
            self.drive.clone(),
            b.peer_map.clone(),
            b.tailscale_ips.clone(),
            b.control_url.clone(),
            self.config.accept_routes,
            b.advertise_routes.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.user_profiles.clone(),
            b.ssh_policy.clone(),
            b.cancel.clone(),
            b.health.clone(),
            b.health_watchdog.clone(),
            b.state_scope.clone(),
            b.node_key.public(),
            b.control_knobs.clone(),
            b.key_expired.clone(),
            b.ipn_backend.clone(),
            Some(key_rotation_ctx),
            b.map_session.clone(),
            Arc::clone(&b.map_tasks),
            b.c2n_router.clone(),
            b.ssh_callbacks.clone(),
            suggested_exit_node.clone(),
            client_updater.clone(),
            b.tailnet_lock.clone(),
            b.domain.clone(),
            b.peer_snapshot_fresh,
        );
        rollback.track(map_update);

        // Taildrop file manager (shared between PeerAPI receive handler
        // and LocalAPI endpoints). Created from the state directory.
        let taildrop = Arc::new(taildrop::TaildropManager::new(
            self.config.state_dir.as_deref(),
            Some(b.ipn_backend.clone()),
        ));

        // PeerAPI server (TUN mode): binds TCP listeners on the node's
        // tailnet IPs (v4 + v6) on the deterministic port.
        let offering_exit_node = self.config.advertise_exit_node;
        let (peerapi_tasks, peerapi_port) = peerapi::spawn_peerapi_tun(
            b.peers.clone(),
            b.user_profiles.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.tailscale_ips.clone(),
            offering_exit_node,
            Some(taildrop.clone()),
            Some(b.sockstats.clone()),
            b.filter.clone(),
            self.drive.clone(),
            b.peer_map.clone(),
        )
        .await;
        for task in peerapi_tasks {
            rollback.track(task);
        }

        // Advertise peerapi4/peerapi6 services to the control plane.
        if let Some(port) = peerapi_port {
            let has_v6 = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
            let services =
                peerapi::peerapi_services(Some(port), if has_v6 { Some(port) } else { None });
            if !services.is_empty() {
                let cc_ep = ControlClient::new(
                    &b.control_url,
                    b.machine_key.clone(),
                    b.server_pub_key.clone(),
                    PROTOCOL_VERSION,
                );
                let node_pub = b.node_key.public();
                let disco_pub = b.disco_key.public();
                let svc_req = MapRequest {
                    Version: CAPABILITY_VERSION,
                    KeepAlive: false,
                    NodeKey: node_pub,
                    DiscoKey: disco_pub,
                    Stream: false,
                    OmitPeers: true,
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: b.hostname.clone(),
                        RoutableIPs: b.advertise_routes.clone(),
                        Services: services,
                        PeerRelay: self.config.peer_relay_server,
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                match cc_ep.send_map_request(&svc_req).await {
                    Ok(()) => log::info!("tsnet: peerapi services advertised (port {port})"),
                    Err(e) => {
                        log::warn!("tsnet: peerapi service advertisement failed (non-fatal): {e}");
                    }
                }
            }
        }

        // Portlist: shared state for the background port-scanning task and
        // the hostinfo hook (TUN mode).
        let portlist_ports: Arc<std::sync::Mutex<Vec<rustscale_portlist::Port>>> =
            Arc::new(std::sync::Mutex::new(vec![]));
        let proxy_mapper = Arc::new(rustscale_proxymap::Mapper::new());

        let pl_ports_hook = portlist_ports.clone();
        let hp_port = peerapi_port;
        let has_v6_hook = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
        rollback
            .hostinfo_hooks
            .push(hostinfo::register_hostinfo_hook(move |hi| {
                let mut services = Vec::new();
                if let Some(port) = hp_port {
                    if port > 0 {
                        services.push(rustscale_tailcfg::Service {
                            Proto: "peerapi4".into(),
                            Port: port,
                            Description: String::new(),
                        });
                        if has_v6_hook {
                            services.push(rustscale_tailcfg::Service {
                                Proto: "peerapi6".into(),
                                Port: port,
                                Description: String::new(),
                            });
                        }
                    }
                }
                if let Ok(ports) = pl_ports_hook.lock() {
                    services.extend(rustscale_portlist::to_services(&ports));
                }
                if !services.is_empty() {
                    hi.Services = services;
                }
            }));

        let pl_ports_task = portlist_ports.clone();
        let pl_cancel = b.cancel.clone();
        let pl_interval = rustscale_portlist::Poller::new(false).interval();
        let portlist_task = tokio::spawn(async move {
            let mut poller = rustscale_portlist::Poller::new(false);
            loop {
                if pl_cancel.is_cancelled() {
                    break;
                }
                let (ports, changed) = poller.poll().await;
                if changed {
                    if let Ok(mut guard) = pl_ports_task.lock() {
                        *guard = ports;
                    }
                }
                tokio::time::sleep(pl_interval).await;
            }
        });
        rollback.track(portlist_task);

        // Periodic Hostinfo refresh (every 10 min, dedup by content hash).
        // In TUN mode, serve/funnel is not available so pass None.
        let hostinfo_loop = spawn_hostinfo_update_loop(
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.home_derp,
            b.peers.clone(),
            b.route_table.clone(),
            None,
            b.overrides.clone(),
            self.config.state_dir.clone(),
            b.backend_log_id.clone(),
            b.ssh_host_keys.clone(),
            self.config.posture_checking,
            self.config.preference_policy.clone(),
        );
        rollback.track(hostinfo_loop);

        // LocalAPI Unix-domain-socket server (optional, default OFF).
        let localapi_socket = if self.config.localapi {
            let path = self.config.localapi_path.clone().unwrap_or_else(|| {
                let dir = self
                    .config
                    .state_dir
                    .clone()
                    .unwrap_or_else(|| std::env::temp_dir().join("rustscale"));
                localapi::default_socket_path(&dir)
            });
            let state = localapi::LocalApiState {
                mutation_fence: Arc::clone(&localapi_mutation_fence),
                mutation_generation: localapi_mutation_generation,
                peers: b.peers.clone(),
                user_profiles: b.user_profiles.clone(),
                health: b.health.clone(),
                dns_config: b.dns_config.clone(),
                packet_drops: b.packet_drops.clone(),
                capture: capture.clone(),
                metrics: localapi::default_metric_registry(),
                prefs: prefs.clone(),
                operator_access: std::sync::Mutex::default(),
                posture_checking: b.posture_checking.clone(),
                profile_mutations: profile_mutations.clone(),
                exit_node_selection: exit_node_selection.clone(),
                tailscale_ips: b.tailscale_ips.clone(),
                our_fqdn: b.our_fqdn.clone(),
                hostname: self.config.hostname.clone(),
                magicsock: b.magicsock.clone(),
                tun_mode: true,
                routecheck: Some(b.routecheck.clone()),
                home_derp: b.home_derp,
                ipn_backend: b.ipn_backend.clone(),
                derp_map: b.derp_map.clone(),
                command_tx: self
                    .pre_started
                    .as_ref()
                    .and_then(|ps| ps.command_tx.clone()),
                state_dir: self.config.state_dir.clone(),
                auth_url: Arc::new(std::sync::Mutex::new(None)),
                login_trigger: self
                    .pre_started
                    .as_ref()
                    .map(|ps| ps.login_trigger.clone())
                    .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
                serve_config: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| serve::ServeConfig::load(d).ok())
                        .unwrap_or_default(),
                )),
                serve_runner: None, // TUN mode has no serve runner
                profiles: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                        .unwrap_or_default(),
                )),
                current_profile: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                        .flatten(),
                )),
                cert_params: self
                    .config
                    .state_dir
                    .clone()
                    .map(|dir| localapi::CertParams {
                        state_dir: dir,
                        control_url: self.config.control_url.clone(),
                        machine_key: b.machine_key.clone(),
                        server_pub_key: b.server_pub_key.clone(),
                        node_key: b.node_key.clone(),
                        capability_version: CAPABILITY_VERSION,
                        protocol_version: PROTOCOL_VERSION,
                    }),
                control_params: Some(localapi::ControlParams {
                    control_url: self.config.control_url.clone(),
                    machine_key: b.machine_key.clone(),
                    server_pub_key: b.server_pub_key.clone(),
                    node_key: b.node_key.clone(),
                    capability_version: CAPABILITY_VERSION,
                    protocol_version: PROTOCOL_VERSION,
                }),
                taildrop: Some(taildrop.clone()),
                drive: self.drive.clone(),
                peer_map: b.peer_map.clone(),
                tailnet_lock: Some(b.tailnet_lock.clone()),
                netstack: None, // TUN mode has no netstack
                filter: std::sync::OnceLock::new(),
                route_table: Some(b.route_table.clone()),
                exit_map_gate: b.exit_map_gate.clone(),
                router: router.clone(),
                logout_trigger: Arc::clone(&self.logout_trigger),
                logout_completion: Arc::clone(&self.logout_completion),
                suggested_exit_node: suggested_exit_node.clone(),
                config_path: self.config.config_path.clone(),
                client_updater: client_updater.clone(),
                audit_logger: Some(audit_logger.clone()),
                preference_policy: self.config.preference_policy.clone(),
                policy_subscription: std::sync::Mutex::new(None),
            };
            // Publish the live filter so `PATCH /prefs` can toggle
            // shields-up mode without a full rebuild.
            let _ = state.filter.set(b.filter.clone());
            let state = Arc::new(state);
            localapi::activate_preference_policy(&state)
                .await
                .map_err(TsnetError::Builder)?;
            let replacing_prestarted = self
                .pre_started
                .as_ref()
                .and_then(|pre_started| pre_started.handle.as_ref())
                .is_some();
            let handle = if replacing_prestarted {
                localapi::spawn_localapi_paused(state, path.clone()).map(
                    |(handle, start, handoff)| {
                        rollback.localapi_start = Some(start);
                        rollback.localapi_handoff = Some(handoff);
                        handle
                    },
                )
            } else {
                localapi::spawn_localapi(state, path.clone())
            };
            if let Some(handle) = handle {
                let socket_path = if replacing_prestarted {
                    path.clone()
                } else {
                    handle.socket_path.clone()
                };
                rollback.localapi = Some(handle);
                log::info!("tsnet: LocalAPI prepared at {}", path.display());
                Some(socket_path)
            } else {
                if replacing_prestarted {
                    return Err(TsnetError::Builder(format!(
                        "failed to prepare LocalAPI replacement at {}",
                        path.display()
                    )));
                }
                log::warn!(
                    "tsnet: LocalAPI failed to bind socket at {}",
                    path.display()
                );
                None
            }
        } else {
            None
        };
        rollback.localapi_socket.clone_from(&localapi_socket);

        // OS DNS configuration (macOS: /etc/resolver entries pointing at
        // 100.100.100.100). Opt-in via `configure_os_dns(true)` — requires
        // root. Best-effort: permission errors are logged and do not prevent
        // up_tun from completing.
        rollback.os_dns_configurator = if self.config.configure_os_dns {
            let dns_cfg_snapshot = b.dns_config.read().await.clone();
            let os_cfg = if let Some(ref dc) = dns_cfg_snapshot {
                build_os_dns_config(dc, &b.domain)
            } else {
                OsConfig {
                    nameservers: vec![IpAddr::V4(MAGICDNS_VIP)],
                    ..Default::default()
                }
            };
            let mut configurator: Box<dyn OsConfigurator + Send> = Box::new(new_os_configurator());
            match configurator.set_dns(&os_cfg) {
                Ok(()) => {
                    log::info!(
                        "tsnet: OS DNS configured ({} match domains, {} search domains)",
                        os_cfg.match_domains.len(),
                        os_cfg.search_domains.len()
                    );
                    Some(configurator)
                }
                Err(e) => {
                    log::warn!("tsnet: OS DNS configuration failed (non-fatal, needs root?): {e}");
                    None
                }
            }
        } else {
            None
        };
        let extension_subscription = self
            .finish_tun_startup(b.ipn_backend.clone(), prefs.clone())
            .await?;
        rollback.commit_localapi_handoff()?;
        let retire_prestarted = self.pre_started.is_some();
        let os_dns_configurator = rollback.take_os_dns_configurator();
        let tasks = rollback.commit_tasks();
        let task_aborts = tasks.iter().map(JoinHandle::abort_handle).collect();

        let startup_backend = b.ipn_backend.clone();
        self.inner = Some(RunningState {
            tailscale_ips: b.tailscale_ips,
            magicsock: b.magicsock,
            netlog: b.netlog,
            data_plane: DataPlane::Tun,
            peers: b.peers,
            peer_map: b.peer_map,
            routecheck: b.routecheck,
            route_table: b.route_table,
            filter: b.filter,
            exit_map_gate: b.exit_map_gate,
            router,
            cancel: b.cancel,
            tasks: Mutex::new(tasks),
            map_tasks: b.map_tasks,
            task_aborts: std::sync::Mutex::new(task_aborts),
            loopback_controls: std::sync::Mutex::new(Vec::new()),
            in_memory_clients: std::sync::Mutex::new(Vec::new()),
            packet_drops: b.packet_drops,
            capture,
            capture_handles: std::sync::Mutex::new(vec![]),
            resolver: b.resolver,
            our_fqdn: b.our_fqdn,
            domain: b.domain.clone(),
            dns_config: b.dns_config,
            user_profiles: b.user_profiles,
            ssh_policy: b.ssh_policy,
            ssh_host_keys: b.ssh_host_keys,
            ssh_callbacks: b.ssh_callbacks,
            monitor: rollback.take_monitor(),
            machine_key: b.machine_key,
            server_pub_key: b.server_pub_key,
            node_key: b.node_key,
            serve: None,
            health: b.health,
            health_watchdog: b.health_watchdog,
            c2n_router: b.c2n_router,
            posture_checking: b.posture_checking,
            control_knobs: b.control_knobs,
            peerapi_port,
            overrides: b.overrides,
            localapi_socket,
            localapi_handle: rollback.take_localapi(),
            key_expired: b.key_expired,
            os_dns_configurator,
            ipn_backend: b.ipn_backend,
            logout_trigger: Arc::clone(&self.logout_trigger),
            logout_completion: Arc::clone(&self.logout_completion),
            fallback_tcp_handlers: Arc::new(std::sync::Mutex::new(vec![])),
            fallback_next_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            prefs: prefs.clone(),
            profile_mutations,
            localapi_mutation_fence,
            localapi_mutation_generation,
            exit_node_selection: exit_node_selection.clone(),
            proxy_mapper,
            portlist_ports,
            client_updater: client_updater.clone(),
            audit_logger,
            tailnet_lock: b.tailnet_lock.clone(),
            hostinfo_hooks: rollback.take_hostinfo_hooks(),
            extension_subscription,
        });

        startup_backend.set_blocked(false);
        if retire_prestarted {
            self.retire_prestarted_after_handoff();
        }
        Ok(self.status())
    }

    // --- shared control-plane bootstrap ---

    fn retire_prestarted_after_handoff(&mut self) {
        let Some(pre_started) = self.pre_started.take() else {
            return;
        };
        let completion = self.startup_supervisor.begin_cleanup();
        spawn_rollback_cleanup("rustscale-prestarted-retire", async move {
            let _completion = completion;
            // The replacement now owns the advertised pathname. Retiring the
            // old generation must not unlink it.
            cleanup_pre_started(pre_started, false).await;
        });
    }

    pub(crate) async fn ensure_extension_host(&mut self) -> Result<(), TsnetError> {
        if self.shutdown_supervisor.has_retained_owner()
            || self.shutdown_supervisor.has_retained_logout()
        {
            return Err(TsnetError::ShutdownIncomplete(
                "previous server owner still requires shutdown retry".into(),
            ));
        }

        if self
            .extension_host
            .as_ref()
            .is_some_and(rustscale_ipnext::ExtensionHost::is_created)
        {
            return Ok(());
        }

        if let Some(host) = self.extension_host.take() {
            match shutdown_extension_host(host).await {
                Ok(()) => {}
                Err(host) => {
                    self.extension_host = Some(host);
                    return Err(TsnetError::Extension(
                        "previous extension host shutdown remains incomplete".into(),
                    ));
                }
            }
        }

        let host = match self.config.extension_registry.as_deref() {
            Some(registry) => {
                rustscale_ipnext::ExtensionHost::new(registry, Arc::clone(&self.system))
            }
            None => rustscale_ipnext::ExtensionHost::new(
                rustscale_ipnext::global_registry(),
                Arc::clone(&self.system),
            ),
        }
        .map_err(|error| TsnetError::Extension(error.to_string()))?;
        self.extension_host = Some(host);
        Ok(())
    }

    pub(crate) async fn finish_tun_startup(
        &mut self,
        ipn_backend: Arc<IpnBackend>,
        live_prefs: Arc<RwLock<rustscale_ipn::Prefs>>,
    ) -> Result<Option<rustscale_ipn::CallbackSubscription>, TsnetError> {
        self.start_extensions_with(ipn_backend, live_prefs).await
    }

    pub(crate) async fn start_extensions_with(
        &mut self,
        ipn_backend: Arc<IpnBackend>,
        live_prefs: Arc<RwLock<rustscale_ipn::Prefs>>,
    ) -> Result<Option<rustscale_ipn::CallbackSubscription>, TsnetError> {
        let Some(host) = self.extension_host.as_ref() else {
            return Ok(None);
        };
        let state_dir = self.config.state_dir.clone();

        let prefs = live_prefs.read().await.clone();
        let profile = state_dir
            .as_ref()
            .and_then(|dir| {
                let current = rustscale_ipn::LoginProfile::load_current_id(dir).ok()??;
                rustscale_ipn::LoginProfile::load_all(dir)
                    .ok()?
                    .into_iter()
                    .find(|profile| profile.ID == current)
            })
            .unwrap_or_default();
        ipn_backend.seed_profile_state(profile.clone(), prefs.clone());
        let handle = host.host();
        let delivery = Arc::new(StartupDelivery::new(handle));
        let state_delivery = Arc::clone(&delivery);
        let profile_delivery = Arc::clone(&delivery);
        let (backend_state, profile_snapshot, subscription) = ipn_backend.subscribe_with_snapshot(
            Arc::new(move |state| {
                state_delivery.enqueue(StartupDeliveryEvent::Backend(state));
            }),
            Arc::new(move |profile, prefs, same_node| {
                profile_delivery.enqueue(StartupDeliveryEvent::Profile(Box::new((
                    profile, prefs, same_node,
                ))));
            }),
        );
        let (profile, prefs, _) = profile_snapshot.unwrap_or((profile, prefs, false));
        host.seed_profile_state(profile.clone(), prefs.clone())
            .map_err(|error| TsnetError::Extension(error.to_string()))?;

        let report = host
            .start()
            .await
            .map_err(|error| TsnetError::Extension(error.to_string()))?;
        for failure in report.failed {
            log::warn!(
                "tsnet: extension {:?} init failed (non-fatal): {}",
                failure.name,
                failure.source
            );
        }

        delivery.activate(vec![
            StartupDeliveryEvent::Profile(Box::new((profile, prefs, false))),
            StartupDeliveryEvent::Backend(backend_state),
        ]);
        Ok(Some(subscription))
    }

    /// Ensure the server is up, starting it if needed. Called by `listen()`
    /// and `dial()` for lazy auto-start. Mirrors Go's `Server.Start()` being
    /// called by `Dial`/`Listen`. If the server is already up, this is a
    /// no-op (idempotent).
    pub async fn ensure_up(&mut self) -> Result<ServerStatus, TsnetError> {
        if self.inner.is_none() {
            Box::pin(self.up()).await?;
        }
        Ok(self.status())
    }

    /// Load prefs from the state directory, or return default if not found.
    pub(crate) fn load_prefs(&self) -> Result<rustscale_ipn::Prefs, TsnetError> {
        let mut prefs = if let Some(ref dir) = self.config.state_dir {
            rustscale_ipn::Prefs::load(dir).map_err(|e| TsnetError::Builder(e.to_string()))?
        } else {
            rustscale_ipn::Prefs::default()
        };
        if let Some(policy) = &self.config.preference_policy {
            let changed = policy.reconcile(&mut prefs).map_err(TsnetError::Builder)?;
            if changed {
                if let Some(ref dir) = self.config.state_dir {
                    prefs
                        .save(dir)
                        .map_err(|error| TsnetError::Builder(error.to_string()))?;
                }
            }
        }
        Ok(prefs)
    }

    /// Set the auth key after construction (used by the daemon when the CLI
    /// provides it via `POST /start`).
    pub fn set_auth_key(&mut self, key: impl Into<String>) {
        self.config.auth_key = Some(key.into());
    }

    /// Start only the LocalAPI server without full bootstrap. Used by the
    /// daemon when no auth key is available — the server enters NeedsLogin
    /// state and waits for CLI-driven `up()` via `POST /start` or
    /// `POST /login-interactive`.
    ///
    /// Returns a command receiver for the daemon to listen on, and the
    /// login trigger Notify (used by `/login-interactive` to unblock
    /// bootstrap's auth wait).
    pub async fn start_localapi_only(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<localapi::DaemonCommand>, TsnetError> {
        self.shutdown_supervisor.wait().await;
        self.startup_supervisor.wait().await;
        if self.shutdown_supervisor.has_retained_logout()
            || self.shutdown_supervisor.has_retained_owner()
        {
            return Err(TsnetError::ShutdownIncomplete(
                "previous server owner still requires shutdown retry".into(),
            ));
        }
        if let Some(pre_started) = self.pre_started.take() {
            let completion = self.shutdown_supervisor.begin_cleanup();
            spawn_rollback_cleanup("rustscale-prestarted-restart", async move {
                let _completion = completion;
                cleanup_pre_started(pre_started, true).await;
            });
            self.shutdown_supervisor.wait().await;
        }
        Self::retry_pending_router_cleanup().await?;

        let ipn_backend = Arc::new(IpnBackend::new("rustscale"));
        ipn_backend.set_want_running();
        ipn_backend.set_auth_cant_continue(true);
        // Block engine updates while waiting for auth — mirrors Go's
        // blockEngineUpdatesLocked(true) on NeedsLogin enter.
        ipn_backend.set_blocked(true);

        let state = self.load_or_create_state()?;
        let was_fresh = state.is_zero();
        let state = if was_fresh {
            let s = PersistedState::generate();
            self.save_state(&s)?;
            s
        } else {
            state
        };
        ipn_backend.set_has_node_key(!state.is_zero());

        let prefs = self.load_prefs().unwrap_or_default();
        let prefs = Arc::new(RwLock::new(prefs));

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let command_tx_clone = command_tx.clone();
        let login_trigger = Arc::new(tokio::sync::Notify::new());
        let auth_url = Arc::new(std::sync::Mutex::new(None));
        let logout_trigger = Arc::clone(&self.logout_trigger);

        let (magicsock, _wg_rx) = Magicsock::new(MagicsockConfig {
            private_key: state.node_key.clone(),
            disco_key: state.disco_key.clone(),
            derp_client: None,
            derp_map: Some(DERPMap::default()),
            home_derp_region: 0,
            udp_bind: None,
            udp_socket: None,
            portmapper: None,
            health: None,
            disable_direct_paths: false,
            peer_relay_server: false,
            relay_server_config: None,
            sockstats: None,
            control_knobs: Some(Arc::new(ControlKnobs::new())),
        })
        .await
        .map_err(TsnetError::Magicsock)?;
        let magicsock = Arc::new(magicsock);
        let mut magicsock_rollback = PrestartedMagicsockRollback::new(
            Arc::clone(&self.shutdown_supervisor),
            Arc::clone(&magicsock),
        );

        let socket_path = if let Some(ref p) = self.config.localapi_path {
            p.clone()
        } else if let Some(ref dir) = self.config.state_dir {
            localapi::default_socket_path(dir)
        } else {
            localapi::default_socket_path(&std::env::temp_dir().join("rustscale"))
        };

        let mutation_fence = localapi::LocalApiMutationFence::new();
        let mutation_generation = mutation_fence.generation();
        let api_state = Arc::new(localapi::LocalApiState {
            mutation_fence: Arc::clone(&mutation_fence),
            mutation_generation,
            peers: Arc::new(RwLock::new(vec![])),
            routecheck: None,
            user_profiles: Arc::new(RwLock::new(BTreeMap::new())),
            health: Tracker::new(),
            dns_config: Arc::new(RwLock::new(None)),
            packet_drops: Arc::new(AtomicU64::new(0)),
            capture: crate::capture::new_slot(),
            metrics: localapi::default_metric_registry(),
            prefs: prefs.clone(),
            operator_access: std::sync::Mutex::default(),
            posture_checking: Arc::new(AtomicBool::new(prefs.read().await.PostureChecking)),
            profile_mutations: Arc::new(tokio::sync::Mutex::new(())),
            exit_node_selection: Arc::new(RwLock::new(ExitNodeSelection::from_prefs(
                &*prefs.read().await,
            ))),
            tailscale_ips: vec![],
            our_fqdn: String::new(),
            hostname: self.config.hostname.clone(),
            magicsock: magicsock.clone(),
            tun_mode: false,
            home_derp: 0,
            ipn_backend: ipn_backend.clone(),
            derp_map: DERPMap::default(),
            command_tx: Some(command_tx),
            state_dir: self.config.state_dir.clone(),
            auth_url: auth_url.clone(),
            login_trigger: login_trigger.clone(),
            serve_config: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| serve::ServeConfig::load(d).ok())
                    .unwrap_or_default(),
            )),
            serve_runner: None,
            profiles: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                    .unwrap_or_default(),
            )),
            current_profile: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                    .flatten(),
            )),
            cert_params: None,
            control_params: None,
            taildrop: None,
            drive: self.drive.clone(),
            peer_map: crate::peer_map::Runtime::new(&[]).expect("empty localapi peer map"),
            tailnet_lock: None,
            netstack: None,
            filter: std::sync::OnceLock::new(),
            route_table: None,
            exit_map_gate: Arc::new(tokio::sync::Mutex::new(())),
            router: None,
            logout_trigger: logout_trigger.clone(),
            logout_completion: Arc::clone(&self.logout_completion),
            suggested_exit_node: Arc::new(RwLock::new(String::new())),
            config_path: self.config.config_path.clone(),
            client_updater: Arc::new(std::sync::Mutex::new(
                rustscale_clientupdate::ClientUpdater::new(env!("CARGO_PKG_VERSION")),
            )),
            audit_logger: None,
            preference_policy: self.config.preference_policy.clone(),
            policy_subscription: std::sync::Mutex::new(None),
        });
        localapi::activate_preference_policy(&api_state)
            .await
            .map_err(TsnetError::Builder)?;

        let handle = localapi::spawn_localapi(api_state.clone(), socket_path.clone());
        if handle.is_some() {
            log::info!(
                "tsnet: LocalAPI (needs-login) listening at {}",
                socket_path.display()
            );
        } else {
            log::warn!("tsnet: LocalAPI failed to bind {}", socket_path.display());
        }

        self.pre_started = Some(PreStartedLocalApi {
            backend: ipn_backend,
            handle,
            magicsock: Some(magicsock_rollback.commit()),
            login_trigger,
            auth_url,
            command_rx: Some(command_rx),
            command_tx: Some(command_tx_clone),
            logout_trigger,
            mutation_fence,
            mutation_generation,
            socket_path,
        });

        Ok(self
            .pre_started
            .as_mut()
            .unwrap()
            .command_rx
            .take()
            .unwrap())
    }

    /// Select transient credentials for the initial register request.
    /// Persisted enrollments authenticate by node identity unless force-login
    /// was explicitly requested.
    pub(crate) async fn initial_registration_auth(
        &mut self,
        state: &PersistedState,
    ) -> Result<Option<TransientAuthKey>, TsnetError> {
        if state.is_enrolled() && !self.config.force_login {
            return Ok(None);
        }
        if self
            .config
            .auth_key
            .as_deref()
            .is_some_and(|key| !key.is_empty())
        {
            return Ok(self.config.auth_key.clone().map(TransientAuthKey::new));
        }

        #[cfg(feature = "identity-federation")]
        rustscale_identityfederation::install()
            .map_err(|error| TsnetError::IdentityFederation(error.to_string()))?;

        let Some(resolve) = rustscale_feature::RESOLVE_AUTH_KEY_VIA_WIF.try_get() else {
            return Ok(None);
        };
        let client_id = &self.config.client_id;
        let id_token = &self.config.id_token;
        let audience = &self.config.audience;
        if client_id.is_empty() && id_token.is_empty() && audience.is_empty() {
            return Ok(None);
        }
        if !client_id.is_empty() && id_token.is_empty() && audience.is_empty() {
            return Err(TsnetError::IdentityFederation(
                "client ID for workload identity federation found, but ID token and audience are empty"
                    .into(),
            ));
        }
        if !id_token.is_empty() && !audience.is_empty() {
            return Err(TsnetError::IdentityFederation(
                "only one of ID token and audience should be for workload identity federation"
                    .into(),
            ));
        }
        if client_id.is_empty() {
            if !id_token.is_empty() {
                return Err(TsnetError::IdentityFederation(
                    "ID token for workload identity federation found, but client ID is empty"
                        .into(),
                ));
            }
            if !audience.is_empty() {
                return Err(TsnetError::IdentityFederation(
                    "audience for workload identity federation found, but client ID is empty"
                        .into(),
                ));
            }
        }

        let auth_key = resolve(rustscale_feature::IdentityFederationRequest {
            base_url: self.config.control_url.clone(),
            client_id: client_id.clone(),
            id_token: id_token.clone(),
            audience: audience.clone(),
            tags: self.config.advertise_tags.clone(),
        })
        .await
        .map_err(|error| TsnetError::IdentityFederation(error.to_string()))?;
        if auth_key.is_empty() {
            Ok(None)
        } else {
            Ok(Some(TransientAuthKey::new(auth_key)))
        }
    }

    /// Shared bootstrapping for `up()` and `up_tun()`: load state, register
    /// with control, start the map long-poll, wait for the first `MapResponse`,
    /// netcheck for a home DERP, connect it, build magicsock + per-peer WG
    /// tunnels + the routing table. Returns the shared handles plus the
    /// still-open map receiver for the update task.
    async fn bootstrap(
        &mut self,
        mut state: PersistedState,
        mut initial_auth: Option<TransientAuthKey>,
    ) -> Result<Bootstrap, TsnetError> {
        // A cancelled prior bootstrap owns its spawned tasks until they have
        // been aborted and joined. Never overlap a retry with that cleanup.
        self.bootstrap_supervisor.wait().await;
        // Effective advertised routes: user-specified subnet routes plus the
        // exit-node default routes (0.0.0.0/0, ::/0) when advertise_exit_node
        // is enabled. Used for Hostinfo.RoutableIPs, the filter's localNets,
        // and link-change endpoint updates.
        let advertise = self.config.effective_advertise_routes();
        let state_scope = self.profile_state_scope();

        // Health tracker + map-poll staleness watchdog (fires if no
        // MapResponse for more than 3 minutes).
        let health = Tracker::new();
        let health_watchdog = Watchdog::new(
            health.clone(),
            WARN_CONTROL,
            "Control connection",
            Severity::High,
            "control connection lost: no map activity for over 3 minutes",
            std::time::Duration::from_mins(3),
        )?;
        let mut bootstrap_rollback = BootstrapRollback::new(
            Arc::clone(&self.bootstrap_supervisor),
            health_watchdog.clone(),
        );

        // Socket-statistics registry (per-label TX/RX byte counters).
        // Shared across magicsock, DERP, DNS, and the C2N/PeerAPI debug
        // endpoints. Best-effort: instrumentation is fire-and-forget atomic
        // increments with no error paths.
        let sockstats = Arc::new(rustscale_sockstats::SockStats::new());

        // IPN state machine backend. Created early so state transitions
        // are tracked from the start. Want_running is set immediately;
        // other inputs are set as bootstrap progresses.
        let ipn_backend = if let Some(ref ps) = self.pre_started {
            ps.backend.clone()
        } else {
            Arc::new(IpnBackend::new("rustscale"))
        };
        ipn_backend.set_want_running();

        // 1. Generate persistent key material when no state was loaded.
        let was_fresh = state.is_zero();
        if was_fresh {
            state = PersistedState::generate();
            self.save_state(&state)?;
        } else if state.network_lock_key.is_zero() {
            // Upgrade older persisted identities with a profile-local Tailnet
            // Lock key before exposing it through LocalAPI status.
            state.network_lock_key = rustscale_key::NLPrivate::generate();
            self.save_state(&state)?;
        }

        let private_log_id = if let Some(scope) = state_scope.as_ref() {
            rustscale_logid::PrivateID::load_or_create(&scope.dir.join("logid-private"))?
        } else {
            rustscale_logid::PrivateID::new()
        };
        let backend_log_id = private_log_id.public().to_string();

        let node_pub = state.node_key.public();
        let disco_pub = state.disco_key.public();

        // We have a node key (generated or loaded from state).
        ipn_backend.set_has_node_key(!state.is_zero());

        // Try to load a cached netmap from the state directory. On a restart
        // with an existing state dir, this lets us skip the blocking first
        // MapResponse fetch (2-5s) and use the cached peers immediately —
        // the streaming long-poll delivers fresh updates in the background.
        let cached_netmap = state_scope.as_ref().and_then(|scope| {
            let cache = NetMapCache::new_scoped(scope, &state.tailnet_identity);
            let cached = cache.load()?;
            (cached.version == 2 && cached.node_key == node_pub).then_some(cached.map_response)
        });

        // 2. Fetch the server's Noise public key (GET /key?v=<version>).
        let server_pub_key = controlhttp::fetch_server_pub_key(
            &self.config.control_url,
            PROTOCOL_VERSION,
            self.config.extra_root_certs.as_deref(),
        )
        .await
        .map_err(|e| TsnetError::Register(rustscale_controlclient::RegisterError::Dial(e)))?;

        // 3. Register with the control plane. Authentication is consumed by
        // this one request and omitted from followups and all later refreshes.
        let mut cc = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        if let Some(certs) = self.config.extra_root_certs.clone() {
            cc.set_extra_root_certs(certs);
        }

        let mut reg_req = RegisterRequest {
            Version: CAPABILITY_VERSION,
            NodeKey: node_pub.clone(),
            Auth: take_initial_register_auth(&mut initial_auth),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                RequestTags: self.config.advertise_tags.clone(),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            Ephemeral: self.config.ephemeral,
            ..Default::default()
        };

        drop(initial_auth);
        let register_result = cc.register(&reg_req).await;
        clear_register_auth(&mut reg_req);
        let reg_resp = register_result.map_err(|e| {
            // Auth/network failure is ambiguous. The key is not retained, so
            // a fresh WIF key is minted if the caller starts again.
            if let Some(scope) = state_scope.as_ref() {
                NetMapCache::new_scoped(scope, &state.tailnet_identity).clear();
                log::warn!("tsnet: cleared netmap cache after register error: {e}");
            }
            ipn_backend.emit_err_message(e.to_string());
            TsnetError::Register(e)
        })?;

        // Server-side error string (e.g. "invalid auth key", "node key revoked").
        if !reg_resp.Error.is_empty() {
            if let Some(scope) = state_scope.as_ref() {
                NetMapCache::new_scoped(scope, &state.tailnet_identity).clear();
                log::warn!(
                    "tsnet: cleared netmap cache after register error: {}",
                    reg_resp.Error
                );
            }
            ipn_backend.emit_err_message(&reg_resp.Error);
            return Err(TsnetError::Builder(format!(
                "control register rejected: {}",
                reg_resp.Error
            )));
        }

        // Node key expired — the server says our key is no longer valid.
        // Clear the cache so we don't reuse a netmap bound to the old key.
        if reg_resp.NodeKeyExpired {
            if let Some(scope) = state_scope.as_ref() {
                NetMapCache::new_scoped(scope, &state.tailnet_identity).clear();
                log::info!("tsnet: cleared netmap cache: node key expired");
            }
            ipn_backend.set_key_expired(true);
        }

        if reg_resp.AuthURL.is_empty() {
            ipn_backend.set_machine_authorized(reg_resp.MachineAuthorized);
            // A pre-started daemon keeps its startup block until all runtime
            // resources and the LocalAPI handoff commit. Authentication alone
            // must not publish Running while Server::up is still cancellable.
            ipn_backend.emit_login_finished();
            state.node_id = reg_resp.User.ID;
            state.enrolled = true;
            self.save_state(&state)?;
        } else {
            ipn_backend.set_auth_cant_continue(true);
            // Block engine updates while waiting for interactive auth.
            ipn_backend.set_blocked(true);
            ipn_backend.emit_browse_to_url(&reg_resp.AuthURL);

            if let Some(ref ps) = self.pre_started {
                {
                    let mut au = ps.auth_url.lock().unwrap();
                    *au = Some(reg_resp.AuthURL.clone());
                }
                ps.login_trigger.notified().await;
                {
                    let mut au = ps.auth_url.lock().unwrap();
                    *au = None;
                }
                ipn_backend.set_auth_cant_continue(false);

                let followup_req = RegisterRequest {
                    Version: CAPABILITY_VERSION,
                    NodeKey: node_pub.clone(),
                    Followup: reg_resp.AuthURL.clone(),
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: self.config.hostname.clone(),
                        RoutableIPs: advertise.clone(),
                        RequestTags: self.config.advertise_tags.clone(),
                        PeerRelay: self.config.peer_relay_server,
                        ..Default::default()
                    }),
                    Ephemeral: self.config.ephemeral,
                    ..Default::default()
                };
                let followup_resp = cc.register(&followup_req).await.map_err(|e| {
                    if let Some(scope) = state_scope.as_ref() {
                        NetMapCache::new_scoped(scope, &state.tailnet_identity).clear();
                    }
                    ipn_backend.emit_err_message(e.to_string());
                    TsnetError::Register(e)
                })?;

                if followup_resp.Error.is_empty() {
                    ipn_backend.set_machine_authorized(followup_resp.MachineAuthorized);
                    ipn_backend.emit_login_finished();
                    state.node_id = followup_resp.User.ID;
                    state.enrolled = true;
                    self.save_state(&state)?;
                } else {
                    ipn_backend.emit_err_message(&followup_resp.Error);
                    return Err(TsnetError::Builder(format!(
                        "control register (followup) rejected: {}",
                        followup_resp.Error
                    )));
                }
            } else {
                return Err(TsnetError::AuthRequired(reg_resp.AuthURL));
            }
        }

        // 3b. Bind the UDP socket early so we can gather local interface
        // endpoints (interface IP + bound port) and advertise them in the
        // MapRequest. Magicsock takes ownership of this socket later, once
        // the DERPMap/home-DERP are known from the first MapResponse.
        // Without advertised endpoints, peers only learn our addresses via
        // CallMeMaybe (one-shot, racy) and two nodes on the same machine
        // never establish a direct UDP path — they stay on DERP.
        let udp_socket = Arc::new(
            tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], self.config.port)))
                .await
                .map_err(TsnetError::Io)?,
        );
        let udp_port = udp_socket.local_addr().map_err(TsnetError::Io)?.port();
        let local_endpoints = rustscale_magicsock::gather_local_endpoints(udp_port);
        self.log_msg(format!("tsnet: local UDP endpoints: {local_endpoints:?}"));

        // Create a port-mapping client (NAT-PMP/PCP/UPnP) so magicsock can
        // publish a port-mapped external endpoint alongside local/STUN
        // endpoints. Best-effort: if the gateway doesn't support any
        // port-mapping protocol, this silently produces no endpoint.
        let portmapper = if self.config.disable_portmapping {
            None
        } else {
            let portmapper = rustscale_portmapper::Client::new();
            portmapper.set_local_port(udp_port);
            Some(portmapper)
        };

        // 3c. Send a lightweight non-streaming MapRequest to push our
        // DiscoKey + Endpoints to the control server BEFORE starting the
        // streaming long-poll. The control server processes the MapRequest
        // body asynchronously and the first streaming MapResponse is
        // generated from registration data (which lacks DiscoKey/Endpoints).
        // Without this pre-update, peers see DiscoKey=zero and Endpoints=[]
        // and can never initiate disco probing for a direct path.
        let endpoint_update_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: false,
            OmitPeers: true,
            Endpoints: local_endpoints.clone(),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        let cc_ep = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        match cc_ep.send_map_request(&endpoint_update_req).await {
            Ok(()) => log::debug!("tsnet: endpoint update sent (DiscoKey + {local_endpoints:?})"),
            Err(e) => log::warn!("tsnet: endpoint update failed (non-fatal): {e}"),
        }

        // 4. Fetch the first MapResponse. If we have a cached netmap, skip
        // the blocking fetch and use the cached data — the streaming
        // long-poll (started below) will deliver fresh updates in the
        // background. This eliminates the 2-5s startup delay on restarts.
        let used_cached_netmap = cached_netmap.is_some();
        let map_resp: MapResponse = if let Some(ref cached) = cached_netmap {
            let peer_count = cached.Peers.as_ref().map_or(0, Vec::len);
            log::debug!(
                "tsnet: using cached netmap ({peer_count} peers); streaming poll will refresh in background"
            );
            cached.clone()
        } else {
            let fetch_req = MapRequest {
                Version: CAPABILITY_VERSION,
                KeepAlive: false,
                NodeKey: node_pub.clone(),
                DiscoKey: disco_pub.clone(),
                Stream: false,
                Endpoints: local_endpoints.clone(),
                Hostinfo: Some(Hostinfo {
                    OS: std::env::consts::OS.to_string(),
                    Hostname: self.config.hostname.clone(),
                    RoutableIPs: advertise.clone(),
                    PeerRelay: self.config.peer_relay_server,
                    ..Default::default()
                }),
                ..Default::default()
            };
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                cc_ep.fetch_map(&fetch_req),
            )
            .await
            .map_err(|_| TsnetError::MapTimeout)??
        };

        if !map_resp.Domain.is_empty() {
            if !state.tailnet_identity.is_empty() && state.tailnet_identity != map_resp.Domain {
                return Err(TsnetError::TailnetLock(
                    "control returned a different tailnet for this durable profile identity".into(),
                ));
            }
            if state.tailnet_identity != map_resp.Domain {
                state.tailnet_identity.clone_from(&map_resp.Domain);
                self.save_state(&state)?;
            }
        }

        let tailnet_lock = tailnet_lock::TailnetLock::open(tailnet_lock::TailnetLockParams {
            control_url: self.config.control_url.clone(),
            machine_key: state.machine_key.clone(),
            server_pub_key: server_pub_key.clone(),
            node_key: state.node_key.clone(),
            signing_key: state.network_lock_key.clone(),
            capability_version: CAPABILITY_VERSION,
            protocol_version: PROTOCOL_VERSION,
            state_dir: state_scope.as_ref().map(|scope| scope.dir.clone()),
            extra_root_certs: self.config.extra_root_certs.clone(),
        })
        .map_err(|error| TsnetError::TailnetLock(error.to_string()))?;
        if used_cached_netmap {
            // No cached TKA state proves that its head or peer snapshot is
            // still current. Even a cached enabled head remains withdrawn
            // until a fresh control response confirms and synchronizes it.
            tailnet_lock.require_fresh_control_state();
        } else if let Err(error) = tailnet_lock
            .apply_control_info(map_resp.TKAInfo.as_ref(), true)
            .await
        {
            // Peer filtering below remains active and drops every peer while
            // authority state is incomplete.
            log::warn!("tsnet: Tailnet Lock synchronization failed closed: {error}");
        }
        tailnet_lock.set_self_node(map_resp.Node.clone());

        let tailscale_ips = extract_tailscale_ips(&map_resp);
        if tailscale_ips.is_empty() {
            return Err(TsnetError::Builder("no tailscale IPs assigned".into()));
        }
        let our_v4 = first_v4(&tailscale_ips)?;

        // We have a netmap — update the IPN state machine. Set netmap_present
        // and engine status (peer count + DERP home as a proxy for live
        // connections). This may transition the state from Starting to Running.
        let peer_count = map_resp
            .Peers
            .iter()
            .flatten()
            .filter(|peer| !peer.Key.is_zero())
            .count() as i32;
        let has_derp_home = map_resp.Node.as_ref().is_some_and(|n| n.HomeDERP > 0);
        ipn_backend.set_netmap_present(true);
        ipn_backend.set_engine_status(peer_count, i32::from(has_derp_home));

        // 6. Pick home DERP. Prefer the control-assigned HomeDERP from our
        // own node in the MapResponse — this ensures both nodes in the same
        // tailnet use the same DERP region. Fall back to netcheck, then to
        // the first available region.
        let derp_map = map_resp.DERPMap.clone().unwrap_or_default();
        let home_derp = if derp_map.Regions.is_empty() {
            0
        } else {
            // Try control-assigned HomeDERP first.
            let assigned = map_resp
                .Node
                .as_ref()
                .map(|n| n.HomeDERP)
                .filter(|&d| d > 0);
            if let Some(d) = assigned {
                log::info!("tsnet: using control-assigned home DERP region {d}");
                d
            } else {
                // Fall back to netcheck.
                match rustscale_netcheck::Prober
                    .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                    .await
                {
                    Ok(r) if r.preferred_derp > 0 => r.preferred_derp,
                    _ => derp_map
                        .Regions
                        .values()
                        .find(|r| !r.Avoid)
                        .or_else(|| derp_map.Regions.values().next())
                        .map_or(0, |r| r.RegionID),
                }
            }
        };

        // The IPN backend normally owns only state-machine data. At this
        // point bootstrap has the shared health tracker and current DERP
        // selection, so install its captive-portal watcher with the real
        // runtime dependencies.
        let (_captive_derp_map_tx, captive_derp_map_rx) =
            tokio::sync::watch::channel(Some(derp_map.clone()));
        let (_captive_preferred_derp_tx, captive_preferred_derp_rx) =
            tokio::sync::watch::channel(home_derp);
        ipn_backend.start_captive_portal_watcher(
            health.clone(),
            rustscale_netcheck::Detector::default(),
            captive_derp_map_rx,
            captive_preferred_derp_rx,
        );

        // 7. Connect home DERP.
        log::info!("tsnet: home DERP region = {home_derp}");
        let derp_client = match connect_home_derp(&derp_map, home_derp, &state.node_key).await {
            Ok(mut c) => {
                // Tell the DERP server this is our preferred (home) node.
                // Go's derphttp.Client sets preferred=true after connecting
                // to the home DERP and calls NotePreferred(true). This lets
                // the DERP server track home-client metrics and is part of
                // the expected handshake.
                if let Err(e) = c.note_preferred(true).await {
                    log::warn!("tsnet: DERP note_preferred failed (non-fatal): {e}");
                }
                log::info!("tsnet: DERP connected to region {home_derp}");
                health.set_healthy(WARN_DERP_HOME);
                Some(c)
            }
            Err(e) => {
                log::warn!("tsnet: DERP connection to region {home_derp} failed: {e}");
                health.set_unhealthy(
                    WARN_DERP_HOME,
                    format!("derp home region {home_derp} unreachable: {e}"),
                );
                None
            }
        };

        let netinfo = NetInfo {
            PreferredDERP: home_derp,
            WorkingUDP: OptBool::True,
            ..Default::default()
        };
        let netinfo_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: false,
            OmitPeers: true,
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                NetInfo: Some(netinfo.clone()),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        match cc_ep.send_map_request(&netinfo_req).await {
            Ok(()) => log::debug!("tsnet: NetInfo (PreferredDERP={home_derp}) sent to control"),
            Err(e) => log::warn!("tsnet: NetInfo update failed (non-fatal): {e}"),
        }

        // 7b. Run a STUN probe now that DERPMap is known, to discover our
        // external (NAT-mapped) IP:port and include it in the endpoint list.
        // This is critical for peers on different networks — without STUN
        // endpoints they can never establish a direct UDP connection.
        let stun_ep: Option<String> = if derp_map.Regions.is_empty() {
            None
        } else {
            // Run STUN probe to discover external IP:port
            match rustscale_netcheck::Prober
                .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                .await
            {
                Ok(report) => {
                    if let Some(g) = report.global_v4 {
                        log::debug!("tsnet: STUN endpoint: {g}");
                        Some(g.to_string())
                    } else {
                        log::warn!("tsnet: STUN probe returned no global_v4");
                        None
                    }
                }
                Err(e) => {
                    log::warn!("tsnet: STUN probe failed (non-fatal): {e}");
                    None
                }
            }
        };

        // Build the enhanced endpoint list: filtered local endpoints + STUN.
        let mut all_endpoints = local_endpoints.clone();
        if let Some(ref stun) = stun_ep {
            all_endpoints.push(stun.clone());
        }
        // Re-send endpoint update with STUN results included.
        let stun_ep_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: false,
            OmitPeers: true,
            Endpoints: all_endpoints,
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                NetInfo: Some(netinfo.clone()),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        match cc_ep.send_map_request(&stun_ep_req).await {
            Ok(()) => log::debug!("tsnet: STUN endpoint update sent ({stun_ep:?})"),
            Err(e) => log::warn!("tsnet: STUN endpoint update failed (non-fatal): {e}"),
        }

        // Start the streaming map long-poll with NetInfo included. This is
        // done after the home DERP is known and connected so the streaming
        // MapRequest carries NetInfo.PreferredDERP from the start.
        // stream_map_loop reconnects automatically when the stream ends.
        let map_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: true,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: true,
            Endpoints: local_endpoints.clone(),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                NetInfo: Some(netinfo.clone()),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            TKAHead: tailnet_lock.head(),
            ..Default::default()
        };

        let (map_tx, map_rx) = mpsc::channel(32);
        let map_session = Arc::new(MapSessionState::new());
        map_session.set_tka_head(tailnet_lock.head());
        let ssh_callbacks = rustscale_controlclient::SshCallbackDispatcher::new();
        let cc2 = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        // The task is started after C2N handlers are built below so callbacks
        // can be answered on this exact streaming Noise session.

        // Control knobs: shared feature-flag store updated from each netmap.
        // Created here (before magicsock) so PMTUD can read PeerMTUEnable at
        // construction time.
        let control_knobs = Arc::new(ControlKnobs::new());
        let initial_knobs = extract_knobs_from_map_response(&map_resp);
        if !initial_knobs.is_empty() {
            control_knobs.apply(initial_knobs);
        }

        // 8. Create magicsock, reusing the UDP socket bound in step 3b so
        // the local endpoints advertised in the MapRequest match the socket
        // magicsock actually owns and reads from.
        let (magicsock_inner, wg_recv) = Magicsock::new(MagicsockConfig {
            private_key: state.node_key.clone(),
            disco_key: state.disco_key.clone(),
            derp_client,
            derp_map: Some(derp_map.clone()),
            home_derp_region: home_derp,
            udp_bind: None,
            udp_socket: Some(udp_socket),
            portmapper,
            health: Some(health.clone()),
            disable_direct_paths: self.config.disable_direct_paths,
            peer_relay_server: self.config.peer_relay_server,
            relay_server_config: self.config.relay_server_config.clone(),
            sockstats: Some(sockstats.clone()),
            control_knobs: Some(control_knobs.clone()),
        })
        .await?;
        let magicsock = Arc::new(magicsock_inner);
        bootstrap_rollback.magicsock = Some(Arc::clone(&magicsock));

        // Start a background port-mapping probe + creation (best-effort, 2s
        // timeout). The cached mapping will be picked up by subsequent
        // `all_endpoints()` calls and published to the control plane.
        magicsock.start_portmap();

        // The server may send peers via Peers (full list) or PeersChanged
        // (delta). The first response often uses PeersChanged.
        let peers = map_resp
            .Peers
            .clone()
            .unwrap_or_else(|| map_resp.PeersChanged.clone());
        let mut peers = peers;
        // Keep the stable-ID-reconciled control view separate from the TKA
        // verified intersection. Authority changes may reauthorize a raw peer
        // without control repeating it, but only verified peers own addresses,
        // tunnels, PeerAPI provenance, or Taildrive grants.
        let raw_peers = peers.clone();
        tailnet_lock.filter_peers(&mut peers);
        let peer_map = crate::peer_map::Runtime::new(&peers)
            .map_err(|error| TsnetError::InvalidNetmap(error.to_string()))?;

        // Install self-node capabilities from the first signed netmap before
        // PeerAPI starts. Taildrive remains disabled unless `drive:share` is
        // present; a needs-login LocalAPI cannot pre-authorize itself.
        if let Some(ref node) = map_resp.Node {
            magicsock.set_self_cap_map(node.CapMap.clone()).await;
            let sharing_allowed = node
                .Capabilities
                .iter()
                .any(|cap| cap == rustscale_drive::NODE_CAPABILITY_TAILDRIVE_SHARE)
                || node
                    .CapMap
                    .contains_key(rustscale_drive::NODE_CAPABILITY_TAILDRIVE_SHARE);
            let mut epoch = self.drive.authorization_write().await;
            self.drive.rotate_authorization_locked(&mut epoch);
            self.drive
                .set_sharing_allowed_locked(sharing_allowed, &mut epoch);
        }
        magicsock.set_netmap(peers.clone()).await?;

        // 9. Per-peer WG tunnels + routing table.
        let wg_tunnels = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut tunnels = wg_tunnels.write().await;
            for peer in &peers {
                if peer.Key.is_zero() {
                    continue;
                }
                let tunn = WgTunn::new(&state.node_key, &peer.Key, rand_index())?;
                tunnels.insert(peer.Key.clone(), Arc::new(Mutex::new(tunn)));
            }
        }

        let peers_arc = Arc::new(RwLock::new(peers.clone()));
        let routecheck = localapi::new_routecheck_client(
            map_resp.Node.clone(),
            peers_arc.clone(),
            magicsock.clone(),
        );
        let route_table = Arc::new(RwLock::new(RouteTable::from_peers_with_opts(
            &peers,
            self.config.accept_routes,
        )));
        let exit_map_gate = Arc::new(tokio::sync::Mutex::new(()));
        let cancel = Arc::new(CancelToken::new());

        // Build the initial packet filter from the first MapResponse. Add our
        // advertised subnet routes to the filter's localNets so packets
        // destined to those subnets are admitted (needed by subnet routers).
        // The peer list supplies the capability map for `cap:<name>` source
        // predicates, and the ShieldsUp pref enables shields-up mode.
        let shields_up = self.load_prefs().unwrap_or_default().ShieldsUp;
        let (mut filter, named_filters) =
            build_filter_from_map_response(&map_resp, &tailscale_ips, &peers, shields_up);
        if !advertise.is_empty() {
            filter.add_local_cidrs(&advertise);
        }
        let filter = Arc::new(std::sync::Mutex::new(filter));
        let packet_drops = Arc::new(AtomicU64::new(0));

        // Netlog is opt-in with the embedding's tailtraffic configuration. Keep
        // the existing virtual filter counter and add the physical magicsock
        // counter from the same logger so their traffic remains in distinct
        // aggregation maps.
        let netlog = if let Some(logtail) = self.config.netlog.clone() {
            let logger = Arc::new(rustscale_netlog::Logger::new());
            let source: Arc<dyn rustscale_netlog::NodeSource> = Arc::new(TsnetNetlogNodeSource {
                self_node: map_resp.Node.clone(),
                peers: peers_arc.clone(),
            });
            logger.start(source, logtail).await?;
            bootstrap_rollback.netlog = Some(Arc::clone(&logger));
            let virtual_counter = logger.make_counter(true).await;
            if let Ok(mut filter) = filter.lock() {
                filter.set_connection_counter(Some(virtual_counter));
            }
            magicsock.set_connection_counter(Some(logger.make_counter(false).await));
            Some(logger)
        } else {
            None
        };

        // MagicDNS: build the shared resolver from the first map response.
        // `Domain` is the tailnet domain (e.g. "tailnet.ts.net"); `DNSConfig`
        // carries `Proxied` and `CertDomains`; peer `Name`s are FQDNs.
        let domain = map_resp.Domain.clone();
        let our_fqdn = map_resp
            .Node
            .as_ref()
            .map(|n| n.Name.clone())
            .unwrap_or_default();
        let dns_config = Arc::new(RwLock::new(map_resp.DNSConfig.clone()));
        let user_profiles = Arc::new(RwLock::new(
            map_resp
                .UserProfiles
                .iter()
                .map(|p| (p.ID, p.clone()))
                .collect(),
        ));
        // SSH policy from the first MapResponse. `None` means the control
        // server hasn't sent a policy yet (SSH server rejects all connections
        // until one arrives). Updated on each subsequent map response.
        let ssh_policy = Arc::new(RwLock::new(map_resp.SSHPolicy.clone()));
        let ssh_host_keys = Arc::new(RwLock::new(Vec::new()));
        let resolver = Arc::new(RwLock::new(MagicDnsResolver::new(
            peers.clone(),
            &domain,
            map_resp.DNSConfig.as_ref(),
        )));

        let c2n_prefs = serde_json::json!({
            "hostname": self.config.hostname,
            "control_url": self.config.control_url,
            "ephemeral": self.config.ephemeral,
            "advertise_routes": self.config.advertise_routes,
            "accept_routes": self.config.accept_routes,
            "advertise_exit_node": self.config.advertise_exit_node,
        });
        let persisted_posture = self
            .load_prefs()
            .map(|prefs| prefs.PostureChecking)
            .unwrap_or(false);
        let posture_checking = Arc::new(AtomicBool::new(
            self.config.posture_checking || persisted_posture,
        ));
        let c2n_log_level = rustscale_c2n::LogLevelState::new();
        let c2n_backend = Arc::new(c2n::TsnetC2nBackend::new(
            c2n::C2nBackendData {
                peers: peers_arc.clone(),
                user_profiles: user_profiles.clone(),
                health: health.clone(),
                dns_config: dns_config.clone(),
                packet_drops: packet_drops.clone(),
                prefs: c2n_prefs,
                tailscale_ips: tailscale_ips.clone(),
                our_fqdn: our_fqdn.clone(),
                magicsock: magicsock.clone(),
                sockstats: sockstats.clone(),
                logtail: self.config.logtail.clone(),
                posture_checking: posture_checking.clone(),
                posture_service: Arc::new(rustscale_posture::IdentityService::default()),
            },
            c2n_log_level,
        ));
        let c2n_router = {
            let mut r = C2nRouter::new();
            c2n::register_c2n_handlers(&mut r, c2n_backend.clone());
            Arc::new(r)
        };
        let map_task = tokio::spawn({
            let ss = map_session.clone();
            let router = c2n_router.clone();
            let callbacks = ssh_callbacks.clone();
            async move {
                cc2.stream_map_loop_with_c2n_and_ssh_callbacks(
                    &map_req,
                    map_tx,
                    Some(ss),
                    router,
                    callbacks,
                )
                .await;
            }
        });
        bootstrap_rollback.set_map_task(map_task);

        // Control knobs created earlier (before magicsock construction).
        // Transfer the logger and map task out of bootstrap compensation as
        // one ownership commit. Every subsequent await is covered by
        // StartupRollback, which requests and joins netlog shutdown.
        let (map_tasks, bootstrap_netlog) = bootstrap_rollback.commit();
        debug_assert_eq!(bootstrap_netlog.is_some(), netlog.is_some());

        Ok(Bootstrap {
            tailscale_ips: tailscale_ips.clone(),
            our_v4,
            magicsock,
            netlog: bootstrap_netlog,
            wg_recv,
            wg_tunnels,
            raw_peers,
            peers: peers_arc,
            peer_map,
            routecheck,
            route_table,
            exit_map_gate,
            cancel,
            map_rx,
            map_tasks,
            node_key: state.node_key.clone(),
            filter,
            named_filters,
            packet_drops,
            resolver,
            our_fqdn,
            domain,
            dns_config,
            user_profiles,
            ssh_policy,
            ssh_host_keys,
            ssh_callbacks,
            machine_key: state.machine_key.clone(),
            server_pub_key,
            disco_key: state.disco_key.clone(),
            control_url: self.config.control_url.clone(),
            hostname: self.config.hostname.clone(),
            advertise_routes: advertise,
            udp_port,
            derp_map,
            home_derp,
            health,
            health_watchdog,
            c2n_router,
            posture_checking,
            control_knobs,
            overrides: self.config.overrides.clone(),
            key_expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ipn_backend,
            map_session,
            sockstats,
            backend_log_id,
            private_log_id,
            tailnet_lock,
            state_scope,
            peer_snapshot_fresh: !used_cached_netmap,
        })
    }

    /// Shut down the server.
    ///
    /// Resource ownership is transferred to a process-lifetime cleanup
    /// supervisor before the first await. Dropping this future or destroying
    /// its caller runtime therefore cannot strand running tasks, sockets,
    /// routes, DNS state, serve listeners, or extensions.
    pub async fn close(&mut self) -> Result<(), TsnetError> {
        if self.shutdown_supervisor.has_retained_logout() {
            return Err(TsnetError::ShutdownIncomplete(
                "logout transaction is incomplete; retry logout before close".into(),
            ));
        }
        // Move every Server-owned generation before the first await. Rollback
        // tasks from a cancelled up/bootstrap are already retained by their
        // supervisors; clone those gates into the same independent cleanup.
        let mut owner = CleanupOwner::take_from(self);
        let drive = Arc::clone(&self.drive);
        let bootstrap_supervisor = Arc::clone(&self.bootstrap_supervisor);
        let startup_supervisor = Arc::clone(&self.startup_supervisor);
        let shutdown_supervisor = Arc::clone(&self.shutdown_supervisor);

        if owner.is_empty() {
            // A cancelled earlier close/logout can own everything already.
            // Join it and claim the complete retained owner for one retry.
            shutdown_supervisor.wait().await;
            startup_supervisor.wait().await;
            bootstrap_supervisor.wait().await;
            if shutdown_supervisor.has_retained_logout() {
                return Err(TsnetError::ShutdownIncomplete(
                    "logout transaction is incomplete; retry logout before close".into(),
                ));
            }
            let Some(retained) = shutdown_supervisor.take_retained_owner() else {
                return Ok(());
            };
            owner = retained;
        }

        // Initialize the process-lifetime runtime before moving the sole owner.
        // Its JoinHandle is detached, not aborted, if this caller runtime dies.
        let cleanup_runtime = lifecycle_cleanup_runtime();
        let completion = shutdown_supervisor.begin_cleanup();
        let cleanup_supervisor = Arc::clone(&shutdown_supervisor);
        let cleanup = cleanup_runtime.spawn(async move {
            let _completion = completion;
            bootstrap_supervisor.wait().await;
            startup_supervisor.wait().await;
            shutdown_supervisor.wait_for_at_most(1).await;
            drive.disable().await;
            match cleanup_server_state(owner).await {
                Ok(()) => Ok(()),
                Err((owner, reason)) => {
                    cleanup_supervisor.retain_owner(owner);
                    Err(TsnetError::ShutdownIncomplete(format!(
                        "server cleanup is busy or failed; retry close: {reason}"
                    )))
                }
            }
        });
        cleanup.await.map_err(|error| {
            TsnetError::ShutdownIncomplete(format!("shutdown worker stopped: {error}"))
        })?
    }

    /// Returns the logout trigger Notify, if the server is running.
    /// The daemon selects on this alongside shutdown signals to handle
    /// POST /logout after the server is up.
    pub fn logout_trigger(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.inner
            .as_ref()
            .map(|inner| inner.logout_trigger.clone())
            .or_else(|| {
                self.pre_started
                    .as_ref()
                    .map(|ps| ps.logout_trigger.clone())
            })
    }

    /// Fail any LocalAPI logout request still waiting when daemon shutdown
    /// intentionally stops durable transaction retries.
    pub fn complete_pending_logout_requests(&self) {
        self.logout_completion.complete(Ok(()));
    }

    pub fn fail_pending_logout_requests(&self, reason: impl Into<String>) {
        self.logout_completion.complete(Err(reason.into()));
    }

    /// Log out: send a logout register request to the control plane
    /// (expiring the node key), clear persisted state, transition the IPN
    /// backend to NeedsLogin, and tear down the running state.
    ///
    /// Mirrors Go's `LocalBackend.Logout` → `controlclient.TryLogout`:
    /// a RegisterRequest with `Expiry` set to the far past (1970-01-01)
    /// tells the control server to expire the node. After that, persisted
    /// keys and netmap cache are cleared so a restart starts fresh.
    ///
    /// After logout, the server is in a `NeedsLogin` state. The daemon
    /// should call `start_localapi_only()` again to accept a new login.
    pub async fn logout(&mut self) -> Result<(), TsnetError> {
        self.shutdown_supervisor.wait().await;
        self.startup_supervisor.wait().await;

        let transaction = if let Some(transaction) = self.shutdown_supervisor.take_retained_logout()
        {
            transaction
        } else if self.inner.is_some() {
            LogoutTransaction {
                owner: CleanupOwner::take_from(self),
                drive: Arc::clone(&self.drive),
                control_url: self.config.control_url.clone(),
                hostname: self.config.hostname.clone(),
                state_dir: self.config.state_dir.clone(),
                state_scope: self.profile_state_scope(),
                tailnet_identity: String::new(),
                prefs: self.load_prefs().unwrap_or_default(),
                completion: Arc::clone(&self.logout_completion),
                phase: LogoutPhase::Quiesce,
                #[cfg(test)]
                state_save_failures: std::mem::take(&mut self.logout_state_save_failures),
            }
        } else {
            if self.shutdown_supervisor.has_retained_owner() {
                return self.close().await;
            }
            return Ok(());
        };
        #[cfg(test)]
        let logout_test_hook = self.logout_test_hook.take();

        // Transfer the explicit transaction before the first cancellable
        // await. The process-lifetime supervisor outlives the caller runtime;
        // a durable failure retains both its phase and all data needed to
        // resume, so it can never degrade into close-only success.
        let cleanup_runtime = lifecycle_cleanup_runtime();
        let completion = self.shutdown_supervisor.begin_cleanup();
        let cleanup_supervisor = Arc::clone(&self.shutdown_supervisor);
        let worker = cleanup_runtime.spawn(async move {
            let _completion = completion;
            #[cfg(test)]
            if let Some((entered, release)) = logout_test_hook {
                entered.wait().await;
                release.wait().await;
            }
            match logout_running_transaction(transaction).await {
                Ok(()) => Ok(()),
                Err((error, transaction)) => {
                    log::warn!(
                        "tsnet: logout paused at {:?} and was retained for retry: {error}",
                        transaction.phase
                    );
                    cleanup_supervisor.retain_logout(transaction);
                    Err(error)
                }
            }
        });
        worker.await.map_err(|error| {
            TsnetError::ShutdownIncomplete(format!("logout worker stopped: {error}"))
        })?
    }

    /// Switch to profile `profile_id`, tearing down the running backend and
    /// restarting with the new profile's prefs. Mirrors Go's
    /// `resetForProfileChangeLocked`.
    ///
    /// Sequence:
    /// 1. `close()` — stop serve listeners, cancel tasks, drop magicsock
    ///    and the control client (like Go's `currentNode` shutdown).
    /// 2. Reload the `ProfileManager` from disk, switch to the target
    ///    profile, and apply its prefs (`ControlURL`, `Hostname`) to
    ///    `self.config` so `up()` bootstraps against the right control
    ///    plane.
    /// 3. If ephemeral, regenerate persisted state so bootstrap creates
    ///    fresh node keys.
    /// 4. `up()` — re-bootstrap the engine, control client, and netstack.
    pub async fn switch_profile(&mut self, profile_id: &str) -> Result<(), TsnetError> {
        // 1. Stop the running engine (like close() but keep the config).
        self.close().await?;
        Self::retry_pending_router_cleanup().await?;

        // 2. Update current profile + prefs from the ProfileManager.
        //    (ProfileManager lives in state_dir on disk; reload it.)
        if let Some(ref dir) = self.config.state_dir {
            let mut pm = rustscale_ipn::ProfileManager::new(dir)
                .map_err(|e| TsnetError::Builder(e.to_string()))?;
            pm.switch_profile(profile_id)
                .map_err(|e| TsnetError::Builder(e.to_string()))?;
            // Apply the profile's prefs to self.config.
            let new_prefs = pm.current_prefs().clone();
            if !new_prefs.ControlURL.is_empty() {
                self.config.control_url.clone_from(&new_prefs.ControlURL);
            }
            if !new_prefs.Hostname.is_empty() {
                self.config.hostname.clone_from(&new_prefs.Hostname);
            }
            // Save prefs to disk so bootstrap picks them up.
            if let Err(e) = new_prefs.save(dir) {
                log::warn!("tsnet: failed to save prefs on profile switch: {e}");
            }
        }

        // 3. Restart the engine. Ephemeral nodes regenerate keys on
        //    restart — clear persisted state so bootstrap generates fresh
        //    keys. (Mirrors Go clearing the node key on profile switch for
        //    ephemeral nodes.)
        if self.config.ephemeral {
            if let Some(ref _dir) = self.config.state_dir {
                let fresh = PersistedState::generate();
                let _ = self.save_state(&fresh);
            }
        }
        Box::pin(self.up()).await?;
        Ok(())
    }

    // --- internal helpers ---

    async fn start_audit_logger(
        state_dir: Option<PathBuf>,
        control_url: String,
        machine_key: MachinePrivate,
        server_pub_key: MachinePublic,
        node_key: NodePrivate,
    ) -> Arc<rustscale_auditlog::Logger> {
        let store: Arc<dyn rustscale_ipn::store::Store> = match &state_dir {
            Some(dir) => Arc::new(rustscale_ipn::store::FileStore::new(dir)),
            None => Arc::new(rustscale_ipn::store::MemStore::new()),
        };
        let log_store = Arc::new(rustscale_auditlog::LogStore::new(store));
        let logger = rustscale_auditlog::Logger::new(rustscale_auditlog::LoggerOptions {
            retry_limit: 10,
            store: log_store,
        });
        let profile_id = state_dir
            .as_ref()
            .and_then(|dir| {
                rustscale_ipn::LoginProfile::load_current_id(dir)
                    .ok()
                    .flatten()
            })
            .unwrap_or_else(|| "default".to_string());
        if let Err(error) = logger.set_profile_id(profile_id) {
            log::warn!("tsnet: failed to configure audit log profile (non-fatal): {error}");
        }

        let mut control_client =
            ControlClient::new(control_url, machine_key, server_pub_key, PROTOCOL_VERSION);
        control_client.set_audit_node_key(node_key.public());
        if let Err(error) = logger.start(Arc::new(control_client)).await {
            log::warn!("tsnet: failed to start audit logger (non-fatal): {error}");
        }
        logger
    }

    pub(crate) fn profile_state_scope(&self) -> Option<crate::state::StateScope> {
        self.config
            .state_dir
            .as_deref()
            .map(|root| crate::state::StateScope::new(root, &self.config.control_url))
    }

    pub(crate) fn load_or_create_state(&self) -> Result<PersistedState, TsnetError> {
        if let Some(scope) = self.profile_state_scope() {
            let path = scope.dir.join("tsnet-state.json");
            if path.exists() {
                let state = PersistedState::load(&path)?;
                if !scope.matches(&state) {
                    return Err(TsnetError::Builder(
                        "persisted identity profile/control binding mismatch".into(),
                    ));
                }
                return Ok(state);
            }

            // Migrate the historical unscoped identity only when ownership is
            // unambiguous. Multi-profile legacy state cannot be attributed
            // safely and is intentionally left unused rather than crossed.
            let root = self.config.state_dir.as_deref().expect("scope has root");
            let legacy = root.join("tsnet-state.json");
            if legacy.exists() {
                let profiles = rustscale_ipn::LoginProfile::load_all(root).unwrap_or_default();
                let current = rustscale_ipn::LoginProfile::load_current_id(root)
                    .ok()
                    .flatten();
                let unambiguous = (profiles.is_empty() && current.is_none())
                    || (profiles.len() == 1
                        && current.as_deref() == Some(profiles[0].ID.as_str())
                        && (profiles[0].ControlURL.is_empty()
                            || profiles[0].ControlURL == self.config.control_url));
                if unambiguous {
                    let mut state = PersistedState::load(&legacy)?;
                    scope.bind(&mut state);
                    state.save(&path)?;
                    rustscale_atomicfile::remove_private(&legacy)?;
                    return Ok(state);
                }
                return Err(TsnetError::Builder(
                    "legacy identity cannot be safely attributed to the active profile".into(),
                ));
            }
        }
        Ok(PersistedState::default())
    }

    pub(crate) fn save_state(&self, state: &PersistedState) -> Result<(), TsnetError> {
        if let Some(scope) = self.profile_state_scope() {
            let mut state = state.clone();
            scope.bind(&mut state);
            state.save(&scope.dir.join("tsnet-state.json"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
const DROP_CLEANUP_DEADLINE: std::time::Duration = std::time::Duration::from_millis(500);
#[cfg(not(test))]
const DROP_CLEANUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
const DROP_CLEANUP_ATTEMPTS: usize = 3;

/// Fail closed without awaiting user code. Graceful cleanup still gets bounded
/// attempts afterwards, but no LocalAPI, map task, Taildrive grant, magicsock
/// transport, or extension publication authority remains live while Drop
/// waits. A router or user callback that ignores cancellation can only survive
/// as a logged OS/user-code leak; the Drop cleanup thread never waits forever.
fn revoke_owner_authority_terminal(owner: &mut CleanupOwner, drive: &crate::drive::Runtime) {
    drive.disable_terminal();
    if let Some(host) = owner.extension_host.as_ref() {
        if host.revoke_publications_now() {
            log::error!(
                "tsnet: terminal cleanup: extension publication callback still executing; \
                 callback is leaked rather than waited forever"
            );
        }
    }
    if let Some(inner) = owner.inner.as_mut() {
        inner.cancel.cancel();
        inner.health_watchdog.stop();
        inner.extension_subscription.take();
        inner.hostinfo_hooks.clear();
        inner
            .ssh_callbacks
            .latch_key_revoked(&inner.node_key.public());
        inner.map_tasks.begin_shutdown();
        for abort in inner
            .task_aborts
            .lock()
            .expect("server task abort lock poisoned")
            .iter()
        {
            abort.abort();
        }
        if let Some(path) = inner.localapi_socket.take() {
            let _ = std::fs::remove_file(path);
        }
        // Drop aborts the accept task and every child; no user handler is
        // called from this terminal path.
        inner.localapi_handle.take();
        inner.magicsock.set_connection_counter(None);
        inner.magicsock.request_shutdown();
        inner.audit_logger.request_stop();
        if let Some(netlog) = inner.netlog.as_ref() {
            netlog.request_stop();
        }
    }
    if let Some(pre_started) = owner.pre_started.as_mut() {
        if let Some(path) = pre_started
            .handle
            .as_ref()
            .map(|handle| handle.socket_path.clone())
        {
            let _ = std::fs::remove_file(path);
        }
        pre_started.handle.take();
        let _ = std::fs::remove_file(&pre_started.socket_path);
        if let Some(magicsock) = pre_started.magicsock.as_ref() {
            magicsock.request_shutdown();
        }
    }
}

pub(crate) fn retain_terminal_logout(transaction: LogoutTransaction) {
    static SENDER: std::sync::OnceLock<std::sync::mpsc::Sender<LogoutTransaction>> =
        std::sync::OnceLock::new();
    let sender = SENDER.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::channel::<LogoutTransaction>();
        std::thread::Builder::new()
            .name("rustscale-logout-continuation".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build terminal logout continuation runtime");
                while let Ok(mut transaction) = receiver.recv() {
                    let mut delay = std::time::Duration::from_millis(25);
                    loop {
                        revoke_owner_authority_terminal(&mut transaction.owner, &transaction.drive);
                        match runtime.block_on(logout_running_transaction(transaction)) {
                            Ok(()) => break,
                            Err((error, retained)) => {
                                transaction = retained;
                                log::warn!(
                                    "tsnet: terminal logout continuation retrying {:?}: {error}",
                                    transaction.phase
                                );
                                std::thread::sleep(delay);
                                delay = (delay * 2).min(std::time::Duration::from_secs(5));
                            }
                        }
                    }
                }
            })
            .expect("spawn terminal logout continuation worker");
        sender
    });
    if let Err(error) = sender.send(transaction) {
        // The worker can stop only after all senders disappear, which the
        // process-global sender prevents. Preserve ownership even after an
        // unexpected panic rather than silently degrading logout into close.
        log::error!("tsnet: terminal logout continuation stopped; retaining leaked transaction");
        std::mem::forget(Box::new(error.0));
    }
}

async fn wait_cleanup_supervisor_until(
    supervisor: &BootstrapSupervisor,
    deadline: tokio::time::Instant,
) -> bool {
    tokio::time::timeout_at(deadline, supervisor.wait())
        .await
        .is_ok()
}

async fn finish_dropped_cleanup(
    mut owner: CleanupOwner,
    drive: Arc<crate::drive::Runtime>,
    bootstrap_supervisor: Arc<BootstrapSupervisor>,
    startup_supervisor: Arc<BootstrapSupervisor>,
    shutdown_supervisor: Arc<BootstrapSupervisor>,
) {
    let deadline = tokio::time::Instant::now() + DROP_CLEANUP_DEADLINE;
    revoke_owner_authority_terminal(&mut owner, &drive);
    // Any in-flight logout worker that finishes after this point transfers its
    // complete phase owner to the process-wide continuation. Move already
    // retained transactions there before a bounded supervisor wait can expire.
    shutdown_supervisor.mark_terminal();
    while let Some(mut transaction) = shutdown_supervisor.take_retained_logout() {
        revoke_owner_authority_terminal(&mut transaction.owner, &transaction.drive);
        retain_terminal_logout(transaction);
    }

    for (name, supervisor) in [
        ("bootstrap", &bootstrap_supervisor),
        ("startup", &startup_supervisor),
        ("shutdown", &shutdown_supervisor),
    ] {
        if !wait_cleanup_supervisor_until(supervisor, deadline).await {
            log::error!(
                "tsnet: terminal cleanup deadline waiting for {name} owner; \
                 authority was revoked, remaining resources are intentionally leaked"
            );
            return;
        }
    }

    let mut owners = Vec::new();
    if !owner.is_empty() {
        owners.push(owner);
    }
    while let Some(mut retained) = shutdown_supervisor.take_retained_owner() {
        revoke_owner_authority_terminal(&mut retained, &drive);
        owners.push(retained);
    }
    while let Some(mut transaction) = shutdown_supervisor.take_retained_logout() {
        revoke_owner_authority_terminal(&mut transaction.owner, &transaction.drive);
        retain_terminal_logout(transaction);
    }

    for mut owner in owners {
        let _completion = shutdown_supervisor.begin_cleanup();
        for attempt in 1..=DROP_CLEANUP_ATTEMPTS {
            revoke_owner_authority_terminal(&mut owner, &drive);
            drive.disable().await;
            match tokio::time::timeout_at(deadline, cleanup_server_state(owner)).await {
                Ok(Ok(())) => break,
                Ok(Err((mut retained, reason))) => {
                    log::warn!("tsnet: terminal cleanup retry required: {reason}");
                    revoke_owner_authority_terminal(&mut retained, &drive);
                    owner = retained;
                    if attempt == DROP_CLEANUP_ATTEMPTS {
                        log::error!(
                            "tsnet: terminal cleanup exhausted {DROP_CLEANUP_ATTEMPTS} attempts; \
                             leaking only revoked resources (router/extension cleanup incomplete)"
                        );
                        break;
                    }
                    let backoff = std::time::Duration::from_millis(25 * (1 << (attempt - 1)));
                    if tokio::time::timeout_at(deadline, tokio::time::sleep(backoff))
                        .await
                        .is_err()
                    {
                        log::error!(
                            "tsnet: terminal cleanup global deadline reached during backoff; \
                             leaking only revoked resources"
                        );
                        break;
                    }
                }
                Err(_) => {
                    // The cleanup future (and its owner) is dropped here. All
                    // admission was synchronously revoked before it started;
                    // dropping this runtime aborts remaining cooperative tasks.
                    log::error!(
                        "tsnet: terminal cleanup global deadline reached; aborted joinable work \
                         and leaked any non-cooperative user callback/router cleanup"
                    );
                    break;
                }
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let mut owner = CleanupOwner::take_from(self);
        if owner.is_empty()
            && !self.shutdown_supervisor.has_active_cleanup()
            && !self.shutdown_supervisor.has_retained_owner()
            && !self.shutdown_supervisor.has_retained_logout()
        {
            return;
        }

        let drive = Arc::clone(&self.drive);
        // Revoke synchronously before relying on thread creation. Even an OS
        // refusal to spawn the bounded worker cannot leave network authority.
        revoke_owner_authority_terminal(&mut owner, &drive);
        let bootstrap_supervisor = Arc::clone(&self.bootstrap_supervisor);
        let startup_supervisor = Arc::clone(&self.startup_supervisor);
        let shutdown_supervisor = Arc::clone(&self.shutdown_supervisor);
        if let Err(error) = std::thread::Builder::new()
            .name("rustscale-server-drop".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build server drop cleanup runtime");
                runtime.block_on(finish_dropped_cleanup(
                    owner,
                    drive,
                    bootstrap_supervisor,
                    startup_supervisor,
                    shutdown_supervisor,
                ));
            })
        {
            log::error!(
                "tsnet: failed to spawn bounded Drop cleanup worker: {error}; \
                 resources were revoked and are terminally leaked"
            );
        }
    }
}

#[cfg(test)]
mod exit_cleanup_tests {
    use super::*;
    use crate::tun_pump::ManagedRouter;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RetryCleanupRouter {
        closes: Arc<AtomicUsize>,
    }

    struct BlockingCleanupRouter {
        entered: std::sync::mpsc::Sender<()>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl rustscale_router::Router for BlockingCleanupRouter {
        fn up(&mut self) -> Result<(), rustscale_router::RouterError> {
            Ok(())
        }

        fn set(
            &mut self,
            _config: &rustscale_router::RouterConfig,
        ) -> Result<(), rustscale_router::RouterError> {
            Ok(())
        }

        fn close(&mut self) -> Result<(), rustscale_router::RouterError> {
            let _ = self.entered.send(());
            let (lock, changed) = &*self.release;
            let mut released = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*released {
                released = changed
                    .wait(released)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            Ok(())
        }
    }

    impl rustscale_router::Router for RetryCleanupRouter {
        fn up(&mut self) -> Result<(), rustscale_router::RouterError> {
            Ok(())
        }

        fn set(
            &mut self,
            _config: &rustscale_router::RouterConfig,
        ) -> Result<(), rustscale_router::RouterError> {
            Ok(())
        }

        fn close(&mut self) -> Result<(), rustscale_router::RouterError> {
            if self.closes.fetch_add(1, Ordering::SeqCst) < 2 {
                Err(rustscale_router::RouterError::InvalidConfig(
                    "injected cleanup failure".into(),
                ))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn blocking_router_close_times_out_off_runtime_and_remains_retryable() {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let owner = Arc::new(std::sync::Mutex::new(ManagedRouter {
            router: Box::new(BlockingCleanupRouter {
                entered: entered_tx,
                release: Arc::clone(&release),
            }),
            tun_name: "rustscale-blocked0".into(),
            exit_node: false,
            security_block_attempted: false,
            security_block_verified: false,
            security_block_reasons: 0,
        }));

        let heartbeat = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            true
        });
        let started = tokio::time::Instant::now();
        let error = wait_router_cleanup(&owner).await.unwrap_err();
        assert!(error.to_string().contains("bounded worker deadline"));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(heartbeat.await.unwrap(), "router close blocked the runtime");
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("router worker did not enter close");

        let (lock, changed) = &*release;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        changed.notify_all();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_router_cleanup(&owner),
        )
        .await
        .expect("router cleanup retry remained blocked")
        .unwrap();
    }

    #[tokio::test]
    async fn cleanup_owner_survives_failure_and_blocks_until_retry_succeeds() {
        let closes = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(std::sync::Mutex::new(ManagedRouter {
            router: Box::new(RetryCleanupRouter {
                closes: closes.clone(),
            }),
            tun_name: "rustscale-test0".into(),
            exit_node: false,
            security_block_attempted: false,
            security_block_verified: false,
            security_block_reasons: 0,
        }));
        Server::router_cleanup_supervisor().lock().unwrap().clear();
        assert!(Server::cleanup_or_supervise(owner).await.is_err());
        assert_eq!(Server::router_cleanup_supervisor().lock().unwrap().len(), 1);

        // Restart admission remains blocked while cleanup is still dirty.
        assert!(Server::retry_pending_router_cleanup().await.is_err());
        assert_eq!(Server::router_cleanup_supervisor().lock().unwrap().len(), 1);
        Server::retry_pending_router_cleanup().await.unwrap();
        assert!(Server::router_cleanup_supervisor()
            .lock()
            .unwrap()
            .is_empty());
        assert_eq!(closes.load(Ordering::SeqCst), 3);
    }
}
