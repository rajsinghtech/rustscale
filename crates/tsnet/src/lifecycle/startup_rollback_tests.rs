use super::*;
use crate::tun_pump::ManagedRouter;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn shared_test_router(router: Box<dyn rustscale_router::Router>) -> SharedRouter {
    Arc::new(std::sync::Mutex::new(ManagedRouter {
        router,
        tun_name: "rustscale-test0".into(),
        exit_node: false,
        security_block_attempted: false,
        security_block_verified: false,
        security_block_reasons: 0,
    }))
}

struct CloseRouter(Arc<AtomicBool>);

impl rustscale_router::Router for CloseRouter {
    fn up(&mut self) -> Result<(), rustscale_router::RouterError> {
        Ok(())
    }

    fn set(
        &mut self,
        _: &rustscale_router::RouterConfig,
    ) -> Result<(), rustscale_router::RouterError> {
        Ok(())
    }

    fn close(&mut self) -> Result<(), rustscale_router::RouterError> {
        self.0.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct OrderedRouter(Arc<std::sync::Mutex<Vec<&'static str>>>);

impl rustscale_router::Router for OrderedRouter {
    fn up(&mut self) -> Result<(), rustscale_router::RouterError> {
        Ok(())
    }

    fn set(
        &mut self,
        _: &rustscale_router::RouterConfig,
    ) -> Result<(), rustscale_router::RouterError> {
        self.0.lock().unwrap().push("set");
        Ok(())
    }

    fn close(&mut self) -> Result<(), rustscale_router::RouterError> {
        self.0.lock().unwrap().push("close");
        Ok(())
    }
}

struct CloseDns {
    closed: Arc<AtomicBool>,
    fail_setup: bool,
}

impl OsConfigurator for CloseDns {
    fn set_dns(&mut self, _: &OsConfig) -> std::io::Result<()> {
        if self.fail_setup {
            return Err(std::io::Error::other(
                "injected partially-applied DNS setup failure",
            ));
        }
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn supports_split_dns(&self) -> bool {
        true
    }
}

struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cancelled_cleanup_waiter_does_not_let_retry_overlap() {
    let supervisor = Arc::new(BootstrapSupervisor::default());
    let completion = supervisor.begin_cleanup();
    let first_supervisor = Arc::clone(&supervisor);
    let first = tokio::spawn(async move { first_supervisor.wait().await });
    tokio::task::yield_now().await;
    first.abort();
    let _ = first.await;

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), supervisor.wait())
            .await
            .is_err()
    );
    drop(completion);
    tokio::time::timeout(std::time::Duration::from_secs(1), supervisor.wait())
        .await
        .expect("retry remained blocked after owned cleanup");
}

#[tokio::test]
async fn overlapping_cleanup_generations_wait_for_every_completion() {
    let supervisor = Arc::new(BootstrapSupervisor::default());
    let first = supervisor.begin_cleanup();
    let second = supervisor.begin_cleanup();
    assert_eq!(supervisor.active_count(), 2);

    drop(first);
    assert_eq!(supervisor.active_count(), 1);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), supervisor.wait())
            .await
            .is_err(),
        "first cleanup incorrectly released overlapping retry gate"
    );

    let third = supervisor.begin_cleanup();
    drop(second);
    assert_eq!(supervisor.active_count(), 1);
    drop(third);
    tokio::time::timeout(std::time::Duration::from_secs(1), supervisor.wait())
        .await
        .expect("retry remained blocked after all cleanup generations completed");
    assert_eq!(supervisor.active_count(), 0);
}

#[tokio::test]
async fn close_transfers_state_before_waiting_and_retry_joins_all_generations() {
    let mut server = Server::builder().build().unwrap();
    let bootstrap = server.bootstrap_supervisor.begin_cleanup();
    let startup = server.startup_supervisor.begin_cleanup();
    let release_bootstrap = Arc::new(tokio::sync::Notify::new());
    let release_startup = Arc::new(tokio::sync::Notify::new());
    let bootstrap_release = Arc::clone(&release_bootstrap);
    let startup_release = Arc::clone(&release_startup);
    tokio::spawn(async move {
        bootstrap_release.notified().await;
        drop(bootstrap);
    });
    tokio::spawn(async move {
        startup_release.notified().await;
        drop(startup);
    });

    let shutdown_supervisor = Arc::clone(&server.shutdown_supervisor);
    let mut close = Box::pin(server.close());
    tokio::select! {
        () = async {
            while shutdown_supervisor.active_count() == 0 {
                tokio::task::yield_now().await;
            }
        } => {}
        result = &mut close => panic!("close skipped retained bootstrap/startup generations: {result:?}"),
    }
    drop(close);
    assert!(server.extension_host.is_none());

    let mut retry = Box::pin(server.close());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut retry)
            .await
            .is_err(),
        "retry overlapped the cancellation-owned close"
    );
    release_bootstrap.notify_one();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut retry)
            .await
            .is_err(),
        "close completed before startup cleanup"
    );
    release_startup.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(1), retry)
        .await
        .expect("retry did not join retained close cleanup")
        .unwrap();
    assert_eq!(shutdown_supervisor.active_count(), 0);
}

#[tokio::test]
async fn dropped_bootstrap_transaction_joins_tasks_before_retry() {
    let supervisor = Arc::new(BootstrapSupervisor::default());
    let dropped = Arc::new(AtomicUsize::new(0));
    let task_drop = DropCount(Arc::clone(&dropped));
    let task = tokio::spawn(async move {
        let _drop = task_drop;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;

    let watchdog = Watchdog::new(
        Tracker::new(),
        "bootstrap-rollback-test",
        "bootstrap rollback",
        Severity::Low,
        "not stopped",
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let mut rollback = BootstrapRollback::new(Arc::clone(&supervisor), watchdog);
    rollback.set_map_task(task);
    drop(rollback);
    tokio::time::timeout(std::time::Duration::from_secs(1), supervisor.wait())
        .await
        .expect("bootstrap cleanup was not joined");
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

struct ActiveTask(Arc<AtomicUsize>);

impl Drop for ActiveTask {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_after_each_spawn_is_joined_before_immediate_retry() {
    use std::os::unix::net::UnixListener;

    const SPAWN_POINTS: usize = 10;
    for cancel_after in 1..=SPAWN_POINTS {
        let supervisor = Arc::new(BootstrapSupervisor::default());
        let cancel = Arc::new(CancelToken::new());
        let watchdog = Watchdog::new(
            Tracker::new(),
            "startup-generation-test",
            "startup generation",
            Severity::Low,
            "not stopped",
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join(format!("spawn-{cancel_after}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();

        let map_active = Arc::clone(&active);
        map_active.fetch_add(1, Ordering::SeqCst);
        let map_started = started_tx.clone();
        let map_task = tokio::spawn(async move {
            let _active = ActiveTask(map_active);
            let _listener = listener;
            map_started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let mut rollback = StartupRollback::new(
            Arc::clone(&supervisor),
            Arc::clone(&cancel),
            watchdog,
            MapSessionTasks::new(map_task),
            None,
        );
        rollback.localapi_socket = Some(socket.clone());

        for _ in 1..cancel_after {
            let task_active = Arc::clone(&active);
            task_active.fetch_add(1, Ordering::SeqCst);
            let task_started = started_tx.clone();
            rollback.track(tokio::spawn(async move {
                let _active = ActiveTask(task_active);
                task_started.send(()).unwrap();
                std::future::pending::<()>().await;
            }));
        }
        for _ in 0..cancel_after {
            started_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("tracked startup task did not start");
        }

        drop(rollback);
        tokio::time::timeout(std::time::Duration::from_secs(3), supervisor.wait())
            .await
            .expect("immediate retry did not wait for startup generation cleanup");
        assert_eq!(active.load(Ordering::SeqCst), 0, "spawn {cancel_after}");
        assert!(!socket.exists(), "stale socket at spawn {cancel_after}");

        let retry_listener = UnixListener::bind(&socket)
            .unwrap_or_else(|error| panic!("retry bind failed at spawn {cancel_after}: {error}"));
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "old generation overlapped retry"
        );
        drop(retry_listener);
        let _ = std::fs::remove_file(&socket);
    }
}

#[tokio::test]
async fn committed_startup_tasks_transfer_to_running_ownership() {
    let supervisor = Arc::new(BootstrapSupervisor::default());
    let cancel = Arc::new(CancelToken::new());
    let watchdog = Watchdog::new(
        Tracker::new(),
        "startup-commit-test",
        "startup commit",
        Severity::Low,
        "not stopped",
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    active.fetch_add(1, Ordering::SeqCst);
    let task_active = Arc::clone(&active);
    let map_task = tokio::spawn(async move {
        let _active = ActiveTask(task_active);
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    let map_tasks = MapSessionTasks::new(map_task);
    let mut rollback = StartupRollback::new(
        Arc::clone(&supervisor),
        cancel,
        watchdog,
        Arc::clone(&map_tasks),
        None,
    );
    let tasks = rollback.commit_tasks();
    drop(rollback);
    assert_eq!(active.load(Ordering::SeqCst), 1);
    assert_eq!(supervisor.active_count(), 0);
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    map_tasks.begin_shutdown();
    map_tasks.join().await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn startup_rollback_joins_late_route_update_before_final_close() {
    let supervisor = Arc::new(BootstrapSupervisor::default());
    let cancel = Arc::new(CancelToken::new());
    let watchdog = Watchdog::new(
        Tracker::new(),
        "route-order-test",
        "route order",
        Severity::Low,
        "not stopped",
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let router = shared_test_router(Box::new(OrderedRouter(Arc::clone(&events))));
    let map_task = tokio::spawn(std::future::pending::<()>());
    let mut rollback = StartupRollback::new(
        Arc::clone(&supervisor),
        Arc::clone(&cancel),
        watchdog,
        MapSessionTasks::new(map_task),
        None,
    );
    rollback.router = Some(Arc::clone(&router));
    let task_cancel = Arc::clone(&cancel);
    rollback.track(tokio::spawn(async move {
        task_cancel.cancelled().await;
        let _ = router
            .lock()
            .unwrap()
            .router
            .set(&rustscale_router::RouterConfig::default());
    }));
    drop(rollback);
    tokio::time::timeout(std::time::Duration::from_secs(3), supervisor.wait())
        .await
        .expect("route-owning generation did not finish");
    assert_eq!(*events.lock().unwrap(), ["set", "close"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_callback_during_close_is_drained_before_extension_shutdown() {
    struct PublishingExtension {
        entered: std::sync::mpsc::Sender<()>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        shutdown: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl rustscale_ipnext::Extension for PublishingExtension {
        fn name(&self) -> &'static str {
            "publication-close"
        }

        async fn init(&self, host: rustscale_ipnext::Host) -> rustscale_ipnext::ExtensionResult {
            let entered = self.entered.clone();
            let release = Arc::clone(&self.release);
            host.hooks()?.backend_state_change.add(Arc::new(move |_| {
                let _ = entered.send(());
                let (lock, changed) = &*release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = changed.wait(released).unwrap();
                }
            }));
            Ok(())
        }

        async fn shutdown(&self) -> rustscale_ipnext::ExtensionResult {
            self.shutdown.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let registry = rustscale_ipnext::ExtensionRegistry::new();
    let extension_release = Arc::clone(&release);
    let extension_shutdown = Arc::clone(&shutdown);
    registry
        .register(rustscale_ipnext::Definition::new(
            "publication-close",
            move |_| {
                Ok(Arc::new(PublishingExtension {
                    entered: entered_tx.clone(),
                    release: Arc::clone(&extension_release),
                    shutdown: Arc::clone(&extension_shutdown),
                }))
            },
        ))
        .unwrap();
    let host =
        rustscale_ipnext::ExtensionHost::new(&registry, Arc::new(rustscale_tsd::System::new()))
            .unwrap();
    host.start().await.unwrap();
    let publisher = host.host();
    let publish = std::thread::spawn(move || {
        publisher
            .publish_backend_state(rustscale_ipn::State::Starting)
            .unwrap();
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("publication callback did not start");

    let retained = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        shutdown_extension_host(host),
    )
    .await
    .expect("extension close did not return at its bounded deadline")
    .expect_err("close passed an active publication callback");
    assert!(!shutdown.load(Ordering::SeqCst));
    {
        let (lock, changed) = &*release;
        *lock.lock().unwrap() = true;
        changed.notify_all();
    }
    publish.join().unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        shutdown_extension_host(retained),
    )
    .await
    .expect("extension close retry did not resume after publication drain")
    .expect("extension close retry failed");
    assert!(shutdown.load(Ordering::SeqCst));
}

#[tokio::test]
async fn post_bootstrap_rollback_stops_and_joins_netlog() {
    let logger = Arc::new(rustscale_netlog::Logger::new());
    let source: Arc<dyn rustscale_netlog::NodeSource> = Arc::new(TsnetNetlogNodeSource {
        self_node: None,
        peers: Arc::new(RwLock::new(Vec::new())),
    });
    logger
        .start(
            source,
            rustscale_logtail::LogTail::new(rustscale_logtail::Config::default()),
        )
        .await
        .unwrap();
    assert!(logger.running().await);

    let supervisor = Arc::new(BootstrapSupervisor::default());
    let watchdog = Watchdog::new(
        Tracker::new(),
        "netlog-startup-rollback",
        "netlog startup rollback",
        Severity::Low,
        "not stopped",
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let map_task = tokio::spawn(std::future::pending::<()>());
    let rollback = StartupRollback::new(
        Arc::clone(&supervisor),
        Arc::new(CancelToken::new()),
        watchdog,
        MapSessionTasks::new(map_task),
        Some(Arc::clone(&logger)),
    );
    drop(rollback);

    tokio::time::timeout(std::time::Duration::from_secs(2), supervisor.wait())
        .await
        .expect("startup rollback did not join netlog");
    assert!(!logger.running().await);
}

#[tokio::test]
async fn startup_supervisor_waits_for_magicsock_socket_release() {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let (magicsock, _recv) = Magicsock::new(MagicsockConfig {
        private_key: NodePrivate::generate(),
        disco_key: DiscoPrivate::generate(),
        derp_client: None,
        derp_map: None,
        home_derp_region: 0,
        udp_bind: Some(addr),
        udp_socket: None,
        portmapper: None,
        health: None,
        disable_direct_paths: false,
        peer_relay_server: false,
        relay_server_config: None,
        sockstats: None,
        control_knobs: None,
    })
    .await
    .unwrap();
    let magicsock = Arc::new(magicsock);
    let supervisor = Arc::new(BootstrapSupervisor::default());
    let cancel = Arc::new(CancelToken::new());
    let watchdog = Watchdog::new(
        Tracker::new(),
        "magicsock-startup-rollback",
        "magicsock startup rollback",
        Severity::Low,
        "not stopped",
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let map_task = tokio::spawn(std::future::pending::<()>());
    let mut rollback = StartupRollback::new(
        Arc::clone(&supervisor),
        cancel,
        watchdog,
        MapSessionTasks::new(map_task),
        None,
    );
    rollback.magicsock = Some(Arc::clone(&magicsock));
    drop(magicsock);
    drop(rollback);

    tokio::time::timeout(std::time::Duration::from_secs(3), supervisor.wait())
        .await
        .expect("magicsock cleanup did not finish before retry");
    let retry = tokio::net::UdpSocket::bind(addr)
        .await
        .expect("startup generation retained fixed magicsock UDP port");
    drop(retry);
}

#[tokio::test]
async fn terminal_drop_cleanup_has_global_attempt_bound() {
    struct RefusesShutdown(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl rustscale_ipnext::Extension for RefusesShutdown {
        fn name(&self) -> &'static str {
            "refuses-shutdown"
        }

        async fn init(&self, _: rustscale_ipnext::Host) -> rustscale_ipnext::ExtensionResult {
            Ok(())
        }

        async fn shutdown(&self) -> rustscale_ipnext::ExtensionResult {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(Box::new(std::io::Error::other("injected terminal leak")))
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let registry = rustscale_ipnext::ExtensionRegistry::new();
    let factory_calls = Arc::clone(&calls);
    registry
        .register(rustscale_ipnext::Definition::new(
            "refuses-shutdown",
            move |_| Ok(Arc::new(RefusesShutdown(Arc::clone(&factory_calls)))),
        ))
        .unwrap();
    let host =
        rustscale_ipnext::ExtensionHost::new(&registry, Arc::new(rustscale_tsd::System::new()))
            .unwrap();
    host.start().await.unwrap();

    let started = tokio::time::Instant::now();
    finish_dropped_cleanup(
        CleanupOwner {
            extension_host: Some(host),
            inner: None,
            pre_started: None,
        },
        crate::drive::Runtime::new(),
        Arc::new(BootstrapSupervisor::default()),
        Arc::new(BootstrapSupervisor::default()),
        Arc::new(BootstrapSupervisor::default()),
    )
    .await;
    assert!(started.elapsed() <= DROP_CLEANUP_DEADLINE + std::time::Duration::from_millis(100));
    assert_eq!(calls.load(Ordering::SeqCst), DROP_CLEANUP_ATTEMPTS);
}

#[test]
fn startup_rollback_dropped_after_runtime_destroys_polled_tun_task_and_routes() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let supervisor = Arc::new(BootstrapSupervisor::default());
    let cancel = Arc::new(CancelToken::new());
    let router_closed = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));

    let rollback = runtime.block_on(async {
        let watchdog = Watchdog::new(
            Tracker::new(),
            "outside-runtime-tun-rollback",
            "outside runtime TUN rollback",
            Severity::Low,
            "not stopped",
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        let map_task = tokio::spawn(std::future::pending::<()>());
        let task_dropped = Arc::clone(&dropped);
        let tun_task = tokio::spawn(async move {
            let _polled_tun_future = DropCount(task_dropped);
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        let mut rollback = StartupRollback::new(
            Arc::clone(&supervisor),
            Arc::clone(&cancel),
            watchdog,
            MapSessionTasks::new(map_task),
            None,
        );
        rollback.track(tun_task);
        rollback.router = Some(shared_test_router(Box::new(CloseRouter(Arc::clone(
            &router_closed,
        )))));
        rollback
    });

    // Model a polled up_tun future escaping block_on and being dropped only
    // after its original runtime owner is gone.
    drop(runtime);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    drop(rollback);
    assert!(cancel.is_cancelled());

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while supervisor.active_count() != 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(supervisor.active_count(), 0);
    assert!(router_closed.load(Ordering::SeqCst));
}

#[test]
fn terminal_drop_is_bounded_with_blocked_publication_callback_and_dead_runtime() {
    struct BlockingPublication {
        entered: std::sync::mpsc::Sender<()>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        shutdown: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl rustscale_ipnext::Extension for BlockingPublication {
        fn name(&self) -> &'static str {
            "blocked-terminal-publication"
        }

        async fn init(&self, host: rustscale_ipnext::Host) -> rustscale_ipnext::ExtensionResult {
            let entered = self.entered.clone();
            let release = Arc::clone(&self.release);
            host.hooks()?.backend_state_change.add(Arc::new(move |_| {
                let _ = entered.send(());
                let (lock, changed) = &*release;
                let mut ready = lock.lock().unwrap();
                while !*ready {
                    ready = changed.wait(ready).unwrap();
                }
            }));
            Ok(())
        }

        async fn shutdown(&self) -> rustscale_ipnext::ExtensionResult {
            self.shutdown.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let registry = Arc::new(rustscale_ipnext::ExtensionRegistry::new());
    let factory_release = Arc::clone(&release);
    let factory_shutdown = Arc::clone(&shutdown);
    registry
        .register(rustscale_ipnext::Definition::new(
            "blocked-terminal-publication",
            move |_| {
                Ok(Arc::new(BlockingPublication {
                    entered: entered_tx.clone(),
                    release: Arc::clone(&factory_release),
                    shutdown: Arc::clone(&factory_shutdown),
                }))
            },
        ))
        .unwrap();
    let server = Server::builder()
        .extension_registry(registry)
        .build()
        .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(server.extension_host.as_ref().unwrap().start())
        .unwrap();
    let publisher = server.extension_host().unwrap();
    let publication = std::thread::spawn(move || {
        publisher
            .publish_backend_state(rustscale_ipn::State::Running)
            .unwrap();
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("publication callback did not block");

    let started = std::time::Instant::now();
    drop(runtime);
    drop(server);
    assert!(started.elapsed() < std::time::Duration::from_millis(200));

    let (lock, changed) = &*release;
    *lock.lock().unwrap() = true;
    changed.notify_all();
    publication.join().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !shutdown.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(shutdown.load(Ordering::SeqCst));
}

#[tokio::test]
async fn dropped_startup_transaction_rolls_back_owned_resources() {
    let cancel = Arc::new(CancelToken::new());
    let tracker = Tracker::new();
    let watchdog = Watchdog::new(
        tracker,
        "startup-rollback-test",
        "startup rollback",
        Severity::Low,
        "not stopped",
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let map_drop = DropCount(Arc::clone(&dropped));
    let map_task = tokio::spawn(async move {
        let _drop = map_drop;
        std::future::pending::<()>().await;
    });
    let task_drop = DropCount(Arc::clone(&dropped));
    let task = tokio::spawn(async move {
        let _drop = task_drop;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;

    let router_closed = Arc::new(AtomicBool::new(false));
    let router = shared_test_router(Box::new(CloseRouter(Arc::clone(&router_closed))));
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("startup.sock");
    std::fs::write(&socket, b"socket").unwrap();

    let supervisor = Arc::new(BootstrapSupervisor::default());
    let mut rollback = StartupRollback::new(
        Arc::clone(&supervisor),
        Arc::clone(&cancel),
        watchdog,
        MapSessionTasks::new(map_task),
        None,
    );
    rollback.track(task);
    let dns_closed = Arc::new(AtomicBool::new(false));
    rollback.router = Some(router);
    rollback.localapi_socket = Some(socket.clone());
    let (dns_owner, setup) = set_os_dns_retaining_owner(
        Box::new(CloseDns {
            closed: Arc::clone(&dns_closed),
            fail_setup: true,
        }),
        &OsConfig::default(),
    );
    assert!(setup.is_err(), "injected DNS setup failure was accepted");
    rollback.os_dns_configurator = Some(dns_owner);
    drop(rollback);

    assert!(cancel.is_cancelled());
    assert!(
        !router_closed.load(Ordering::SeqCst),
        "router closed before route-mutating tasks joined"
    );
    assert!(!dns_closed.load(Ordering::SeqCst));
    assert!(!socket.exists());
    tokio::time::timeout(std::time::Duration::from_secs(3), supervisor.wait())
        .await
        .expect("startup task/monitor cleanup was not joined before retry");
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert!(router_closed.load(Ordering::SeqCst));
    assert!(dns_closed.load(Ordering::SeqCst));
}
