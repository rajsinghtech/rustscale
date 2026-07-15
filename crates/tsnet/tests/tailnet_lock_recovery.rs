//! End-to-end ambiguous Tailnet Lock initialization recovery.

use std::time::{Duration, Instant};

use rustscale_key::NLPublic;
use rustscale_localclient::LocalClient;
use rustscale_tailcfg::MapResponse;
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tka::{disablement_kdf, Key, KeyKind};
use rustscale_tsnet::Server;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commit_then_drop_keeps_receipt_and_resumes_without_new_secrets() {
    let mut control = TestControlServer::new();
    control.start().await.unwrap();
    control.add_fake_node();

    let state = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let socket = sockets.path().join("lock-recovery.sock");
    let mut server = Server::builder()
        .hostname("lock-recovery")
        .auth_key("tskey-test")
        .control_url(control.base_url())
        .state_dir(state.path())
        .localapi_path(&socket)
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("startup deadline")
        .expect("startup");

    let client = LocalClient::new(&socket);
    let status = client.tailnet_lock_status().await.unwrap();
    let public: NLPublic = status["PublicKey"].as_str().unwrap().parse().unwrap();
    let secret = vec![0x73; 32];
    control.drop_next_tka_init_finish_response();
    let requests_before = control.tka_request_connections().len();
    let result = client
        .tailnet_lock_init(&serde_json::json!({
            "Keys": [Key {
                kind: KeyKind::Key25519,
                votes: 1,
                public: public.raw32().to_vec(),
                meta: None,
            }],
            "DisablementValues": [disablement_kdf(&secret)],
            "DisablementSecrets": [secret.clone()],
            "SupportDisablement": [],
            "Resume": false,
        }))
        .await;
    assert!(result.is_err(), "finish response was intentionally dropped");

    let requests = control.tka_request_connections();
    let init = &requests[requests_before..requests_before + 2];
    assert_eq!(init[0].0, "/machine/tka/init/begin");
    assert_eq!(init[1].0, "/machine/tka/init/finish");
    assert_eq!(init[0].1, init[1].1, "init must be session-bound");

    let _receipt = walk_files(state.path())
        .into_iter()
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name == "tailnet-lock-init-receipt.json")
        })
        .expect("durable receipt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&_receipt).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(_receipt.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let pending_transaction = loop {
        let status = client.tailnet_lock_status().await.unwrap();
        if status["Enabled"].as_bool().unwrap_or(false)
            && status["StateConsistent"].as_bool().unwrap_or(false)
        {
            break status["InitReceipt"]["TransactionID"]
                .as_str()
                .unwrap()
                .to_string();
        }
        assert!(
            Instant::now() < deadline,
            "control commit was not recovered"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let resumed = client
        .tailnet_lock_init(&serde_json::json!({"Resume": true}))
        .await
        .unwrap();
    assert_eq!(
        resumed["DisablementSecrets"],
        serde_json::json!([secret]),
        "resume must return the original secrets"
    );
    assert_eq!(
        resumed["InitReceipt"]["TransactionID"], pending_transaction,
        "resume must not create a replacement transaction"
    );
    server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cached_locked_netmap_stays_revoked_until_fresh_control_confirmation() {
    let mut control = TestControlServer::new();
    control.start().await.unwrap();
    control.add_fake_node();

    let state = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let socket = sockets.path().join("cached-lock.sock");
    let mut server = Server::builder()
        .hostname("cached-lock")
        .auth_key("tskey-test")
        .control_url(control.base_url())
        .state_dir(state.path())
        .localapi_path(&socket)
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("startup deadline")
        .expect("startup");

    let client = LocalClient::new(&socket);
    let status = client.tailnet_lock_status().await.unwrap();
    let public: NLPublic = status["PublicKey"].as_str().unwrap().parse().unwrap();
    let secret = vec![0x29; 32];
    let initialized = client
        .tailnet_lock_init(&serde_json::json!({
            "Keys": [Key {
                kind: KeyKind::Key25519,
                votes: 1,
                public: public.raw32().to_vec(),
                meta: None,
            }],
            "DisablementValues": [disablement_kdf(&secret)],
            "DisablementSecrets": [secret],
            "SupportDisablement": [],
            "Resume": false,
        }))
        .await
        .unwrap();
    let self_key = initialized["NodeKey"].as_str().unwrap().parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.status().peer_count != 1 {
        assert!(
            Instant::now() < deadline,
            "locked peer did not become visible"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Preserve the last complete locked netmap in the cache while preventing
    // the restarted stream from immediately racing the fail-closed assertion.
    assert!(control.add_raw_map_response(
        &self_key,
        MapResponse {
            KeepAlive: true,
            ..Default::default()
        },
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.close().await;

    let mut restarted = Server::builder()
        .hostname("cached-lock")
        .control_url(control.base_url())
        .state_dir(state.path())
        .localapi_path(&socket)
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(
        Duration::from_secs(60),
        restarted.up(),
    ))
    .await
    .expect("cached startup deadline")
    .expect("cached startup");
    assert_eq!(
        restarted.status().peer_count,
        0,
        "a cached locked authority/head must never reactivate cached peers"
    );

    // A fresh generated full snapshot carries the current TKA head. The
    // previously signed peer then recovers, while the newly added unsigned
    // peer remains filtered.
    control.resume_auto_map(&self_key);
    control.add_fake_node();
    let deadline = Instant::now() + Duration::from_secs(10);
    while restarted.status().peer_count != 1 {
        assert!(
            Instant::now() < deadline,
            "fresh control confirmation did not recover signed peers"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    restarted.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profile_switches_isolate_identity_cache_signing_key_and_chonk() {
    let mut control = TestControlServer::new();
    control.start().await.unwrap();
    control.add_fake_node();
    let state = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let socket = sockets.path().join("profiles.sock");

    rustscale_ipn::LoginProfile::save_current_id(state.path(), "profile-a").unwrap();
    let mut first = Server::builder()
        .hostname("profile-a")
        .auth_key("tskey-test")
        .control_url(control.base_url())
        .state_dir(state.path())
        .localapi_path(&socket)
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(Duration::from_secs(60), first.up()))
        .await
        .unwrap()
        .unwrap();
    let client = LocalClient::new(&socket);
    let a = client.tailnet_lock_status().await.unwrap();
    let a_public: NLPublic = a["PublicKey"].as_str().unwrap().parse().unwrap();
    let secret = vec![0x41; 32];
    let initialized = client
        .tailnet_lock_init(&serde_json::json!({
            "Keys": [Key { kind: KeyKind::Key25519, votes: 1, public: a_public.raw32().to_vec(), meta: None }],
            "DisablementValues": [disablement_kdf(&secret)],
            "DisablementSecrets": [secret],
            "SupportDisablement": [],
            "Resume": false,
        }))
        .await
        .unwrap();
    first.close().await;

    rustscale_ipn::LoginProfile::save_current_id(state.path(), "profile-b").unwrap();
    let mut second = Server::builder()
        .hostname("profile-b")
        .auth_key("tskey-test")
        .control_url(control.base_url())
        .state_dir(state.path())
        .localapi_path(&socket)
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(Duration::from_secs(60), second.up()))
        .await
        .unwrap()
        .unwrap();
    let b = LocalClient::new(&socket)
        .tailnet_lock_status()
        .await
        .unwrap();
    assert_ne!(
        a["PublicKey"], b["PublicKey"],
        "profiles reused a signing key"
    );
    assert!(b["Enabled"].as_bool().unwrap());
    second.close().await;

    rustscale_ipn::LoginProfile::save_current_id(state.path(), "profile-a").unwrap();
    let mut restored = Server::builder()
        .hostname("profile-a")
        .control_url(control.base_url())
        .state_dir(state.path())
        .localapi_path(&socket)
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(Duration::from_secs(60), restored.up()))
        .await
        .unwrap()
        .unwrap();
    let restored_status = LocalClient::new(&socket)
        .tailnet_lock_status()
        .await
        .unwrap();
    assert_eq!(a["PublicKey"], restored_status["PublicKey"]);
    assert_eq!(initialized["Head"], restored_status["Head"]);

    let state_files = walk_files(state.path());
    assert_eq!(
        state_files
            .iter()
            .filter(|path| path
                .file_name()
                .is_some_and(|name| name == "tsnet-state.json"))
            .count(),
        2
    );
    assert!(
        state_files
            .iter()
            .filter(|path| path
                .components()
                .any(|component| component.as_os_str() == "tailnet-lock"))
            .count()
            >= 2,
        "each profile must own a distinct authority store"
    );
    restored.close().await;
}

fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut output = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                output.push(path);
            }
        }
    }
    output
}
