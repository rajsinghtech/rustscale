#![cfg(feature = "identity-federation")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn federated_auth_is_reminted_after_drop_and_omitted_when_enrolled() {
    rustscale_identityfederation::install().unwrap();
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls = resolver_calls.clone();
    let resolver: rustscale_feature::IdentityFederationResolver = Arc::new(move |_| {
        let sequence = hook_calls.fetch_add(1, Ordering::SeqCst) + 1;
        // Distinct one-use keys make accidental replay observable through the
        // resolver call count without retaining either key in the test.
        Box::pin(async move { Ok(format!("federated-one-use-{sequence}")) })
    });
    let _override = rustscale_feature::RESOLVE_AUTH_KEY_VIA_WIF.override_for_test(resolver);

    let mut control = TestControlServer::new();
    control.start().await.unwrap();
    control.drop_next_register_response();
    let state_dir = tempfile::tempdir().unwrap();

    let mut first = Server::builder()
        .disable_portmapping(true)
        .hostname("federated-retry")
        .control_url(control.base_url())
        .state_dir(state_dir.path())
        .client_id("client")
        .id_token("provider-token")
        .advertise_tags(vec!["tag:workload".into()])
        .build()
        .unwrap();

    let first_result = Box::pin(tokio::time::timeout(Duration::from_secs(20), first.up()))
        .await
        .expect("dropped register response timed out");
    assert!(first_result.is_err());
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.register_auth_presence(), [true]);

    // The generated node keys were persisted before the ambiguous failure,
    // but no enrollment marker was. A new attempt must call the resolver and
    // therefore use federated-one-use-2 rather than replaying the first key.
    Box::pin(tokio::time::timeout(Duration::from_secs(60), first.up()))
        .await
        .expect("retry timed out")
        .expect("retry failed");
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 2);
    assert_eq!(control.register_auth_presence(), [true, true]);
    let fingerprints = control.register_auth_fingerprints();
    assert!(fingerprints[0].is_some());
    assert!(fingerprints[1].is_some());
    assert_ne!(fingerprints[0], fingerprints[1]);
    first.close().await.unwrap();

    // Once the successful response has persisted enrollment, a restart uses
    // node identity only and does not invoke WIF or send RegisterRequest.Auth.
    let mut persisted = Server::builder()
        .disable_portmapping(true)
        .hostname("federated-retry")
        .control_url(control.base_url())
        .state_dir(state_dir.path())
        .client_id("client")
        .id_token("provider-token")
        .advertise_tags(vec!["tag:workload".into()])
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(
        Duration::from_secs(60),
        persisted.up(),
    ))
    .await
    .expect("persisted startup timed out")
    .expect("persisted startup failed");
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 2);
    assert_eq!(control.register_auth_presence(), [true, true, false]);
    assert_eq!(control.register_auth_fingerprints()[2], None);
    persisted.close().await.unwrap();

    // Explicit force-login is the only persisted path that mints and sends a
    // new federated auth key.
    let mut forced = Server::builder()
        .disable_portmapping(true)
        .hostname("federated-retry")
        .control_url(control.base_url())
        .state_dir(state_dir.path())
        .client_id("client")
        .id_token("provider-token")
        .advertise_tags(vec!["tag:workload".into()])
        .force_login(true)
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(Duration::from_secs(60), forced.up()))
        .await
        .expect("force-login startup timed out")
        .expect("force-login startup failed");
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 3);
    assert_eq!(control.register_auth_presence(), [true, true, false, true]);
    forced.close().await.unwrap();
}
