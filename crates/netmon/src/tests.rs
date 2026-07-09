use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::monitor::{Monitor, StateProvider};
use super::state::{InterfaceMeta, IpPrefix, State};
fn ip4(s: &str) -> IpPrefix {
    let (ip, bits) = s.split_once('/').unwrap_or((s, "32"));
    IpPrefix {
        ip: std::net::IpAddr::V4(ip.parse().unwrap()),
        bits: bits.parse().unwrap(),
    }
}

fn meta(up: bool, lo: bool) -> InterfaceMeta {
    InterfaceMeta {
        is_up: up,
        is_loopback: lo,
    }
}

fn state_en0_up(ip: &str) -> State {
    let mut interface_ips = BTreeMap::new();
    interface_ips.insert("en0".into(), vec![ip4(ip)]);
    let mut interface_meta = BTreeMap::new();
    interface_meta.insert("en0".into(), meta(true, false));
    State {
        interface_ips,
        interface_meta,
        have_v4: true,
        have_v6: false,
        default_route_interface: "en0".into(),
    }
}

#[test]
fn test_state_equal() {
    let a = state_en0_up("192.168.1.10/24");
    let b = state_en0_up("192.168.1.10/24");
    assert!(a.equal(&b));
}

#[test]
fn test_state_major_ip_added() {
    let mut a = state_en0_up("192.168.1.10/24");
    let mut b = state_en0_up("192.168.1.10/24");
    b.interface_ips
        .get_mut("en0")
        .unwrap()
        .push(ip4("10.0.0.5/8"));
    a.have_v4 = true;
    b.have_v4 = true;
    assert!(b.is_major_change_from(&a));
}

#[test]
fn test_state_minor_default_route_only() {
    let a = state_en0_up("192.168.1.10/24");
    let mut b = state_en0_up("192.168.1.10/24");
    b.default_route_interface = "en1".into();
    assert!(!b.is_major_change_from(&a));
    assert!(!a.equal(&b));
}

#[test]
fn test_state_up_down_transition() {
    let a = state_en0_up("192.168.1.10/24");
    let mut b = state_en0_up("192.168.1.10/24");
    b.interface_meta.insert("en0".into(), meta(false, false));
    b.have_v4 = false;
    assert!(b.is_major_change_from(&a));
}

#[test]
fn test_state_interface_removed() {
    let a = state_en0_up("192.168.1.10/24");
    let mut b = state_en0_up("192.168.1.10/24");
    b.interface_ips.remove("en0");
    b.interface_meta.remove("en0");
    b.have_v4 = false;
    assert!(b.is_major_change_from(&a));
}

#[test]
fn test_state_loopback_ignored() {
    let mut a = state_en0_up("192.168.1.10/24");
    a.interface_ips
        .insert("lo0".into(), vec![ip4("127.0.0.1/8")]);
    a.interface_meta.insert("lo0".into(), meta(true, true));

    let mut b = state_en0_up("192.168.1.10/24");
    b.interface_ips
        .insert("lo0".into(), vec![ip4("127.0.0.2/8")]);
    b.interface_meta.insert("lo0".into(), meta(true, true));

    assert!(!b.is_major_change_from(&a));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_monitor_detects_change_with_fake_provider() {
    let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let state_a = state_en0_up("192.168.1.10/24");
    let mut state_b = state_en0_up("192.168.1.10/24");
    state_b
        .interface_ips
        .get_mut("en0")
        .unwrap()
        .push(ip4("10.0.0.5/8"));

    let count = call_count.clone();
    let provider: StateProvider = Arc::new(move || {
        let n = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            Some(state_a.clone())
        } else {
            Some(state_b.clone())
        }
    });

    let monitor = Monitor::with_state_provider(provider)
        .unwrap()
        .with_poll_interval(Duration::from_millis(50));

    let deltas: Arc<Mutex<Vec<super::monitor::ChangeDelta>>> = Arc::new(Mutex::new(Vec::new()));
    let deltas_clone = deltas.clone();

    let handle = monitor.start(move |delta| {
        let d = deltas_clone.clone();
        async move {
            d.lock().unwrap().push(delta);
        }
    });

    let found = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if deltas.lock().unwrap().iter().any(|d| d.major) {
                return;
            }
        }
    })
    .await;

    handle.shutdown();
    assert!(found.is_ok(), "did not detect a major change in time");
    let recorded = deltas.lock().unwrap();
    assert!(!recorded.is_empty());
    assert!(recorded.iter().any(|d| d.major));
}
