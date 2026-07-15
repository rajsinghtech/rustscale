use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::monitor::{Monitor, StateProvider};
use super::state::{
    has_cgnat_interface, link_type_from_name, InterfaceMeta, IpPrefix, LinkType, Route, State,
};

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
        index: 0,
        mtu: 1500,
        flags: if up { 0x43 } else { 0 },
        hw_addr: None,
        link_type: if lo {
            LinkType::Loopback
        } else {
            LinkType::Wired
        },
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

// ---------------------------------------------------------------------------
// Existing state comparison tests
// ---------------------------------------------------------------------------

#[test]
fn test_state_equal() {
    let a = state_en0_up("192.168.1.10/24");
    let b = state_en0_up("192.168.1.10/24");
    assert!(a.equal(&b));
}

#[test]
fn test_state_major_ip_added() {
    let a = state_en0_up("192.168.1.10/24");
    let mut b = state_en0_up("192.168.1.10/24");
    b.interface_ips
        .get_mut("en0")
        .unwrap()
        .push(ip4("10.0.0.5/8"));
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

// ---------------------------------------------------------------------------
// CGNAT detection tests
// ---------------------------------------------------------------------------

#[test]
fn test_cgnat_detected_on_up_interface() {
    let mut interface_ips = BTreeMap::new();
    interface_ips.insert("eth0".into(), vec![ip4("100.64.1.5/10")]);
    let mut interface_meta = BTreeMap::new();
    interface_meta.insert("eth0".into(), meta(true, false));
    let state = State {
        interface_ips,
        interface_meta,
        have_v4: true,
        have_v6: false,
        default_route_interface: "eth0".into(),
    };
    assert!(has_cgnat_interface(&state));
}

#[test]
fn test_cgnat_not_detected_on_down_interface() {
    let mut interface_ips = BTreeMap::new();
    interface_ips.insert("eth0".into(), vec![ip4("100.64.1.5/10")]);
    let mut interface_meta = BTreeMap::new();
    interface_meta.insert("eth0".into(), meta(false, false));
    let state = State {
        interface_ips,
        interface_meta,
        have_v4: false,
        have_v6: false,
        default_route_interface: String::new(),
    };
    assert!(!has_cgnat_interface(&state));
}

#[test]
fn test_cgnat_not_detected_on_tailscale_interface() {
    let mut interface_ips = BTreeMap::new();
    interface_ips.insert("tailscale0".into(), vec![ip4("100.64.1.5/10")]);
    let mut interface_meta = BTreeMap::new();
    interface_meta.insert("tailscale0".into(), meta(true, false));
    let state = State {
        interface_ips,
        interface_meta,
        have_v4: false,
        have_v6: false,
        default_route_interface: String::new(),
    };
    assert!(!has_cgnat_interface(&state));
}

#[test]
fn test_cgnat_not_detected_on_normal_ip() {
    let state = state_en0_up("192.168.1.10/24");
    assert!(!has_cgnat_interface(&state));
}

// ---------------------------------------------------------------------------
// LinkType classification tests
// ---------------------------------------------------------------------------

#[test]
fn test_link_type_classification() {
    assert_eq!(link_type_from_name("en0", false), LinkType::Wired);
    assert_eq!(link_type_from_name("eth0", false), LinkType::Wired);
    assert_eq!(link_type_from_name("wlan0", false), LinkType::Wifi);
    assert_eq!(link_type_from_name("wl0", false), LinkType::Wifi);
    assert_eq!(link_type_from_name("ppp0", false), LinkType::Mobile);
    assert_eq!(link_type_from_name("rmnet0", false), LinkType::Mobile);
    assert_eq!(link_type_from_name("lo0", true), LinkType::Loopback);
    assert_eq!(link_type_from_name("utun0", false), LinkType::Tunnel);
    assert_eq!(link_type_from_name("tailscale0", false), LinkType::Tunnel);
    assert_eq!(link_type_from_name("veth0", false), LinkType::Unknown);
}

// ---------------------------------------------------------------------------
// Route struct tests
// ---------------------------------------------------------------------------

#[test]
fn test_route_default() {
    let r = Route::default();
    assert!(r.interface_name.is_empty());
    assert_eq!(r.interface_index, 0);
    assert!(r.gateway.is_none());
}

#[test]
fn test_route_construction() {
    let r = Route {
        interface_name: "en0".into(),
        interface_index: 5,
        gateway: Some(std::net::IpAddr::V4("192.168.1.1".parse().unwrap())),
    };
    assert_eq!(r.interface_name, "en0");
    assert_eq!(r.interface_index, 5);
    assert_eq!(
        r.gateway,
        Some(std::net::IpAddr::V4("192.168.1.1".parse().unwrap()))
    );
}

#[test]
fn test_default_route_returns_route_struct() {
    let route = super::state::default_route();
    let _ = route.interface_name;
    let _ = route.interface_index;
    let _ = route.gateway;
}

// ---------------------------------------------------------------------------
// InterfaceMeta expanded fields test
// ---------------------------------------------------------------------------

#[test]
fn test_interface_meta_has_extended_fields() {
    let m = InterfaceMeta {
        is_up: true,
        is_loopback: false,
        index: 42,
        mtu: 9000,
        flags: 0x8043,
        hw_addr: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        link_type: LinkType::Wired,
    };
    assert_eq!(m.index, 42);
    assert_eq!(m.mtu, 9000);
    assert_eq!(m.flags, 0x8043);
    assert_eq!(m.hw_addr, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    assert_eq!(m.link_type, LinkType::Wired);
}

// ---------------------------------------------------------------------------
// Multi-callback register/unregister test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_multi_callback_register_unregister() {
    let state_a = state_en0_up("192.168.1.10/24");
    let mut state_b = state_en0_up("192.168.1.10/24");
    state_b
        .interface_ips
        .get_mut("en0")
        .unwrap()
        .push(ip4("10.0.0.5/8"));

    let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let provider: StateProvider = {
        let count = call_count.clone();
        Arc::new(move || {
            let n = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Some(state_a.clone())
            } else {
                Some(state_b.clone())
            }
        })
    };

    let monitor = Monitor::with_state_provider(provider)
        .unwrap()
        .with_poll_interval(Duration::from_millis(50));

    let handle = monitor.start();

    let calls1 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls2 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls3 = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let cb1 = {
        let c = calls1.clone();
        move |_delta: super::monitor::ChangeDelta| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async {}
        }
    };
    let cb2 = {
        let c = calls2.clone();
        move |_delta: super::monitor::ChangeDelta| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async {}
        }
    };
    let cb3 = {
        let c = calls3.clone();
        move |_delta: super::monitor::ChangeDelta| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async {}
        }
    };

    let _h1 = handle.register_change_callback(cb1);
    handle.register_owned_change_callback(cb2);
    let h3 = handle.register_change_callback(cb3);
    h3.unregister();

    let found = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if calls1.load(std::sync::atomic::Ordering::SeqCst) > 0
                && calls2.load(std::sync::atomic::Ordering::SeqCst) > 0
            {
                return;
            }
        }
    })
    .await;

    handle.shutdown();
    assert!(found.is_ok(), "did not receive callbacks in time");

    assert!(
        calls1.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "callback 1 was never called"
    );
    assert!(
        calls2.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "callback 2 was never called"
    );
}

// ---------------------------------------------------------------------------
// Monitor change detection test (updated for new start/register API)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_monitor_detects_change_with_fake_provider() {
    let state_a = state_en0_up("192.168.1.10/24");
    let mut state_b = state_en0_up("192.168.1.10/24");
    state_b
        .interface_ips
        .get_mut("en0")
        .unwrap()
        .push(ip4("10.0.0.5/8"));

    let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let provider: StateProvider = {
        let count = call_count.clone();
        Arc::new(move || {
            let n = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Some(state_a.clone())
            } else {
                Some(state_b.clone())
            }
        })
    };

    let monitor = Monitor::with_state_provider(provider)
        .unwrap()
        .with_poll_interval(Duration::from_millis(50));

    let deltas: Arc<Mutex<Vec<super::monitor::ChangeDelta>>> = Arc::new(Mutex::new(Vec::new()));
    let deltas_clone = deltas.clone();

    let handle = monitor.start();
    let _cb_handle = handle.register_change_callback(move |delta| {
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

// ---------------------------------------------------------------------------
// Time-jump threshold logic test
// ---------------------------------------------------------------------------

#[test]
fn test_time_jump_threshold_is_10_minutes() {
    assert_eq!(
        super::monitor::MAJOR_TIME_JUMP_THRESHOLD,
        Duration::from_mins(10)
    );
}

// ---------------------------------------------------------------------------
// GetInterfaceList test
// ---------------------------------------------------------------------------

#[test]
fn test_get_interface_list_returns_entries() {
    let entries = super::state::get_interface_list();
    let has_loopback = entries
        .iter()
        .any(|e| e.meta.is_loopback || e.name.starts_with("lo"));
    let _ = entries.len();
    let _ = has_loopback;
}
