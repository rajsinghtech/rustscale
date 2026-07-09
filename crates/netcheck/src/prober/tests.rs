//! Prober tests: an in-process fake STUN server, preferred-region selection
//! logic, NAT mapping-variation detection, and hysteresis.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use rustscale_tailcfg::{DERPMap, DERPNode, DERPRegion};
use tokio::net::UdpSocket;

use super::*;
use crate::stun::{parse_binding_request, response};

/// A minimal fake STUN server: receives binding requests on a bound UDP
/// socket and replies with a `XOR-MAPPED-ADDRESS` reflecting the client's
/// source address (or a fixed reflexive address when `fixed_reflexive` is set).
struct FakeStunServer {
    addr: SocketAddr,
    fixed_reflexive: Option<SocketAddr>,
    delay: Duration,
}

impl FakeStunServer {
    async fn start(fixed_reflexive: Option<SocketAddr>, delay: Duration) -> std::io::Result<Self> {
        let sock = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = sock.local_addr()?;
        let server = Self {
            addr,
            fixed_reflexive,
            delay,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        if let Ok(tx_id) = parse_binding_request(&buf[..n]) {
                            let reflexive = server.fixed_reflexive.unwrap_or(src);
                            if server.delay > Duration::ZERO {
                                tokio::time::sleep(server.delay).await;
                            }
                            let resp = response(&tx_id, reflexive);
                            let _ = sock.send_to(&resp, src).await;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(server)
    }
}

/// Build a DERPMap with one region per fake server, each region's node pointing
/// at the server's loopback address via `STUNTestIP`.
fn map_from_servers(servers: &[(i32, FakeStunServer)]) -> DERPMap {
    let mut regions = BTreeMap::new();
    for (rid, srv) in servers {
        let node = DERPNode {
            Name: format!("{}a", rid),
            RegionID: *rid,
            HostName: format!("derp{}.tailscale.com", rid),
            STUNTestIP: srv.addr.ip().to_string(),
            STUNPort: srv.addr.port() as i32,
            ..Default::default()
        };
        regions.insert(
            *rid,
            DERPRegion {
                RegionID: *rid,
                RegionCode: format!("r{}", rid),
                RegionName: format!("Region {}", rid),
                Nodes: Some(vec![node]),
                ..Default::default()
            },
        );
    }
    DERPMap {
        Regions: regions,
        ..Default::default()
    }
}

#[tokio::test]
async fn prober_picks_lowest_latency_region() {
    // Two regions: region 1 replies after ~20ms, region 2 replies immediately.
    let slow = FakeStunServer::start(None, Duration::from_millis(20))
        .await
        .unwrap();
    let fast = FakeStunServer::start(None, Duration::ZERO).await.unwrap();
    let dm = map_from_servers(&[(1, slow), (2, fast)]);

    let prober = Prober::default();
    let opts = ProberOpts {
        report_timeout: Duration::from_secs(2),
        probe_timeout: Duration::from_millis(400),
        ..Default::default()
    };
    let report = prober.run(&dm, &opts).await.expect("report");

    assert!(report.udp, "at least one STUN round trip completed");
    assert!(report.ipv4, "v4 probes succeeded");
    assert!(
        report.region_latency.contains_key(&1) && report.region_latency.contains_key(&2),
        "both regions probed: {:?}",
        report.region_latency
    );
    assert_eq!(report.preferred_derp, 2, "fastest region wins");
}

#[tokio::test]
async fn prober_reports_reflexive_v4_endpoint() {
    let fixed = "127.0.0.1:9999".parse().unwrap();
    let srv = FakeStunServer::start(Some(fixed), Duration::ZERO)
        .await
        .unwrap();
    let dm = map_from_servers(&[(1, srv)]);

    let prober = Prober::default();
    let report = prober
        .run(&dm, &ProberOpts::default())
        .await
        .expect("report");
    assert_eq!(report.global_v4, Some(fixed));
    assert_eq!(
        report.region_v4_latency.get(&1),
        report.region_latency.get(&1)
    );
}

#[tokio::test]
async fn prober_detects_mapping_varies_by_dest() {
    // Two regions, each reporting a *different* fixed reflexive v4 address.
    let srv1 = FakeStunServer::start(Some("127.0.0.1:1111".parse().unwrap()), Duration::ZERO)
        .await
        .unwrap();
    let srv2 = FakeStunServer::start(Some("127.0.0.1:2222".parse().unwrap()), Duration::ZERO)
        .await
        .unwrap();
    let dm = map_from_servers(&[(1, srv1), (2, srv2)]);

    let prober = Prober::default();
    let report = prober
        .run(&dm, &ProberOpts::default())
        .await
        .expect("report");
    assert_eq!(
        report.mapping_varies_by_dest_ip,
        Some(true),
        "different reflexive endpoints across destinations"
    );
}

#[tokio::test]
async fn prober_detects_mapping_consistent_across_dest() {
    // Two regions reporting the *same* fixed reflexive v4 address.
    let same: SocketAddr = "127.0.0.1:5555".parse().unwrap();
    let srv1 = FakeStunServer::start(Some(same), Duration::ZERO)
        .await
        .unwrap();
    let srv2 = FakeStunServer::start(Some(same), Duration::ZERO)
        .await
        .unwrap();
    let dm = map_from_servers(&[(1, srv1), (2, srv2)]);

    let prober = Prober::default();
    let report = prober
        .run(&dm, &ProberOpts::default())
        .await
        .expect("report");
    assert_eq!(
        report.mapping_varies_by_dest_ip,
        Some(false),
        "same reflexive endpoint across destinations"
    );
}

#[tokio::test]
async fn prober_skips_disabled_stun() {
    // STUNPort = -1 disables STUN; the region should be unprobeable.
    let node = DERPNode {
        Name: "1a".into(),
        RegionID: 1,
        HostName: "derp1.tailscale.com".into(),
        STUNPort: -1,
        ..Default::default()
    };
    let mut regions = BTreeMap::new();
    regions.insert(
        1,
        DERPRegion {
            RegionID: 1,
            RegionCode: "r1".into(),
            RegionName: "Region 1".into(),
            Nodes: Some(vec![node]),
            ..Default::default()
        },
    );
    let dm = DERPMap {
        Regions: regions,
        ..Default::default()
    };

    let prober = Prober::default();
    let err = prober.run(&dm, &ProberOpts::default()).await.unwrap_err();
    assert!(matches!(err, NetcheckError::NoRegions), "{err:?}");
}

#[tokio::test]
async fn prober_handles_unreachable_region() {
    // Point at a port nobody's listening on; the probe should time out and the
    // region should be absent from the latency map, but run() still succeeds.
    let node = DERPNode {
        Name: "1a".into(),
        RegionID: 1,
        HostName: "derp1.tailscale.com".into(),
        STUNTestIP: "127.0.0.1".into(),
        STUNPort: 1, // discard port; nothing listening
        ..Default::default()
    };
    let mut regions = BTreeMap::new();
    regions.insert(
        1,
        DERPRegion {
            RegionID: 1,
            RegionCode: "r1".into(),
            RegionName: "Region 1".into(),
            Nodes: Some(vec![node]),
            ..Default::default()
        },
    );
    let dm = DERPMap {
        Regions: regions,
        ..Default::default()
    };

    let prober = Prober::default();
    let opts = ProberOpts {
        report_timeout: Duration::from_millis(800),
        probe_timeout: Duration::from_millis(100),
        max_retries: 1,
        ..Default::default()
    };
    let report = prober.run(&dm, &opts).await.expect("report");
    assert!(!report.udp, "no STUN round trip completed");
    assert!(report.region_latency.is_empty());
    assert_eq!(report.preferred_derp, 0);
}

#[tokio::test]
async fn prober_sets_os_has_ipv6_when_bindable() {
    // This is environment-dependent; just assert the field is consistent with
    // whether we can bind a v6 loopback socket ourselves.
    let can_bind = UdpSocket::bind("[::1]:0").await.is_ok();
    let srv = FakeStunServer::start(None, Duration::ZERO).await.unwrap();
    let dm = map_from_servers(&[(1, srv)]);
    let report = Prober::default()
        .run(&dm, &ProberOpts::default())
        .await
        .expect("report");
    assert_eq!(report.os_has_ipv6, can_bind);
}

// --- pure-logic selection tests (no sockets) -------------------------------

#[test]
fn hysteresis_keeps_old_region_within_absolute_diff() {
    // Previous = 1 @ 25ms; new best = 2 @ 20ms. Diff = 5ms < 10ms threshold.
    let mut m = BTreeMap::new();
    m.insert(1, Duration::from_millis(25));
    m.insert(2, Duration::from_millis(20));
    assert_eq!(pick_with_hysteresis(&m, 1), 1, "keep old within threshold");
}

#[test]
fn hysteresis_switches_when_improvement_is_large() {
    // Previous = 1 @ 50ms; new best = 2 @ 20ms. Diff = 30ms > 10ms threshold.
    let mut m = BTreeMap::new();
    m.insert(1, Duration::from_millis(50));
    m.insert(2, Duration::from_millis(20));
    assert_eq!(pick_with_hysteresis(&m, 1), 2, "switch when clearly better");
}

#[test]
fn hysteresis_no_previous_picks_best() {
    let mut m = BTreeMap::new();
    m.insert(1, Duration::from_millis(50));
    m.insert(2, Duration::from_millis(20));
    assert_eq!(pick_with_hysteresis(&m, 0), 2);
}

#[test]
fn hysteresis_empty_map_keeps_previous() {
    assert_eq!(pick_with_hysteresis(&BTreeMap::new(), 5), 5);
}

#[test]
fn hysteresis_old_region_unreachable_switches() {
    // Previous = 1 but it has no latency sample (unreachable this round);
    // new best = 2 @ 20ms. Should switch to 2.
    let mut m = BTreeMap::new();
    m.insert(2, Duration::from_millis(20));
    assert_eq!(pick_with_hysteresis(&m, 1), 2);
}
