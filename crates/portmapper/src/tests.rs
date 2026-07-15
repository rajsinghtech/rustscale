//! Tests for the portmapper crate.
//!
//! All tests run against in-process fakes on localhost — none depend on a
//! real LAN port mapper. The fake IGD mirrors Go's `igd_test.go`: a local
//! UDP SSDP responder + PMP/PCP responder + HTTP server serving canned
//! root-desc XML + SOAP endpoints.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

use crate::client::ReleaseTestGate;
use crate::{pcp, Client, GatewayInfo, MappingKind};

struct AsyncGate {
    reached: tokio::sync::Barrier,
    resume: tokio::sync::Barrier,
}

impl AsyncGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            reached: tokio::sync::Barrier::new(2),
            resume: tokio::sync::Barrier::new(2),
        })
    }
}

/// A fake Internet Gateway Device for testing. Supports fake PMP, PCP,
/// and/or UPnP. All listeners are on localhost.
struct FakeIgd {
    pxp_sock: Arc<UdpSocket>,
    upnp_sock: Arc<UdpSocket>,
    http_addr: SocketAddr,
    do_pmp: AtomicBool,
    do_pcp: AtomicBool,
    do_upnp: AtomicBool,
    pmp_external_ip: Ipv4Addr,
    pcp_mutation: Option<PcpMutation>,
    upnp_permanent_malformed: bool,
    upnp_delete_fault: bool,
    closed: Arc<AtomicBool>,
    pmp_recv_count: Arc<AtomicU32>,
    pmp_map_count: Arc<AtomicU32>,
    pcp_recv_count: Arc<AtomicU32>,
    pcp_map_count: Arc<AtomicU32>,
    pcp_nonces: Arc<Mutex<Vec<[u8; 12]>>>,
    upnp_disco_count: Arc<AtomicU32>,
    upnp_add_count: Arc<AtomicU32>,
    upnp_delete_count: Arc<AtomicU32>,
    add_mapping_gate: Mutex<Option<Arc<AsyncGate>>>,
    external_ip_gate: Mutex<Option<Arc<AsyncGate>>>,
}

impl FakeIgd {
    async fn start(opts: IgdOpts) -> Arc<Self> {
        let pxp_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upnp_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();

        let closed = Arc::new(AtomicBool::new(false));
        let igd = Arc::new(Self {
            pxp_sock,
            upnp_sock,
            http_addr,
            do_pmp: AtomicBool::new(opts.pmp),
            do_pcp: AtomicBool::new(opts.pcp),
            do_upnp: AtomicBool::new(opts.upnp),
            pmp_external_ip: opts.pmp_external_ip,
            pcp_mutation: opts.pcp_mutation,
            upnp_permanent_malformed: opts.upnp_permanent_malformed,
            upnp_delete_fault: opts.upnp_delete_fault,
            closed: closed.clone(),
            pmp_recv_count: Arc::new(AtomicU32::new(0)),
            pmp_map_count: Arc::new(AtomicU32::new(0)),
            pcp_recv_count: Arc::new(AtomicU32::new(0)),
            pcp_map_count: Arc::new(AtomicU32::new(0)),
            pcp_nonces: Arc::new(Mutex::new(Vec::new())),
            upnp_disco_count: Arc::new(AtomicU32::new(0)),
            upnp_add_count: Arc::new(AtomicU32::new(0)),
            upnp_delete_count: Arc::new(AtomicU32::new(0)),
            add_mapping_gate: Mutex::new(None),
            external_ip_gate: Mutex::new(None),
        });

        // Spawn handlers.
        let igd_pxp = igd.clone();
        tokio::spawn(async move { igd_pxp.serve_pxp().await });
        let igd_upnp = igd.clone();
        tokio::spawn(async move { igd_upnp.serve_ssdp().await });
        let igd_http = igd.clone();
        tokio::spawn(async move { igd_http.serve_http(http_listener).await });

        igd
    }

    fn pxp_port(&self) -> u16 {
        self.pxp_sock.local_addr().unwrap().port()
    }

    fn upnp_port(&self) -> u16 {
        self.upnp_sock.local_addr().unwrap().port()
    }

    fn http_url(&self) -> String {
        format!(
            "http://{}:{}/rootDesc.xml",
            self.http_addr.ip(),
            self.http_addr.port()
        )
    }

    fn gate_add_mapping(&self, gate: Option<Arc<AsyncGate>>) {
        *self.add_mapping_gate.lock().unwrap() = gate;
    }

    fn gate_external_ip(&self, gate: Option<Arc<AsyncGate>>) {
        *self.external_ip_gate.lock().unwrap() = gate;
    }

    fn set_protocols(&self, pmp: bool, pcp: bool, upnp: bool) {
        self.do_pmp.store(pmp, Ordering::SeqCst);
        self.do_pcp.store(pcp, Ordering::SeqCst);
        self.do_upnp.store(upnp, Ordering::SeqCst);
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    async fn serve_pxp(self: Arc<Self>) {
        let mut buf = [0u8; 1500];
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            if let Ok(Ok((n, src))) =
                timeout(Duration::from_millis(10), self.pxp_sock.recv_from(&mut buf)).await
            {
                if n < 2 {
                    continue;
                }
                let ver = buf[0];
                match ver {
                    0 => self.clone().handle_pmp(&buf[..n], src).await,
                    2 => self.clone().handle_pcp(&buf[..n], src).await,
                    _ => {}
                }
            }
        }
    }

    async fn handle_pmp(self: Arc<Self>, pkt: &[u8], src: SocketAddr) {
        self.pmp_recv_count.fetch_add(1, Ordering::Relaxed);
        if !self.do_pmp.load(Ordering::Relaxed) || pkt.len() < 2 {
            return;
        }
        let op = pkt[1];
        if op == 0 {
            let mut resp = [0u8; 12];
            resp[1] = 0x80; // reply | op 0
            resp[4..8].copy_from_slice(&12345u32.to_be_bytes());
            let ip = self.pmp_external_ip.octets();
            resp[8] = ip[0];
            resp[9] = ip[1];
            resp[10] = ip[2];
            resp[11] = ip[3];
            let _ = self.pxp_sock.send_to(&resp, src).await;
        } else if op == 1 {
            self.pmp_map_count.fetch_add(1, Ordering::Relaxed);
            let mut resp = [0u8; 16];
            resp[1] = 0x81; // reply | op 1
            resp[4..8].copy_from_slice(&12345u32.to_be_bytes());
            if pkt.len() >= 6 {
                resp[8..10].copy_from_slice(&pkt[4..6]);
            }
            resp[10..12].copy_from_slice(&4242u16.to_be_bytes());
            resp[12..16].copy_from_slice(&pkt[8..12]);
            let _ = self.pxp_sock.send_to(&resp, src).await;
        }
    }

    async fn handle_pcp(self: Arc<Self>, pkt: &[u8], src: SocketAddr) {
        self.pcp_recv_count.fetch_add(1, Ordering::Relaxed);
        if pkt.len() < 24 {
            return;
        }
        let op = pkt[1];
        if op == 1 && pkt.len() >= 60 {
            self.pcp_map_count.fetch_add(1, Ordering::Relaxed);
            let mut nonce = [0_u8; 12];
            nonce.copy_from_slice(&pkt[24..36]);
            self.pcp_nonces.lock().unwrap().push(nonce);
        }
        match op {
            0 if self.do_pcp.load(Ordering::Relaxed) => {
                let resp = pcp::build_disco_response(op);
                let _ = self.pxp_sock.send_to(&resp, src).await;
            }
            1 if self.do_pcp.load(Ordering::Relaxed) && pkt.len() >= 60 => {
                let mut resp = pcp::build_map_response(pkt);
                match self.pcp_mutation {
                    Some(PcpMutation::Nonce) => resp[24] ^= 1,
                    Some(PcpMutation::Protocol) => resp[36] = 6,
                    Some(PcpMutation::InternalPort) => {
                        resp[40..42].copy_from_slice(&1u16.to_be_bytes());
                    }
                    _ => {}
                }
                let socket = if self.pcp_mutation == Some(PcpMutation::Source) {
                    &self.upnp_sock
                } else {
                    &self.pxp_sock
                };
                let _ = socket.send_to(&resp, src).await;
            }
            _ => {}
        }
    }

    async fn serve_ssdp(self: Arc<Self>) {
        let mut buf = [0u8; 1500];
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            if let Ok(Ok((n, src))) = timeout(
                Duration::from_millis(10),
                self.upnp_sock.recv_from(&mut buf),
            )
            .await
            {
                let pkt = &buf[..n];
                if pkt.windows(8).any(|w| w == b"M-SEARCH") {
                    self.upnp_disco_count.fetch_add(1, Ordering::Relaxed);
                    if self.do_upnp.load(Ordering::Relaxed) {
                        let location = self.http_url();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\n\
                             CACHE-CONTROL: max-age=120\r\n\
                             ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                             USN: uuid:test::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                             EXT:\r\n\
                             SERVER: Test/1.0 UPnP/1.1\r\n\
                             LOCATION: {location}\r\n\r\n"
                        );
                        let _ = self.upnp_sock.send_to(resp.as_bytes(), src).await;
                    }
                }
            }
        }
    }

    async fn serve_http(self: Arc<Self>, listener: TcpListener) {
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            if let Ok(Ok((mut stream, _))) =
                timeout(Duration::from_millis(10), listener.accept()).await
            {
                let igd = self.clone();
                tokio::spawn(async move {
                    igd.handle_http(&mut stream).await;
                });
            }
        }
    }

    async fn handle_http(
        self: Arc<Self>,
        stream: &mut (impl AsyncReadExt + Unpin + AsyncWriteExt),
    ) {
        let mut buf = vec![0u8; 4096];
        let n = match stream.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => return,
        };
        let req = String::from_utf8_lossy(&buf[..n]);
        let first_line = req.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }
        let method = parts[0];
        let path = parts[1];

        if method == "GET" && path == "/rootDesc.xml" {
            let body = TEST_ROOT_DESC;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        }

        if method == "POST" && path == "/ctl/IPConn" {
            let action = req
                .lines()
                .find_map(|l| l.strip_prefix("SOAPAction: "))
                .map(|s| s.trim().trim_matches('"').to_string())
                .unwrap_or_default();

            if action.contains("AddPortMapping") {
                self.upnp_add_count.fetch_add(1, Ordering::Relaxed);
                let gate = self.add_mapping_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.reached.wait().await;
                    gate.resume.wait().await;
                }
                if self.upnp_permanent_malformed {
                    if req.contains("<NewLeaseDuration>0</NewLeaseDuration>") {
                        write_soap_response(stream, "").await;
                    } else {
                        write_soap_response(stream, r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><errorCode>725</errorCode></s:Fault></s:Body></s:Envelope>"#).await;
                    }
                } else {
                    write_soap_response(stream, TEST_ADD_PORT_MAPPING_RESPONSE).await;
                }
                return;
            }
            if action.contains("GetExternalIPAddress") {
                let gate = self.external_ip_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.reached.wait().await;
                    gate.resume.wait().await;
                }
                write_soap_response(stream, TEST_GET_EXTERNAL_IP_RESPONSE).await;
                return;
            }
            if action.contains("DeletePortMapping") {
                self.upnp_delete_count.fetch_add(1, Ordering::Relaxed);
                if self.upnp_delete_fault {
                    write_soap_response(stream, r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><errorCode>501</errorCode></s:Fault></s:Body></s:Envelope>"#).await;
                    return;
                }
                write_soap_response(stream, r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>"#).await;
                return;
            }
        }

        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    }
}

async fn write_soap_response(stream: &mut (impl AsyncWriteExt + Unpin), body: &str) {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PcpMutation {
    Nonce,
    Protocol,
    InternalPort,
    Source,
}

struct IgdOpts {
    pmp: bool,
    pcp: bool,
    upnp: bool,
    pmp_external_ip: Ipv4Addr,
    pcp_mutation: Option<PcpMutation>,
    upnp_permanent_malformed: bool,
    upnp_delete_fault: bool,
}

impl Default for IgdOpts {
    fn default() -> Self {
        Self {
            pmp: false,
            pcp: false,
            upnp: false,
            pmp_external_ip: Ipv4Addr::new(123, 123, 123, 123),
            pcp_mutation: None,
            upnp_permanent_malformed: false,
            upnp_delete_fault: false,
        }
    }
}

fn make_test_client(igd: &FakeIgd) -> Client {
    let client = Client::new();
    client.set_gateway_lookup(Box::new(|| {
        Some(GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(1, 2, 3, 4),
        })
    }));
    client.set_test_pxp_port(igd.pxp_port());
    client.set_test_upnp_port(igd.upnp_port());
    client.set_local_port(12345);
    client
}

const TEST_ROOT_DESC: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>1</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Tailscale Test Router</friendlyName>
    <manufacturer>Tailscale</manufacturer>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <friendlyName>WANDevice</friendlyName>
        <manufacturer>MiniUPnP</manufacturer>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <friendlyName>WANConnectionDevice</friendlyName>
            <manufacturer>MiniUPnP</manufacturer>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <SCPDURL>/WANIPCn.xml</SCPDURL>
                <controlURL>/ctl/IPConn</controlURL>
                <eventSubURL>/evt/IPConn</eventSubURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>"#;

const TEST_ADD_PORT_MAPPING_RESPONSE: &str = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>"#;

const TEST_GET_EXTERNAL_IP_RESPONSE: &str = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>123.123.123.123</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>"#;

// --- PMP probe + mapping test ---

#[tokio::test]
async fn test_pmp_probe_and_mapping() {
    let igd = FakeIgd::start(IgdOpts {
        pmp: true,
        ..Default::default()
    })
    .await;
    let client = make_test_client(&igd);

    let result = client.probe().await.expect("probe");
    assert!(result.pmp, "should detect PMP");
    assert!(!result.pcp);
    assert!(!result.upnp);

    let mapping = client.create_or_get_mapping().await.expect("mapping");
    assert_eq!(mapping.kind, MappingKind::Pmp);
    assert_eq!(
        mapping.external.ip(),
        std::net::IpAddr::V4(Ipv4Addr::new(123, 123, 123, 123))
    );
    assert_eq!(mapping.external.port(), 4242);
    assert!(mapping.is_valid());
    assert!(!mapping.needs_renewal());

    let m2 = client
        .create_or_get_mapping()
        .await
        .expect("cached mapping");
    assert_eq!(m2.external, mapping.external);

    client.close();
    igd.close();
}

// --- PCP probe + mapping test ---

#[tokio::test]
async fn test_pcp_probe_and_mapping() {
    let igd = FakeIgd::start(IgdOpts {
        pcp: true,
        ..Default::default()
    })
    .await;
    let client = make_test_client(&igd);

    let result = client.probe().await.expect("probe");
    assert!(result.pcp, "should detect PCP");
    assert!(!result.pmp);
    assert!(!result.upnp);

    let mapping = client.create_or_get_mapping().await.expect("mapping");
    assert_eq!(mapping.kind, MappingKind::Pcp);
    assert_eq!(mapping.external.port(), 4242);
    assert!(mapping.is_valid());

    client.close();
    igd.close();
}

#[tokio::test]
async fn pcp_map_identity_mismatches_fail_closed() {
    for mutation in [
        PcpMutation::Nonce,
        PcpMutation::Protocol,
        PcpMutation::InternalPort,
        PcpMutation::Source,
    ] {
        let igd = FakeIgd::start(IgdOpts {
            pcp: true,
            pcp_mutation: Some(mutation),
            ..Default::default()
        })
        .await;
        let client = make_test_client(&igd);
        assert!(
            client.create_or_get_mapping().await.is_err(),
            "{mutation:?} response must fail"
        );
        assert!(client.cached_mapping().is_none());
        igd.close();
    }
}

#[tokio::test]
async fn pcp_nonce_is_reused_for_renewal_and_delete() {
    let igd = FakeIgd::start(IgdOpts {
        pcp: true,
        ..Default::default()
    })
    .await;
    let client = make_test_client(&igd);
    let clock = Arc::new(Mutex::new(Instant::now()));
    client.set_test_clock(Box::new({
        let clock = clock.clone();
        move || *clock.lock().unwrap()
    }));

    client.create_or_get_mapping().await.expect("PCP create");
    *clock.lock().unwrap() += Duration::from_secs(3601);
    client.create_or_get_mapping().await.expect("PCP renewal");
    client.close();
    timeout(Duration::from_secs(1), async {
        loop {
            if igd.pcp_nonces.lock().unwrap().len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("PCP deletion");
    let nonces = igd.pcp_nonces.lock().unwrap();
    assert_eq!(nonces.len(), 3);
    assert_ne!(nonces[0], [0; 12]);
    assert!(nonces.iter().all(|nonce| *nonce == nonces[0]));
    igd.close();
}

// --- UPnP probe + mapping test ---

#[tokio::test]
async fn test_upnp_probe_and_mapping() {
    let igd = FakeIgd::start(IgdOpts {
        upnp: true,
        ..Default::default()
    })
    .await;
    let client = make_test_client(&igd);

    let result = client.probe().await.expect("probe");
    assert!(result.upnp, "should detect UPnP");
    assert!(!result.pmp);
    assert!(!result.pcp);

    let mapping = client.create_or_get_mapping().await.expect("mapping");
    assert_eq!(mapping.kind, MappingKind::Upnp);
    assert_eq!(
        mapping.external.ip(),
        std::net::IpAddr::V4(Ipv4Addr::new(123, 123, 123, 123))
    );
    assert!(igd.upnp_add_count.load(Ordering::Relaxed) > 0);

    client.close();
    igd.close();
}

#[tokio::test]
async fn dropped_upnp_caller_is_supervised_through_external_ip_commit() {
    let igd = FakeIgd::start(IgdOpts {
        upnp: true,
        ..Default::default()
    })
    .await;
    let gate = AsyncGate::new();
    igd.gate_external_ip(Some(gate.clone()));
    let client = make_test_client(&igd);
    let caller_client = client.clone();
    let caller = tokio::spawn(async move { caller_client.create_or_get_mapping().await });

    gate.reached.wait().await;
    caller.abort();
    gate.resume.wait().await;

    let mapping = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(mapping) = client.cached_mapping() {
                break mapping;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("supervisor must finish UPnP allocation");
    assert_eq!(mapping.kind, MappingKind::Upnp);
    assert_eq!(igd.upnp_add_count.load(Ordering::SeqCst), 1);

    client.close();
    igd.close();
}

#[tokio::test]
async fn thousands_of_aborted_waiters_share_one_blocked_allocation() {
    let igd = FakeIgd::start(IgdOpts {
        upnp: true,
        ..Default::default()
    })
    .await;
    let gate = AsyncGate::new();
    igd.gate_external_ip(Some(gate.clone()));
    let client = make_test_client(&igd);
    let primary_client = client.clone();
    let primary = tokio::spawn(async move { primary_client.create_or_get_mapping().await });
    gate.reached.wait().await;

    let mut waiters = Vec::new();
    for _ in 0..2_000 {
        let waiter_client = client.clone();
        waiters.push(tokio::spawn(async move {
            waiter_client.create_or_get_mapping().await
        }));
    }
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(client.owned_task_counts().0, 1);
    for waiter in waiters {
        waiter.abort();
    }
    tokio::task::yield_now().await;
    assert_eq!(client.owned_task_counts().0, 1);

    gate.resume.wait().await;
    assert_eq!(primary.await.unwrap().unwrap().kind, MappingKind::Upnp);
    let _ = client.cached_mapping();
    assert_eq!(client.owned_task_counts().0, 0);
    assert_eq!(igd.upnp_add_count.load(Ordering::SeqCst), 1);
    igd.close();
}

#[tokio::test]
async fn ambiguous_upnp_add_is_compensated_before_key_reuse() {
    let igd = FakeIgd::start(IgdOpts {
        upnp: true,
        ..Default::default()
    })
    .await;
    let gate = AsyncGate::new();
    igd.gate_add_mapping(Some(gate.clone()));
    let client = make_test_client(&igd);
    let caller_client = client.clone();
    let caller = tokio::spawn(async move { caller_client.create_or_get_mapping().await });

    gate.reached.wait().await;
    caller.abort();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    igd.gate_add_mapping(None);
    gate.resume.wait().await;
    timeout(Duration::from_secs(2), async {
        loop {
            if igd.upnp_delete_count.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("ambiguous allocation compensation");
    assert!(client.cached_mapping().is_none());

    // Confirmed compensation removes the permanent same-key gate.
    let mapping = client
        .create_or_get_mapping()
        .await
        .expect("safe key reuse");
    assert_eq!(mapping.kind, MappingKind::Upnp);
    client.close();
    igd.close();
}

#[tokio::test]
async fn malformed_permanent_add_never_expires_or_reuses_key() {
    let igd = FakeIgd::start(IgdOpts {
        upnp: true,
        upnp_permanent_malformed: true,
        upnp_delete_fault: true,
        ..Default::default()
    })
    .await;
    let client = make_test_client(&igd);
    assert!(client.create_or_get_mapping().await.is_err());
    let adds = igd.upnp_add_count.load(Ordering::SeqCst);
    assert_eq!(adds, 2, "requested then permanent Add attempts");

    // Even far beyond the finite lease duration, permanent ambiguity remains
    // gated until DeletePortMapping is positively confirmed.
    let clock = Arc::new(Mutex::new(Instant::now() + Duration::from_secs(86_400)));
    client.set_test_clock(Box::new({
        let clock = clock.clone();
        move || *clock.lock().unwrap()
    }));
    assert!(client.create_or_get_mapping().await.is_err());
    assert_eq!(igd.upnp_add_count.load(Ordering::SeqCst), adds);

    igd.set_protocols(true, false, false);
    assert!(client.create_or_get_mapping().await.is_err());
    assert_eq!(
        igd.pmp_map_count.load(Ordering::SeqCst),
        0,
        "uncertain same-key UPnP cleanup must gate protocol switch"
    );
    igd.close();
}

#[tokio::test]
async fn shutdown_cancels_blocked_supervisor_without_late_commit() {
    let igd = FakeIgd::start(IgdOpts {
        upnp: true,
        ..Default::default()
    })
    .await;
    let gate = AsyncGate::new();
    igd.gate_external_ip(Some(gate.clone()));
    let client = make_test_client(&igd);
    let operation_client = client.clone();
    let operation = tokio::spawn(async move { operation_client.create_or_get_mapping().await });
    gate.reached.wait().await;

    let first_client = client.clone();
    let first_shutdown =
        tokio::spawn(async move { first_client.shutdown(Duration::from_millis(50)).await });
    tokio::task::yield_now().await;
    let second_client = client.clone();
    let second_shutdown =
        tokio::spawn(async move { second_client.shutdown(Duration::from_millis(50)).await });
    let third_client = client.clone();
    let third_shutdown =
        tokio::spawn(async move { third_client.shutdown(Duration::from_millis(50)).await });
    first_shutdown.abort();
    let second_error = second_shutdown.await.unwrap().unwrap_err().to_string();
    let third_error = third_shutdown.await.unwrap().unwrap_err().to_string();
    assert_eq!(second_error, third_error);
    gate.resume.wait().await;
    igd.gate_external_ip(None);
    let _ = operation.await;
    assert!(client.cached_mapping().is_none());
    client
        .shutdown(Duration::from_secs(2))
        .await
        .expect("retained allocation cleanup retry");
    assert!(igd.upnp_delete_count.load(Ordering::SeqCst) >= 1);
    igd.close();
}

// --- No services test ---

#[tokio::test]
async fn test_no_services_probe() {
    let igd = FakeIgd::start(IgdOpts::default()).await;
    let client = make_test_client(&igd);

    let result = client.probe().await.expect("probe");
    assert!(!result.any(), "should detect no services");

    let err = client.create_or_get_mapping().await;
    assert!(err.is_err());

    igd.close();
}

// --- Cached mapping test ---

#[tokio::test]
async fn test_cached_mapping_or_start_creating() {
    let igd = FakeIgd::start(IgdOpts {
        pcp: true,
        ..Default::default()
    })
    .await;
    let client = make_test_client(&igd);

    // First call: no cache → (None, false).
    let (ext, ok) = client.get_cached_mapping_or_start_creating_one();
    assert!(!ok);
    assert!(ext.is_none());

    // Probe to populate PCP saw-time, then create a mapping directly.
    let _ = client.probe().await;
    let mapping = client.create_or_get_mapping().await.expect("mapping");
    assert_eq!(mapping.kind, MappingKind::Pcp);

    // Now the cached mapping should be returned.
    let (ext, ok) = client.get_cached_mapping_or_start_creating_one();
    assert!(ok, "should have cached mapping");
    assert_eq!(ext, Some(mapping.external));

    client.close();
    igd.close();
}

// --- Concurrent create calls are singleflight per client ---

async fn assert_concurrent_create_singleflight(opts: IgdOpts, expected: MappingKind) {
    let igd = FakeIgd::start(opts).await;
    let client = make_test_client(&igd);
    let barrier = Arc::new(tokio::sync::Barrier::new(4));
    let mut workers = Vec::new();
    for _ in 0..3 {
        let client = client.clone();
        let barrier = barrier.clone();
        workers.push(tokio::spawn(async move {
            barrier.wait().await;
            client.create_or_get_mapping().await
        }));
    }
    barrier.wait().await;

    let mut mappings = Vec::new();
    for worker in workers {
        mappings.push(worker.await.unwrap().expect("singleflight mapping"));
    }
    assert!(mappings.iter().all(|mapping| mapping.kind == expected));
    assert!(mappings
        .iter()
        .all(|mapping| mapping.external == mappings[0].external));
    match expected {
        MappingKind::Pmp => assert_eq!(igd.pmp_map_count.load(Ordering::SeqCst), 1),
        MappingKind::Pcp => assert_eq!(igd.pcp_map_count.load(Ordering::SeqCst), 1),
        MappingKind::Upnp => assert_eq!(igd.upnp_add_count.load(Ordering::SeqCst), 1),
    }

    client.close();
    igd.close();
}

#[tokio::test]
async fn concurrent_pmp_create_is_singleflight() {
    assert_concurrent_create_singleflight(
        IgdOpts {
            pmp: true,
            ..Default::default()
        },
        MappingKind::Pmp,
    )
    .await;
}

#[tokio::test]
async fn concurrent_pcp_create_is_singleflight() {
    assert_concurrent_create_singleflight(
        IgdOpts {
            pcp: true,
            ..Default::default()
        },
        MappingKind::Pcp,
    )
    .await;
}

#[tokio::test]
async fn concurrent_upnp_create_is_singleflight() {
    assert_concurrent_create_singleflight(
        IgdOpts {
            upnp: true,
            ..Default::default()
        },
        MappingKind::Upnp,
    )
    .await;
}

// --- Gateway change invalidates mappings ---

#[tokio::test]
async fn test_gateway_change_invalidates() {
    let igd = FakeIgd::start(IgdOpts {
        pcp: true,
        ..Default::default()
    })
    .await;
    let client = make_test_client(&igd);

    let _ = client.probe().await;
    let _mapping = client.create_or_get_mapping().await.expect("mapping");
    assert!(client.have_mapping());

    client.set_gateway_lookup(Box::new(|| {
        Some(GatewayInfo {
            gateway: Ipv4Addr::new(127, 0, 0, 2),
            self_ip: Ipv4Addr::new(5, 6, 7, 8),
        })
    }));

    let _ = client.probe().await;
    assert!(
        !client.have_mapping(),
        "mapping should be invalidated after gateway change"
    );

    client.close();
    igd.close();
}

// --- Gateway reappearance forces a complete protocol reprobe ---

async fn assert_gateway_reappearance_reprobes(opts: IgdOpts, expected: MappingKind) {
    let igd = FakeIgd::start(opts).await;
    let client = make_test_client(&igd);

    // Mapping creation itself must perform the initial all-protocol probe.
    let first = client.create_or_get_mapping().await.expect("first mapping");
    assert_eq!(first.kind, expected);

    client.set_gateway_lookup(Box::new(|| None));
    assert_eq!(
        client.get_cached_mapping_or_start_creating_one(),
        (None, false)
    );

    let pmp_before = igd.pmp_recv_count.load(Ordering::SeqCst);
    let pcp_before = igd.pcp_recv_count.load(Ordering::SeqCst);
    let upnp_before = igd.upnp_disco_count.load(Ordering::SeqCst);
    client.set_gateway_lookup(Box::new(|| {
        Some(GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(1, 2, 3, 4),
        })
    }));

    assert_eq!(
        client.get_cached_mapping_or_start_creating_one(),
        (None, false),
        "reappearance must start fresh mapping work"
    );
    let second = timeout(Duration::from_secs(3), async {
        loop {
            if let Some(mapping) = client.cached_mapping() {
                break mapping;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("mapping after gateway reappearance");
    assert_eq!(second.kind, expected);
    assert!(
        igd.pmp_recv_count.load(Ordering::SeqCst) > pmp_before,
        "reappearance must reprobe PMP"
    );
    assert!(
        igd.pcp_recv_count.load(Ordering::SeqCst) > pcp_before,
        "reappearance must reprobe PCP"
    );
    assert!(
        igd.upnp_disco_count.load(Ordering::SeqCst) > upnp_before,
        "reappearance must reprobe UPnP"
    );

    client.close();
    igd.close();
}

#[tokio::test]
async fn pcp_only_gateway_recovers_after_reappearance() {
    assert_gateway_reappearance_reprobes(
        IgdOpts {
            pcp: true,
            ..Default::default()
        },
        MappingKind::Pcp,
    )
    .await;
}

#[tokio::test]
async fn upnp_only_gateway_recovers_after_reappearance() {
    assert_gateway_reappearance_reprobes(
        IgdOpts {
            upnp: true,
            ..Default::default()
        },
        MappingKind::Upnp,
    )
    .await;
}

// --- Identical reappearance waits for old release completion ---

async fn assert_identical_replacement_waits_for_release(opts: IgdOpts, expected: MappingKind) {
    let igd = FakeIgd::start(opts).await;
    let client = make_test_client(&igd);
    let first = client.create_or_get_mapping().await.expect("first mapping");
    assert_eq!(first.kind, expected);

    let gate = ReleaseTestGate::new();
    client.set_test_release_gate(Some(gate.clone()));
    client.set_gateway_lookup(Box::new(|| None));
    assert_eq!(
        client.get_cached_mapping_or_start_creating_one(),
        (None, false)
    );
    gate.wait_reached().await;

    let pmp_maps_before = igd.pmp_map_count.load(Ordering::SeqCst);
    let upnp_adds_before = igd.upnp_add_count.load(Ordering::SeqCst);
    client.set_gateway_lookup(Box::new(|| {
        Some(GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(1, 2, 3, 4),
        })
    }));
    let replacement_client = client.clone();
    let replacement = tokio::spawn(async move { replacement_client.create_or_get_mapping().await });

    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(
        !replacement.is_finished(),
        "replacement bypassed old release"
    );
    assert_eq!(igd.pmp_map_count.load(Ordering::SeqCst), pmp_maps_before);
    assert_eq!(igd.upnp_add_count.load(Ordering::SeqCst), upnp_adds_before);

    gate.resume().await;
    let second = replacement.await.unwrap().expect("replacement mapping");
    assert_eq!(second.kind, expected);
    match expected {
        MappingKind::Pmp => {
            assert_eq!(
                igd.pmp_map_count.load(Ordering::SeqCst),
                pmp_maps_before + 2
            );
        }
        MappingKind::Upnp => {
            assert_eq!(igd.upnp_delete_count.load(Ordering::SeqCst), 1);
            assert_eq!(
                igd.upnp_add_count.load(Ordering::SeqCst),
                upnp_adds_before + 1
            );
        }
        MappingKind::Pcp => unreachable!(),
    }

    client.set_test_release_gate(None);
    client.close();
    igd.close();
}

#[tokio::test]
async fn identical_pmp_mapping_waits_for_delayed_delete() {
    assert_identical_replacement_waits_for_release(
        IgdOpts {
            pmp: true,
            ..Default::default()
        },
        MappingKind::Pmp,
    )
    .await;
}

#[tokio::test]
async fn identical_upnp_mapping_waits_for_delayed_delete() {
    assert_identical_replacement_waits_for_release(
        IgdOpts {
            upnp: true,
            ..Default::default()
        },
        MappingKind::Upnp,
    )
    .await;
}

// --- Trust-expired renewals force a complete protocol reprobe ---

async fn assert_trust_expiry_reprobes(opts: IgdOpts, expected: MappingKind) {
    let igd = FakeIgd::start(opts).await;
    let client = make_test_client(&igd);
    let clock = Arc::new(Mutex::new(Instant::now()));
    client.set_test_clock(Box::new({
        let clock = clock.clone();
        move || *clock.lock().unwrap()
    }));

    let first = client.create_or_get_mapping().await.expect("first mapping");
    assert_eq!(first.kind, expected);

    let pmp_before = igd.pmp_recv_count.load(Ordering::SeqCst);
    let pcp_before = igd.pcp_recv_count.load(Ordering::SeqCst);
    let upnp_before = igd.upnp_disco_count.load(Ordering::SeqCst);
    *clock.lock().unwrap() += Duration::from_secs(3601);

    let renewed = client
        .create_or_get_mapping()
        .await
        .expect("mapping renewal after trust expiry");
    assert_eq!(renewed.kind, expected);
    assert!(
        igd.pmp_recv_count.load(Ordering::SeqCst) > pmp_before,
        "trust expiry must reprobe PMP (before={pmp_before}, after={})",
        igd.pmp_recv_count.load(Ordering::SeqCst)
    );
    assert!(
        igd.pcp_recv_count.load(Ordering::SeqCst) > pcp_before,
        "trust expiry must reprobe PCP"
    );
    assert!(
        igd.upnp_disco_count.load(Ordering::SeqCst) > upnp_before,
        "trust expiry must reprobe UPnP"
    );

    client.close();
    igd.close();
}

#[tokio::test]
async fn pcp_only_mapping_renews_after_trust_expiry() {
    assert_trust_expiry_reprobes(
        IgdOpts {
            pcp: true,
            ..Default::default()
        },
        MappingKind::Pcp,
    )
    .await;
}

#[tokio::test]
async fn upnp_only_mapping_renews_after_trust_expiry() {
    assert_trust_expiry_reprobes(
        IgdOpts {
            upnp: true,
            ..Default::default()
        },
        MappingKind::Upnp,
    )
    .await;
}

#[tokio::test]
async fn protocol_switch_releases_old_mapping_before_replacement() {
    let igd = FakeIgd::start(IgdOpts {
        pcp: true,
        ..Default::default()
    })
    .await;
    let client = make_test_client(&igd);
    let clock = Arc::new(Mutex::new(Instant::now()));
    client.set_test_clock(Box::new({
        let clock = clock.clone();
        move || *clock.lock().unwrap()
    }));
    let first = client.create_or_get_mapping().await.expect("PCP mapping");
    assert_eq!(first.kind, MappingKind::Pcp);

    igd.set_protocols(true, false, false);
    *clock.lock().unwrap() += Duration::from_secs(3601);
    let switch_started = Instant::now();
    assert!(client.create_or_get_mapping().await.is_err());
    assert!(
        switch_started.elapsed() >= crate::PROBE_TIMEOUT,
        "PCP deletion confirmation must be attempted"
    );
    assert_eq!(igd.pcp_map_count.load(Ordering::SeqCst), 2);
    assert_eq!(
        igd.pmp_map_count.load(Ordering::SeqCst),
        0,
        "unconfirmed same-key PCP cleanup must gate PMP replacement"
    );
    assert!(client.cached_mapping().is_none());

    client.close();
    igd.close();
}

#[tokio::test]
async fn upnp_service_switch_releases_old_service_before_replacement() {
    let igd_a = FakeIgd::start(IgdOpts {
        upnp: true,
        ..Default::default()
    })
    .await;
    let client = make_test_client(&igd_a);
    let clock = Arc::new(Mutex::new(Instant::now()));
    client.set_test_clock(Box::new({
        let clock = clock.clone();
        move || *clock.lock().unwrap()
    }));
    client.create_or_get_mapping().await.expect("service A");

    let igd_b = FakeIgd::start(IgdOpts {
        upnp: true,
        ..Default::default()
    })
    .await;
    client.set_test_pxp_port(igd_b.pxp_port());
    client.set_test_upnp_port(igd_b.upnp_port());
    *clock.lock().unwrap() += Duration::from_secs(3601);
    let replacement = client.create_or_get_mapping().await.expect("service B");
    assert_eq!(replacement.kind, MappingKind::Upnp);
    assert_eq!(igd_a.upnp_delete_count.load(Ordering::SeqCst), 1);
    assert_eq!(igd_b.upnp_add_count.load(Ordering::SeqCst), 1);

    client.close();
    igd_a.close();
    igd_b.close();
}

// --- Real gateway probe test (marked #[ignore]) ---

#[tokio::test]
#[ignore = "requires LAN portmapper"]
async fn test_real_gateway_probe() {
    let client = Client::new();
    client.set_local_port(12345);
    if let Ok(r) = client.probe().await {
        eprintln!("probe result: pmp={} pcp={} upnp={}", r.pmp, r.pcp, r.upnp);
    }
}
