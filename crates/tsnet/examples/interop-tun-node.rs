//! interop-tun-node — one node of the out-of-process TUN repro.
//!
//! The corrected privileged TUN parity gate: the in-process repro
//! (`tests::interop_tun_rust_dials_go`) succeeds even though the failure
//! mode only appears when the data-plane endpoints live in *separate*
//! processes, like the benchmark harness. This binary is one half of that
//! split. `tools/interop-tun-oops.sh` runs two copies under sudo:
//!
//! 1. `interop-tun-node server` — brings up a rustscale node in TUN mode,
//!    asserts the Linux kernel state (ifindex/flags/MTU, policy rules,
//!    table-52 routes), then echoes on a TCP and a UDP socket bound to its
//!    tailnet IP until one full TCP session completes.
//! 2. `interop-tun-node client` — a second rustscale node in TUN mode in a
//!    separate process, with its own TUN device and kernel-state assertions.
//!    It waits for the server in its netmap, exchanges cadenced UDP
//!    datagrams (issue #75 shape) and a TCP payload through the kernel/TUN
//!    path, then closes its write side so the server exits cleanly.
//!
//! Every line is timestamped and role-tagged; the driver captures full logs
//! from both processes and requires the structured `OOPS_*` markers. Any
//! failure exits non-zero — this binary only runs inside the privileged
//! harness, so there is no skip path.
//!
//! # Usage
//!
//! ```sh
//! sudo interop-tun-node server --authkey-file /run/oops-auth --hostname rs-oops-s \
//!   --state-dir /tmp/oops-s --tun-name tun0 --port 18282 --udp-port 18283 \
//!   --ready-fifo /tmp/oops-ready --peer-ready-fifo /tmp/oops-peer-ready
//! sudo interop-tun-node client --authkey-file /run/oops-auth --hostname rs-oops-c \
//!   --state-dir /tmp/oops-c --tun-name tun0 --peer 100.64.0.1 \
//!   --port 18282 --udp-port 18283 --peer-ready-fifo /tmp/oops-peer-ready
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use rustscale_tsnet::{Server, TunModeConfig};
use rustscale_tun::TunConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Tailnet MTU, matching the kernel-state contract in the test suite.
const MTU: usize = 1280;
/// Number of cadenced UDP datagrams the client exchanges with the server.
const UDP_DATAGRAMS: u32 = 10;
/// Spacing between client UDP sends (issue #75 cadence shape).
const UDP_CADENCE: Duration = Duration::from_millis(200);
/// Per-datagram echo deadline.
const UDP_ECHO_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded number of kernel/TUN UDP probes allowed for control-plane endpoint
/// propagation before the cadenced workload begins. A peer IP in the netmap
/// can precede its freshly announced local UDP endpoint, so a single first
/// application datagram is not a valid direct-path readiness signal.
const UDP_DIRECT_PROBE_ATTEMPTS: u32 = 12;
/// Deadline for the peer to appear in the client netmap.
const PEER_DEADLINE: Duration = Duration::from_secs(90);
/// Deadline for a tailnet IPv4 address after `up_tun` returns.
const IP_DEADLINE: Duration = Duration::from_secs(90);
/// Server-side deadline for the client's TCP connection after READY.
const ACCEPT_DEADLINE: Duration = Duration::from_secs(240);
/// Idle deadline inside the TCP echo session.
const TCP_IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Server,
    Client,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Server => "server",
            Role::Client => "client",
        }
    }
}

struct Args {
    role: Role,
    authkey: Option<String>,
    authkey_file: Option<String>,
    hostname: String,
    state_dir: String,
    tun_name: String,
    tcp_port: u16,
    udp_port: u16,
    peer: Option<Ipv4Addr>,
    ready_fifo: Option<String>,
    peer_ready_fifo: Option<String>,
    phase_fifo: Option<String>,
}

impl Args {
    /// Read the auth key only from its protected file when requested, keeping
    /// live ephemeral credentials out of process command lines and logs.
    fn auth_key(&self) -> Result<String, Box<dyn std::error::Error>> {
        match (&self.authkey, &self.authkey_file) {
            (Some(_), Some(_)) => Err("--authkey and --authkey-file are mutually exclusive".into()),
            (Some(key), None) if !key.is_empty() => Ok(key.clone()),
            (None, Some(path)) => {
                let key = std::fs::read_to_string(path)?.trim().to_owned();
                if key.is_empty() {
                    Err(format!("auth key file {path:?} is empty").into())
                } else {
                    Ok(key)
                }
            }
            _ => Err("--authkey or --authkey-file is required".into()),
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: interop-tun-node <server|client> (--authkey K|--authkey-file F) --hostname H \
         --state-dir D --tun-name N [--port P] [--udp-port U] [--peer V4] [--ready-fifo F] \
         [--peer-ready-fifo F] [--phase-fifo F]"
    );
    std::process::exit(2);
}

fn take_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> &'a str {
    *i += 1;
    if *i >= args.len() {
        eprintln!("missing value for {flag}");
        usage();
    }
    &args[*i]
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let role = match args[0].as_str() {
        "server" => Role::Server,
        "client" => Role::Client,
        _ => usage(),
    };
    let mut parsed = Args {
        role,
        authkey: None,
        authkey_file: None,
        hostname: String::new(),
        state_dir: String::new(),
        tun_name: String::new(),
        tcp_port: 18282,
        udp_port: 18283,
        peer: None,
        ready_fifo: None,
        peer_ready_fifo: None,
        phase_fifo: None,
    };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--authkey" => {
                parsed.authkey = Some(take_value(&args, &mut i, "--authkey").to_string());
            }
            "--authkey-file" => {
                parsed.authkey_file = Some(take_value(&args, &mut i, "--authkey-file").to_string());
            }
            "--hostname" => parsed.hostname = take_value(&args, &mut i, "--hostname").to_string(),
            "--state-dir" => {
                parsed.state_dir = take_value(&args, &mut i, "--state-dir").to_string();
            }
            "--tun-name" => parsed.tun_name = take_value(&args, &mut i, "--tun-name").to_string(),
            "--port" => {
                parsed.tcp_port = take_value(&args, &mut i, "--port")
                    .parse()
                    .unwrap_or_else(|_| usage());
            }
            "--udp-port" => {
                parsed.udp_port = take_value(&args, &mut i, "--udp-port")
                    .parse()
                    .unwrap_or_else(|_| usage());
            }
            "--peer" => {
                parsed.peer = Some(
                    take_value(&args, &mut i, "--peer")
                        .parse()
                        .unwrap_or_else(|_| usage()),
                );
            }
            "--ready-fifo" => {
                parsed.ready_fifo = Some(take_value(&args, &mut i, "--ready-fifo").to_string());
            }
            "--peer-ready-fifo" => {
                parsed.peer_ready_fifo =
                    Some(take_value(&args, &mut i, "--peer-ready-fifo").to_string());
            }
            "--phase-fifo" => {
                parsed.phase_fifo = Some(take_value(&args, &mut i, "--phase-fifo").to_string());
            }
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
        i += 1;
    }
    if parsed.hostname.is_empty() || parsed.state_dir.is_empty() || parsed.tun_name.is_empty() {
        eprintln!("--hostname, --state-dir, and --tun-name are required");
        usage();
    }
    if parsed.authkey.is_some() == parsed.authkey_file.is_some() {
        eprintln!("exactly one of --authkey or --authkey-file is required");
        usage();
    }
    if parsed.role == Role::Client && parsed.peer.is_none() {
        eprintln!("client role requires --peer");
        usage();
    }
    if parsed.role == Role::Server && parsed.ready_fifo.is_none() {
        eprintln!("server role requires --ready-fifo");
        usage();
    }
    if parsed.role == Role::Client && parsed.ready_fifo.is_some() {
        eprintln!("client role must not receive --ready-fifo");
        usage();
    }
    if parsed.peer_ready_fifo.is_none() {
        eprintln!("--peer-ready-fifo is required");
        usage();
    }
    if parsed.role == Role::Server && parsed.phase_fifo.is_some() {
        eprintln!("server role must not receive --phase-fifo");
        usage();
    }
    parsed
}

/// Timestamped, role-tagged structured evidence line.
fn line(start: Instant, role: Role, msg: &str) {
    eprintln!(
        "{:>9}ms [{}] {msg}",
        start.elapsed().as_millis(),
        role.as_str()
    );
}

/// Notify the harness only after the server has a tailnet-bound listener.
/// A FIFO gives a bounded blocking handoff without a readiness polling loop.
fn signal_ready(path: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let mut fifo = std::fs::OpenOptions::new().write(true).open(path)?;
    writeln!(fifo, "{message}")?;
    Ok(())
}

/// Minimal stderr logger so the tsnet/magicsock internals appear in the
/// captured logs. Level defaults to debug, overridable via OOPS_LOG_LEVEL.
struct StderrLogger {
    start: Instant,
    role: Role,
}

impl log::Log for StderrLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        eprintln!(
            "{:>9}ms [{}] {:5} {}: {}",
            self.start.elapsed().as_millis(),
            self.role.as_str(),
            record.level(),
            record.target(),
            record.args()
        );
    }

    fn flush(&self) {}
}

fn init_logger(start: Instant, role: Role) {
    let level = match std::env::var("OOPS_LOG_LEVEL").as_deref() {
        Ok("trace") => log::LevelFilter::Trace,
        Ok("info") => log::LevelFilter::Info,
        Ok("warn") => log::LevelFilter::Warn,
        Ok("error") => log::LevelFilter::Error,
        _ => log::LevelFilter::Debug,
    };
    log::set_boxed_logger(Box::new(StderrLogger { start, role })).expect("logger installs once");
    log::set_max_level(level);
}

fn command_output(program: &str, args: &[&str], assertion: &str) -> String {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("{assertion}: failed to run {program} {args:?}: {error}"));
    assert!(
        output.status.success(),
        "{assertion}: {program} {args:?} failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("{assertion}: command output was not UTF-8: {error}"))
}

/// Assert the same Linux kernel contract as `tests::interop_tun_rust_dials_go`
/// and return the interface index for evidence logging.
#[cfg(target_os = "linux")]
fn assert_kernel_state(tun_name: &str, expected_mtu: usize) -> u32 {
    let sysfs = std::path::Path::new("/sys/class/net").join(tun_name);
    let read_sysfs = |field: &str| {
        std::fs::read_to_string(sysfs.join(field)).unwrap_or_else(|error| {
            panic!("real TUN gate: failed to read {tun_name} {field}: {error}")
        })
    };

    let ifindex = read_sysfs("ifindex")
        .trim()
        .parse::<u32>()
        .expect("real TUN gate: interface index must be numeric");
    assert_ne!(ifindex, 0, "real TUN gate: interface index must be nonzero");

    let flags_text = read_sysfs("flags");
    let flags = u32::from_str_radix(flags_text.trim().trim_start_matches("0x"), 16)
        .expect("real TUN gate: interface flags must be hexadecimal");
    assert_ne!(
        flags & 1,
        0,
        "real TUN gate: {tun_name} must have IFF_UP set (flags={flags_text:?})"
    );

    let mtu = read_sysfs("mtu")
        .trim()
        .parse::<usize>()
        .expect("real TUN gate: interface MTU must be numeric");
    assert_eq!(
        mtu, expected_mtu,
        "real TUN gate: kernel MTU for {tun_name} does not match the configured MTU"
    );

    let rules = command_output(
        "ip",
        &["-4", "-details", "rule", "show"],
        "real TUN gate policy rules",
    );
    let base = 5_000 + (ifindex % 200) * 100;
    for (preference, target) in [
        (base + 10, "lookup main"),
        (base + 30, "lookup default"),
        (base + 50, "unreachable"),
        (base + 70, "lookup 52"),
    ] {
        let prefix = format!("{preference}:");
        let rule = rules
            .lines()
            .find(|line| line.split_whitespace().next() == Some(prefix.as_str()))
            .unwrap_or_else(|| {
                panic!(
                    "real TUN gate: missing IPv4 policy rule at preference {preference}\n{rules}"
                )
            });
        assert!(
            rule.contains("proto 201"),
            "real TUN gate: rule {preference} is not protocol 201: {rule}"
        );
        assert!(
            rule.contains(target),
            "real TUN gate: rule {preference} does not select {target}: {rule}"
        );
    }

    let routes = command_output(
        "ip",
        &["-4", "route", "show", "table", "52"],
        "real TUN gate table 52 routes",
    );
    let tailnet_route = routes.lines().find(|line| {
        line.split_whitespace().next() == Some("100.64.0.0/10")
            && line.contains(&format!("dev {tun_name}"))
    });
    assert!(
        tailnet_route.is_some(),
        "real TUN gate: table 52 is missing 100.64.0.0/10 via {tun_name}\n{routes}"
    );
    assert!(
        routes.lines().any(|line| {
            line.split_whitespace().next() == Some("100.100.100.100")
                && line.contains(&format!("dev {tun_name}"))
        }),
        "real TUN gate: table 52 is missing the MagicDNS service route via {tun_name}\n{routes}"
    );

    ifindex
}

#[cfg(not(target_os = "linux"))]
fn assert_kernel_state(_tun_name: &str, _expected_mtu: usize) -> u32 {
    panic!("the out-of-process TUN repro only runs on Linux");
}

#[cfg(target_os = "linux")]
fn tun_counters(tun_name: &str) -> (u64, u64) {
    let statistics = std::path::Path::new("/sys/class/net")
        .join(tun_name)
        .join("statistics");
    let read_counter = |field: &str| {
        std::fs::read_to_string(statistics.join(field))
            .unwrap_or_else(|error| {
                panic!("real TUN gate: cannot read {tun_name} {field}: {error}")
            })
            .trim()
            .parse::<u64>()
            .unwrap_or_else(|error| panic!("real TUN gate: invalid {tun_name} {field}: {error}"))
    };
    (read_counter("rx_bytes"), read_counter("tx_bytes"))
}

#[cfg(not(target_os = "linux"))]
fn tun_counters(_tun_name: &str) -> (u64, u64) {
    panic!("the out-of-process TUN repro only runs on Linux");
}

/// Verify that an ordinary socket's destination lookup selects this endpoint's
/// TUN. Kernel route existence alone is insufficient evidence of the path.
fn assert_tun_route(tun_name: &str, peer: Ipv4Addr, local: Ipv4Addr) -> String {
    let destination = peer.to_string();
    let route = command_output(
        "ip",
        &["-4", "route", "get", &destination],
        "real TUN gate route lookup",
    );
    assert!(
        route.lines().any(|line| {
            line.contains(&format!("dev {tun_name}")) && line.contains(&format!("src {local}"))
        }),
        "real TUN gate: route to {peer} must select {tun_name} with node source {local}: {route}"
    );
    assert!(
        !route.contains("src 100.100.100.100"),
        "real TUN gate: MagicDNS service VIP contaminated peer source selection: {route}"
    );
    route.trim().to_owned()
}

fn assert_tun_traffic(role: Role, start: Instant, tun_name: &str, before: (u64, u64)) {
    let after = tun_counters(tun_name);
    assert!(
        after.0 > before.0 && after.1 > before.1,
        "real TUN gate: {} traffic did not cross both directions of {tun_name} \
         (rx {}->{}, tx {}->{})",
        role.as_str(),
        before.0,
        after.0,
        before.1,
        after.1,
    );
    line(
        start,
        role,
        &format!(
            "OOPS_{}_TUN_TRAFFIC dev={tun_name} rx_before={} rx_after={} tx_before={} tx_after={}",
            role.as_str().to_uppercase(),
            before.0,
            after.0,
            before.1,
            after.1,
        ),
    );
}

/// Bring the node up in TUN mode with OS routes applied and assert the
/// kernel contract. Returns the server's tailnet IPv4 address.
async fn up_tun_node(
    args: &Args,
    start: Instant,
) -> Result<(Server, Ipv4Addr), Box<dyn std::error::Error>> {
    let mut server = Server::builder()
        .hostname(args.hostname.clone())
        .auth_key(args.auth_key()?)
        .ephemeral(true)
        .disable_portmapping(true)
        .state_dir(std::path::PathBuf::from(&args.state_dir))
        .localapi_path(std::path::PathBuf::from(&args.state_dir).join("localapi.sock"))
        .build()?;

    let tun = TunConfig {
        name: args.tun_name.clone(),
        mtu: MTU,
    };
    Box::pin(server.up_tun(TunModeConfig {
        tun: tun.clone(),
        apply_routes: true,
        exit_node: None,
    }))
    .await?;
    line(
        start,
        args.role,
        &format!("up_tun complete: dev={} mtu={MTU}", tun.name),
    );

    let ifindex = assert_kernel_state(&tun.name, tun.mtu);
    line(
        start,
        args.role,
        &format!(
            "OOPS_KERNEL_OK role={} dev={} ifindex={ifindex} mtu={MTU} table=52 tailnet_route=100.64.0.0/10",
            args.role.as_str(),
            tun.name
        ),
    );

    // up_tun returns once the device and control channel exist, but the
    // tailnet address can still be settling. Poll status for our IPv4.
    let deadline = Instant::now() + IP_DEADLINE;
    loop {
        let status = server.status();
        if let Some(v4) = status.tailscale_ips.iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        }) {
            let tun_addrs = command_output(
                "ip",
                &["-4", "-o", "addr", "show", "dev", &tun.name],
                "real TUN gate node address ownership",
            );
            assert!(
                tun_addrs.contains(&format!("inet {v4}/32")),
                "real TUN gate: node address {v4}/32 is missing from {}: {tun_addrs}",
                tun.name
            );
            assert!(
                !tun_addrs.contains("100.100.100.100"),
                "real TUN gate: MagicDNS service VIP is incorrectly owned by {}: {tun_addrs}",
                tun.name
            );
            let loopback_addrs = command_output(
                "ip",
                &["-4", "-o", "addr", "show", "dev", "lo"],
                "real TUN gate MagicDNS loopback ownership",
            );
            assert!(
                loopback_addrs.contains("inet 100.100.100.100/32"),
                "real TUN gate: loopback does not own MagicDNS service VIP: {loopback_addrs}"
            );
            line(
                start,
                args.role,
                &format!(
                    "OOPS_SOURCE_OWNERSHIP_OK role={} node={v4} dev={} magicdns=100.100.100.100 dev=lo",
                    args.role.as_str(),
                    tun.name
                ),
            );
            return Ok((server, v4));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no tailnet IPv4 address within {}s (up={} ips={:?})",
                IP_DEADLINE.as_secs(),
                status.up,
                status.tailscale_ips
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Wait until this endpoint's own control view contains exactly one IPv4 peer.
/// The protected harness creates a fresh two-node tailnet, so this proves the
/// reverse netmap publication boundary instead of relying on repeated data
/// probes to infer whether the server has learned the client.
async fn wait_for_single_ipv4_peer(
    server: &Server,
    start: Instant,
    role: Role,
) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + PEER_DEADLINE;
    loop {
        let status = server.status();
        let peers: Vec<Ipv4Addr> = status
            .peers
            .iter()
            .flat_map(|peer| peer.ips.iter())
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .collect();
        match peers.as_slice() {
            [peer] => {
                line(start, role, &format!("OOPS_SERVER_PEER_OK ip={peer}"));
                return Ok(*peer);
            }
            [] if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            [] => {
                return Err(format!(
                    "server control view remained empty for {}s",
                    PEER_DEADLINE.as_secs()
                )
                .into());
            }
            _ => {
                return Err(format!(
                    "fresh two-node tailnet exposed multiple IPv4 peers to server: {peers:?}"
                )
                .into());
            }
        }
    }
}

async fn run_server(args: &Args, start: Instant) -> Result<(), Box<dyn std::error::Error>> {
    let (mut server, v4) = up_tun_node(args, start).await?;
    let tun_before = tun_counters(&args.tun_name);

    let listener = tokio::time::timeout(
        Duration::from_secs(10),
        TcpListener::bind((v4, args.tcp_port)),
    )
    .await??;
    let udp = UdpSocket::bind((v4, args.udp_port)).await?;
    let ready = format!(
        "OOPS_SERVER_READY ip={v4} tcp={} udp={}",
        args.tcp_port, args.udp_port
    );
    line(start, args.role, &ready);
    signal_ready(
        args.ready_fifo
            .as_deref()
            .ok_or("server role requires --ready-fifo")?,
        &ready,
    )?;

    // Do not let the client infer reverse control-plane publication from a
    // series of dropped application packets. Rendezvous only after the server
    // itself sees the client's IPv4 identity, then admit the real TUN probes.
    let client_ip = wait_for_single_ipv4_peer(&server, start, args.role).await?;
    let peer_ready_fifo = args
        .peer_ready_fifo
        .clone()
        .ok_or("server role requires --peer-ready-fifo")?;
    tokio::task::spawn_blocking(move || {
        signal_ready(
            &peer_ready_fifo,
            &format!("OOPS_SERVER_PEER_OK ip={client_ip}"),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("server peer-ready handoff task failed: {error}"))??;

    // UDP echo loop: one evidence line per datagram until aborted.
    let udp_start = start;
    let udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match udp.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    let payload = String::from_utf8_lossy(&buf[..n]);
                    let marker = if payload.starts_with("interop-tun-oops-direct-probe ") {
                        "OOPS_SERVER_DIRECT_PROBE_ECHO"
                    } else {
                        "OOPS_SERVER_UDP_ECHO"
                    };
                    line(
                        udp_start,
                        Role::Server,
                        &format!("{marker} src={src} bytes={n} payload={payload:?}"),
                    );
                    if udp.send_to(&buf[..n], src).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    line(udp_start, Role::Server, &format!("UDP recv error: {error}"));
                    break;
                }
            }
        }
    });

    // Exactly one TCP echo session; EOF from the client ends the repro.
    let (mut stream, peer) = tokio::time::timeout(ACCEPT_DEADLINE, listener.accept())
        .await
        .map_err(|_| "client never connected before the accept deadline")??;
    line(
        start,
        args.role,
        &format!("OOPS_SERVER_TCP_ACCEPT peer={peer}"),
    );
    let peer_v4 = match peer.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err("server accepted a non-IPv4 tailnet peer".into()),
    };
    let route = assert_tun_route(&args.tun_name, peer_v4, v4);
    line(
        start,
        args.role,
        &format!("OOPS_SERVER_TUN_ROUTE peer={peer_v4} route={route}"),
    );
    let mut total = 0_u64;
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(TCP_IO_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                stream.write_all(&buf[..n]).await?;
                total += n as u64;
            }
            Ok(Err(error)) => return Err(format!("TCP read failed: {error}").into()),
            Err(_) => return Err("TCP echo session stalled".into()),
        }
    }
    line(
        start,
        args.role,
        &format!("OOPS_SERVER_TCP_DONE bytes={total}"),
    );
    assert_tun_traffic(args.role, start, &args.tun_name, tun_before);

    udp_task.abort();
    server.close().await?;
    line(start, args.role, "OOPS_SERVER_DONE");
    Ok(())
}

/// Wait for the server peer to appear in the client netmap.
async fn wait_for_peer(
    server: &Server,
    peer: Ipv4Addr,
    start: Instant,
    role: Role,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = IpAddr::V4(peer);
    let deadline = Instant::now() + PEER_DEADLINE;
    loop {
        let status = server.status();
        if status.peers.iter().any(|p| p.ips.contains(&target)) {
            line(start, role, &format!("OOPS_CLIENT_PEER_OK ip={peer}"));
            return Ok(());
        }
        if Instant::now() >= deadline {
            let peers: Vec<String> = status
                .peers
                .iter()
                .map(|p| format!("  {} ips={:?} path={:?}", p.name, p.ips, p.path_class))
                .collect();
            return Err(format!(
                "peer {peer} never appeared in netmap after {}s\ncurrent peers ({}):\n{}",
                PEER_DEADLINE.as_secs(),
                peers.len(),
                peers.join("\n")
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn run_client(args: &Args, start: Instant) -> Result<(), Box<dyn std::error::Error>> {
    let peer = args.peer.ok_or("client role requires --peer")?;
    let (mut server, v4) = up_tun_node(args, start).await?;

    wait_for_peer(&server, peer, start, args.role).await?;
    let tun_before = tun_counters(&args.tun_name);
    let route = assert_tun_route(&args.tun_name, peer, v4);
    line(
        start,
        args.role,
        &format!("OOPS_CLIENT_TUN_ROUTE peer={peer} route={route}"),
    );

    let peer_ready_fifo = args
        .peer_ready_fifo
        .clone()
        .ok_or("client role requires --peer-ready-fifo")?;
    let reverse_ready =
        tokio::task::spawn_blocking(move || std::fs::read_to_string(peer_ready_fifo))
            .await
            .map_err(|error| format!("reverse peer-ready handoff task failed: {error}"))??;
    let expected_reverse = format!("OOPS_SERVER_PEER_OK ip={v4}");
    if reverse_ready.trim() != expected_reverse {
        return Err(format!(
            "server learned unexpected reverse peer: expected {expected_reverse:?}, got {:?}",
            reverse_ready.trim()
        )
        .into());
    }
    line(start, args.role, "OOPS_CLIENT_REVERSE_PEER_READY");

    // A peer can be published to the netmap before the control plane has
    // relayed its recently announced namespace-local UDP endpoint. Establish
    // transport readiness with bounded real TUN probes rather than accepting a
    // path enum or a delay as proof. Every attempt uses the same application
    // socket and a finite echo deadline; only an echoed payload admits the
    // subsequent fixed-cadence workload.
    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    udp.connect((peer, args.udp_port)).await?;
    let mut direct_ready = false;
    for attempt in 1..=UDP_DIRECT_PROBE_ATTEMPTS {
        let payload = format!("interop-tun-oops-direct-probe attempt={attempt}");
        udp.send(payload.as_bytes()).await?;
        let deadline = Instant::now() + UDP_ECHO_TIMEOUT;
        loop {
            let mut buf = [0u8; 2048];
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, udp.recv(&mut buf)).await {
                Ok(Ok(n)) if buf[..n] == *payload.as_bytes() => {
                    line(
                        start,
                        args.role,
                        &format!("OOPS_CLIENT_DIRECT_PROBE_OK attempt={attempt}"),
                    );
                    direct_ready = true;
                    break;
                }
                Ok(Ok(n))
                    if String::from_utf8_lossy(&buf[..n])
                        .starts_with("interop-tun-oops-direct-probe attempt=") =>
                {
                    // A timed-out probe can still be echoed after the next
                    // attempt is sent. Drain that authenticated application
                    // echo within this attempt's original deadline rather
                    // than mistaking ordinary UDP reordering for corruption.
                    line(
                        start,
                        args.role,
                        &format!("OOPS_CLIENT_DIRECT_PROBE_STALE attempt={attempt}"),
                    );
                }
                Ok(Ok(n)) => {
                    return Err(format!(
                        "UDP direct probe mismatch attempt={attempt}: sent {payload:?}, got {:?}",
                        String::from_utf8_lossy(&buf[..n])
                    )
                    .into());
                }
                Ok(Err(error)) => return Err(format!("UDP direct probe failed: {error}").into()),
                Err(_) => {
                    line(
                        start,
                        args.role,
                        &format!("OOPS_CLIENT_DIRECT_PROBE_TIMEOUT attempt={attempt}"),
                    );
                    break;
                }
            }
        }
        if direct_ready {
            break;
        }
    }
    if !direct_ready {
        return Err(format!(
            "UDP direct readiness was not established after {UDP_DIRECT_PROBE_ATTEMPTS} bounded probes"
        )
        .into());
    }

    // UDP cadence exchange (issue #75 traffic shape): fixed-spacing
    // datagrams, each echoed by the server process across the TUN boundary.
    for i in 0..UDP_DATAGRAMS {
        let payload = format!("interop-tun-oops-udp seq={i}");
        let sent = Instant::now();
        udp.send(payload.as_bytes()).await?;
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(UDP_ECHO_TIMEOUT, udp.recv(&mut buf))
            .await
            .map_err(|_| format!("UDP echo seq={i} timed out"))??;
        if buf[..n] != *payload.as_bytes() {
            return Err(format!(
                "UDP echo mismatch seq={i}: sent {payload:?}, got {:?}",
                String::from_utf8_lossy(&buf[..n])
            )
            .into());
        }
        line(
            start,
            args.role,
            &format!(
                "OOPS_CLIENT_UDP_SEQ i={i} rtt_ms={}",
                sent.elapsed().as_millis()
            ),
        );
        tokio::time::sleep(UDP_CADENCE).await;
    }
    line(
        start,
        args.role,
        &format!("OOPS_CLIENT_UDP_ROUNDTRIP_OK count={UDP_DATAGRAMS}"),
    );

    // Keep the endpoint alive while the parent obtains public CLI/LocalAPI
    // evidence, blocks only the namespace-local direct underlay, exercises an
    // authenticated DERP ping, and waits for freshness expiry. The FIFO is
    // optional for direct local invocations; the protected gate always uses it.
    if let Some(path) = args.phase_fifo.clone() {
        line(start, args.role, "OOPS_CLIENT_PATH_EVIDENCE_READY");
        tokio::task::spawn_blocking(move || std::fs::read_to_string(path))
            .await
            .map_err(|error| format!("path phase handoff task failed: {error}"))??;
        line(start, args.role, "OOPS_CLIENT_PATH_EVIDENCE_DONE");
    }

    // TCP roundtrip through the kernel/TUN path. The server readiness FIFO
    // makes retries unnecessary: a failed first dial is a failed workload.
    let dial = (peer, args.tcp_port);
    let mut stream = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(dial))
        .await
        .map_err(|_| "OS connect to server echo timed out")??;

    let payload = b"interop-tun-oops-tcp-payload";
    stream.write_all(payload).await?;
    let mut got = vec![0_u8; payload.len()];
    tokio::time::timeout(TCP_IO_TIMEOUT, stream.read_exact(&mut got))
        .await
        .map_err(|_| "TCP echo read timed out")??;
    if got != payload {
        return Err("TCP echo mismatch through TUN".into());
    }
    line(
        start,
        args.role,
        &format!("OOPS_CLIENT_TCP_ROUNDTRIP_OK bytes={}", payload.len()),
    );
    assert_tun_traffic(args.role, start, &args.tun_name, tun_before);
    // EOF lets the server end its session and exit 0.
    stream.shutdown().await?;

    server.close().await?;
    line(start, args.role, "OOPS_CLIENT_DONE");
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let start = Instant::now();
    let args = parse_args();
    init_logger(start, args.role);
    line(
        start,
        args.role,
        &format!(
            "starting out-of-process TUN repro node: hostname={} tun={} pid={}",
            args.hostname,
            args.tun_name,
            std::process::id()
        ),
    );
    let result = match args.role {
        Role::Server => run_server(&args, start).await,
        Role::Client => run_client(&args, start).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            line(
                start,
                args.role,
                &format!("OOPS_FATAL role={} error={error}", args.role.as_str()),
            );
            ExitCode::FAILURE
        }
    }
}
