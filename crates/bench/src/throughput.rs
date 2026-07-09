//! Throughput client: dial a rustscale-bench server and measure TCP throughput.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustscale_netstack::NetstackStream;
use rustscale_tsnet::{Server, ServerStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{
    read_ack, write_header, Header, DIR_BIDIR, DIR_DOWN, DIR_UP, FIREHOSE_BUF_SIZE,
    MODE_THROUGHPUT, READ_BUF_SIZE,
};

pub struct Sample {
    pub elapsed_secs: u64,
    pub mbps: f64,
}

pub struct ThroughputResult {
    pub direction: String,
    pub duration_secs: u64,
    pub parallel: usize,
    pub path_class: String,
    pub tailscale_ip: String,
    pub target: String,
    pub total_bytes: u64,
    pub total_mbps: f64,
    pub up_bytes: u64,
    pub up_mbps: f64,
    pub down_bytes: u64,
    pub down_mbps: f64,
    pub samples: Vec<Sample>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    authkey: String,
    target: String,
    duration: u64,
    direction: &str,
    parallel: usize,
    hostname: String,
    control_url: String,
    state_dir: Option<std::path::PathBuf>,
) -> Result<ThroughputResult, Box<dyn std::error::Error>> {
    let dir_byte = match direction {
        "up" => DIR_UP,
        "down" => DIR_DOWN,
        "bidir" => DIR_BIDIR,
        other => return Err(format!("invalid direction: {other}").into()),
    };

    let mut builder = Server::builder()
        .hostname(hostname)
        .auth_key(authkey)
        .ephemeral(true)
        .control_url(control_url);
    if let Some(ref d) = state_dir {
        builder = builder.state_dir(d);
    }
    let mut server = builder.build()?;
    server.up().await?;

    let status = server.status();
    let my_ip = status
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(v4.to_string()),
            _ => None,
        })
        .unwrap_or_default();
    eprintln!("client up: ip={my_ip}, waiting for peer {target}");

    // Wait for the target peer to appear in the netmap.
    if let Some(ip) = extract_target_ip(&target) {
        wait_for_peer(&server, ip, Duration::from_secs(90)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Dial N connections (with retry).
    let mut streams: Vec<NetstackStream> = Vec::with_capacity(parallel);
    for i in 0..parallel {
        let mut ok = false;
        for attempt in 1..=3u32 {
            eprintln!("dial {}/{} attempt {attempt}", i + 1, parallel);
            match tokio::time::timeout(Duration::from_secs(45), server.dial(&target)).await {
                Ok(Ok(s)) => {
                    streams.push(s);
                    ok = true;
                    break;
                }
                Ok(Err(e)) => eprintln!("dial {i} attempt {attempt} failed: {e}"),
                Err(_) => eprintln!("dial {i} attempt {attempt} timed out (45s)"),
            }
            if attempt < 3 {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        if !ok {
            return Err(format!("failed to dial connection {i} after 3 attempts").into());
        }
    }
    eprintln!("all {parallel} connection(s) established");

    // Exchange headers.
    let hdr = Header {
        mode: MODE_THROUGHPUT,
        direction: dir_byte,
        duration_secs: duration as u32,
        count: 0,
    };
    for stream in &mut streams {
        write_header(stream, &hdr).await?;
        read_ack(stream).await?;
    }
    eprintln!("headers exchanged, starting {direction} test for {duration}s");

    // Shared byte counters.
    let up_counter = Arc::new(AtomicU64::new(0));
    let down_counter = Arc::new(AtomicU64::new(0));

    // Sampler: stores (elapsed_secs, cumulative_bytes) every 1s.
    let tick_data: Arc<tokio::sync::Mutex<Vec<(u64, u64)>>> =
        Arc::new(tokio::sync::Mutex::new(vec![]));
    let sampler_up = up_counter.clone();
    let sampler_down = down_counter.clone();
    let sampler_data = tick_data.clone();
    let sampler = tokio::spawn(async move {
        // Record baseline at t=0.
        let baseline = sampler_up.load(Ordering::Relaxed) + sampler_down.load(Ordering::Relaxed);
        sampler_data.lock().await.push((0, baseline));
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await; // discard immediate tick
        let mut elapsed = 0u64;
        loop {
            interval.tick().await;
            elapsed += 1;
            let total = sampler_up.load(Ordering::Relaxed) + sampler_down.load(Ordering::Relaxed);
            sampler_data.lock().await.push((elapsed, total));
        }
    });

    // Run the test on each connection.
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(parallel);
    for stream in streams {
        let uc = up_counter.clone();
        let dc = down_counter.clone();
        let dur = Duration::from_secs(duration);
        tasks.push(tokio::spawn(async move {
            run_single(stream, dir_byte, dur, uc, dc).await;
        }));
    }

    for t in &mut tasks {
        let _ = t.await;
    }
    sampler.abort();

    // Compute per-second Mbps from cumulative ticks.
    let ticks: Vec<(u64, u64)> = tick_data.lock().await.clone();
    let samples = compute_samples(&ticks);

    // Final stats.
    let final_status = server.status();
    let path_class = extract_path_class(&final_status, &target);
    let up_bytes = up_counter.load(Ordering::Relaxed);
    let down_bytes = down_counter.load(Ordering::Relaxed);
    let total_bytes = up_bytes + down_bytes;
    let total_mbps = bytes_to_mbps(total_bytes, duration as f64);
    let up_mbps = bytes_to_mbps(up_bytes, duration as f64);
    let down_mbps = bytes_to_mbps(down_bytes, duration as f64);

    server.close().await;

    Ok(ThroughputResult {
        direction: direction.to_string(),
        duration_secs: duration,
        parallel,
        path_class,
        tailscale_ip: my_ip,
        target: target.clone(),
        total_bytes,
        total_mbps,
        up_bytes,
        up_mbps,
        down_bytes,
        down_mbps,
        samples,
    })
}

async fn run_single(
    stream: NetstackStream,
    dir: u8,
    duration: Duration,
    up_counter: Arc<AtomicU64>,
    down_counter: Arc<AtomicU64>,
) {
    match dir {
        DIR_UP => run_up(stream, duration, up_counter).await,
        DIR_DOWN => run_down(stream, down_counter).await,
        DIR_BIDIR => run_bidir(stream, duration, up_counter, down_counter).await,
        _ => {}
    }
}

async fn run_up(stream: NetstackStream, duration: Duration, counter: Arc<AtomicU64>) {
    let mut stream = stream;
    let buf = vec![0xA5u8; FIREHOSE_BUF_SIZE];
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.write(&buf)).await {
            Ok(Ok(n)) => {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            _ => break,
        }
    }
    let _ = stream.shutdown().await;
}

async fn run_down(stream: NetstackStream, counter: Arc<AtomicU64>) {
    let mut stream = stream;
    let mut buf = vec![0u8; READ_BUF_SIZE];
    // Hard timeout: duration + 30s grace period to prevent infinite hang
    // if the server's shutdown signal is lost in the netstack channel.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            eprintln!("WARN: read timeout (120s), aborting");
            break;
        }
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
}

async fn run_bidir(
    stream: NetstackStream,
    duration: Duration,
    up_counter: Arc<AtomicU64>,
    down_counter: Arc<AtomicU64>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write_buf = vec![0xA5u8; FIREHOSE_BUF_SIZE];
    let up_c = up_counter;
    let writer = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, writer.write(&write_buf)).await {
                Ok(Ok(n)) => {
                    up_c.fetch_add(n as u64, Ordering::Relaxed);
                }
                _ => break,
            }
        }
        let _ = writer.shutdown().await;
    });

    let mut read_buf = vec![0u8; READ_BUF_SIZE];
    let read_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let remaining = read_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, reader.read(&mut read_buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                down_counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
    let _ = writer.await;
}

fn compute_samples(ticks: &[(u64, u64)]) -> Vec<Sample> {
    if ticks.len() < 2 {
        return vec![];
    }
    let mut out = Vec::with_capacity(ticks.len() - 1);
    for i in 1..ticks.len() {
        let (elapsed, cumulative) = ticks[i];
        let (_, prev) = ticks[i - 1];
        let delta = cumulative.saturating_sub(prev);
        let mbps = bytes_to_mbps(delta, 1.0);
        out.push(Sample {
            elapsed_secs: elapsed,
            mbps,
        });
    }
    out
}

fn bytes_to_mbps(bytes: u64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        return 0.0;
    }
    (bytes as f64 * 8.0) / 1_000_000.0 / seconds
}

pub(crate) fn extract_target_ip(target: &str) -> Option<std::net::Ipv4Addr> {
    let host = target.rsplit_once(':').map(|(h, _)| h)?;
    host.parse::<std::net::Ipv4Addr>().ok()
}

pub(crate) async fn wait_for_peer(
    server: &Server,
    target_ip: std::net::Ipv4Addr,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let st = server.status();
        if st.peers.iter().any(|p| {
            p.ips
                .iter()
                .any(|ip| matches!(ip, std::net::IpAddr::V4(v4) if *v4 == target_ip))
        }) {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            eprintln!("WARN: peer {target_ip} not found in netmap after {timeout:?}");
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub(crate) fn extract_path_class(status: &ServerStatus, target: &str) -> String {
    let target_ip = extract_target_ip(target);
    for peer in &status.peers {
        if let Some(ip) = target_ip {
            if peer
                .ips
                .iter()
                .any(|p| matches!(p, std::net::IpAddr::V4(v4) if *v4 == ip))
            {
                return path_class_str(peer.path_class).to_string();
            }
        }
    }
    "unknown".to_string()
}

fn path_class_str(pc: rustscale_magicsock::PathClass) -> &'static str {
    match pc {
        rustscale_magicsock::PathClass::Direct => "direct",
        rustscale_magicsock::PathClass::Derp => "derp",
        rustscale_magicsock::PathClass::Relay => "relay",
        rustscale_magicsock::PathClass::None => "none",
    }
}
