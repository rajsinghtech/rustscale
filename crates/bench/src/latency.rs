//! Latency client: measure RTT of small ping-pong messages over the tailnet.

use std::time::{Duration, Instant};

use rustscale_tsnet::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{read_ack, write_header, Header, MODE_LATENCY, PING_SIZE};

pub struct LatencyResult {
    pub count: usize,
    pub path_class: String,
    pub tailscale_ip: String,
    pub target: String,
    pub min_us: u64,
    pub max_us: u64,
    pub mean_us: f64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
}

pub async fn run(
    authkey: String,
    target: String,
    count: usize,
    hostname: String,
    control_url: String,
    state_dir: Option<std::path::PathBuf>,
) -> Result<LatencyResult, Box<dyn std::error::Error>> {
    let mut builder = Server::builder()
        .hostname(hostname)
        .auth_key(authkey)
        .ephemeral(true)
        .control_url(control_url);
    if let Some(ref d) = state_dir {
        builder = builder.state_dir(d);
    }
    let mut server = builder.build()?;
    Box::pin(server.up()).await?;

    let status = server.status();
    let my_ip = status
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(v4.to_string()),
            _ => None,
        })
        .unwrap_or_default();
    eprintln!("latency client up: ip={my_ip}, waiting for peer {target}");

    if let Some(ip) = super::throughput::extract_target_ip(&target) {
        super::throughput::wait_for_peer(&server, ip, Duration::from_secs(90)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Dial the server.
    let mut stream = {
        let mut connected = None;
        for attempt in 1..=3u32 {
            eprintln!("dial attempt {attempt}");
            match tokio::time::timeout(Duration::from_secs(45), server.dial(&target)).await {
                Ok(Ok(s)) => {
                    connected = Some(s);
                    break;
                }
                Ok(Err(e)) => eprintln!("dial attempt {attempt} failed: {e}"),
                Err(_) => eprintln!("dial attempt {attempt} timed out"),
            }
            if attempt < 3 {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        connected.ok_or("failed to dial after 3 attempts")?
    };

    // Exchange header + ack.
    let hdr = Header {
        mode: MODE_LATENCY,
        direction: 0,
        duration_secs: 0,
        count: count as u32,
    };
    write_header(&mut stream, &hdr).await?;
    read_ack(&mut stream).await?;
    eprintln!("latency test: {count} ping-pong rounds");

    // Run ping-pong.
    let mut rtts_us: Vec<u64> = Vec::with_capacity(count);
    let mut ping_buf = [0u8; PING_SIZE];
    let mut pong_buf = [0u8; PING_SIZE];

    for i in 0..count {
        // Encode sequence number in the ping.
        ping_buf[..4].copy_from_slice(b"PING");
        ping_buf[4..8].copy_from_slice(&(i as u32).to_be_bytes());

        let start = Instant::now();
        stream.write_all(&ping_buf).await?;
        stream.read_exact(&mut pong_buf).await?;
        let rtt = start.elapsed().as_micros() as u64;
        rtts_us.push(rtt);
    }

    let _ = stream.shutdown().await;

    // Compute percentiles.
    rtts_us.sort_unstable();
    let len = rtts_us.len();
    let pct = |p: f64| -> u64 {
        if len == 0 {
            return 0;
        }
        let idx = ((len as f64 - 1.0) * p).round() as usize;
        rtts_us[idx.min(len - 1)]
    };
    let min_us = *rtts_us.first().unwrap_or(&0);
    let max_us = *rtts_us.last().unwrap_or(&0);
    let mean_us = rtts_us.iter().map(|&v| v as f64).sum::<f64>() / len as f64;
    let p50_us = pct(0.50);
    let p95_us = pct(0.95);
    let p99_us = pct(0.99);

    // Final path class.
    let final_status = server.status();
    let path_class = super::throughput::extract_path_class(&final_status, &target);

    server.close().await.unwrap();

    Ok(LatencyResult {
        count,
        path_class,
        tailscale_ip: my_ip,
        target,
        min_us,
        max_us,
        mean_us,
        p50_us,
        p95_us,
        p99_us,
    })
}
