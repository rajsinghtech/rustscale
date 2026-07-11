//! Latency client: measure RTT of small ping-pong messages over the tailnet.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tailscale::{Config, Device};
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
    state_dir: Option<PathBuf>,
) -> Result<LatencyResult, Box<dyn std::error::Error>> {
    let key_file = resolve_key_file(state_dir.as_ref())?;
    let mut config = Config::default_with_key_file(&key_file).await?;
    config.requested_hostname = Some(hostname);
    config.control_server_url = url::Url::parse(&control_url)?;

    let dev = Device::new(&config, Some(authkey)).await?;
    let my_ip = dev.ipv4_addr().await?;
    let my_ip_str = my_ip.to_string();
    eprintln!("latency client up: ip={my_ip_str}, target={target}");

    tokio::time::sleep(Duration::from_secs(3)).await;

    let target_addr: SocketAddr = target.parse().map_err(|e| {
        format!("failed to parse target '{target}' as SocketAddr (ip:port): {e}")
    })?;

    let mut stream = {
        let mut connected = None;
        for attempt in 1..=3u32 {
            eprintln!("dial attempt {attempt}");
            match tokio::time::timeout(Duration::from_secs(45), dev.tcp_connect(target_addr))
                .await
            {
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

    let hdr = Header {
        mode: MODE_LATENCY,
        direction: 0,
        duration_secs: 0,
        count: count as u32,
    };
    write_header(&mut stream, &hdr).await?;
    read_ack(&mut stream).await?;
    eprintln!("latency test: {count} ping-pong rounds");

    let mut rtts_us: Vec<u64> = Vec::with_capacity(count);
    let mut ping_buf = [0u8; PING_SIZE];
    let mut pong_buf = [0u8; PING_SIZE];

    for i in 0..count {
        ping_buf[..4].copy_from_slice(b"PING");
        ping_buf[4..8].copy_from_slice(&(i as u32).to_be_bytes());

        let start = Instant::now();
        stream.write_all(&ping_buf).await?;
        stream.read_exact(&mut pong_buf).await?;
        let rtt = start.elapsed().as_micros() as u64;
        rtts_us.push(rtt);
    }

    let _ = stream.shutdown().await;

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

    dev.shutdown(Some(Duration::from_secs(10))).await;

    Ok(LatencyResult {
        count,
        path_class: "derp".to_string(),
        tailscale_ip: my_ip_str,
        target,
        min_us,
        max_us,
        mean_us,
        p50_us,
        p95_us,
        p99_us,
    })
}

fn resolve_key_file(state_dir: Option<&PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(d) = state_dir {
        Ok(d.join("tsrs_keys.json"))
    } else {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        Ok(dir.join(format!("tsrs-bench-{pid}.json")))
    }
}
