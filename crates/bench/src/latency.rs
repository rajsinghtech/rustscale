//! RSB1 TCP ping-pong latency over userspace tsnet or kernel TCP/TUN.

use crate::protocol::{read_ack, write_go, write_header, Header, MODE_LATENCY, PING_SIZE};
use rustscale_tsnet::Server;
use std::error::Error;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct LatencyResult {
    pub transport: &'static str,
    pub requested: usize,
    pub successful: usize,
    pub timed_out: usize,
    pub malformed: usize,
    pub path_class: String,
    pub tailscale_ip: String,
    pub target: String,
    pub min_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub samples_ns: Vec<u64>,
}

pub async fn run_userspace(
    authkey: String,
    target: String,
    count: usize,
    hostname: String,
    control_url: String,
    state_dir: Option<std::path::PathBuf>,
) -> Result<LatencyResult, Box<dyn Error>> {
    // A supplied state directory is a restart-stable transport identity. Do
    // not ask control to reap it between the throughput and latency processes.
    let ephemeral = state_dir.is_none();
    let mut builder = Server::builder()
        .hostname(hostname)
        .auth_key(authkey)
        .ephemeral(ephemeral)
        .disable_portmapping(true)
        .control_url(control_url);
    if let Some(ref d) = state_dir {
        builder = builder.state_dir(d);
    }
    let mut server = builder.build()?;
    Box::pin(server.up()).await?;
    let my_ip = server
        .status()
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(v4.to_string()),
            _ => None,
        })
        .unwrap_or_default();
    if let Some(ip) = super::throughput::extract_target_ip(&target) {
        super::throughput::wait_for_peer(&server, ip, Duration::from_secs(90)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    // A measured latency process gets one connection attempt. Retrying here
    // would add unreported setup work to the endpoint resource window.
    let stream = tokio::time::timeout(Duration::from_secs(180), server.dial(&target))
        .await
        .map_err(|_| "RSB1 latency connection setup timeout")??;
    let path = super::throughput::extract_path_class(&server.status(), &target);
    let result = measure(stream, "userspace-tsnet", target, count, path, my_ip).await?;
    super::throughput::close_userspace(&mut server).await?;
    Ok(result)
}

pub async fn run_kernel(target: String, count: usize) -> Result<LatencyResult, Box<dyn Error>> {
    let stream =
        tokio::time::timeout(Duration::from_secs(180), TcpStream::connect(&target)).await??;
    stream.set_nodelay(true)?;
    measure(
        stream,
        "kernel-tcp",
        target,
        count,
        "externally-gated".into(),
        String::new(),
    )
    .await
}

async fn measure<S>(
    mut stream: S,
    transport: &'static str,
    target: String,
    count: usize,
    path_class: String,
    tailscale_ip: String,
) -> Result<LatencyResult, Box<dyn Error>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let wire_count = u32::try_from(count)?;
    tokio::time::timeout(Duration::from_secs(30), async {
        write_header(
            &mut stream,
            &Header {
                mode: MODE_LATENCY,
                direction: 0,
                duration_secs: 0,
                count: wire_count,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
        read_ack(&mut stream)
            .await
            .map_err(|error| error.to_string())?;
        write_go(&mut stream)
            .await
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "RSB1 latency setup timeout")??;
    // Connection and RSB1 setup are complete before the latency clock starts.
    let mut samples = Vec::with_capacity(count);
    let mut timed_out = 0;
    let mut malformed = 0;
    for sequence in 0..count {
        let mut ping = [0; PING_SIZE];
        ping[..4].copy_from_slice(b"PING");
        ping[4..].copy_from_slice(&(sequence as u32).to_be_bytes());
        let start = Instant::now();
        let exchange = async {
            stream.write_all(&ping).await?;
            let mut pong = [0; PING_SIZE];
            stream.read_exact(&mut pong).await?;
            Ok::<_, std::io::Error>(pong)
        };
        match tokio::time::timeout(Duration::from_secs(5), exchange).await {
            Ok(Ok(pong)) if pong == ping => {
                samples.push(start.elapsed().as_nanos().try_into().unwrap_or(u64::MAX));
            }
            Ok(Ok(_)) => malformed += 1,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                timed_out += 1;
                break;
            }
        }
    }
    let _ = stream.shutdown().await;
    if samples.len() != count {
        return Err(format!("incomplete latency sample: requested={count} successful={} timed_out={timed_out} malformed={malformed}", samples.len()).into());
    }
    let mut ordered = samples.clone();
    ordered.sort_unstable();
    let len = ordered.len();
    let pct = |p: f64| ordered[((len as f64 - 1.0) * p).round() as usize];
    Ok(LatencyResult {
        transport,
        requested: count,
        successful: len,
        timed_out,
        malformed,
        path_class,
        tailscale_ip,
        target,
        min_ns: ordered[0],
        max_ns: ordered[len - 1],
        mean_ns: ordered.iter().map(|&v| v as f64).sum::<f64>() / len as f64,
        p50_ns: pct(0.50),
        p95_ns: pct(0.95),
        p99_ns: pct(0.99),
        samples_ns: samples,
    })
}
