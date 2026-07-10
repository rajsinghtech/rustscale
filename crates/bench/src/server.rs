//! Server mode: join a tailnet, listen on a port, accept benchmark connections.

use std::time::Duration;

use rustscale_netstack::NetstackStream;
use rustscale_tsnet::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{
    read_header, write_ack, Header, DIR_BIDIR, DIR_DOWN, DIR_UP, FIREHOSE_BUF_SIZE, MODE_LATENCY,
    MODE_THROUGHPUT, PING_SIZE, READ_BUF_SIZE,
};

pub async fn run(
    authkey: String,
    port: u16,
    hostname: String,
    control_url: String,
    state_dir: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let ip = status
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .ok_or("no IPv4 tailnet address")?;
    eprintln!("BENCH_IP {ip}");
    eprintln!("BENCH_PORT {port}");
    eprintln!("BENCH_READY 1");

    let mut listener = server.listen(port).await?;
    eprintln!("listening on {ip}:{port}");

    loop {
        let accept_result =
            tokio::time::timeout(Duration::from_secs(30 * 60), listener.accept()).await;
        let stream = match accept_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                eprintln!("accept error: {e}");
                continue;
            }
            Err(_) => {
                eprintln!("accept idle timeout (1800s), shutting down");
                break;
            }
        };
        eprintln!("accepted connection");
        let write_buf = vec![0xA5u8; FIREHOSE_BUF_SIZE];
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &write_buf).await {
                eprintln!("connection handler error: {e}");
            }
        });
    }

    server.close().await;
    Ok(())
}

async fn handle_connection(
    mut stream: NetstackStream,
    write_buf: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let hdr = read_header(&mut stream).await?;
    write_ack(&mut stream).await?;

    match hdr.mode {
        MODE_THROUGHPUT => handle_throughput(stream, write_buf, &hdr).await,
        MODE_LATENCY => handle_latency(stream, hdr.count).await,
        _ => Err(format!("unknown mode: {}", hdr.mode).into()),
    }
}

async fn handle_throughput(
    mut stream: NetstackStream,
    write_buf: &[u8],
    hdr: &Header,
) -> Result<(), Box<dyn std::error::Error>> {
    let duration = Duration::from_secs(u64::from(hdr.duration_secs));
    match hdr.direction {
        DIR_UP => {
            // Client sends, server reads and discards until EOF.
            let mut discard = vec![0u8; READ_BUF_SIZE];
            loop {
                let n = stream.read(&mut discard).await?;
                if n == 0 {
                    break;
                }
            }
        }
        DIR_DOWN => {
            // Server sends firehose for duration, then shuts down write side.
            let deadline = tokio::time::Instant::now() + duration;
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, stream.write_all(write_buf)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(format!("write error: {e}").into()),
                    Err(_) => break,
                }
            }
            // Drain delay: let the netstack poll loop process pending channel
            // items before we send the shutdown signal (empty Vec). Without
            // this, the channel may be full and poll_shutdown's try_send is
            // silently dropped, causing the client to hang waiting for EOF.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = stream.shutdown().await;
        }
        DIR_BIDIR => {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let wbuf: Vec<u8> = write_buf.to_vec();
            let writer = tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + duration;
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match tokio::time::timeout(remaining, writer.write_all(&wbuf)).await {
                        Ok(Ok(())) => {}
                        _ => break,
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = writer.shutdown().await;
            });

            let mut discard = vec![0u8; READ_BUF_SIZE];
            loop {
                let n = reader.read(&mut discard).await?;
                if n == 0 {
                    break;
                }
            }
            let _ = writer.await;
        }
        _ => return Err(format!("unknown direction: {}", hdr.direction).into()),
    }
    Ok(())
}

async fn handle_latency(
    mut stream: NetstackStream,
    count: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; PING_SIZE];
    for _ in 0..count {
        stream.read_exact(&mut buf).await?;
        stream.write_all(&buf).await?;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = stream.shutdown().await;
    Ok(())
}
