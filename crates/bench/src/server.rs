//! Server mode for both embedded userspace tsnet and kernel TCP/TUN.

use std::error::Error;
use std::time::Duration;

use rustscale_tsnet::Server;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::protocol::{
    read_go, read_header, write_ack, Header, DIR_BIDIR, DIR_DOWN, DIR_UP, FIREHOSE_BUF_SIZE,
    MODE_LATENCY, MODE_THROUGHPUT, PING_SIZE, READ_BUF_SIZE,
};

// The client has one 180-second deadline for a complete 1000-stream fan-out.
// Keep each accepted handler alive slightly longer so early connections do not
// expire while the final SOCKS5/TUN handshakes complete before common GO.
const SETUP_TIMEOUT: Duration = Duration::from_secs(210);
const IO_GRACE: Duration = Duration::from_secs(30);
const LATENCY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 2048;

pub async fn run_userspace(
    authkey: String,
    port: u16,
    hostname: String,
    control_url: String,
    state_dir: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let mut builder = Server::builder()
        .hostname(hostname)
        .auth_key(authkey)
        .ephemeral(true)
        // Benchmark VMs have public endpoints; NAT mapping adds no path value
        // and can make short-lived trial shutdown wait on an uncertain release.
        .disable_portmapping(true)
        .control_url(control_url);
    if let Some(ref directory) = state_dir {
        builder = builder.state_dir(directory);
    }
    let mut server = builder.build()?;
    Box::pin(server.up()).await?;
    let ip = server
        .status()
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .ok_or("no IPv4 tailnet address")?;
    let mut listener = server.listen(port).await?;
    eprintln!("BENCH_IP {ip}\nBENCH_PORT {port}\nBENCH_READY 1");
    eprintln!("listening on {ip}:{port} via userspace-tsnet");
    // Both transports have the same lifecycle and handler limit: they remain
    // available until explicitly stopped by the matrix cleanup path.
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = limit.clone().acquire_owned().await?;
        match listener.accept().await {
            Ok(stream) => spawn_connection(stream, permit),
            Err(error) => eprintln!("accept error: {error}"),
        }
    }
}

pub async fn run_kernel(port: u16, bind: std::net::IpAddr) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind((bind, port)).await?;
    eprintln!("BENCH_IP {bind}\nBENCH_PORT {port}\nBENCH_READY 1");
    eprintln!("listening on {bind}:{port} via kernel-tcp");
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = limit.clone().acquire_owned().await?;
        let (stream, _) = listener.accept().await?;
        spawn_connection(stream, permit);
    }
}

fn spawn_connection<S>(stream: S, permit: tokio::sync::OwnedSemaphorePermit)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(error) = handle_connection(stream).await {
            eprintln!("connection handler error: {error}");
        }
    });
}

async fn handle_connection<S>(mut stream: S) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let header = tokio::time::timeout(SETUP_TIMEOUT, read_header(&mut stream))
        .await
        .map_err(|_| "RSB1 header timeout")??;
    tokio::time::timeout(SETUP_TIMEOUT, write_ack(&mut stream))
        .await
        .map_err(|_| "RSB1 ready timeout")??;
    // No workload starts at ACK time. Every throughput worker is already
    // spawned before its client sends GO, eliminating sequential handshake
    // time from early streams.
    tokio::time::timeout(SETUP_TIMEOUT, read_go(&mut stream))
        .await
        .map_err(|_| "RSB1 go timeout")??;
    match header.mode {
        MODE_THROUGHPUT => handle_throughput(stream, &header).await,
        MODE_LATENCY => handle_latency(stream, header.count).await,
        _ => Err(format!("unknown mode: {}", header.mode).into()),
    }
}

async fn handle_throughput<S>(
    mut stream: S,
    header: &Header,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let duration = Duration::from_secs(u64::from(header.duration_secs));
    let deadline = duration + IO_GRACE;
    let workload = async {
        let write_buf = vec![0xA5; FIREHOSE_BUF_SIZE];
        match header.direction {
            DIR_UP => {
                let mut discard = vec![0; READ_BUF_SIZE];
                while stream.read(&mut discard).await? != 0 {}
                Ok(())
            }
            DIR_DOWN => write_for_duration(&mut stream, &write_buf, duration).await,
            DIR_BIDIR => {
                let (mut reader, mut writer) = tokio::io::split(stream);
                let writer_task =
                    async { write_for_duration(&mut writer, &write_buf, duration).await };
                let reader_task = async {
                    let mut discard = vec![0; READ_BUF_SIZE];
                    while reader.read(&mut discard).await? != 0 {}
                    Ok::<_, std::io::Error>(())
                };
                let (write_result, read_result) = tokio::join!(writer_task, reader_task);
                write_result?;
                read_result?;
                Ok(())
            }
            _ => Err(format!("unknown direction: {}", header.direction).into()),
        }
    };
    tokio::time::timeout(deadline, workload)
        .await
        .map_err(|_| "throughput handler timeout")?
}

async fn write_for_duration<S: AsyncWrite + Unpin>(
    stream: &mut S,
    buf: &[u8],
    duration: Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.write_all(buf)).await {
            Ok(result) => result?,
            Err(_) => break,
        }
    }
    // Netstack shutdown is asynchronous; retain the established drain margin.
    tokio::time::sleep(Duration::from_millis(200)).await;
    stream.shutdown().await?;
    Ok(())
}

async fn handle_latency<S>(mut stream: S, count: u32) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0; PING_SIZE];
    for _ in 0..count {
        tokio::time::timeout(LATENCY_EXCHANGE_TIMEOUT, async {
            stream.read_exact(&mut buf).await?;
            stream.write_all(&buf).await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| "latency exchange timeout")??;
    }
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{read_ack, write_go, write_header, Header};

    #[tokio::test]
    async fn kernel_tcp_speaks_rsb1_latency_ready_go() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream).await.unwrap();
        });
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        write_header(
            &mut client,
            &Header {
                mode: MODE_LATENCY,
                direction: 0,
                duration_secs: 0,
                count: 1,
            },
        )
        .await
        .unwrap();
        read_ack(&mut client).await.unwrap();
        write_go(&mut client).await.unwrap();
        client.write_all(b"PING\0\0\0\x01").await.unwrap();
        let mut pong = [0; PING_SIZE];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"PING\0\0\0\x01");
        server.await.unwrap();
    }
}
