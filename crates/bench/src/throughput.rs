//! Throughput client shared by userspace tsnet and kernel TCP/TUN.

use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustscale_tsnet::{Server, ServerStatus};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::protocol::{
    read_ack, write_go, write_header, Header, DIR_BIDIR, DIR_DOWN, DIR_UP, FIREHOSE_BUF_SIZE,
    MODE_THROUGHPUT, READ_BUF_SIZE,
};

// One bounded setup deadline applies to the complete connection and RSB1
// handshake fan-out. It is deliberately longer than the server's normal
// direct-path setup while remaining finite for failed 1000-stream trials.
const SETUP_DEADLINE: Duration = Duration::from_secs(180);

pub struct Sample {
    pub elapsed_secs: u64,
    pub mbps: f64,
}
pub struct ThroughputResult {
    pub transport: &'static str,
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
    pub established: usize,
    pub handshaken: usize,
    pub completed: usize,
}

pub(crate) fn log_userspace_identity(server: &Server, role: &str) -> Result<(), Box<dyn Error>> {
    let node = server
        .node_key()
        .ok_or("userspace node identity unavailable")?;
    let disco = server
        .magicsock()
        .ok_or("userspace discovery identity unavailable")?
        .disco_public();
    eprintln!("BENCH_IDENTITY role={role} node={node} disco={disco}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_userspace(
    authkey: String,
    target: String,
    duration: u64,
    direction: &str,
    parallel: usize,
    hostname: String,
    control_url: String,
    state_dir: Option<std::path::PathBuf>,
) -> Result<ThroughputResult, Box<dyn Error>> {
    // A supplied state directory is a restart-stable node identity. Its disco
    // identity remains process-local so peers invalidate the prior UDP path.
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
    let operation: Result<ThroughputResult, Box<dyn Error>> = async {
        Box::pin(server.up()).await?;
        log_userspace_identity(&server, "client")?;
        let my_ip = server
            .status()
            .tailscale_ips
            .iter()
            .find_map(|ip| match ip {
                std::net::IpAddr::V4(v4) => Some(v4.to_string()),
                _ => None,
            })
            .unwrap_or_default();
        if let Some(ip) = extract_target_ip(&target) {
            wait_for_peer(&server, ip, Duration::from_secs(90)).await?;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        // Resolve once and admit TCP handshakes in the netstack's bounded
        // listener-sized window. The primitive owns the common deadline and
        // fails the requested set atomically without retrying a stream.
        let streams = server
            .dial_many(&target, parallel, SETUP_DEADLINE)
            .await
            .map_err(|error| format!("capacity error: {error}"))?;
        // Match the pinned-Go comparator's observation boundary: classify the
        // path only after the measured transfer has completed successfully.
        // A fresh embedded process can still be converging immediately after
        // dial setup, so the pre-measurement snapshot is not the trial's
        // retained post-workload path evidence.
        let mut result = measure(
            streams,
            "userspace-tsnet",
            target.clone(),
            duration,
            direction,
            parallel,
            "unknown".into(),
            my_ip,
        )
        .await?;
        result.path_class = extract_path_class(&server.status(), &target);
        Ok(result)
    }
    .await;
    // Stream Drop queues the netstack TCP close. Keep the packet pump alive
    // for the same bounded drain grace used by the server writer so FINs reach
    // the long-lived peer before this short-lived trial tears down tsnet.
    // Without this, later trial processes can encounter prior live four-tuples
    // even though every preceding workload worker completed.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let shutdown = close_userspace(&mut server).await;
    match (operation, shutdown) {
        (Ok(result), Ok(())) => {
            eprintln!("BENCH_SHUTDOWN role=client status=clean");
            Ok(result)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(shutdown_error)) => {
            Err(format!("{error}; userspace shutdown also failed: {shutdown_error}").into())
        }
    }
}

pub(crate) async fn close_userspace(server: &mut Server) -> Result<(), Box<dyn Error>> {
    let mut last_error = None;
    for attempt in 1..=5 {
        match server.close().await {
            Ok(()) => return Ok(()),
            Err(error) => {
                eprintln!("userspace shutdown attempt {attempt}/5 failed: {error}");
                last_error = Some(error);
                if attempt < 5 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
    Err(last_error
        .map_or_else(
            || "userspace shutdown incomplete".into(),
            |error| format!("userspace shutdown incomplete after 5 attempts: {error}"),
        )
        .into())
}

pub async fn run_kernel(
    target: String,
    duration: u64,
    direction: &str,
    parallel: usize,
) -> Result<ThroughputResult, Box<dyn Error>> {
    // Establish kernel TCP streams concurrently. A SOCKS5/local bridge accepts
    // locally before opening the tailnet side, so serial connects can otherwise
    // leave early server handlers waiting for GO while the 1000th stream is
    // still being created.
    let connect_target = target.clone();
    let connect_all = async move {
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..parallel {
            let target = connect_target.clone();
            tasks.spawn(async move {
                let stream = TcpStream::connect(&target)
                    .await
                    .map_err(|error| format!("connection {index}: {error}"))?;
                stream
                    .set_nodelay(true)
                    .map_err(|error| format!("connection {index} TCP_NODELAY: {error}"))?;
                Ok::<_, String>((index, stream))
            });
        }
        let mut connected = Vec::with_capacity(parallel);
        while let Some(joined) = tasks.join_next().await {
            let item = joined.map_err(|error| format!("connection worker failed: {error}"))??;
            connected.push(item);
        }
        connected.sort_unstable_by_key(|(index, _)| *index);
        Ok::<_, String>(connected.into_iter().map(|(_, stream)| stream).collect())
    };
    let streams = tokio::time::timeout(SETUP_DEADLINE, connect_all)
        .await
        .map_err(|_| format!("capacity error: did not establish all {parallel} requested connections before the common setup deadline"))??;
    measure(
        streams,
        "kernel-tcp",
        target,
        duration,
        direction,
        parallel,
        "externally-gated".into(),
        String::new(),
    )
    .await
}

async fn handshake_stream<S>(
    index: usize,
    mut stream: S,
    header: Header,
) -> Result<(usize, S), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_header(&mut stream, &header)
        .await
        .map_err(|error| format!("stream {index} header: {error}"))?;
    read_ack(&mut stream)
        .await
        .map_err(|error| format!("stream {index} ACK: {error}"))?;
    Ok((index, stream))
}

async fn measure<S>(
    mut streams: Vec<S>,
    transport: &'static str,
    target: String,
    duration: u64,
    direction: &str,
    parallel: usize,
    path_class: String,
    tailscale_ip: String,
) -> Result<ThroughputResult, Box<dyn Error>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let dir = match direction {
        "up" => DIR_UP,
        "down" => DIR_DOWN,
        "bidir" => DIR_BIDIR,
        other => return Err(format!("invalid direction: {other}").into()),
    };
    let header = Header {
        mode: MODE_THROUGHPUT,
        direction: dir,
        duration_secs: u32::try_from(duration)?,
        count: 0,
    };
    let established = streams.len();
    // Bound header/ACK admission by the same receive-safe window as TCP
    // setup. Streams are reassembled by index before the common GO barrier;
    // no workload byte can flow while any handshake is incomplete.
    let setup = async move {
        let mut input = streams.drain(..).enumerate();
        let mut tasks = tokio::task::JoinSet::new();
        for (index, stream) in input.by_ref().take(rustscale_netstack::TCP_DIAL_WINDOW) {
            tasks.spawn(handshake_stream(index, stream, header));
        }
        let mut ready = Vec::with_capacity(parallel);
        while let Some(joined) = tasks.join_next().await {
            let item =
                joined.map_err(|error| format!("protocol setup worker failed: {error}"))??;
            ready.push(item);
            if let Some((index, stream)) = input.next() {
                tasks.spawn(handshake_stream(index, stream, header));
            }
        }
        ready.sort_unstable_by_key(|(index, _)| *index);
        Ok::<_, String>(
            ready
                .into_iter()
                .map(|(_, stream)| stream)
                .collect::<Vec<_>>(),
        )
    };
    let streams = tokio::time::timeout(SETUP_DEADLINE, setup)
        .await
        .map_err(|_| {
            format!("protocol setup timeout: established={established} requested={parallel}")
        })??;
    let handshaken = streams.len();
    // Timing begins only after every connection and protocol handshake is ready.
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let tick_data = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let sampler_data = tick_data.clone();
    let sampler_up = up.clone();
    let sampler_down = down.clone();
    let sampler = tokio::spawn(async move {
        sampler_data.lock().await.push((
            0,
            sampler_up.load(Ordering::Relaxed) + sampler_down.load(Ordering::Relaxed),
        ));
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;
        let mut elapsed = 0;
        loop {
            interval.tick().await;
            elapsed += 1;
            sampler_data.lock().await.push((
                elapsed,
                sampler_up.load(Ordering::Relaxed) + sampler_down.load(Ordering::Relaxed),
            ));
        }
    });
    let barrier = Arc::new(tokio::sync::Barrier::new(parallel + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for stream in streams {
        tasks.spawn(run_single(
            stream,
            dir,
            Duration::from_secs(duration),
            up.clone(),
            down.clone(),
            barrier.clone(),
        ));
    }
    // Every worker exists and every stream has completed RSB1 setup before GO.
    barrier.wait().await;
    let mut completed = 0;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => completed += 1,
            Ok(Err(error)) => {
                tasks.abort_all();
                sampler.abort();
                return Err(format!("throughput stream failed: established={established} handshaken={handshaken} completed={completed} requested={parallel}: {error}").into());
            }
            Err(error) => {
                tasks.abort_all();
                sampler.abort();
                return Err(format!("throughput worker failed: established={established} handshaken={handshaken} completed={completed} requested={parallel}: {error}").into());
            }
        }
    }
    sampler.abort();
    let samples = compute_samples(&tick_data.lock().await);
    let up_bytes = up.load(Ordering::Relaxed);
    let down_bytes = down.load(Ordering::Relaxed);
    let total_bytes = up_bytes + down_bytes;
    Ok(ThroughputResult {
        transport,
        direction: direction.into(),
        duration_secs: duration,
        parallel,
        path_class,
        tailscale_ip,
        target,
        total_bytes,
        total_mbps: bytes_to_mbps(total_bytes, duration as f64),
        up_bytes,
        up_mbps: bytes_to_mbps(up_bytes, duration as f64),
        down_bytes,
        down_mbps: bytes_to_mbps(down_bytes, duration as f64),
        samples,
        established,
        handshaken,
        completed,
    })
}

async fn run_single<S>(
    mut stream: S,
    dir: u8,
    duration: Duration,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    barrier: Arc<tokio::sync::Barrier>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    barrier.wait().await;
    tokio::time::timeout(Duration::from_secs(30), write_go(&mut stream))
        .await
        .map_err(|_| "GO timeout".to_string())?
        .map_err(|error| error.to_string())?;
    match dir {
        DIR_UP => run_up(stream, duration, up).await,
        DIR_DOWN => run_down(stream, duration, down).await,
        DIR_BIDIR => run_bidir(stream, duration, up, down).await,
        _ => unreachable!(),
    }
}
async fn run_up<S: AsyncWrite + Unpin>(
    mut stream: S,
    duration: Duration,
    counter: Arc<AtomicU64>,
) -> Result<(), String> {
    let buf = vec![0xA5; FIREHOSE_BUF_SIZE];
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.write(&buf)).await {
            Ok(Ok(0)) => return Err("zero-length throughput write".into()),
            Ok(Ok(n)) => {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Ok(Err(error)) => return Err(format!("write error: {error}")),
            Err(_) => break,
        }
    }
    stream
        .shutdown()
        .await
        .map_err(|error| format!("shutdown error: {error}"))?;
    Ok(())
}
async fn run_down<S: AsyncRead + Unpin>(
    mut stream: S,
    duration: Duration,
    counter: Arc<AtomicU64>,
) -> Result<(), String> {
    let mut buf = vec![0; READ_BUF_SIZE];
    let started = tokio::time::Instant::now();
    let deadline = started + duration;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                if started.elapsed() + Duration::from_millis(100) < duration {
                    return Err("premature EOF".into());
                }
                return Ok(());
            }
            Ok(Ok(n)) => {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Ok(Err(error)) => return Err(format!("read error: {error}")),
            // The reverse sender may have bytes queued behind the exact
            // measurement boundary. Stop at the requested wall-clock duration
            // rather than waiting for EOF and counting post-window backlog.
            Err(_) => return Ok(()),
        }
    }
}
async fn run_bidir<S>(
    stream: S,
    duration: Duration,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, writer) = tokio::io::split(stream);
    let (read_result, write_result) = tokio::join!(
        run_down(reader, duration, down),
        run_up(writer, duration, up)
    );
    read_result?;
    write_result?;
    Ok(())
}
fn compute_samples(ticks: &[(u64, u64)]) -> Vec<Sample> {
    ticks
        .windows(2)
        .map(|pair| Sample {
            elapsed_secs: pair[1].0,
            mbps: bytes_to_mbps(pair[1].1.saturating_sub(pair[0].1), 1.0),
        })
        .collect()
}
fn bytes_to_mbps(bytes: u64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        0.0
    } else {
        bytes as f64 * 8.0 / 1_000_000.0 / seconds
    }
}

pub(crate) fn extract_target_ip(target: &str) -> Option<std::net::Ipv4Addr> {
    target.rsplit_once(':')?.0.parse().ok()
}
pub(crate) async fn wait_for_peer(
    server: &Server,
    target_ip: std::net::Ipv4Addr,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if server.status().peers.iter().any(|p| {
            p.ips
                .iter()
                .any(|ip| matches!(ip, std::net::IpAddr::V4(v4) if *v4 == target_ip))
        }) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let peers = server
        .status()
        .peers
        .iter()
        .map(|peer| format!("{}:{:?}:{:?}", peer.name, peer.ips, peer.path_class))
        .collect::<Vec<_>>()
        .join(",");
    Err(format!(
        "peer-map readiness timeout: target={target_ip} peers=[{peers}]"
    ))
}
pub(crate) fn extract_path_class(status: &ServerStatus, target: &str) -> String {
    let Some(target_ip) = extract_target_ip(target) else {
        return "unknown".into();
    };
    status
        .peers
        .iter()
        .find(|peer| {
            peer.ips
                .iter()
                .any(|ip| matches!(ip, std::net::IpAddr::V4(v4) if *v4 == target_ip))
        })
        .map_or_else(
            || "unknown".into(),
            |peer| {
                match peer.path_class {
                    rustscale_magicsock::PathClass::Direct => "direct",
                    rustscale_magicsock::PathClass::Derp => "derp",
                    rustscale_magicsock::PathClass::Relay => "relay",
                    rustscale_magicsock::PathClass::None => "none",
                }
                .into()
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{read_go, read_header, write_ack};
    use tokio::net::TcpListener;

    async fn synthetic_rsb1_round(parallel: usize) -> ThroughputResult {
        let mut clients = Vec::with_capacity(parallel);
        let mut servers = tokio::task::JoinSet::new();
        for index in 0..parallel {
            let (client, mut server) = tokio::io::duplex(1024);
            clients.push(client);
            servers.spawn(async move {
                let header = read_header(&mut server)
                    .await
                    .unwrap_or_else(|error| panic!("stream {index} read header: {error}"));
                assert_eq!(header.mode, MODE_THROUGHPUT, "stream {index}");
                write_ack(&mut server)
                    .await
                    .unwrap_or_else(|error| panic!("stream {index} write ACK: {error}"));
                read_go(&mut server)
                    .await
                    .unwrap_or_else(|error| panic!("stream {index} read GO: {error}"));
                server
                    .shutdown()
                    .await
                    .unwrap_or_else(|error| panic!("stream {index} shutdown: {error}"));
            });
        }

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            measure(
                clients,
                "userspace-tsnet",
                "100.64.0.1:5201".into(),
                0,
                "down",
                parallel,
                "direct".into(),
                "100.64.0.2".into(),
            ),
        )
        .await
        .expect("round deadline")
        .expect("complete RSB1 round");
        while let Some(joined) = servers.join_next().await {
            joined.expect("server worker");
        }
        result
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn repeated_userspace_p1_p10_p100_p500_rounds_count_every_stream() {
        for _ in 0..3 {
            for parallel in [1, 10, 100, 500] {
                let result = synthetic_rsb1_round(parallel).await;
                assert_eq!(
                    (result.established, result.handshaken, result.completed),
                    (parallel, parallel, parallel)
                );
            }
        }
    }

    // This preserves the stream index in a failure and exercises the exact
    // long-lived RSB1 down-path teardown that previously stranded stream 679
    // in a P1000 fan-out: client readers stop at the timing boundary, then
    // every server writer must still complete its shutdown.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn userspace_p1000_rsb1_down_shutdown_completes_every_stream() {
        const STREAMS: usize = 1000;
        let result = synthetic_rsb1_round(STREAMS).await;
        assert_eq!(
            (result.established, result.handshaken, result.completed),
            (STREAMS, STREAMS, STREAMS)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn incomplete_userspace_handshake_rejects_partial_capacity_and_joins_workers() {
        const STREAMS: usize = 10;
        const REJECTED: usize = 4;
        let mut clients = Vec::with_capacity(STREAMS);
        let mut servers = tokio::task::JoinSet::new();
        for index in 0..STREAMS {
            let (client, mut server) = tokio::io::duplex(1024);
            clients.push(client);
            servers.spawn(async move {
                let _ = read_header(&mut server).await;
                if index == REJECTED {
                    return;
                }
                let _ = write_ack(&mut server).await;
                let _ = read_go(&mut server).await;
            });
        }

        let error = match measure(
            clients,
            "userspace-tsnet",
            "100.64.0.1:5201".into(),
            0,
            "down",
            STREAMS,
            "direct".into(),
            "100.64.0.2".into(),
        )
        .await
        {
            Ok(_) => panic!("partial handshake must not produce a sample"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(&format!("stream {REJECTED} ACK")), "{error}");
        tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(joined) = servers.join_next().await {
                joined.expect("server worker");
            }
        })
        .await
        .expect("failed setup leaked an RSB1 worker");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn kernel_setup_completes_all_one_thousand_streams() {
        const STREAMS: usize = 1000;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            for _ in 0..STREAMS {
                let (mut stream, _) = listener.accept().await.unwrap();
                handlers.spawn(async move {
                    let header = read_header(&mut stream).await.unwrap();
                    assert_eq!(header.mode, MODE_THROUGHPUT);
                    write_ack(&mut stream).await.unwrap();
                    read_go(&mut stream).await.unwrap();
                });
            }
            while let Some(result) = handlers.join_next().await {
                result.unwrap();
            }
        });

        // A zero-duration internal trial isolates setup from data-plane speed.
        // The public CLI rejects zero, so production measurements still run
        // for their declared positive duration.
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            run_kernel(address.to_string(), 0, "down", STREAMS),
        )
        .await
        .expect("1000-stream setup exceeded the local gate")
        .unwrap();
        assert_eq!(
            (result.established, result.handshaken, result.completed),
            (STREAMS, STREAMS, STREAMS)
        );
        server.await.unwrap();
    }
}
