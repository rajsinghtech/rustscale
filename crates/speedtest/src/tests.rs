use std::collections::VecDeque;
use std::future::pending;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::*;

async fn read_line(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await.unwrap();
        line.push(byte);
        if byte == b'\n' {
            return line;
        }
    }
}

async fn write_config(stream: &mut (impl AsyncWrite + Unpin), config: &Config) {
    let mut wire = serde_json::to_vec(config).unwrap();
    wire.push(b'\n');
    stream.write_all(&wire).await.unwrap();
}

#[test]
fn control_messages_are_byte_compatible() {
    let config = Config {
        version: PROTOCOL_VERSION,
        test_duration_ns: 5_000_000_000,
        direction: Direction::Download,
    };
    assert_eq!(
        serde_json::to_vec(&config).unwrap(),
        br#"{"version":2,"time":5000000000,"direction":0}"#
    );
    assert_eq!(
        serde_json::to_vec(&ConfigResponse::default()).unwrap(),
        b"{}"
    );
    assert_eq!(
        serde_json::to_vec(&ConfigResponse {
            error: Some(String::new())
        })
        .unwrap(),
        b"{}"
    );
    assert_eq!(
        serde_json::to_vec(&ConfigResponse {
            error: Some("bad config".into())
        })
        .unwrap(),
        br#"{"error":"bad config"}"#
    );
}

#[test]
fn direction_and_result_helpers_match_upstream() {
    assert_eq!(Direction::Download.to_string(), "download");
    assert_eq!(Direction::Upload.to_string(), "upload");
    assert!(serde_json::from_str::<Direction>("2").is_err());

    let start = Instant::now();
    let result = Result {
        bytes: 1_000_000,
        interval_start: start,
        interval_end: start + Duration::from_secs(2),
        is_total: false,
    };
    assert_eq!(result.interval(), Duration::from_secs(2));
    assert!((result.megabytes() - 1.0).abs() < f64::EPSILON);
    assert!((result.megabits() - 8.0).abs() < f64::EPSILON);
    assert!((result.mbits_per_sec() - 4.0).abs() < f64::EPSILON);
}

#[tokio::test]
async fn version_mismatch_has_upstream_response_text() {
    let (mut client, mut server) = tokio::io::duplex(2048);
    let task = tokio::spawn(async move { handle_connection(&mut server).await });
    write_config(
        &mut client,
        &Config {
            version: 1,
            test_duration_ns: 5_000_000_000,
            direction: Direction::Download,
        },
    )
    .await;

    assert_eq!(
        read_line(&mut client).await,
        b"{\"error\":\"version mismatch! Server is version 2, client is version 1\"}\n"
    );
    assert!(matches!(
        task.await.unwrap(),
        Err(SpeedtestError::VersionMismatch {
            server: 2,
            client: 1
        })
    ));
}

#[tokio::test]
async fn server_rejects_duration_below_and_above_bounds() {
    for nanos in [4_999_999_999, 30_000_000_001, -1] {
        let (mut client, mut server) = tokio::io::duplex(2048);
        let task = tokio::spawn(async move { handle_connection(&mut server).await });
        write_config(
            &mut client,
            &Config {
                version: PROTOCOL_VERSION,
                test_duration_ns: nanos,
                direction: Direction::Download,
            },
        )
        .await;
        let response = read_line(&mut client).await;
        assert_eq!(
            response,
            b"{\"error\":\"test duration must be within 5s and 30s\"}\n"
        );
        assert!(matches!(
            task.await.unwrap(),
            Err(SpeedtestError::InvalidDuration)
        ));
    }
}

#[tokio::test]
async fn client_rejects_invalid_duration_before_writing() {
    for duration in [
        Duration::ZERO,
        MIN_DURATION.checked_sub(Duration::from_nanos(1)).unwrap(),
        MAX_DURATION + Duration::from_nanos(1),
    ] {
        let (mut client, mut peer) = tokio::io::duplex(64);
        assert!(matches!(
            run(&mut client, Direction::Download, duration).await,
            Err(SpeedtestError::InvalidDuration)
        ));
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }
}

#[tokio::test]
async fn oversized_control_frame_is_bounded_and_rejected() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { handle_connection(&mut server).await });
    client
        .write_all(&vec![b'x'; MAX_CONTROL_FRAME_SIZE + 1])
        .await
        .unwrap();
    let error = task.await.unwrap().unwrap_err();
    assert!(matches!(
        error,
        SpeedtestError::ControlFrameTooLarge {
            limit: MAX_CONTROL_FRAME_SIZE
        }
    ));
}

#[tokio::test]
async fn truncated_and_malformed_control_frames_fail_closed() {
    for wire in [&b"{\"version\":"[..], &b"not-json\n"[..]] {
        let (mut client, mut server) = tokio::io::duplex(2048);
        let task = tokio::spawn(async move { handle_connection(&mut server).await });
        client.write_all(wire).await.unwrap();
        client.shutdown().await.unwrap();
        let error = task.await.unwrap().unwrap_err();
        if wire.ends_with(b"\n") {
            assert!(matches!(error, SpeedtestError::Json(_)));
        } else {
            assert!(matches!(
                error,
                SpeedtestError::TruncatedControlFrame { .. }
            ));
        }
    }
}

#[tokio::test]
async fn explicit_cancellation_stops_a_stalled_handshake() {
    let (mut client, _peer) = tokio::io::duplex(1024);
    let cancellation = CancellationToken::new();
    let child = cancellation.clone();
    let task = tokio::spawn(async move {
        run_with_cancellation(&mut client, Direction::Download, MIN_DURATION, &child).await
    });
    tokio::task::yield_now().await;
    cancellation.cancel();
    assert!(matches!(
        task.await.unwrap(),
        Err(SpeedtestError::Cancelled)
    ));
}

#[tokio::test(start_paused = true)]
async fn stalled_handshake_obeys_monotonic_deadline() {
    let (mut client, _peer) = tokio::io::duplex(1024);
    let task =
        tokio::spawn(async move { run(&mut client, Direction::Download, MIN_DURATION).await });
    tokio::task::yield_now().await;
    tokio::time::advance(HANDSHAKE_TIMEOUT + Duration::from_millis(1)).await;
    assert!(matches!(
        task.await.unwrap(),
        Err(SpeedtestError::Timeout {
            operation: "reading a control frame"
        })
    ));
}

#[tokio::test(start_paused = true)]
async fn stalled_data_phase_obeys_deadline() {
    let (mut receiver, _peer) = tokio::io::duplex(64);
    let task = tokio::spawn(async move {
        do_test(
            &mut receiver,
            Direction::Download,
            Duration::from_millis(20),
            &CancellationToken::new(),
            &TokioClock,
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(DATA_IO_GRACE + Duration::from_millis(21)).await;
    assert!(matches!(
        task.await.unwrap(),
        Err(SpeedtestError::Timeout {
            operation: "reading test data"
        })
    ));
}

#[tokio::test]
async fn duplex_handles_partial_io_and_preserves_block_counts() {
    // A capacity far smaller than one wire block forces many partial reads and
    // writes without involving sockets or wall-clock dependencies.
    let (mut uploader, mut downloader) = tokio::io::duplex(16 * 1024);
    let upload_cancel = CancellationToken::new();
    let download_cancel = CancellationToken::new();
    let duration = Duration::from_millis(30);
    let (uploaded, downloaded) = tokio::join!(
        do_test(
            &mut uploader,
            Direction::Upload,
            duration,
            &upload_cancel,
            &TokioClock
        ),
        do_test(
            &mut downloader,
            Direction::Download,
            duration,
            &download_cancel,
            &TokioClock
        )
    );
    let uploaded = uploaded.unwrap();
    let downloaded = downloaded.unwrap();
    let upload_total = uploaded.last().unwrap();
    let download_total = downloaded.last().unwrap();
    assert!(upload_total.is_total);
    assert!(download_total.is_total);
    assert!(upload_total.bytes >= BLOCK_SIZE as u64);
    assert_eq!(upload_total.bytes, download_total.bytes);
    assert_eq!(upload_total.bytes % BLOCK_SIZE as u64, 0);
}

#[tokio::test]
async fn truncated_data_block_fails_closed_without_counting_it() {
    let (mut producer, mut consumer) = tokio::io::duplex(8192);
    let producer_task = tokio::spawn(async move {
        let bytes = vec![7_u8; BLOCK_SIZE - 1];
        producer.write_all(&bytes).await.unwrap();
        producer.shutdown().await.unwrap();
    });
    let error = do_test(
        &mut consumer,
        Direction::Download,
        Duration::from_millis(20),
        &CancellationToken::new(),
        &TokioClock,
    )
    .await
    .unwrap_err();
    producer_task.await.unwrap();
    assert!(matches!(
        error,
        SpeedtestError::TruncatedDataBlock {
            received,
            expected: BLOCK_SIZE
        } if received == BLOCK_SIZE - 1
    ));
}

#[derive(Default)]
struct ZeroWriter;

impl AsyncRead for ZeroWriter {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ZeroWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn zero_progress_writer_is_rejected() {
    let error = do_test(
        &mut ZeroWriter,
        Direction::Upload,
        Duration::from_millis(20),
        &CancellationToken::new(),
        &TokioClock,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        SpeedtestError::ZeroProgress {
            operation: "writing test data"
        }
    ));
}

#[derive(Clone)]
struct StepClock {
    now: Arc<Mutex<Instant>>,
}

impl StepClock {
    fn new() -> Self {
        Self {
            now: Arc::new(Mutex::new(Instant::now())),
        }
    }

    fn advance(&self, duration: Duration) {
        let mut now = self.now.lock().unwrap();
        *now += duration;
    }
}

impl Clock for StepClock {
    fn now(&self) -> Instant {
        *self.now.lock().unwrap()
    }

    fn sleep_until(&self, _deadline: Instant) -> SleepFuture<'_> {
        Box::pin(pending())
    }
}

struct SteppedWriter {
    clock: StepClock,
    steps: VecDeque<Duration>,
}

impl AsyncRead for SteppedWriter {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SteppedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let step = self.steps.pop_front().unwrap_or(Duration::from_secs(1));
        self.clock.advance(step);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn measurement_intervals_follow_upstream_semantics() {
    let clock = StepClock::new();
    let mut stream = SteppedWriter {
        clock: clock.clone(),
        steps: VecDeque::from([
            Duration::from_millis(400),
            Duration::from_millis(600),
            Duration::from_millis(20),
        ]),
    };
    let results = do_test(
        &mut stream,
        Direction::Upload,
        Duration::from_secs(1),
        &CancellationToken::new(),
        &clock,
    )
    .await
    .unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].bytes, 2 * BLOCK_SIZE as u64);
    assert_eq!(results[0].interval(), Duration::from_secs(1));
    assert!(!results[0].is_total);
    assert_eq!(results[1].bytes, BLOCK_SIZE as u64);
    assert_eq!(results[1].interval(), Duration::from_millis(20));
    assert!(!results[1].is_total);
    assert_eq!(results[2].bytes, 3 * BLOCK_SIZE as u64);
    assert_eq!(results[2].interval(), Duration::from_millis(1020));
    assert!(results[2].is_total);
}

#[test]
fn server_concurrency_is_strictly_bounded() {
    assert_eq!(Server::default().max_connections(), DEFAULT_MAX_CONNECTIONS);
    assert!(Server::new(1).is_ok());
    assert!(Server::new(MAX_CONNECTIONS).is_ok());
    assert!(matches!(
        Server::new(0),
        Err(SpeedtestError::InvalidConcurrency { .. })
    ));
    assert!(matches!(
        Server::new(MAX_CONNECTIONS + 1),
        Err(SpeedtestError::InvalidConcurrency { .. })
    ));
}
