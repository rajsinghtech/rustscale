//! A TCP throughput test protocol compatible with Tailscale's speedtest service.

use std::result::Result as StdResult;

mod client;
mod protocol;
mod server;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

pub use client::run;
pub use protocol::{
    Config, ConfigResponse, Direction, Result, BLOCK_SIZE, DEFAULT_DURATION, DEFAULT_PORT,
    INCREMENT, MAX_DURATION, MIN_DURATION, MIN_INTERVAL, PROTOCOL_VERSION,
};
pub use server::{handle_connection, serve};

/// Errors returned by speedtest protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum SpeedtestError {
    /// A handshake JSON message could not be encoded or decoded.
    #[error("json handshake error: {0}")]
    Json(#[from] serde_json::Error),
    /// The TCP stream encountered an I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The server rejected the handshake.
    #[error("server refused: {0}")]
    ServerRefused(String),
    /// The peer uses a different speedtest protocol version.
    #[error("version mismatch")]
    VersionMismatch,
    /// The requested test duration cannot be represented by the protocol.
    #[error("invalid duration: {0}")]
    InvalidDuration(String),
}

async fn write_json_line<S, T>(stream: &mut S, message: &T) -> StdResult<(), SpeedtestError>
where
    S: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let mut data = serde_json::to_vec(message)?;
    data.push(b'\n');
    stream.write_all(&data).await?;
    Ok(())
}

async fn read_json_line<S, T>(stream: &mut S) -> StdResult<T, SpeedtestError>
where
    S: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut data = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            return Ok(serde_json::from_slice(&data)?);
        }
        data.push(byte);
    }
}

async fn do_test<S>(stream: &mut S, conf: Config) -> StdResult<Vec<Result>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; BLOCK_SIZE];
    if conf.direction == Direction::Upload {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buffer);
    }

    let duration = std::time::Duration::from_nanos(conf.test_duration_ns);
    let start_time = Instant::now();
    let deadline = start_time + duration;
    // The peer closes its write half when it finishes. Retain a small grace
    // period so a read-side endpoint can observe that EOF instead of racing
    // the peer's final block at the nominal test deadline.
    let read_deadline = deadline + std::time::Duration::from_secs(5);
    let mut last_calculated = start_time;
    let mut interval_bytes = 0_u64;
    let mut total_bytes = 0_u64;
    let mut results = Vec::new();

    loop {
        let bytes = match conf.direction {
            Direction::Upload => {
                stream.write_all(&buffer).await?;
                stream.flush().await?;
                buffer.len() as u64
            }
            Direction::Download => {
                tokio::select! {
                    read = stream.read_exact(&mut buffer) => match read {
                        Ok(bytes) => bytes as u64,
                        Err(error) if matches!(error.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset) => break,
                        Err(error) => return Err(error.into()),
                    },
                    () = tokio::time::sleep_until(read_deadline) => break,
                }
            }
        };

        interval_bytes += bytes;
        total_bytes += bytes;
        let current_time = Instant::now();
        if current_time.duration_since(last_calculated) >= INCREMENT {
            results.push(Result {
                bytes: interval_bytes,
                interval_start: last_calculated,
                interval_end: current_time,
                is_total: false,
            });
            last_calculated = current_time;
            interval_bytes = 0;
        }

        if conf.direction == Direction::Upload && current_time >= deadline {
            break;
        }
    }

    let end_time = Instant::now();
    if conf.direction == Direction::Upload {
        stream.shutdown().await?;
    }

    if end_time.duration_since(last_calculated) >= MIN_INTERVAL {
        results.push(Result {
            bytes: interval_bytes,
            interval_start: last_calculated,
            interval_end: end_time,
            is_total: false,
        });
    }
    results.push(Result {
        bytes: total_bytes,
        interval_start: start_time,
        interval_end: end_time,
        is_total: true,
    });

    Ok(results)
}
