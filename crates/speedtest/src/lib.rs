//! Async client and server for Tailscale's version 2 TCP speedtest protocol.
//!
//! The control exchange is newline-delimited JSON and the data phase is a
//! stream of 2 MiB blocks. The public client and connection handler accept any
//! Tokio transport, which keeps tests hermetic and permits use with tsnet.

#![forbid(unsafe_code)]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::time::Duration;

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

mod client;
mod protocol;
mod server;

pub use client::{run, run_with_cancellation};
pub use protocol::{
    Config, ConfigResponse, Direction, Result, BLOCK_SIZE, DEFAULT_DURATION, DEFAULT_PORT,
    INCREMENT, MAX_CONTROL_FRAME_SIZE, MAX_DURATION, MAX_RESULT_COUNT, MIN_DURATION, MIN_INTERVAL,
    PROTOCOL_VERSION,
};
pub use server::{handle_connection, handle_connection_with_cancellation, serve, Server};
pub use tokio_util::sync::CancellationToken;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DATA_IO_GRACE: Duration = Duration::from_secs(5);
pub const DEFAULT_MAX_CONNECTIONS: usize = 16;
pub const MAX_CONNECTIONS: usize = 64;

type SleepFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep_until(&self, deadline: Instant) -> SleepFuture<'_>;
}

#[derive(Clone, Copy)]
struct TokioClock;

impl Clock for TokioClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Instant) -> SleepFuture<'_> {
        Box::pin(tokio::time::sleep_until(deadline))
    }
}

/// Errors returned by speedtest protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum SpeedtestError {
    #[error("JSON control message error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("i/o error while {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("timed out while {operation}")]
    Timeout { operation: &'static str },
    #[error("speedtest operation cancelled")]
    Cancelled,
    #[error("server refused: {0}")]
    ServerRefused(String),
    #[error("version mismatch! Server is version {server}, client is version {client}")]
    VersionMismatch { server: i32, client: i32 },
    #[error("test duration must be within 5s and 30s")]
    InvalidDuration,
    #[error("control frame exceeded {limit} bytes")]
    ControlFrameTooLarge { limit: usize },
    #[error("peer closed while sending a control frame ({received} bytes received)")]
    TruncatedControlFrame { received: usize },
    #[error("peer closed partway through a data block ({received} of {expected} bytes)")]
    TruncatedDataBlock { received: usize, expected: usize },
    #[error("peer made zero progress while {operation}")]
    ZeroProgress { operation: &'static str },
    #[error("byte counter overflow")]
    ByteCountOverflow,
    #[error("result count exceeded {limit}")]
    TooManyResults { limit: usize },
    #[error("clock moved backwards")]
    ClockMovedBackwards,
    #[error("maximum concurrent connections must be between 1 and {max}")]
    InvalidConcurrency { max: usize },
    #[error("speedtest worker task failed: {0}")]
    Worker(String),
}

fn io_error(operation: &'static str, source: io::Error) -> SpeedtestError {
    SpeedtestError::Io { operation, source }
}

fn validate_duration(duration: Duration) -> StdResult<(), SpeedtestError> {
    if !(MIN_DURATION..=MAX_DURATION).contains(&duration) {
        return Err(SpeedtestError::InvalidDuration);
    }
    Ok(())
}

fn duration_from_config(config: &Config) -> StdResult<Duration, SpeedtestError> {
    let nanos =
        u64::try_from(config.test_duration_ns).map_err(|_| SpeedtestError::InvalidDuration)?;
    let duration = Duration::from_nanos(nanos);
    validate_duration(duration)?;
    Ok(duration)
}

async fn read_some<S>(
    stream: &mut S,
    buffer: &mut [u8],
    deadline: Instant,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
    operation: &'static str,
) -> StdResult<usize, SpeedtestError>
where
    S: AsyncRead + Unpin,
{
    if cancellation.is_cancelled() {
        return Err(SpeedtestError::Cancelled);
    }
    if clock.now() >= deadline {
        return Err(SpeedtestError::Timeout { operation });
    }
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(SpeedtestError::Cancelled),
        () = clock.sleep_until(deadline) => Err(SpeedtestError::Timeout { operation }),
        result = stream.read(buffer) => result.map_err(|error| io_error(operation, error)),
    }
}

async fn write_some<S>(
    stream: &mut S,
    buffer: &[u8],
    deadline: Instant,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
    operation: &'static str,
) -> StdResult<usize, SpeedtestError>
where
    S: AsyncWrite + Unpin,
{
    if cancellation.is_cancelled() {
        return Err(SpeedtestError::Cancelled);
    }
    if clock.now() >= deadline {
        return Err(SpeedtestError::Timeout { operation });
    }
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(SpeedtestError::Cancelled),
        () = clock.sleep_until(deadline) => Err(SpeedtestError::Timeout { operation }),
        result = stream.write(buffer) => result.map_err(|error| io_error(operation, error)),
    }
}

async fn write_all_bounded<S>(
    stream: &mut S,
    mut buffer: &[u8],
    deadline: Instant,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
    operation: &'static str,
) -> StdResult<(), SpeedtestError>
where
    S: AsyncWrite + Unpin,
{
    while !buffer.is_empty() {
        let written = write_some(stream, buffer, deadline, cancellation, clock, operation).await?;
        if written == 0 {
            return Err(SpeedtestError::ZeroProgress { operation });
        }
        buffer = &buffer[written..];
    }
    Ok(())
}

async fn flush_bounded<S>(
    stream: &mut S,
    deadline: Instant,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
    operation: &'static str,
) -> StdResult<(), SpeedtestError>
where
    S: AsyncWrite + Unpin,
{
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(SpeedtestError::Cancelled),
        () = clock.sleep_until(deadline) => Err(SpeedtestError::Timeout { operation }),
        result = stream.flush() => result.map_err(|error| io_error(operation, error)),
    }
}

async fn shutdown_bounded<S>(
    stream: &mut S,
    deadline: Instant,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
) -> StdResult<(), SpeedtestError>
where
    S: AsyncWrite + Unpin,
{
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(SpeedtestError::Cancelled),
        () = clock.sleep_until(deadline) => Err(SpeedtestError::Timeout { operation: "closing the data stream" }),
        result = stream.shutdown() => result.map_err(|error| io_error("closing the data stream", error)),
    }
}

async fn write_json_line<S, T>(
    stream: &mut S,
    message: &T,
    deadline: Instant,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
) -> StdResult<(), SpeedtestError>
where
    S: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let mut data = serde_json::to_vec(message)?;
    if data.len() > MAX_CONTROL_FRAME_SIZE {
        return Err(SpeedtestError::ControlFrameTooLarge {
            limit: MAX_CONTROL_FRAME_SIZE,
        });
    }
    data.push(b'\n');
    write_all_bounded(
        stream,
        &data,
        deadline,
        cancellation,
        clock,
        "writing a control frame",
    )
    .await?;
    flush_bounded(
        stream,
        deadline,
        cancellation,
        clock,
        "flushing a control frame",
    )
    .await
}

async fn read_json_line<S, T>(
    stream: &mut S,
    deadline: Instant,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
) -> StdResult<T, SpeedtestError>
where
    S: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut data = Vec::with_capacity(128);
    let mut byte = [0_u8; 1];
    loop {
        let count = read_some(
            stream,
            &mut byte,
            deadline,
            cancellation,
            clock,
            "reading a control frame",
        )
        .await?;
        if count == 0 {
            return Err(SpeedtestError::TruncatedControlFrame {
                received: data.len(),
            });
        }
        if byte[0] == b'\n' {
            return serde_json::from_slice(&data).map_err(Into::into);
        }
        if data.len() == MAX_CONTROL_FRAME_SIZE {
            return Err(SpeedtestError::ControlFrameTooLarge {
                limit: MAX_CONTROL_FRAME_SIZE,
            });
        }
        data.push(byte[0]);
    }
}

enum BlockRead {
    Complete,
    CleanEof,
}

async fn read_block<S>(
    stream: &mut S,
    buffer: &mut [u8],
    deadline: Instant,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
) -> StdResult<BlockRead, SpeedtestError>
where
    S: AsyncRead + Unpin,
{
    let mut received = 0;
    while received < buffer.len() {
        let count = read_some(
            stream,
            &mut buffer[received..],
            deadline,
            cancellation,
            clock,
            "reading test data",
        )
        .await?;
        if count == 0 {
            return if received == 0 {
                Ok(BlockRead::CleanEof)
            } else {
                Err(SpeedtestError::TruncatedDataBlock {
                    received,
                    expected: buffer.len(),
                })
            };
        }
        received += count;
    }
    Ok(BlockRead::Complete)
}

fn elapsed(later: Instant, earlier: Instant) -> StdResult<Duration, SpeedtestError> {
    later
        .checked_duration_since(earlier)
        .ok_or(SpeedtestError::ClockMovedBackwards)
}

fn push_result(results: &mut Vec<Result>, result: Result) -> StdResult<(), SpeedtestError> {
    if results.len() == MAX_RESULT_COUNT {
        return Err(SpeedtestError::TooManyResults {
            limit: MAX_RESULT_COUNT,
        });
    }
    results.push(result);
    Ok(())
}

async fn do_test<S>(
    stream: &mut S,
    direction: Direction,
    duration: Duration,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
) -> StdResult<Vec<Result>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; BLOCK_SIZE];
    if direction == Direction::Upload {
        rand::rngs::OsRng
            .try_fill_bytes(&mut buffer)
            .map_err(|error| io_error("generating test data", io::Error::other(error)))?;
    }

    let start_time = clock.now();
    let data_deadline = start_time + duration + DATA_IO_GRACE;
    let mut last_calculated = start_time;
    let mut current_time = None;
    let mut interval_bytes = 0_u64;
    let mut total_bytes = 0_u64;
    let mut results = Vec::with_capacity(MAX_RESULT_COUNT);

    loop {
        match direction {
            Direction::Upload => {
                write_all_bounded(
                    stream,
                    &buffer,
                    data_deadline,
                    cancellation,
                    clock,
                    "writing test data",
                )
                .await?;
            }
            Direction::Download => {
                if matches!(
                    read_block(stream, &mut buffer, data_deadline, cancellation, clock).await?,
                    BlockRead::CleanEof
                ) {
                    break;
                }
            }
        }

        interval_bytes = interval_bytes
            .checked_add(BLOCK_SIZE as u64)
            .ok_or(SpeedtestError::ByteCountOverflow)?;
        total_bytes = total_bytes
            .checked_add(BLOCK_SIZE as u64)
            .ok_or(SpeedtestError::ByteCountOverflow)?;
        let now = clock.now();
        current_time = Some(now);

        if elapsed(now, last_calculated)? >= INCREMENT {
            push_result(
                &mut results,
                Result {
                    bytes: interval_bytes,
                    interval_start: last_calculated,
                    interval_end: now,
                    is_total: false,
                },
            )?;
            last_calculated = now;
            interval_bytes = 0;
        }

        if direction == Direction::Upload && elapsed(now, start_time)? > duration {
            break;
        }
    }

    if direction == Direction::Upload {
        shutdown_bounded(stream, data_deadline, cancellation, clock).await?;
    }

    let Some(end_time) = current_time else {
        return Ok(results);
    };
    if elapsed(end_time, last_calculated)? > MIN_INTERVAL {
        push_result(
            &mut results,
            Result {
                bytes: interval_bytes,
                interval_start: last_calculated,
                interval_end: end_time,
                is_total: false,
            },
        )?;
    }
    if elapsed(end_time, start_time)? > MIN_INTERVAL {
        push_result(
            &mut results,
            Result {
                bytes: total_bytes,
                interval_start: start_time,
                interval_end: end_time,
                is_total: true,
            },
        )?;
    }
    Ok(results)
}

#[cfg(test)]
mod tests;
