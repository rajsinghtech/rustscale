use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    do_test, read_json_line, validate_duration, write_json_line, CancellationToken, Config,
    ConfigResponse, Direction, SpeedtestError, TokioClock, HANDSHAKE_TIMEOUT, PROTOCOL_VERSION,
};
use crate::{Clock, Result as SpeedtestResult};

/// Run a speedtest over an already connected stream.
///
/// The duration is checked against the upstream 5–30 second bounds before any
/// bytes are written. Dropping this future cancels it; use
/// [`run_with_cancellation`] when cancellation must be signalled explicitly.
pub async fn run<S>(
    stream: &mut S,
    direction: Direction,
    duration: Duration,
) -> Result<Vec<SpeedtestResult>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_with_cancellation(stream, direction, duration, &CancellationToken::new()).await
}

/// Run a speedtest with explicit cancellation.
pub async fn run_with_cancellation<S>(
    stream: &mut S,
    direction: Direction,
    duration: Duration,
    cancellation: &CancellationToken,
) -> Result<Vec<SpeedtestResult>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_with_clock(stream, direction, duration, cancellation, &TokioClock).await
}

pub(crate) async fn run_with_clock<S>(
    stream: &mut S,
    direction: Direction,
    duration: Duration,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
) -> Result<Vec<SpeedtestResult>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_duration(duration)?;
    let test_duration_ns =
        i64::try_from(duration.as_nanos()).map_err(|_| SpeedtestError::InvalidDuration)?;
    let config = Config {
        version: PROTOCOL_VERSION,
        test_duration_ns,
        direction,
    };
    let handshake_deadline = clock.now() + HANDSHAKE_TIMEOUT;
    write_json_line(stream, &config, handshake_deadline, cancellation, clock).await?;

    let response: ConfigResponse =
        read_json_line(stream, handshake_deadline, cancellation, clock).await?;
    if let Some(error) = response.error.filter(|error| !error.is_empty()) {
        return Err(SpeedtestError::ServerRefused(error));
    }

    do_test(stream, direction, duration, cancellation, clock).await
}
