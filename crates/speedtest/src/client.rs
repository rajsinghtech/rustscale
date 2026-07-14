use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::protocol::{Config, ConfigResponse, Direction, PROTOCOL_VERSION};
use crate::{do_test, read_json_line, write_json_line, Result as SpeedtestResult, SpeedtestError};

/// Run a speedtest client over the given stream.
///
/// `stream` must implement `tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin`.
/// When composed with `tsnet::Server::dial()`, pass the returned `NetstackStream`.
pub async fn run<S>(
    stream: &mut S,
    direction: Direction,
    duration: Duration,
) -> std::result::Result<Vec<SpeedtestResult>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let test_duration_ns = u64::try_from(duration.as_nanos()).map_err(|_| {
        SpeedtestError::InvalidDuration("duration exceeds the protocol maximum".into())
    })?;
    if test_duration_ns == 0 {
        return Err(SpeedtestError::InvalidDuration(
            "duration must be greater than zero".into(),
        ));
    }

    let config = Config {
        version: PROTOCOL_VERSION,
        test_duration_ns,
        direction,
    };
    write_json_line(stream, &config).await?;
    stream.flush().await?;

    let response: ConfigResponse = read_json_line(stream).await?;
    if let Some(error) = response.error {
        return Err(SpeedtestError::ServerRefused(error));
    }

    do_test(stream, config).await
}
