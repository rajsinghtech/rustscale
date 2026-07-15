use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::{JoinError, JoinSet};

use crate::{
    do_test, duration_from_config, read_json_line, write_json_line, CancellationToken, Clock,
    Config, ConfigResponse, Result as SpeedtestResult, SpeedtestError, TokioClock,
    DEFAULT_MAX_CONNECTIONS, HANDSHAKE_TIMEOUT, MAX_CONNECTIONS, PROTOCOL_VERSION,
};

/// A bounded speedtest server.
#[derive(Debug, Clone)]
pub struct Server {
    max_connections: usize,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

impl Server {
    /// Construct a server with an explicit concurrent-test bound.
    pub fn new(max_connections: usize) -> Result<Self, SpeedtestError> {
        if !(1..=MAX_CONNECTIONS).contains(&max_connections) {
            return Err(SpeedtestError::InvalidConcurrency {
                max: MAX_CONNECTIONS,
            });
        }
        Ok(Self { max_connections })
    }

    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Accept connections until cancellation. At most `max_connections` data
    /// buffers and tests are active at once; malformed clients are isolated to
    /// their connection and do not stop the listener.
    pub async fn serve(
        &self,
        listener: TcpListener,
        cancellation: CancellationToken,
    ) -> Result<(), SpeedtestError> {
        let permits = Arc::new(Semaphore::new(self.max_connections));
        let mut workers = JoinSet::new();
        let mut worker_failure = None;

        loop {
            while let Some(joined) = workers.try_join_next() {
                if let Err(error) = joined {
                    worker_failure = Some(error);
                    break;
                }
            }
            if worker_failure.is_some() {
                break;
            }

            let permit = tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                permit = Arc::clone(&permits).acquire_owned() => permit
                    .map_err(|_| SpeedtestError::Worker("connection limiter closed".into()))?,
            };

            let accepted = tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    drop(permit);
                    break;
                }
                accepted = listener.accept() => accepted,
            };
            let (mut stream, _) = match accepted {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    cancellation.cancel();
                    drain_workers(&mut workers).await?;
                    return Err(SpeedtestError::Io {
                        operation: "accepting a speedtest connection",
                        source: error,
                    });
                }
            };

            let child_cancellation = cancellation.child_token();
            workers.spawn(async move {
                let _permit = permit;
                // Peer protocol errors are connection-local. A task panic is
                // still surfaced by the parent through JoinSet.
                let _ = handle_connection_with_cancellation(&mut stream, &child_cancellation).await;
            });
        }

        cancellation.cancel();
        drain_workers(&mut workers).await?;
        if let Some(error) = worker_failure {
            return Err(worker_error(error));
        }
        Ok(())
    }
}

fn worker_error(error: JoinError) -> SpeedtestError {
    SpeedtestError::Worker(error.to_string())
}

async fn drain_workers(workers: &mut JoinSet<()>) -> Result<(), SpeedtestError> {
    while let Some(joined) = workers.join_next().await {
        joined.map_err(worker_error)?;
    }
    Ok(())
}

/// Serve with the default concurrency bound until cancellation.
pub async fn serve(
    listener: TcpListener,
    cancellation: CancellationToken,
) -> Result<(), SpeedtestError> {
    Server::default().serve(listener, cancellation).await
}

/// Handle one speedtest connection with default cancellation state.
pub async fn handle_connection<S>(stream: &mut S) -> Result<Vec<SpeedtestResult>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_connection_with_cancellation(stream, &CancellationToken::new()).await
}

/// Handle one speedtest connection with explicit cancellation.
pub async fn handle_connection_with_cancellation<S>(
    stream: &mut S,
    cancellation: &CancellationToken,
) -> Result<Vec<SpeedtestResult>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_connection_with_clock(stream, cancellation, &TokioClock).await
}

pub(crate) async fn handle_connection_with_clock<S>(
    stream: &mut S,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
) -> Result<Vec<SpeedtestResult>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake_deadline = clock.now() + HANDSHAKE_TIMEOUT;
    let mut config: Config =
        match read_json_line(stream, handshake_deadline, cancellation, clock).await {
            Ok(config) => config,
            Err(error) => {
                reject(
                    stream,
                    error.to_string(),
                    handshake_deadline,
                    cancellation,
                    clock,
                )
                .await;
                return Err(error);
            }
        };

    if config.version != PROTOCOL_VERSION {
        let error = SpeedtestError::VersionMismatch {
            server: PROTOCOL_VERSION,
            client: config.version,
        };
        reject(
            stream,
            error.to_string(),
            handshake_deadline,
            cancellation,
            clock,
        )
        .await;
        return Err(error);
    }

    let duration = match duration_from_config(&config) {
        Ok(duration) => duration,
        Err(error) => {
            reject(
                stream,
                error.to_string(),
                handshake_deadline,
                cancellation,
                clock,
            )
            .await;
            return Err(error);
        }
    };

    config.direction = config.direction.reverse();
    write_json_line(
        stream,
        &ConfigResponse::default(),
        handshake_deadline,
        cancellation,
        clock,
    )
    .await?;
    do_test(stream, config.direction, duration, cancellation, clock).await
}

async fn reject<S>(
    stream: &mut S,
    error: String,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    clock: &dyn Clock,
) where
    S: AsyncWrite + Unpin,
{
    // Preserve the protocol error as the function result. The response is
    // best-effort because a malformed peer may already have stopped reading.
    let _ = write_json_line(
        stream,
        &ConfigResponse { error: Some(error) },
        deadline,
        cancellation,
        clock,
    )
    .await;
}
