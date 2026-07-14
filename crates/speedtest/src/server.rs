use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, ToSocketAddrs};

use crate::protocol::{Config, ConfigResponse, PROTOCOL_VERSION};
use crate::{do_test, read_json_line, write_json_line, Result as SpeedtestResult, SpeedtestError};

/// Handle one speedtest connection. Reverses the direction, runs the test, and
/// returns per-interval results from the server's side.
pub async fn handle_connection<S>(
    stream: &mut S,
) -> std::result::Result<Vec<SpeedtestResult>, SpeedtestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut config: Config = match read_json_line(stream).await {
        Ok(config) => config,
        Err(error) => {
            let response = ConfigResponse {
                error: Some(error.to_string()),
            };
            let _ = write_json_line(stream, &response).await;
            let _ = stream.flush().await;
            return Err(error);
        }
    };

    config.direction = config.direction.reverse();
    if config.version != PROTOCOL_VERSION {
        let error = format!(
            "version mismatch! Server is version {PROTOCOL_VERSION}, client is version {}",
            config.version
        );
        write_json_line(stream, &ConfigResponse { error: Some(error) }).await?;
        stream.flush().await?;
        return Err(SpeedtestError::VersionMismatch);
    }

    write_json_line(stream, &ConfigResponse { error: None }).await?;
    stream.flush().await?;
    do_test(stream, config).await
}

/// Accept speedtest connections until the listener is closed.
pub async fn serve<L>(listener: L) -> std::result::Result<(), SpeedtestError>
where
    L: ToSocketAddrs,
{
    let listener = TcpListener::bind(listener).await?;
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                tokio::spawn(async move {
                    let _ = handle_connection(&mut stream).await;
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}
