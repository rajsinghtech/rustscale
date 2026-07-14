//! `rustscale nc` — netcat-like connection via the daemon.

use std::path::Path;

use rustscale_localclient::LocalClient;
use tokio::io::AsyncWriteExt;

use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, _json: bool) -> Result<(), CliError> {
    let client = LocalClient::new(socket);
    let status = client.status().await?;
    if let Some(description) = crate::commands::status::backend_state_description(&status) {
        return Err(CliError(description));
    }

    if args.len() != 2 || args.iter().any(|arg| arg.starts_with('-')) {
        return Err(CliError(
            "usage: rustscale nc <hostname-or-IP> <port>".into(),
        ));
    }
    let host = &args[0];
    let port: u16 = args[1]
        .parse()
        .map_err(|_| CliError(format!("invalid port: {}", args[1])))?;

    let stream = client.dial_tcp_stream(host, port).await?;
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let mut stdin_to_stream = tokio::spawn(async move {
        let result = tokio::io::copy(&mut tokio::io::stdin(), &mut write_half).await;
        if result.is_ok() {
            write_half.shutdown().await?;
        }
        result
    });
    let mut stream_to_stdout =
        tokio::spawn(
            async move { tokio::io::copy(&mut read_half, &mut tokio::io::stdout()).await },
        );

    // A closed stdin or remote stream ends an nc session. Abort the other
    // half so a pipeline does not wait forever for an unrelated EOF.
    let result = tokio::select! {
        result = &mut stdin_to_stream => {
            stream_to_stdout.abort();
            result
        }
        result = &mut stream_to_stdout => {
            stdin_to_stream.abort();
            result
        }
    };
    result
        .map_err(|error| CliError(error.to_string()))?
        .map_err(|error| CliError(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::commands::status::backend_state_description;

    #[test]
    fn nc_allows_only_running_or_starting_backend_states() {
        for state in ["Running", "Starting"] {
            assert!(backend_state_description(&json!({"BackendState": state})).is_none());
        }
        for (state, description) in [
            ("Stopped", "Tailscale is stopped."),
            ("NeedsLogin", "Logged out."),
            (
                "NeedsMachineAuth",
                "Machine is not yet approved by tailnet admin.",
            ),
            ("NoState", "unexpected state: NoState"),
        ] {
            assert_eq!(
                backend_state_description(&json!({"BackendState": state})).as_deref(),
                Some(description)
            );
        }
        assert_eq!(
            backend_state_description(&json!({
                "BackendState": "NeedsLogin",
                "AuthURL": "https://login.example.test/"
            }))
            .as_deref(),
            Some("Logged out.\nLog in at: https://login.example.test/")
        );
    }
}
