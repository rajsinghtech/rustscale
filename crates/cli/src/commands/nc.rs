//! `rustscale nc` — connect stdin/stdout to a tailnet TCP service through
//! the authorized LocalAPI dial transport.

use std::net::IpAddr;
use std::path::Path;

use rustscale_localclient::LocalClient;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::CliError;

const HELP: &str = "Connect to a port on a host, connected to stdin/stdout.

The connection is made by rustscaled through the tailnet. stdin EOF closes
only the remote write side; rustscale nc continues draining remote output.

Usage: rustscale nc <hostname-or-IP> <port>

Flags:
  -h, --help  show this help";
const COPY_BUFFER_BYTES: usize = 16 * 1024;

pub async fn run(args: Vec<String>, socket: &Path, _json: bool) -> Result<(), CliError> {
    if args
        .iter()
        .any(|argument| matches!(argument.as_str(), "-h" | "--help" | "-help"))
    {
        if args.len() != 1 {
            return Err(CliError(
                "usage: rustscale nc <hostname-or-IP> <port>".into(),
            ));
        }
        println!("{HELP}");
        return Ok(());
    }

    let operation = run_uncancelled(&args, socket);
    tokio::pin!(operation);
    tokio::select! {
        result = &mut operation => result,
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|error| CliError(format!("nc: failed to listen for cancellation: {error}")))?;
            Err(CliError("nc: canceled".into()))
        }
    }
}

async fn run_uncancelled(args: &[String], socket: &Path) -> Result<(), CliError> {
    // Match upstream ordering: report daemon state before command argument
    // errors, except that command help is handled before entering this path.
    let client = LocalClient::new(socket);
    let status = client.status_bounded().await?;
    if let Some(description) = crate::commands::status::backend_state_description(&status) {
        return Err(CliError(description));
    }

    let (host, port) = parse_target(args)?;
    let stream = client
        .dial_tcp_stream(host, port)
        .await
        .map_err(|error| CliError(format!("Dial({host:?}, {port}): {error}")))?;
    pump_duplex(tokio::io::stdin(), tokio::io::stdout(), stream).await
}

fn parse_target(args: &[String]) -> Result<(&str, u16), CliError> {
    if args.len() != 2 {
        return Err(CliError(
            "usage: rustscale nc <hostname-or-IP> <port>".into(),
        ));
    }
    let host = args[0].as_str();
    validate_host(host)?;
    let port_text = args[1].as_str();
    if port_text.is_empty() || !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError(format!("invalid port number {port_text:?}")));
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| CliError(format!("invalid port number {port_text:?}")))?;
    Ok((host, port))
}

fn validate_host(host: &str) -> Result<(), CliError> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if valid {
        Ok(())
    } else {
        Err(CliError(format!("invalid hostname or IP {host:?}")))
    }
}

async fn pump_duplex<R, W, S>(mut input: R, mut output: W, stream: S) -> Result<(), CliError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);
    let upload = async {
        copy_bounded(&mut input, &mut remote_write).await?;
        // stdin EOF is a TCP half-close, not session completion. The daemon
        // propagates this shutdown to the tailnet stream while download drains.
        remote_write.shutdown().await
    };
    let download = async {
        copy_bounded(&mut remote_read, &mut output).await?;
        output.flush().await
    };
    tokio::pin!(upload);
    tokio::pin!(download);

    tokio::select! {
        result = &mut upload => {
            result.map_err(|error| CliError(format!("nc upload: {error}")))?;
            download.await.map_err(|error| CliError(format!("nc download: {error}")))?;
        }
        result = &mut download => {
            // A remote EOF ends the session. Dropping `upload` and both split
            // halves closes the LocalAPI stream; no pump task survives return.
            result.map_err(|error| CliError(format!("nc download: {error}")))?;
        }
    }
    Ok(())
}

async fn copy_bounded<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0u64;
    let mut buffer = Box::new([0u8; COPY_BUFFER_BYTES]);
    loop {
        let count = reader.read(buffer.as_mut_slice()).await?;
        if count == 0 {
            return Ok(copied);
        }
        writer.write_all(&buffer[..count]).await?;
        copied = copied.saturating_add(count as u64);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::commands::status::backend_state_description;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_upstream_argument_shape_and_ports() {
        assert_eq!(parse_target(&args(&["peer", "0"])).unwrap(), ("peer", 0));
        assert_eq!(
            parse_target(&args(&["2001:db8::1", "65535"])).unwrap(),
            ("2001:db8::1", 65535)
        );
        for invalid in ["+1", "-1", "65536", "1x", ""] {
            assert!(
                parse_target(&args(&["peer", invalid])).is_err(),
                "{invalid}"
            );
        }
        assert!(parse_target(&args(&["peer:80"])).is_err());
    }

    #[test]
    fn validates_ip_and_dns_hosts() {
        for valid in [
            "100.64.0.1",
            "fd7a:115c:a1e0::1",
            "peer",
            "peer.example.ts.net",
            "peer.example.ts.net.",
            "a-b",
        ] {
            assert!(validate_host(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            ".",
            "peer..example",
            "-peer",
            "peer-",
            "peer name",
            "[fd7a:115c:a1e0::1]",
            "peer\r\nInjected: yes",
        ] {
            assert!(validate_host(invalid).is_err(), "{invalid:?}");
        }
    }

    #[tokio::test]
    async fn pump_preserves_binary_and_drains_after_input_half_close() {
        let payload = b"\x00\xffbinary\r\n\x80".to_vec();
        let reply = b"after-eof\x00\xfe".to_vec();
        let (client, mut remote) = tokio::io::duplex(64);
        let expected_payload = payload.clone();
        let expected_reply = reply.clone();
        let peer = tokio::spawn(async move {
            let mut received = Vec::new();
            remote.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected_payload);
            remote.write_all(&expected_reply).await.unwrap();
            remote.shutdown().await.unwrap();
        });

        let (output_writer, mut output_reader) = tokio::io::duplex(64);
        pump_duplex(std::io::Cursor::new(payload), output_writer, client)
            .await
            .unwrap();
        let mut output = Vec::new();
        output_reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, reply);
        peer.await.unwrap();
    }

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
