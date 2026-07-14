//! `rustscale wait` — wait for the backend to reach Running state.
//!
//! The daemon can take a moment to create its LocalAPI socket, so this first
//! waits for the socket to become reachable and then watches the IPN bus. The
//! latter avoids a polling delay once the backend transitions to Running.

use std::path::Path;
use std::time::Duration;

use rustscale_ipn::{State, NOTIFY_INITIAL_STATE};
use rustscale_localclient::LocalClient;

use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, _json: bool) -> Result<(), CliError> {
    let timeout = parse_wait_timeout(&args)?;
    let client = LocalClient::new(socket);

    if timeout.is_zero() {
        wait_for_reachable(&client).await?;
        wait_for_running(&client).await
    } else {
        let deadline = tokio::time::Instant::now() + timeout;
        tokio::time::timeout_at(deadline, wait_for_reachable(&client))
            .await
            .map_err(|_| {
                CliError("wait: timed out waiting for daemon to become reachable".into())
            })??;
        tokio::time::timeout_at(deadline, wait_for_running(&client))
            .await
            .map_err(|_| CliError(format!("wait: timed out after {}s", timeout.as_secs())))?
    }
}

/// Poll status until the daemon responds, with exponential backoff capped at
/// two seconds.
async fn wait_for_reachable(client: &LocalClient) -> Result<(), CliError> {
    let mut delay = Duration::from_millis(100);
    loop {
        if client.status().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }
}

/// Watch the IPN bus until it reports the Running state.
async fn wait_for_running(client: &LocalClient) -> Result<(), CliError> {
    let mut watch = client.watch_ipn_bus(NOTIFY_INITIAL_STATE).await?;
    loop {
        match watch.next().await {
            Ok(Some(notify)) if notify.State == Some(State::Running) => return Ok(()),
            Ok(Some(_)) => {}
            Ok(None) => return Err(CliError("wait: daemon connection closed".into())),
            Err(error) => return Err(CliError(format!("wait: {error}"))),
        }
    }
}

/// Parse `--timeout` as a Go-style duration, or a bare number of seconds.
/// Zero means wait indefinitely.
fn parse_wait_timeout(args: &[String]) -> Result<Duration, CliError> {
    let mut timeout = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let value = if arg == "--timeout" {
            index += 1;
            args.get(index)
                .map(String::as_str)
                .ok_or_else(|| CliError("--timeout requires a value".into()))?
        } else if let Some(value) = arg.strip_prefix("--timeout=") {
            value
        } else if arg.starts_with('-') {
            return Err(CliError(format!("unknown flag: {arg}")));
        } else {
            return Err(CliError(format!("unexpected argument: {arg}")));
        };

        if timeout.replace(parse_duration(value)?).is_some() {
            return Err(CliError("--timeout specified more than once".into()));
        }
        index += 1;
    }
    Ok(timeout.unwrap_or(Duration::ZERO))
}

fn parse_duration(value: &str) -> Result<Duration, CliError> {
    if value == "0" {
        return Ok(Duration::ZERO);
    }

    // Preserve the CLI's historic bare-seconds form before parsing Go's
    // compound duration syntax (for example, `1m30s`).
    if let Ok(seconds) = value.parse::<f64>() {
        return duration_from_seconds(seconds, value);
    }

    let mut remaining = value;
    let mut seconds = 0.0;
    while !remaining.is_empty() {
        let number_end = remaining
            .find(|character: char| !(character.is_ascii_digit() || character == '.'))
            .unwrap_or(remaining.len());
        let number = remaining[..number_end]
            .parse::<f64>()
            .map_err(|_| CliError(format!("invalid --timeout value: {value}")))?;
        let (unit, multiplier) = [
            ("ns", 1e-9),
            ("us", 1e-6),
            ("µs", 1e-6),
            ("ms", 1e-3),
            ("s", 1.0),
            ("m", 60.0),
            ("h", 3_600.0),
        ]
        .into_iter()
        .find(|(unit, _)| remaining[number_end..].starts_with(unit))
        .ok_or_else(|| CliError(format!("invalid --timeout value: {value}")))?;
        seconds += number * multiplier;
        remaining = &remaining[number_end + unit.len()..];
    }
    duration_from_seconds(seconds, value)
}

fn duration_from_seconds(seconds: f64, original: &str) -> Result<Duration, CliError> {
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(CliError(format!("invalid --timeout value: {original}")));
    }
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| CliError(format!("invalid --timeout value: {original}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wait_timeout_forms() {
        assert_eq!(parse_wait_timeout(&[]).unwrap(), Duration::ZERO);
        assert_eq!(
            parse_wait_timeout(&["--timeout=5s".into()]).unwrap(),
            Duration::from_secs(5)
        );
        assert_eq!(
            parse_wait_timeout(&["--timeout".into(), "1m".into()]).unwrap(),
            Duration::from_secs(60)
        );
        assert_eq!(
            parse_wait_timeout(&["--timeout=500".into()]).unwrap(),
            Duration::from_secs(500)
        );
        assert_eq!(
            parse_wait_timeout(&["--timeout=1m30s".into()]).unwrap(),
            Duration::from_secs(90)
        );
        assert_eq!(
            parse_wait_timeout(&["--timeout=0".into()]).unwrap(),
            Duration::ZERO
        );
    }

    #[test]
    fn rejects_invalid_wait_timeout() {
        assert!(parse_wait_timeout(&["--timeout=-1s".into()]).is_err());
        assert!(parse_wait_timeout(&["--timeout=wat".into()]).is_err());
    }
}
