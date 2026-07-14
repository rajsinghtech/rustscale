//! `rustscale wait` — wait for the backend and its configured interface.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use rustscale_ipn::{State, NOTIFY_INITIAL_STATE};
use rustscale_localclient::LocalClient;
use serde_json::Value;

use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, _json: bool) -> Result<(), CliError> {
    let timeout = parse_wait_timeout(&args)?;
    let client = LocalClient::new(socket);
    let wait = wait_until_ready(&client);
    if timeout.is_zero() {
        wait.await
    } else {
        tokio::time::timeout_at(tokio::time::Instant::now() + timeout, wait)
            .await
            .map_err(|_| CliError(format!("wait: timed out after {}s", timeout.as_secs())))?
    }
}

async fn wait_until_ready(client: &LocalClient) -> Result<(), CliError> {
    wait_for_reachable(client).await?;
    let first_ip = wait_for_running(client).await?;
    if status_uses_tun(&client.status().await?) {
        wait_for_interface_ip(first_ip).await?;
    }
    Ok(())
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

/// Watch the IPN bus until Running, then verify that status has an address.
async fn wait_for_running(client: &LocalClient) -> Result<IpAddr, CliError> {
    let mut watch = client.watch_ipn_bus(NOTIFY_INITIAL_STATE).await?;
    loop {
        match watch.next().await {
            Ok(Some(notify)) if notify.State == Some(State::Running) => {
                if let Some(ip) = running_status(&client.status().await?)? {
                    return Ok(ip);
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => return Err(CliError("wait: daemon connection closed".into())),
            Err(error) => return Err(CliError(format!("wait: {error}"))),
        }
    }
}

fn running_status(status: &Value) -> Result<Option<IpAddr>, CliError> {
    let Some(first) = status
        .get("TailscaleIPs")
        .and_then(Value::as_array)
        .and_then(|ips| ips.first())
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    let first_ip = first
        .parse()
        .map_err(|_| CliError(format!("wait: invalid Tailscale IP in status: {first}")))?;
    Ok(Some(first_ip))
}

fn status_uses_tun(status: &Value) -> bool {
    status.get("TUN").and_then(Value::as_bool).unwrap_or(false)
}

async fn wait_for_interface_ip(ip: IpAddr) -> Result<(), CliError> {
    let mut delay = Duration::from_millis(100);
    loop {
        if check_for_interface_ip(ip).is_ok() {
            return Ok(());
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }
}

fn check_for_interface_ip(ip: IpAddr) -> Result<(), CliError> {
    let interfaces = if_addrs::get_if_addrs().map_err(|error| CliError(error.to_string()))?;
    if interface_has_ip(ip, interfaces.into_iter().map(|interface| interface.ip())) {
        Ok(())
    } else {
        Err(CliError(format!("wait: no interface has IP {ip}")))
    }
}

fn interface_has_ip(target: IpAddr, addresses: impl IntoIterator<Item = IpAddr>) -> bool {
    let target = unmap_ip(target);
    addresses.into_iter().map(unmap_ip).any(|ip| ip == target)
}

fn unmap_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Parse `--timeout` as a Go duration. A bare zero is the sole bare-number
/// form accepted and means wait indefinitely, matching `flag.Duration`.
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
    if value.is_empty() || value.starts_with(['-', '+']) {
        return Err(CliError(format!("invalid --timeout value: {value}")));
    }

    let mut remaining = value;
    let mut seconds = 0.0;
    while !remaining.is_empty() {
        let number_end = remaining
            .find(|character: char| !(character.is_ascii_digit() || character == '.'))
            .unwrap_or(remaining.len());
        if number_end == 0 {
            return Err(CliError(format!("invalid --timeout value: {value}")));
        }
        let number: f64 = remaining[..number_end]
            .parse()
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
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(CliError(format!("invalid --timeout value: {value}")));
    }
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| CliError(format!("invalid --timeout value: {value}")))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn parses_go_duration_timeout_forms() {
        assert_eq!(parse_wait_timeout(&[]).unwrap(), Duration::ZERO);
        assert_eq!(
            parse_wait_timeout(&["--timeout=5s".into()]).unwrap(),
            Duration::from_secs(5)
        );
        assert_eq!(
            parse_wait_timeout(&["--timeout".into(), "1m30s".into()]).unwrap(),
            Duration::from_secs(90)
        );
        assert_eq!(
            parse_wait_timeout(&["--timeout=0".into()]).unwrap(),
            Duration::ZERO
        );
        assert!(parse_wait_timeout(&["--timeout=500".into()]).is_err());
    }

    #[test]
    fn running_status_requires_a_valid_tailscale_ip() {
        assert_eq!(
            running_status(&serde_json::json!({"TUN": false})).unwrap(),
            None
        );
        assert!(running_status(&serde_json::json!({"TailscaleIPs": ["not-an-ip"]})).is_err());
        assert_eq!(
            running_status(&serde_json::json!({"TailscaleIPs": ["100.64.0.1"], "TUN": false}))
                .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
        );
    }

    #[test]
    fn tun_decision_uses_the_fresh_status_response() {
        assert!(!status_uses_tun(&serde_json::json!({"TUN": false})));
        assert!(status_uses_tun(&serde_json::json!({"TUN": true})));
    }

    #[test]
    fn interface_ip_comparison_unmaps_ipv4_mapped_ipv6() {
        assert!(interface_has_ip(
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            [IpAddr::V6("::ffff:100.64.0.1".parse::<Ipv6Addr>().unwrap())],
        ));
    }
}
