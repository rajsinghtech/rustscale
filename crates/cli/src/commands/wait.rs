//! `rustscale wait` — wait for the backend and its configured interface.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use rustscale_ipn::{State, NOTIFY_INITIAL_STATE};
use rustscale_localclient::{LocalClient, LocalClientError, WatchIpnBus};
use serde_json::Value;

use crate::CliError;

const HELP: &str = "Wait for Tailscale resources to be available.

With no arguments, this command blocks until rustscaled is reachable, its
backend is Running, and the Tailscale interface has a Tailscale IP. In
userspace-networking mode it only waits for rustscaled and Running.

Usage: rustscale wait [--timeout <duration>]

Flags:
  --timeout <duration>  how long to wait (0 means indefinitely)
  -h, --help            show this help";

struct WaitArgs {
    timeout: Option<Duration>,
    help: bool,
}

pub async fn run(args: Vec<String>, socket: &Path, _json: bool) -> Result<(), CliError> {
    let options = parse_wait_args(&args)?;
    if options.help {
        println!("{HELP}");
        return Ok(());
    }

    let client = LocalClient::new(socket);
    let operation = wait_until_ready(&client);
    tokio::pin!(operation);

    let cancelled = async {
        tokio::signal::ctrl_c().await.map_err(|error| {
            CliError(format!("wait: failed to listen for cancellation: {error}"))
        })?;
        Err(CliError("wait: canceled".into()))
    };
    tokio::pin!(cancelled);

    if let Some(timeout) = options.timeout {
        tokio::select! {
            result = &mut operation => result,
            result = &mut cancelled => result,
            () = tokio::time::sleep(timeout) => Err(CliError("wait: timed out".into())),
        }
    } else {
        tokio::select! {
            result = &mut operation => result,
            result = &mut cancelled => result,
        }
    }
}

async fn wait_until_ready(client: &LocalClient) -> Result<(), CliError> {
    // Subscribe first rather than reading status and then subscribing. The
    // initial-state mask supplies the current state and closes that race.
    let mut watch = subscribe_when_reachable(client).await?;
    let first_ip = wait_for_running(client, &mut watch).await?;
    if status_uses_tun(&client.status_without_peers().await?) {
        wait_for_interface_ip(first_ip).await?;
    }
    Ok(())
}

/// Retry only daemon reachability failures. HTTP, authentication, protocol,
/// and stream errors are definitive and must not be hidden by a retry loop.
async fn subscribe_when_reachable(client: &LocalClient) -> Result<WatchIpnBus, CliError> {
    let mut delay = Duration::from_millis(100);
    loop {
        match client.watch_ipn_bus(NOTIFY_INITIAL_STATE).await {
            Ok(watch) => return Ok(watch),
            Err(LocalClientError::Connect(_)) => {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(2));
            }
            Err(error) => return Err(CliError(format!("wait: {error}"))),
        }
    }
}

/// Ignore every valid backend state except Running. `NotifyInitialState` makes
/// an already-reached Running state observable without a separate status poll.
async fn wait_for_running(
    client: &LocalClient,
    watch: &mut WatchIpnBus,
) -> Result<IpAddr, CliError> {
    loop {
        match watch.next().await {
            Ok(Some(notify)) if notify.State == Some(State::Running) => {
                if let Some(ip) = running_status(&client.status_without_peers().await?)? {
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

/// Parse the standard Go flag forms accepted upstream. Repeated timeout flags
/// use the last value, as `flag.DurationVar` does. Non-positive durations mean
/// no deadline because upstream only installs a timeout when the value is > 0.
fn parse_wait_args(args: &[String]) -> Result<WaitArgs, CliError> {
    let mut timeout = None;
    let mut help = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            index += 1;
            if index != args.len() {
                return Err(CliError(format!(
                    "unexpected arguments: {:?}",
                    &args[index..]
                )));
            }
            break;
        }
        let value = if matches!(arg.as_str(), "--help" | "-help" | "-h") {
            help = true;
            index += 1;
            continue;
        } else if matches!(arg.as_str(), "--timeout" | "-timeout") {
            index += 1;
            args.get(index)
                .map(String::as_str)
                .ok_or_else(|| CliError(format!("{arg} requires a value")))?
        } else if let Some(value) = arg
            .strip_prefix("--timeout=")
            .or_else(|| arg.strip_prefix("-timeout="))
        {
            value
        } else if arg.starts_with('-') {
            return Err(CliError(format!("unknown flag: {arg}")));
        } else {
            return Err(CliError(format!("unexpected arguments: {args:?}")));
        };
        timeout = parse_go_duration(value)?;
        index += 1;
    }
    Ok(WaitArgs { timeout, help })
}

/// Parse the subset of Go's `time.ParseDuration` used by CLI flags, including
/// compound and fractional values and both microsecond spellings.
fn parse_go_duration(value: &str) -> Result<Option<Duration>, CliError> {
    let invalid = || CliError(format!("invalid --timeout value: {value}"));
    if value.is_empty() {
        return Err(invalid());
    }

    let (sign, mut remaining) = match value.as_bytes()[0] {
        b'-' => (-1.0, &value[1..]),
        b'+' => (1.0, &value[1..]),
        _ => (1.0, value),
    };
    if remaining.is_empty() {
        return Err(invalid());
    }
    if remaining == "0" {
        return Ok(None);
    }

    let mut seconds = 0.0;
    while !remaining.is_empty() {
        let number_end = remaining
            .find(|character: char| !(character.is_ascii_digit() || character == '.'))
            .unwrap_or(remaining.len());
        if number_end == 0 {
            return Err(invalid());
        }
        let number: f64 = remaining[..number_end].parse().map_err(|_| invalid())?;
        let (unit, multiplier) = [
            ("ns", 1e-9),
            ("us", 1e-6),
            ("µs", 1e-6),
            ("μs", 1e-6),
            ("ms", 1e-3),
            ("s", 1.0),
            ("m", 60.0),
            ("h", 3_600.0),
        ]
        .into_iter()
        .find(|(unit, _)| remaining[number_end..].starts_with(unit))
        .ok_or_else(invalid)?;
        seconds += number * multiplier;
        remaining = &remaining[number_end + unit.len()..];
    }

    let seconds = sign * seconds;
    if !seconds.is_finite() {
        return Err(invalid());
    }
    if seconds <= 0.0 {
        return Ok(None);
    }
    let duration = Duration::try_from_secs_f64(seconds).map_err(|_| invalid())?;
    Ok((!duration.is_zero()).then_some(duration))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_upstream_wait_flag_and_duration_forms() {
        assert!(parse_wait_args(&[]).unwrap().timeout.is_none());
        assert_eq!(
            parse_wait_args(&strings(&["--timeout=5s"]))
                .unwrap()
                .timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            parse_wait_args(&strings(&["-timeout", "1m30s"]))
                .unwrap()
                .timeout,
            Some(Duration::from_secs(90))
        );
        assert!(parse_wait_args(&strings(&["--timeout=-1s"]))
            .unwrap()
            .timeout
            .is_none());
        assert_eq!(
            parse_wait_args(&strings(&["--timeout=1s", "-timeout=2s"]))
                .unwrap()
                .timeout,
            Some(Duration::from_secs(2))
        );
        assert!(parse_wait_args(&strings(&["--help"])).unwrap().help);
        assert!(parse_wait_args(&strings(&["--"])).is_ok());
    }

    #[test]
    fn rejects_invalid_wait_arguments() {
        assert!(parse_wait_args(&strings(&["Running"])).is_err());
        assert!(parse_wait_args(&strings(&["--timeout=500"])).is_err());
        assert!(parse_wait_args(&strings(&["--unknown"])).is_err());
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
    fn interface_ip_comparison_unmaps_ipv4_mapped_ipv6() {
        assert!(interface_has_ip(
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            [IpAddr::V6("::ffff:100.64.0.1".parse::<Ipv6Addr>().unwrap())],
        ));
    }
}
