//! `rustscale ping` — ping a peer.
//!
//! Ports the compatible disco-ping behavior of Tailscale's `ping` command.

use std::path::Path;
use std::time::Duration;

use rustscale_localclient::LocalClient;

use crate::CliError;

/// Parsed CLI ping flags.
#[derive(Debug, PartialEq, Eq)]
struct PingArgs {
    ip: String,
    ping_type: &'static str,
    size: usize,
    count: usize,
    until_direct: bool,
    timeout: Duration,
}

fn parse_duration(value: &str) -> Result<Duration, CliError> {
    let (number, unit) = if let Some(number) = value.strip_suffix("ms") {
        (number, "ms")
    } else if let Some(number) = value.strip_suffix('s') {
        (number, "s")
    } else if let Some(number) = value.strip_suffix('m') {
        (number, "m")
    } else if let Some(number) = value.strip_suffix('h') {
        (number, "h")
    } else {
        return Err(CliError(format!("invalid --timeout value: {value}")));
    };
    if number.is_empty() || number.starts_with('-') {
        return Err(CliError(format!("invalid --timeout value: {value}")));
    }
    let number: f64 = number
        .parse()
        .map_err(|_| CliError(format!("invalid --timeout value: {value}")))?;
    if !number.is_finite() || number < 0.0 {
        return Err(CliError(format!("invalid --timeout value: {value}")));
    }
    let seconds = match unit {
        "ms" => number / 1_000.0,
        "s" => number,
        "m" => number * 60.0,
        "h" => number * 3_600.0,
        _ => unreachable!(),
    };
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| CliError(format!("invalid --timeout value: {value}")))
}

fn parse_ping_args(args: &[String]) -> Result<PingArgs, CliError> {
    let mut ip = None;
    let mut ping_type = "disco";
    let mut size = 0usize;
    let mut count = 10usize;
    let mut until_direct = true;
    let mut timeout = Duration::from_secs(5);

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let value = |flag: &str, i: &mut usize| -> Result<String, CliError> {
            *i += 1;
            args.get(*i)
                .cloned()
                .filter(|value| !value.starts_with('-'))
                .ok_or_else(|| CliError(format!("{flag} requires a value")))
        };
        match arg.as_str() {
            "--tsmp" => ping_type = "tsmp",
            "--icmp" => ping_type = "icmp",
            "--peerapi" => ping_type = "peerapi",
            "--size" | "-s" => {
                let raw = value(arg, &mut i)?;
                size = raw
                    .parse()
                    .map_err(|_| CliError(format!("invalid {arg} value: {raw}")))?;
            }
            "--count" | "-c" => {
                let raw = value(arg, &mut i)?;
                count = raw
                    .parse()
                    .map_err(|_| CliError(format!("invalid {arg} value: {raw}")))?;
            }
            "--timeout" => timeout = parse_duration(&value(arg, &mut i)?)?,
            "--until-direct" | "-d" => until_direct = true,
            "--help" | "-h" => return Err(CliError("usage: rustscale ping <ip> [flags]".into())),
            value if let Some(raw) = value.strip_prefix("--size=") => {
                size = raw
                    .parse()
                    .map_err(|_| CliError(format!("invalid --size value: {raw}")))?;
            }
            value
                if let Some(raw) = value
                    .strip_prefix("--count=")
                    .or_else(|| value.strip_prefix("-c=")) =>
            {
                count = raw
                    .parse()
                    .map_err(|_| CliError(format!("invalid --count value: {raw}")))?;
            }
            value if let Some(raw) = value.strip_prefix("--timeout=") => {
                timeout = parse_duration(raw)?;
            }
            value if let Some(raw) = value.strip_prefix("--until-direct=") => {
                until_direct = match raw {
                    "true" => true,
                    "false" => false,
                    _ => return Err(CliError(format!("invalid --until-direct value: {raw}"))),
                };
            }
            value if value.starts_with('-') => {
                return Err(CliError(format!("unknown flag: {value}")))
            }
            value => {
                if ip.replace(value.to_string()).is_some() {
                    return Err(CliError("usage: rustscale ping <ip> [flags]".into()));
                }
            }
        }
        i += 1;
    }

    Ok(PingArgs {
        ip: ip.ok_or_else(|| CliError("usage: rustscale ping <ip> [flags]".into()))?,
        ping_type,
        size,
        count,
        until_direct,
        timeout,
    })
}

fn print_help() {
    println!("Usage: rustscale ping <ip> [flags]");
    println!();
    println!("Flags:");
    println!("  --tsmp                     Send TSMP pings");
    println!("  --icmp                     Send ICMP pings");
    println!("  --peerapi                  Send PeerAPI pings");
    println!("  --size, -s <bytes>         Ping payload size (default 0)");
    println!("  --count, -c <count>        Maximum pings; 0 retries indefinitely (default 10)");
    println!("  --timeout <duration>       Per-ping timeout (default 5s)");
    println!("  --until-direct[=true|false]  Stop after a direct path (default true)");
}

#[derive(Default)]
struct PingProgress {
    any_pong: bool,
}

impl PingProgress {
    fn exhausted(&self, until_direct: bool) -> Result<(), CliError> {
        if !self.any_pong {
            Err(CliError("no reply".into()))
        } else if until_direct {
            Err(CliError("direct connection not established".into()))
        } else {
            Ok(())
        }
    }
}

pub async fn run(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print_help();
        return Ok(());
    }
    let parsed = parse_ping_args(&args)?;
    let client = LocalClient::new(socket);
    let mut progress = PingProgress::default();
    let mut sent = 0usize;

    loop {
        sent += 1;
        match tokio::time::timeout(
            parsed.timeout,
            client.ping(&parsed.ip, parsed.ping_type, parsed.size),
        )
        .await
        {
            Ok(Ok(result)) if result.Err.is_empty() => {
                progress.any_pong = true;
                let latency_ms = (result.LatencySeconds * 1000.0).round() as u64;
                let via = if !result.PeerRelay.is_empty() {
                    format!("peer-relay({})", result.PeerRelay)
                } else if result.DERPRegionID != 0 {
                    format!("DERP({})", result.DERPRegionCode)
                } else if !result.Endpoint.is_empty() {
                    result.Endpoint.clone()
                } else {
                    parsed.ping_type.to_string()
                };
                println!(
                    "pong from {} ({}) via {} in {}ms",
                    result.NodeName, result.NodeIP, via, latency_ms
                );
                if matches!(parsed.ping_type, "tsmp" | "icmp" | "peerapi")
                    || (parsed.until_direct
                        && result.DERPRegionID == 0
                        && result.PeerRelay.is_empty()
                        && !result.Endpoint.is_empty())
                {
                    return Ok(());
                }
            }
            Ok(Ok(result)) => eprintln!("ping error: {}", result.Err),
            Ok(Err(error)) => eprintln!("ping error: {error}"),
            Err(_) => eprintln!("ping \"{}\" timed out", parsed.ip),
        }
        if parsed.count != 0 && sent == parsed.count {
            return progress.exhausted(parsed.until_direct);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parses_compatible_count_timeout_and_until_direct_flags() {
        let parsed = parse_ping_args(&args(&[
            "100.64.0.1",
            "--count=0",
            "--timeout",
            "500ms",
            "--until-direct=false",
        ]))
        .unwrap();
        assert_eq!(parsed.count, 0);
        assert_eq!(parsed.timeout, Duration::from_millis(500));
        assert!(!parsed.until_direct);
        assert_eq!(
            parse_ping_args(&args(&["-c=2", "--timeout=1m", "100.64.0.1"]))
                .unwrap()
                .count,
            2
        );
    }

    #[test]
    fn rejects_malformed_and_unknown_flags() {
        for input in [
            args(&["100.64.0.1", "--count=wat"]),
            args(&["100.64.0.1", "--timeout=5"]),
            args(&["100.64.0.1", "--until-direct=maybe"]),
            args(&["100.64.0.1", "--bogus"]),
            args(&["100.64.0.1", "--count"]),
        ] {
            assert!(parse_ping_args(&input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn termination_matches_direct_ping_semantics() {
        assert_eq!(
            PingProgress::default().exhausted(true).unwrap_err().0,
            "no reply"
        );
        let replied = PingProgress { any_pong: true };
        assert_eq!(
            replied.exhausted(true).unwrap_err().0,
            "direct connection not established"
        );
        assert!(replied.exhausted(false).is_ok());
    }
}
