//! `rustscale ping` — ping a peer.
//!
//! Ports the compatible disco-ping behavior of Tailscale's `ping` command.

use std::future::Future;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use rustscale_ipnstate::{PeerStatus, PingResult, Status};
use rustscale_localclient::{LocalClient, LocalClientError};

use crate::CliError;

/// Parsed CLI ping flags.
#[derive(Debug, PartialEq, Eq)]
struct PingArgs {
    target: String,
    ping_type: &'static str,
    size: usize,
    count: usize,
    until_direct: bool,
    timeout: Duration,
}

const SYSTEM_DNS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedTarget {
    ip: IpAddr,
    is_self: bool,
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
    let mut target = None;
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
            "--count" | "--c" | "-c" => {
                let raw = value(arg, &mut i)?;
                count = raw
                    .parse()
                    .map_err(|_| CliError(format!("invalid {arg} value: {raw}")))?;
            }
            "--timeout" => timeout = parse_duration(&value(arg, &mut i)?)?,
            "--until-direct" | "-d" => until_direct = true,
            "--help" | "-h" => {
                return Err(CliError(
                    "usage: rustscale ping <hostname-or-IP> [flags]".into(),
                ));
            }
            value => {
                if let Some(raw) = value.strip_prefix("--size=") {
                    size = raw
                        .parse()
                        .map_err(|_| CliError(format!("invalid --size value: {raw}")))?;
                } else if let Some(raw) = value
                    .strip_prefix("--count=")
                    .or_else(|| value.strip_prefix("--c="))
                    .or_else(|| value.strip_prefix("-c="))
                {
                    count = raw
                        .parse()
                        .map_err(|_| CliError(format!("invalid --count value: {raw}")))?;
                } else if let Some(raw) = value.strip_prefix("--timeout=") {
                    timeout = parse_duration(raw)?;
                } else if let Some(raw) = value.strip_prefix("--until-direct=") {
                    until_direct = match raw {
                        "true" => true,
                        "false" => false,
                        _ => return Err(CliError(format!("invalid --until-direct value: {raw}"))),
                    };
                } else if value.starts_with('-') {
                    return Err(CliError(format!("unknown flag: {value}")));
                } else if target.replace(value.to_string()).is_some() {
                    return Err(CliError(
                        "usage: rustscale ping <hostname-or-IP> [flags]".into(),
                    ));
                }
            }
        }
        i += 1;
    }

    Ok(PingArgs {
        target: target
            .ok_or_else(|| CliError("usage: rustscale ping <hostname-or-IP> [flags]".into()))?,
        ping_type,
        size,
        count,
        until_direct,
        timeout,
    })
}

fn print_help() {
    println!("Usage: rustscale ping <hostname-or-IP> [flags]");
    println!();
    println!("Flags:");
    println!("  --tsmp                     Send TSMP pings");
    println!("  --icmp                     Send ICMP pings");
    println!("  --peerapi                  Send PeerAPI pings");
    println!("  --size, -s <bytes>         Ping payload size (default 0)");
    println!("  --c, --count, -c <count>   Number of pings; 0 retries indefinitely (default 10)");
    println!("  --timeout <duration>       Per-ping timeout (default 5s)");
    println!("  --until-direct[=true|false]  Stop after a direct path (default true)");
}

fn magicdns_name_matches(status: &Status, peer: &PeerStatus, target: &str) -> bool {
    let target = target.trim_end_matches('.').to_ascii_lowercase();
    let dns_name = peer.DNSName.trim_end_matches('.').to_ascii_lowercase();
    if dns_name.is_empty() {
        return false;
    }
    if target == dns_name {
        return true;
    }

    let suffix = status.MagicDNSSuffix.trim_matches('.').to_ascii_lowercase();
    let short_name = if suffix.is_empty() {
        dns_name.split('.').next().unwrap_or(&dns_name)
    } else {
        dns_name
            .strip_suffix(&suffix)
            .and_then(|name| name.strip_suffix('.'))
            .unwrap_or_else(|| dns_name.split('.').next().unwrap_or(&dns_name))
    };
    target == short_name
}

fn status_target(status: &Status, target: &str) -> Result<Option<ResolvedTarget>, CliError> {
    let resolved_peer = |peer: &PeerStatus, is_self| -> Result<Option<ResolvedTarget>, CliError> {
        if !magicdns_name_matches(status, peer, target) {
            return Ok(None);
        }
        let ip = peer
            .TailscaleIPs
            .first()
            .copied()
            .ok_or_else(|| CliError("node found but lacks an IP".into()))?;
        Ok(Some(ResolvedTarget { ip, is_self }))
    };

    if let Some(peer) = status.SelfPeer.as_deref() {
        if let Some(resolved) = resolved_peer(peer, true)? {
            return Ok(Some(resolved));
        }
    }
    for peer in status.Peer.values() {
        if let Some(resolved) = resolved_peer(peer, false)? {
            return Ok(Some(resolved));
        }
    }
    Ok(None)
}

async fn first_ip_with_timeout<F>(
    host: &str,
    timeout: Duration,
    lookup: F,
) -> Result<IpAddr, CliError>
where
    F: Future<Output = Result<Vec<IpAddr>, String>>,
{
    match tokio::time::timeout(timeout, lookup).await {
        Ok(Ok(addresses)) => addresses
            .into_iter()
            .next()
            .ok_or_else(|| CliError(format!("no IPs found for {host:?}"))),
        Ok(Err(error)) => Err(CliError(format!(
            "error looking up IP of {host:?}: {error}"
        ))),
        Err(_) => Err(CliError(format!(
            "error looking up IP of {host:?}: lookup timed out after {timeout:?}"
        ))),
    }
}

async fn resolve_target(client: &LocalClient, target: &str) -> Result<ResolvedTarget, CliError> {
    if let Ok(ip) = target.parse() {
        return Ok(ResolvedTarget { ip, is_self: false });
    }

    let status: Status = serde_json::from_value(client.status().await?)
        .map_err(|error| CliError(format!("invalid status response: {error}")))?;
    if let Some(resolved) = status_target(&status, target)? {
        return Ok(resolved);
    }

    let lookup_target = target.to_string();
    let lookup = async move {
        tokio::net::lookup_host((lookup_target.as_str(), 0))
            .await
            .map(|addresses| addresses.map(|address| address.ip()).collect())
            .map_err(|error| error.to_string())
    };
    let ip = first_ip_with_timeout(target, SYSTEM_DNS_TIMEOUT, lookup).await?;
    Ok(ResolvedTarget { ip, is_self: false })
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

async fn ping_target<F, Fut>(parsed: &PingArgs, ip: IpAddr, mut ping: F) -> Result<(), CliError>
where
    F: FnMut(IpAddr, &'static str, usize) -> Fut,
    Fut: Future<Output = Result<PingResult, LocalClientError>>,
{
    let mut progress = PingProgress::default();
    let mut sent = 0usize;

    loop {
        sent += 1;
        match tokio::time::timeout(parsed.timeout, ping(ip, parsed.ping_type, parsed.size)).await {
            Ok(Ok(result)) if result.Err.is_empty() => {
                progress.any_pong = true;
                let latency_ms = (result.LatencySeconds * 1000.0).round() as u64;
                let via = if !result.PeerRelay.is_empty() {
                    format!("peer-relay({})", result.PeerRelay)
                } else if result.DERPRegionID != 0 {
                    derp_path_label(&result)
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
            Ok(Ok(result)) if result.IsLocalIP => {
                println!("{}", result.Err);
                return Ok(());
            }
            Ok(Ok(result)) => return Err(CliError(result.Err)),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                eprintln!("ping \"{ip}\" timed out");
                // Dropping this HTTP request cannot cancel ping work already running
                // in the daemon. Do not overlap it with a fresh CLI retry.
                return progress.exhausted(parsed.until_direct);
            }
        }
        if parsed.count != 0 && sent == parsed.count {
            return progress.exhausted(parsed.until_direct);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Format only the DERP identity returned by the completed ping. The numeric
/// region is the observed transport identity; the optional code is only its
/// current control-plane display name.
fn derp_path_label(result: &PingResult) -> String {
    if result.DERPRegionCode.is_empty() {
        format!("DERP({})", result.DERPRegionID)
    } else {
        format!("DERP({})", result.DERPRegionCode)
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
    let resolved = resolve_target(&client, &parsed.target).await?;
    if resolved.is_self {
        println!("{} is local Tailscale IP", resolved.ip);
        return Ok(());
    }
    ping_target(&parsed, resolved.ip, |ip, ping_type, size| {
        client.ping(ip, ping_type, size)
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        for input in [
            args(&["--c", "3", "100.64.0.1"]),
            args(&["--c=4", "100.64.0.1"]),
            args(&["--count", "5", "100.64.0.1"]),
            args(&["--count=6", "100.64.0.1"]),
            args(&["-c", "7", "100.64.0.1"]),
        ] {
            assert!(parse_ping_args(&input).is_ok(), "{input:?}");
        }
    }

    #[test]
    fn rejects_malformed_and_unknown_flags() {
        for input in [
            args(&["100.64.0.1", "--count=wat"]),
            args(&["100.64.0.1", "--c=wat"]),
            args(&["100.64.0.1", "--c"]),
            args(&["100.64.0.1", "--c", "-1"]),
            args(&["100.64.0.1", "--timeout=5"]),
            args(&["100.64.0.1", "--until-direct=maybe"]),
            args(&["100.64.0.1", "--bogus"]),
            args(&["100.64.0.1", "--count"]),
        ] {
            assert!(parse_ping_args(&input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn derp_ping_label_falls_back_to_the_observed_region_id() {
        assert_eq!(
            derp_path_label(&PingResult {
                DERPRegionID: 7,
                ..Default::default()
            }),
            "DERP(7)"
        );
        assert_eq!(
            derp_path_label(&PingResult {
                DERPRegionID: 7,
                DERPRegionCode: "test-region".into(),
                ..Default::default()
            }),
            "DERP(test-region)"
        );
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

    fn peer(dns_name: &str, ip: &str) -> PeerStatus {
        PeerStatus {
            DNSName: dns_name.into(),
            TailscaleIPs: vec![ip.parse().unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn resolves_peer_and_self_magicdns_full_and_short_names() {
        let peer_status = peer("Peer-One.Example.ts.net.", "100.64.0.2");
        let self_status = peer("Self-One.Example.ts.net.", "100.64.0.1");
        let status = Status {
            MagicDNSSuffix: "example.ts.net".into(),
            SelfPeer: Some(Box::new(self_status)),
            Peer: BTreeMap::from([("node-key".into(), peer_status)]),
            ..Default::default()
        };

        for target in ["peer-one", "PEER-ONE.example.ts.net."] {
            assert_eq!(
                status_target(&status, target).unwrap(),
                Some(ResolvedTarget {
                    ip: "100.64.0.2".parse().unwrap(),
                    is_self: false,
                })
            );
        }
        for target in ["self-one", "SELF-ONE.example.ts.net"] {
            assert_eq!(
                status_target(&status, target).unwrap(),
                Some(ResolvedTarget {
                    ip: "100.64.0.1".parse().unwrap(),
                    is_self: true,
                })
            );
        }
    }

    #[test]
    fn matching_status_node_without_an_ip_is_an_error() {
        let status = Status {
            Peer: BTreeMap::from([(
                "node-key".into(),
                PeerStatus {
                    DNSName: "peer.example.ts.net.".into(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        assert_eq!(
            status_target(&status, "peer").unwrap_err().0,
            "node found but lacks an IP"
        );
    }

    #[tokio::test]
    async fn system_dns_fallback_has_a_deterministic_bound() {
        let lookup = std::future::pending::<Result<Vec<IpAddr>, String>>();
        let error = first_ip_with_timeout("slow.example", Duration::from_millis(25), lookup)
            .await
            .unwrap_err();
        assert_eq!(
            error.0,
            "error looking up IP of \"slow.example\": lookup timed out after 25ms"
        );
    }

    fn ping_args(timeout: Duration) -> PingArgs {
        PingArgs {
            target: "peer".into(),
            ping_type: "disco",
            size: 0,
            count: 10,
            until_direct: true,
            timeout,
        }
    }

    #[tokio::test]
    async fn structured_ping_error_stops_without_retrying() {
        let calls = AtomicUsize::new(0);
        let result = ping_target(
            &ping_args(Duration::from_secs(1)),
            "100.64.0.2".parse().unwrap(),
            |_, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(PingResult {
                    Err: "TSMP ping not yet implemented".into(),
                    ..Default::default()
                }))
            },
        )
        .await;

        assert_eq!(result.unwrap_err().0, "TSMP ping not yet implemented");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn timed_out_ping_does_not_start_an_overlapping_retry() {
        let calls = AtomicUsize::new(0);
        let result = ping_target(
            &ping_args(Duration::from_millis(25)),
            "100.64.0.2".parse().unwrap(),
            |_, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<PingResult, LocalClientError>>()
            },
        )
        .await;

        assert_eq!(result.unwrap_err().0, "no reply");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
