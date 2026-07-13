//! `rustscale ping` — ping a peer.
//!
//! Ports Go's `cmd/tailscale/cli/ping.go`. Sends disco pings (default),
//! ICMP, TSMP, or peerapi pings to a peer and prints latency + path info
//! in the Go-compatible format:
//!
//! ```text
//! pong from <hostname> (<ip>) via DERP(nyc) in 23ms
//! ```

use std::path::Path;
use std::time::Duration;

use rustscale_localclient::LocalClient;

use crate::CliError;

/// Parsed CLI ping flags.
struct PingArgs {
    ip: String,
    ping_type: &'static str,
    size: usize,
    count: usize,
    until_direct: bool,
}

/// Parse `rustscale ping` arguments. Supports:
/// - `--tsmp` / `--icmp` / `--peerapi` — ping type
/// - `--size` / `-s` — ping payload size
/// - `--count` / `-c` — number of pings (default 10)
/// - `--until-direct` / `-d` — exit once a direct path is found
fn parse_ping_args(args: &[String]) -> PingArgs {
    let mut ip = String::new();
    let mut ping_type = "disco";
    let mut size = 0usize;
    let mut count = 10usize;
    let mut until_direct = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tsmp" => ping_type = "tsmp",
            "--icmp" => ping_type = "icmp",
            "--peerapi" => ping_type = "peerapi",
            "--size" | "-s" => {
                i += 1;
                size = args.get(i).and_then(|a| a.parse().ok()).unwrap_or(0);
            }
            "--count" | "-c" => {
                i += 1;
                count = args.get(i).and_then(|a| a.parse().ok()).unwrap_or(10);
            }
            "--until-direct" | "-d" => until_direct = true,
            "--help" | "-h" => {
                println!("Usage: rustscale ping <ip> [flags]");
                println!();
                println!("Flags:");
                println!("  --tsmp          Send TSMP pings (Tailscale protocol)");
                println!("  --icmp          Send ICMP pings");
                println!("  --peerapi       Send PeerAPI pings");
                println!("  --size, -s      Ping payload size (default 0)");
                println!("  --count, -c     Number of pings (default 10)");
                println!("  --until-direct, -d  Exit once a direct path is found");
                std::process::exit(0);
            }
            s if !s.starts_with('-') => ip = s.to_string(),
            _ => {}
        }
        i += 1;
    }

    PingArgs {
        ip,
        ping_type,
        size,
        count,
        until_direct,
    }
}

pub async fn run(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let parsed = parse_ping_args(&args);
    if parsed.ip.is_empty() {
        return Err(CliError("usage: rustscale ping <ip> [--tsmp|--icmp|--peerapi] [--size=N] [--count=N] [--until-direct]".into()));
    }

    let client = LocalClient::new(socket);
    let ping_type = parsed.ping_type;

    for _ in 0..parsed.count {
        match client.ping(&parsed.ip, ping_type, parsed.size).await {
            Ok(result) => {
                if result.Err.is_empty() {
                    let latency_ms = (result.LatencySeconds * 1000.0).round() as u64;
                    let via = if !result.PeerRelay.is_empty() {
                        format!("peer-relay({})", result.PeerRelay)
                    } else if result.DERPRegionID != 0 {
                        format!("DERP({})", result.DERPRegionCode)
                    } else if !result.Endpoint.is_empty() {
                        result.Endpoint.clone()
                    } else {
                        ping_type.to_string()
                    };
                    println!(
                        "pong from {} ({}) via {} in {}ms",
                        result.NodeName, result.NodeIP, via, latency_ms,
                    );
                    if parsed.until_direct
                        && result.DERPRegionID == 0
                        && result.PeerRelay.is_empty()
                        && !result.Endpoint.is_empty()
                    {
                        return Ok(());
                    }
                } else {
                    eprintln!("ping error: {}", result.Err);
                }
            }
            Err(e) => {
                eprintln!("ping error: {e}");
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}
