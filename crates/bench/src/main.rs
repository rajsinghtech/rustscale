//! rustscale-bench — throughput and latency benchmark harness for rustscale tsnet.
//!
//! Modes:
//!   server  — join a tailnet, listen on a port, accept benchmark connections
//!   client  — dial a server and measure TCP throughput (up/down/bidir)
//!   latency — measure RTT of small ping-pong messages

#![forbid(unsafe_code)]

mod latency;
mod protocol;
mod server;
mod throughput;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "rustscale-bench",
    about = "Throughput and latency benchmark for rustscale tsnet"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output results as JSON to stdout (machine-parseable).
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Server mode: join a tailnet and accept benchmark connections.
    Server {
        /// Tailscale auth key.
        #[arg(long)]
        authkey: String,
        /// Port to listen on.
        #[arg(long, default_value = "5201")]
        port: u16,
        /// Hostname for this node.
        #[arg(long, default_value = "bench-server")]
        hostname: String,
        /// Control-plane URL.
        #[arg(long, default_value = "controlplane.tailscale.com")]
        control_url: String,
        /// State directory (for persistent keys).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Client mode: dial a server and measure throughput.
    Client {
        /// Tailscale auth key.
        #[arg(long)]
        authkey: String,
        /// Target address (ip:port or hostname:port).
        #[arg(long)]
        target: String,
        /// Test duration in seconds.
        #[arg(long, default_value = "10")]
        duration: u64,
        /// Direction: up, down, or bidir.
        #[arg(long, default_value = "down")]
        direction: String,
        /// Number of parallel connections.
        #[arg(long, default_value = "1")]
        parallel: usize,
        /// Hostname for this node.
        #[arg(long, default_value = "bench-client")]
        hostname: String,
        /// Control-plane URL.
        #[arg(long, default_value = "controlplane.tailscale.com")]
        control_url: String,
        /// State directory.
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Latency mode: measure RTT of small ping-pong messages.
    Latency {
        /// Tailscale auth key.
        #[arg(long)]
        authkey: String,
        /// Target address (ip:port or hostname:port).
        #[arg(long)]
        target: String,
        /// Number of ping-pong rounds.
        #[arg(long, default_value = "1000")]
        count: usize,
        /// Hostname for this node.
        #[arg(long, default_value = "bench-latency")]
        hostname: String,
        /// Control-plane URL.
        #[arg(long, default_value = "controlplane.tailscale.com")]
        control_url: String,
        /// State directory.
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .event_interval(1)
        .build()
        .unwrap();
    runtime.block_on(async_main());
}

async fn async_main() {
    let cli = Cli::parse();
    let json = cli.json;
    let result = match cli.command {
        Command::Server {
            authkey,
            port,
            hostname,
            control_url,
            state_dir,
        } => Box::pin(server::run(authkey, port, hostname, control_url, state_dir)).await,
        Command::Client {
            authkey,
            target,
            duration,
            direction,
            parallel,
            hostname,
            control_url,
            state_dir,
        } => {
            let res = Box::pin(throughput::run(
                authkey,
                target,
                duration,
                &direction,
                parallel,
                hostname,
                control_url,
                state_dir,
            ))
            .await;
            match res {
                Ok(r) => {
                    if json {
                        print_throughput_json(&r);
                    } else {
                        print_throughput_table(&r);
                    }
                    return;
                }
                Err(e) => Err(e),
            }
        }
        Command::Latency {
            authkey,
            target,
            count,
            hostname,
            control_url,
            state_dir,
        } => {
            let res = Box::pin(latency::run(
                authkey,
                target,
                count,
                hostname,
                control_url,
                state_dir,
            ))
            .await;
            match res {
                Ok(r) => {
                    if json {
                        print_latency_json(&r);
                    } else {
                        print_latency_table(&r);
                    }
                    return;
                }
                Err(e) => Err(e),
            }
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn print_throughput_table(r: &throughput::ThroughputResult) {
    eprintln!();
    eprintln!("═══ rustscale-bench throughput results ═══");
    eprintln!("  direction : {}", r.direction);
    eprintln!("  duration  : {}s", r.duration_secs);
    eprintln!("  parallel  : {}", r.parallel);
    eprintln!("  path      : {}", r.path_class);
    eprintln!("  client IP : {}", r.tailscale_ip);
    eprintln!("  target    : {}", r.target);
    eprintln!();
    if r.direction == "bidir" {
        eprintln!(
            "  up   : {:.2} Mbps  ({} bytes)",
            r.up_mbps,
            format_bytes(r.up_bytes)
        );
        eprintln!(
            "  down : {:.2} Mbps  ({} bytes)",
            r.down_mbps,
            format_bytes(r.down_bytes)
        );
    }
    eprintln!(
        "  total: {:.2} Mbps  ({} bytes)",
        r.total_mbps,
        format_bytes(r.total_bytes)
    );
    eprintln!();
    if !r.samples.is_empty() {
        eprintln!("  per-second samples (Mbps):");
        for s in &r.samples {
            eprintln!("    t={:>3}s  {:>8.2} Mbps", s.elapsed_secs, s.mbps);
        }
        eprintln!();
    }
}

fn print_throughput_json(r: &throughput::ThroughputResult) {
    let samples: Vec<serde_json::Value> = r
        .samples
        .iter()
        .map(|s| {
            serde_json::json!({
                "elapsed_secs": s.elapsed_secs,
                "mbps": s.mbps,
            })
        })
        .collect();

    let obj = serde_json::json!({
        "tool": "rustscale-bench",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": "throughput",
        "direction": r.direction,
        "duration_secs": r.duration_secs,
        "parallel": r.parallel,
        "path_class": r.path_class,
        "tailscale_ip": r.tailscale_ip,
        "target": r.target,
        "total_bytes": r.total_bytes,
        "total_mbps": r.total_mbps,
        "up_bytes": r.up_bytes,
        "up_mbps": r.up_mbps,
        "down_bytes": r.down_bytes,
        "down_mbps": r.down_mbps,
        "samples": samples,
    });
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}

fn print_latency_table(r: &latency::LatencyResult) {
    eprintln!();
    eprintln!("═══ rustscale-bench latency results ═══");
    eprintln!("  count     : {}", r.count);
    eprintln!("  path      : {}", r.path_class);
    eprintln!("  client IP : {}", r.tailscale_ip);
    eprintln!("  target    : {}", r.target);
    eprintln!();
    eprintln!("  min   : {} us", r.min_us);
    eprintln!("  mean  : {:.1} us", r.mean_us);
    eprintln!("  p50   : {} us", r.p50_us);
    eprintln!("  p95   : {} us", r.p95_us);
    eprintln!("  p99   : {} us", r.p99_us);
    eprintln!("  max   : {} us", r.max_us);
    eprintln!();
}

fn print_latency_json(r: &latency::LatencyResult) {
    let obj = serde_json::json!({
        "tool": "rustscale-bench",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": "latency",
        "count": r.count,
        "path_class": r.path_class,
        "tailscale_ip": r.tailscale_ip,
        "target": r.target,
        "min_us": r.min_us,
        "max_us": r.max_us,
        "mean_us": r.mean_us,
        "p50_us": r.p50_us,
        "p95_us": r.p95_us,
        "p99_us": r.p99_us,
    });
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
