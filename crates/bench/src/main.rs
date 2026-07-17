//! rustscale-bench — one RSB1 workload over userspace tsnet or kernel TCP/TUN.
#![forbid(unsafe_code)]
mod latency;
mod protocol;
mod server;
mod throughput;

use clap::{Parser, Subcommand, ValueEnum};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Transport {
    Userspace,
    KernelTcp,
}
#[derive(Parser)]
#[command(
    name = "rustscale-bench",
    about = "RSB1 throughput and latency benchmark",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, global = true)]
    json: bool,
}
#[derive(Subcommand)]
enum Command {
    Server {
        #[arg(long, value_enum, default_value = "userspace")]
        transport: Transport,
        /// Required only for --transport userspace.
        #[arg(long)]
        authkey: Option<String>,
        #[arg(long, default_value = "5201")]
        port: u16,
        #[arg(long, default_value = "0.0.0.0")]
        bind: IpAddr,
        #[arg(long, default_value = "bench-server")]
        hostname: String,
        #[arg(long, default_value = "controlplane.tailscale.com")]
        control_url: String,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    Client {
        #[arg(long, value_enum, default_value = "userspace")]
        transport: Transport,
        /// Required only for --transport userspace.
        #[arg(long)]
        authkey: Option<String>,
        #[arg(long)]
        target: String,
        #[arg(long, default_value="10", value_parser=clap::value_parser!(u64).range(1..))]
        duration: u64,
        #[arg(long, default_value="down", value_parser=["up","down","bidir"])]
        direction: String,
        #[arg(long, default_value="1", value_parser=parse_parallel)]
        parallel: usize,
        #[arg(long, default_value = "bench-client")]
        hostname: String,
        #[arg(long, default_value = "controlplane.tailscale.com")]
        control_url: String,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    Latency {
        #[arg(long, value_enum, default_value = "userspace")]
        transport: Transport,
        /// Required only for --transport userspace.
        #[arg(long)]
        authkey: Option<String>,
        #[arg(long)]
        target: String,
        #[arg(long, default_value="1000", value_parser=parse_positive_usize)]
        count: usize,
        #[arg(long, default_value = "bench-latency")]
        hostname: String,
        #[arg(long, default_value = "controlplane.tailscale.com")]
        control_url: String,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

fn parse_parallel(value: &str) -> Result<usize, String> {
    let value: usize = value
        .parse()
        .map_err(|_| "parallel must be an integer".to_string())?;
    if (1..=1000).contains(&value) {
        Ok(value)
    } else {
        Err("parallel must be in 1..=1000".into())
    }
}
fn parse_positive_usize(value: &str) -> Result<usize, String> {
    let value: usize = value
        .parse()
        .map_err(|_| "value must be a positive integer".to_string())?;
    if value > 0 {
        Ok(value)
    } else {
        Err("value must be positive".into())
    }
}

fn require_auth(transport: Transport, authkey: Option<String>) -> Result<Option<String>, String> {
    match (transport, authkey) {
        (Transport::Userspace, None) => {
            Err("--authkey is required for --transport userspace".into())
        }
        (Transport::KernelTcp, Some(_)) => {
            Err("--authkey is not applicable to --transport kernel-tcp".into())
        }
        (_, value) => Ok(value),
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = validate_contract(&cli) {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .event_interval(1)
        .build()
        .unwrap();
    if let Err(error) = runtime.block_on(async_main(cli)) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn validate_contract(cli: &Cli) -> Result<(), String> {
    let (transport, has_auth) = match &cli.command {
        Command::Server {
            transport, authkey, ..
        }
        | Command::Client {
            transport, authkey, ..
        }
        | Command::Latency {
            transport, authkey, ..
        } => (*transport, authkey.is_some()),
    };
    match (transport, has_auth) {
        (Transport::Userspace, false) => {
            Err("--authkey is required for --transport userspace".into())
        }
        (Transport::KernelTcp, true) => {
            Err("--authkey is not applicable to --transport kernel-tcp".into())
        }
        _ => Ok(()),
    }
}

async fn async_main(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let json = cli.json;
    match cli.command {
        Command::Server {
            transport,
            authkey,
            port,
            bind,
            hostname,
            control_url,
            state_dir,
        } => {
            let auth = require_auth(transport, authkey)?;
            match transport {
                Transport::Userspace => {
                    server::run_userspace(auth.unwrap(), port, hostname, control_url, state_dir)
                        .await
                }
                Transport::KernelTcp => server::run_kernel(port, bind).await,
            }
        }
        Command::Client {
            transport,
            authkey,
            target,
            duration,
            direction,
            parallel,
            hostname,
            control_url,
            state_dir,
        } => {
            let auth = require_auth(transport, authkey)?;
            let result = match transport {
                Transport::Userspace => {
                    throughput::run_userspace(
                        auth.unwrap(),
                        target,
                        duration,
                        &direction,
                        parallel,
                        hostname,
                        control_url,
                        state_dir,
                    )
                    .await?
                }
                Transport::KernelTcp => {
                    throughput::run_kernel(target, duration, &direction, parallel).await?
                }
            };
            if json {
                print_throughput_json(&result);
            } else {
                eprintln!(
                    "{} {} streams: {:.2} Mbps",
                    result.transport, result.parallel, result.total_mbps
                );
            }
            Ok(())
        }
        Command::Latency {
            transport,
            authkey,
            target,
            count,
            hostname,
            control_url,
            state_dir,
        } => {
            let auth = require_auth(transport, authkey)?;
            let result = match transport {
                Transport::Userspace => {
                    latency::run_userspace(
                        auth.unwrap(),
                        target,
                        count,
                        hostname,
                        control_url,
                        state_dir,
                    )
                    .await?
                }
                Transport::KernelTcp => latency::run_kernel(target, count).await?,
            };
            if json {
                print_latency_json(&result);
            } else {
                eprintln!(
                    "{} p50={} us p95={} us p99={} us",
                    result.transport,
                    result.p50_ns / 1000,
                    result.p95_ns / 1000,
                    result.p99_ns / 1000
                );
            }
            Ok(())
        }
    }
}
fn print_throughput_json(r: &throughput::ThroughputResult) {
    let samples: Vec<_> = r
        .samples
        .iter()
        .map(|s| serde_json::json!({"elapsed_secs":s.elapsed_secs,"mbps":s.mbps}))
        .collect();
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "tool":"rustscale-bench","version":env!("CARGO_PKG_VERSION"),"mode":"throughput","transport":r.transport,
        "protocol":"RSB1","payload_bytes":protocol::FIREHOSE_BUF_SIZE,"direction":r.direction,"duration_secs":r.duration_secs,
        "parallel":r.parallel,"path_class":r.path_class,"tailscale_ip":r.tailscale_ip,"target":r.target,
        "total_bytes":r.total_bytes,"total_mbps":r.total_mbps,"up_bytes":r.up_bytes,"up_mbps":r.up_mbps,
        "down_bytes":r.down_bytes,"down_mbps":r.down_mbps,"samples":samples,
        "established":r.established,"handshaken":r.handshaken,"completed":r.completed
    })).unwrap());
}
fn print_latency_json(r: &latency::LatencyResult) {
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "tool":"rustscale-bench","version":env!("CARGO_PKG_VERSION"),"mode":"latency","transport":r.transport,
        "protocol":"RSB1-tcp-pingpong","payload_bytes":protocol::PING_SIZE,"percentile_method":"nearest-rank-rounded-index",
        "requested":r.requested,"successful":r.successful,"timed_out":r.timed_out,"malformed":r.malformed,"count":r.successful,
        "path_class":r.path_class,"tailscale_ip":r.tailscale_ip,"target":r.target,
        "min_ns":r.min_ns,"max_ns":r.max_ns,"mean_ns":r.mean_ns,"p50_ns":r.p50_ns,"p95_ns":r.p95_ns,"p99_ns":r.p99_ns,
        "min_us":r.min_ns as f64/1000.0,"max_us":r.max_ns as f64/1000.0,"mean_us":r.mean_ns/1000.0,"p50_us":r.p50_ns as f64/1000.0,"p95_us":r.p95_ns as f64/1000.0,"p99_us":r.p99_ns as f64/1000.0,
        "samples_ns":r.samples_ns
    })).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    #[test]
    fn metadata_version() {
        assert_eq!(
            Cli::command().get_version(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }
    #[test]
    fn kernel_transport_needs_no_auth() {
        let cli = Cli::try_parse_from([
            "bench",
            "client",
            "--transport",
            "kernel-tcp",
            "--target",
            "127.0.0.1:1",
        ])
        .unwrap();
        if let Command::Client {
            transport, authkey, ..
        } = cli.command
        {
            assert_eq!(require_auth(transport, authkey).unwrap(), None);
            assert!(validate_contract(&Cli {
                command: Command::Client {
                    transport,
                    authkey: None,
                    target: "127.0.0.1:1".into(),
                    duration: 1,
                    direction: "down".into(),
                    parallel: 1,
                    hostname: "x".into(),
                    control_url: "x".into(),
                    state_dir: None
                },
                json: false
            })
            .is_ok());
        } else {
            panic!()
        }
    }
    #[test]
    fn userspace_requires_auth() {
        let cli = Cli::try_parse_from(["bench", "client", "--target", "100.64.0.1:1"]).unwrap();
        if let Command::Client {
            transport, authkey, ..
        } = cli.command
        {
            assert!(require_auth(transport, authkey).is_err());
        } else {
            panic!()
        }
    }
    #[test]
    fn kernel_rejects_auth() {
        assert!(require_auth(Transport::KernelTcp, Some("secret".into())).is_err());
    }
    #[test]
    fn default_bind_is_safe_all_interfaces() {
        let cli = Cli::try_parse_from(["bench", "server", "--transport", "kernel-tcp"]).unwrap();
        if let Command::Server { bind, .. } = cli.command {
            assert_eq!(bind, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        } else {
            panic!()
        }
    }
}
