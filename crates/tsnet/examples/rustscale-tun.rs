//! rustscale-tun — TUN-mode Tailscale client CLI.
//!
//! Brings up a rustscale server in TUN mode, prints periodic status, and
//! shuts down cleanly on Ctrl-C.
//!
//! # Usage
//!
//! ```sh
//! sudo cargo run --example rustscale-tun -- \
//!   --authkey tskey-... \
//!   --hostname my-rustscale \
//!   --state-dir /var/lib/rustscale \
//!   --tun-name utun \
//!   --apply-routes
//! ```
//!
//! `--authkey` can be omitted if `TS_AUTHKEY` is set in the environment.
//! Requires root (utun creation is privileged).

use std::time::Duration;

use rustscale_tsnet::{Server, TunModeConfig};
use rustscale_tun::TunConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut authkey = std::env::var("TS_AUTHKEY").unwrap_or_default();
    let mut hostname = "rustscale".to_string();
    let mut state_dir: Option<String> = None;
    let mut tun_name = "utun".to_string();
    let mut control_url = rustscale_tsnet::DEFAULT_CONTROL_URL.to_string();
    let mut apply_routes = false;
    let mut exit_node: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--authkey" => {
                i += 1;
                if i < args.len() {
                    authkey = args[i].clone();
                }
            }
            "--hostname" => {
                i += 1;
                if i < args.len() {
                    hostname = args[i].clone();
                }
            }
            "--state-dir" => {
                i += 1;
                if i < args.len() {
                    state_dir = Some(args[i].clone());
                }
            }
            "--tun-name" => {
                i += 1;
                if i < args.len() {
                    tun_name = args[i].clone();
                }
            }
            "--control-url" => {
                i += 1;
                if i < args.len() {
                    control_url = args[i].clone();
                }
            }
            "--apply-routes" => {
                apply_routes = true;
            }
            "--exit-node" => {
                i += 1;
                if i < args.len() {
                    exit_node = Some(args[i].clone());
                }
            }
            "--help" | "-h" => {
                eprintln!("rustscale-tun — TUN-mode Tailscale client\n");
                eprintln!("Usage: sudo rustscale-tun [OPTIONS]\n");
                eprintln!("Options:");
                eprintln!("  --authkey <key>       Tailscale auth key (or TS_AUTHKEY env)");
                eprintln!("  --hostname <name>     Node hostname (default: rustscale)");
                eprintln!("  --state-dir <dir>     State directory for persistent keys");
                eprintln!("  --tun-name <name>     TUN device name (default: utun)");
                eprintln!("  --control-url <url>   Control plane URL");
                eprintln!("  --apply-routes        Bring up interface + add routes (needs root)");
                eprintln!("  --exit-node <ip|name> Select a peer as exit node (requires --apply-routes for OS routes)");
                eprintln!("  --help                Show this help");
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if authkey.is_empty() {
        eprintln!("error: --authkey or TS_AUTHKEY env var is required");
        std::process::exit(2);
    }

    let mut builder = Server::builder()
        .hostname(hostname.as_str())
        .auth_key(authkey.as_str())
        .control_url(control_url.as_str())
        .ephemeral(true);

    if let Some(ref dir) = state_dir {
        builder = builder.state_dir(std::path::PathBuf::from(dir));
    }

    let mut server = builder.build()?;

    let tun_config = TunModeConfig {
        tun: TunConfig {
            name: tun_name.clone(),
            mtu: 1280,
        },
        apply_routes,
        exit_node,
    };

    eprintln!("bringing up TUN mode: device={tun_name}, apply_routes={apply_routes}");
    if let Some(ref en) = tun_config.exit_node {
        eprintln!("exit node: {en}");
    }
    eprintln!("this requires root for utun creation");

    server.up_tun(tun_config).await?;

    let status = server.status();
    eprintln!("online: {}", status.up);
    eprintln!("tailscale IPs: {:?}", status.tailscale_ips);
    eprintln!("peers: {}", status.peer_count);

    // Ctrl-C handler.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("\nreceived Ctrl-C, shutting down...");
        let _ = shutdown_tx.send(()).await;
    });

    // Periodic status printer.
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let st = server.status();
                eprintln!(
                    "status: up={} peers={} ips={:?}",
                    st.up, st.peer_count, st.tailscale_ips
                );
                for peer in &st.peers {
                    eprintln!(
                        "  peer {} ({}) ips={:?} path={:?}",
                        peer.name, peer.node_key, peer.ips, peer.path_class
                    );
                }
            }
            _ = shutdown_rx.recv() => {
                break;
            }
        }
    }

    server.close().await;
    eprintln!("shutdown complete");
    Ok(())
}
