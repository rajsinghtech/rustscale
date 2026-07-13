#[allow(clippy::wildcard_imports)]
use super::*;

/// TUN data-plane pump: TUN device <-> WG <-> magicsock.
///
/// Inbound (from network): magicsock recv -> WG decapsulate -> TUN write.
/// Outbound (from OS): TUN read -> route lookup -> WG encapsulate -> magicsock send.
/// WG timer ticks run on a 250ms interval.
pub(crate) async fn run_tun_pump(
    magicsock: Arc<Magicsock>,
    mut wg_recv: mpsc::Receiver<rustscale_magicsock::WgDatagram>,
    tun: Arc<dyn Tun>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut packet = Vec::with_capacity(tun.mtu());

    loop {
        if cancel.is_cancelled() {
            break;
        }

        tokio::select! {
            // TUN read -> route -> WG encapsulate -> magicsock send.
            result = tun.read_packet(&mut packet) => {
                match result {
                    Ok(()) => {
                        {
                            let mut filt = filter.lock().unwrap();
                            filt.update_outbound(&packet);
                        }
                        encapsulate_and_send(&magicsock, &wg_tunnels, &route_table, &packet).await;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        eprintln!("tun read error: {e}");
                        break;
                    }
                }
            }
            // magicsock recv -> WG decapsulate -> filter -> TUN write.
            result = wg_recv.recv() => {
                if let Some(dgram) = result {
                    process_tun_inbound(
                        &magicsock, &wg_tunnels, &filter, &packet_drops, &tun, &dgram,
                    ).await;

                    // Drain any additional immediately-available datagrams
                    // to batch a burst of packets into a single scheduler turn.
                    while let Ok(more) = wg_recv.try_recv() {
                        process_tun_inbound(
                            &magicsock, &wg_tunnels, &filter, &packet_drops, &tun, &more,
                        ).await;
                    }
                } else {
                    eprintln!("tsnet: magicsock wg channel closed (tun)");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
            _ = ticker.tick() => {
                tick_wg_timers(&magicsock, &wg_tunnels).await;
            }
        }
    }
}
/// Create a TUN device and optionally apply OS routes.
/// On macOS/Linux this creates the real device and installs routes when
/// `config.apply_routes` is true. On other platforms it returns an error.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) async fn create_tun_device(
    config: &TunModeConfig,
    b: &Bootstrap,
    accept_routes: bool,
) -> Result<Arc<dyn Tun>, TsnetError> {
    let dev = rustscale_tun::create(&config.tun)?;
    if config.apply_routes {
        apply_tun_routes(dev.name(), &b.tailscale_ips, config.tun.mtu)?;
        if accept_routes {
            let rt = b.route_table.read().await;
            apply_accepted_subnet_routes(dev.name(), &rt)?;
        }
        if config.exit_node.is_some() {
            apply_exit_node_routes(dev.name())?;
        }
    }
    Ok(Arc::new(dev))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[allow(clippy::unused_async)]
pub(crate) async fn create_tun_device(
    _config: &TunModeConfig,
    _b: &Bootstrap,
    _accept_routes: bool,
) -> Result<Arc<dyn Tun>, TsnetError> {
    Err(TsnetError::Builder(
        "TUN mode not supported on this platform".into(),
    ))
}

/// Bring the TUN interface up and add tailnet routes. Requires root.
///
/// On macOS: `ifconfig <name> up <our_v4>/32`, `route add 100.64.0.0/10 -interface <name>`.
/// On Linux: `ip link set <name> up`, `ip addr add <our_v4>/32 dev <name>`,
/// `ip route add 100.64.0.0/10 dev <name>`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn apply_tun_routes(ifname: &str, tailscale_ips: &[IpAddr], _mtu: usize) -> Result<(), TsnetError> {
    let our_v4 = first_v4(tailscale_ips)?;
    let v4_str = our_v4.to_string();
    let cgnat = rustscale_tsaddr::cgnat_range().to_string();

    #[cfg(target_os = "macos")]
    {
        run_cmd(
            "ifconfig",
            &["-v", ifname, "inet", &format!("{v4_str}/32"), "up"],
        )?;
        run_cmd(
            "route",
            &["-q", "add", "-net", &cgnat, "-interface", ifname],
        )?;
    }
    #[cfg(target_os = "linux")]
    {
        run_cmd("ip", &["link", "set", ifname, "up"])?;
        run_cmd(
            "ip",
            &["addr", "add", &format!("{v4_str}/32"), "dev", ifname],
        )?;
        run_cmd("ip", &["route", "add", &cgnat, "dev", ifname])?;
    }
    Ok(())
}

/// Install peer-advertised subnet routes (non-tailnet CIDRs from the route
/// table) as OS routes pointing at the TUN device. Only called in TUN mode
/// when both `apply_routes` and `accept_routes` are enabled. Requires root.
///
/// **Note**: this installs the routes known at `up_tun` time. Dynamically
/// appearing routes (from later map-stream deltas) are not yet reflected in
/// the OS table — a future improvement. The in-process `RouteTable` always
/// has the latest entries.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn apply_accepted_subnet_routes(ifname: &str, rt: &RouteTable) -> Result<(), TsnetError> {
    for (net, prefix, _peer) in rt.entries() {
        let cidr = format!("{net}/{prefix}");
        // Skip tailnet-range prefixes — those are handled by apply_tun_routes
        // (100.64.0.0/10) and don't need per-prefix OS routes.
        if rustscale_tsaddr::is_tailscale_ip(net) {
            continue;
        }
        #[cfg(target_os = "macos")]
        {
            // Best-effort: ignore "route already exists" failures.
            let _ = run_cmd("route", &["-q", "add", "-net", &cidr, "-interface", ifname]);
        }
        #[cfg(target_os = "linux")]
        {
            let _ = run_cmd("ip", &["route", "add", &cidr, "dev", ifname]);
        }
    }
    Ok(())
}

/// Install OS-level default-route overrides so all non-tailnet traffic enters
/// the TUN device, enabling exit-node usage in TUN mode. Only called when
/// `apply_routes` is true and an exit node is selected. Requires root.
///
/// **macOS**: installs two `/1` routes per address family
/// (`0.0.0.0/1` + `128.0.0.0/1` for IPv4, `::/1` + `8000::/1` for IPv6).
/// Together these cover the entire address space and are more specific than
/// the default route (`0.0.0.0/0`), so they override it without deleting it —
/// mirroring how `tailscaled` overrides the default on macOS. The original
/// default route is preserved for traffic that explicitly avoids the TUN
/// (though rustscale does not yet install bypass routes for DERP/control;
/// see `TunModeConfig::exit_node` docs).
///
/// **Linux**: best-effort `ip route add 0.0.0.0/0 dev <tun>` and
/// `::/0 dev <tun>`. This may fail or conflict with an existing default
/// route; failures are logged but non-fatal.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn apply_exit_node_routes(ifname: &str) -> Result<(), TsnetError> {
    #[cfg(target_os = "macos")]
    {
        // IPv4: two /1 routes covering 0.0.0.0 – 255.255.255.255.
        run_cmd(
            "route",
            &["-q", "add", "-net", "0.0.0.0/1", "-interface", ifname],
        )?;
        run_cmd(
            "route",
            &["-q", "add", "-net", "128.0.0.0/1", "-interface", ifname],
        )?;
        // IPv6: two /1 routes covering :: – ffff::.
        run_cmd(
            "route",
            &["-q", "add", "-inet6", "::/1", "-interface", ifname],
        )?;
        run_cmd(
            "route",
            &["-q", "add", "-inet6", "8000::/1", "-interface", ifname],
        )?;
    }
    #[cfg(target_os = "linux")]
    {
        // Best-effort: ignore failures (default route may already exist).
        let _ = run_cmd("ip", &["route", "add", "0.0.0.0/0", "dev", ifname]);
        let _ = run_cmd("ip", &["-6", "route", "add", "::/0", "dev", ifname]);
    }
    Ok(())
}

/// Run a command, returning an error if it exits non-zero.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_cmd(prog: &str, args: &[&str]) -> Result<(), TsnetError> {
    let status = std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .map_err(|e| TsnetError::Builder(format!("spawn {prog}: {e}")))?;
    if !status.success() {
        return Err(TsnetError::Builder(format!(
            "{prog} {args:?} exited with {status}"
        )));
    }
    Ok(())
}
