//! `rustscale netcheck` — print an analysis of local network conditions.
//!
//! Ports Go's `cmd/tailscale/cli/netcheck.go`. This is a client-side probe:
//! it reuses `crates/netcheck` directly to run STUN probes against each DERP
//! region and prints a Go-style report. The DERP map is fetched from the
//! daemon's `/localapi/v0/netmap` endpoint; if the daemon is down, an empty
//! DERP map is used (and the prober will report no regions).

use std::path::Path;
use std::time::Duration;

use rustscale_localclient::LocalClient;
use rustscale_netcheck::{Prober, ProberOpts, Report};
use rustscale_tailcfg::DERPMap;

use crate::CliError;

pub async fn run(_args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    // Try to get the DERP map from the daemon.
    let derp_map = fetch_derp_map(socket).await;

    if derp_map.Regions.is_empty() {
        eprintln!("netcheck: no DERP map available from daemon and no embedded default.");
        eprintln!("netcheck: cannot run network probe without a DERP map.");
        return Err(CliError(
            "no DERP map available (is rustscaled running?)".into(),
        ));
    }

    // Run the netcheck probe.
    let prober = Prober;
    let opts = ProberOpts::default();
    let report = prober
        .run(&derp_map, &opts)
        .await
        .map_err(|e| CliError(format!("netcheck: {e}")))?;

    print_netcheck_report(&derp_map, &report);

    Ok(())
}

/// Fetch the DERP map from the daemon's netmap endpoint. Falls back to an
/// empty DERP map if the daemon is unreachable.
async fn fetch_derp_map(socket: &Path) -> DERPMap {
    let client = LocalClient::new(socket);
    match client.derp_map().await {
        Ok(dm) => dm,
        Err(e) => {
            eprintln!("netcheck: could not fetch DERP map from daemon: {e}");
            DERPMap::default()
        }
    }
}

/// Print the report in Go's human-readable format.
fn print_netcheck_report(dm: &DERPMap, report: &Report) {
    println!();
    println!("Report:");
    let now = report
        .now
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or_else(
            || "unknown".to_string(),
            |d| format!("{:?}", Duration::from_secs(d.as_secs())),
        );
    println!("\t* Time: {now}");
    println!("\t* UDP: {}", report.udp);

    if let Some(v4) = report.global_v4 {
        println!("\t* IPv4: yes, {v4}");
    } else {
        println!("\t* IPv4: (no addr found)");
    }

    if let Some(v6) = report.global_v6 {
        println!("\t* IPv6: yes, {v6}");
    } else if report.ipv6 {
        println!("\t* IPv6: (no addr found)");
    } else if report.os_has_ipv6 {
        println!("\t* IPv6: no, but OS has support");
    } else {
        println!("\t* IPv6: no, unavailable in OS");
    }

    let mvbdi = match report.mapping_varies_by_dest_ip {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    };
    println!("\t* MappingVariesByDestIP: {mvbdi}");

    // DERP latencies.
    if report.region_latency.is_empty() {
        println!("\t* Nearest DERP: unknown (no response to latency probes)");
    } else {
        if report.preferred_derp != 0 {
            if let Some(region) = dm.Regions.get(&report.preferred_derp) {
                println!("\t* Nearest DERP: {}", region.RegionName);
            } else {
                println!(
                    "\t* Nearest DERP: {} (region not found in map)",
                    report.preferred_derp
                );
            }
        } else {
            println!("\t* Nearest DERP: [none]");
        }
        println!("\t* DERP latency:");

        // Sort region IDs by latency (regions with latency first, then by ID).
        let mut rids: Vec<i32> = dm.Regions.keys().copied().collect();
        rids.sort_by(|a, b| {
            let la = report.region_latency.get(a);
            let lb = report.region_latency.get(b);
            match (la, lb) {
                (Some(la), Some(lb)) => la.cmp(lb),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(b),
            }
        });

        for rid in rids {
            let latency = report
                .region_latency
                .get(&rid)
                .map(|d| {
                    let ms = d.as_secs_f64() * 1000.0;
                    format!("{ms:.1}ms")
                })
                .unwrap_or_default();
            if let Some(region) = dm.Regions.get(&rid) {
                println!(
                    "\t\t- {:3}: {:7} ({})",
                    region.RegionCode, latency, region.RegionName
                );
            }
        }
    }
}
