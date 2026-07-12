use std::path::Path;

use rustscale_localclient::LocalClient;
use rustscale_tsnet::{HTTPHandler, ServeConfig, TCPPortHandler, WebServerConfig, FUNNEL_PORTS};

use crate::flags::{parse_bool_flag, parse_str_flag, parse_u16_flag};
use crate::CliError;

/// Mode: serve (tailnet only) or funnel (public internet).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ServeMode {
    Serve,
    Funnel,
}

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    if args.is_empty() {
        serve_usage("serve");
        return Err(CliError("no subcommand".into()));
    }

    // Check for subcommands: status, reset
    match args[0].as_str() {
        "status" => {
            let sub_args = args[1..].to_vec();
            return run_status(sub_args, socket, json, ServeMode::Serve).await;
        }
        "reset" => {
            return run_reset(socket, ServeMode::Serve).await;
        }
        _ => {}
    }

    // Otherwise, it's `serve [flags] <target>` — parse flags + positional.
    run_set(args, socket, ServeMode::Serve).await
}

/// `serve status [--json]` — print the current serve config.
async fn run_status(
    args: Vec<String>,
    socket: &Path,
    json: bool,
    mode: ServeMode,
) -> Result<(), CliError> {
    let json = parse_bool_flag(&args, "json").unwrap_or(json);
    let lc = LocalClient::new(socket);
    let (cfg, _etag) = lc.get_serve_config().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&cfg).unwrap_or_default());
        return Ok(());
    }

    print_serve_config(&cfg, mode);
    Ok(())
}

/// `serve reset` — clear the serve config.
async fn run_reset(socket: &Path, _mode: ServeMode) -> Result<(), CliError> {
    let lc = LocalClient::new(socket);
    let (cfg, etag) = lc.get_serve_config().await?;

    if cfg.is_empty() {
        println!("No serve config to reset.");
        return Ok(());
    }

    let empty = ServeConfig::default();
    lc.set_serve_config(&empty, &etag).await?;
    println!("Serve config reset.");
    Ok(())
}

/// `serve [--bg] [--https=PORT|--http=PORT|--tcp=PORT|--tls-terminated-tcp=PORT]
///  [--set-path PATH] <target>` — set or update the serve config.
async fn run_set(args: Vec<String>, socket: &Path, mode: ServeMode) -> Result<(), CliError> {
    let bg = parse_bool_flag(&args, "bg").unwrap_or(false);
    let https_port = parse_u16_flag(&args, "https");
    let http_port = parse_u16_flag(&args, "http");
    let tcp_port = parse_u16_flag(&args, "tcp");
    let tls_term_tcp_port = parse_u16_flag(&args, "tls-terminated-tcp");
    let set_path = parse_str_flag(&args, "set-path").unwrap_or_else(|| "/".to_string());

    // Foreground mode not yet supported.
    if !bg {
        return Err(CliError(
            "foreground serve not yet supported; use --bg".into(),
        ));
    }

    // Determine the target from positional args.
    let positional: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .collect();
    let target = positional
        .first()
        .ok_or_else(|| CliError("missing <target> (port, host:port, or URL)".into()))?;

    // Determine serve type and port from flags.
    let mut type_count = 0;
    let mut serve_type = "https";
    let mut serve_port: u16 = 443;

    if let Some(p) = https_port {
        serve_type = "https";
        serve_port = p;
        type_count += 1;
    }
    if let Some(p) = http_port {
        serve_type = "http";
        serve_port = p;
        type_count += 1;
    }
    if let Some(p) = tcp_port {
        serve_type = "tcp";
        serve_port = p;
        type_count += 1;
    }
    if let Some(p) = tls_term_tcp_port {
        serve_type = "tls-terminated-tcp";
        serve_port = p;
        type_count += 1;
    }

    if type_count == 0 {
        // Default to https:443.
        serve_type = "https";
        serve_port = 443;
    } else if type_count > 1 {
        return Err(CliError(
            "cannot serve multiple types for a single mount point".into(),
        ));
    }

    // Funnel port validation (client-side).
    if mode == ServeMode::Funnel && !FUNNEL_PORTS.contains(&serve_port) {
        return Err(CliError(format!(
            "port {serve_port} is not allowed for funnel; allowed ports: 443, 8443, 10000"
        )));
    }

    // Get the current config + ETag.
    let lc = LocalClient::new(socket);
    let (mut cfg, etag) = lc.get_serve_config().await?;

    // Get the DNS name from status.
    let status = lc.status().await?;
    let dns_name = status
        .get("Self")
        .and_then(|s| s.get("DNSName"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_end_matches('.')
        .to_string();

    if dns_name.is_empty() {
        return Err(CliError(
            "cannot determine node DNS name; is the daemon running?".into(),
        ));
    }

    let host_port = format!("{dns_name}:{serve_port}");

    // Apply the serve config based on type.
    match serve_type {
        "https" | "http" => {
            let use_tls = serve_type == "https";

            // Check if TCP forward is already on this port.
            if cfg.TCP.contains_key(&serve_port) && !cfg.TCP[&serve_port].TCPForward.is_empty() {
                return Err(CliError(format!(
                    "cannot serve web; already serving TCP on port {serve_port}"
                )));
            }

            // Set the TCP handler.
            let handler = cfg.TCP.entry(serve_port).or_insert_with(|| TCPPortHandler {
                HTTPS: use_tls,
                HTTP: !use_tls,
                ..Default::default()
            });
            if use_tls {
                handler.HTTPS = true;
                handler.HTTP = false;
            } else {
                handler.HTTP = true;
                handler.HTTPS = false;
            }

            // Set the web handler.
            let web = cfg
                .Web
                .entry(host_port.clone())
                .or_insert_with(WebServerConfig::default);
            let http_handler = HTTPHandler {
                Proxy: expand_proxy_target(target),
                ..Default::default()
            };
            web.Handlers.insert(set_path.clone(), http_handler);
        }
        "tcp" | "tls-terminated-tcp" => {
            let terminate_tls = serve_type == "tls-terminated-tcp";

            // Check if web is already on this port.
            if cfg.TCP.contains_key(&serve_port)
                && (cfg.TCP[&serve_port].HTTPS || cfg.TCP[&serve_port].HTTP)
            {
                return Err(CliError(format!(
                    "cannot serve TCP; already serving web on port {serve_port}"
                )));
            }

            let forward_target = expand_tcp_target(target);
            let handler = TCPPortHandler {
                TCPForward: forward_target,
                TerminateTLS: if terminate_tls {
                    dns_name.clone()
                } else {
                    String::new()
                },
                ..Default::default()
            };
            cfg.TCP.insert(serve_port, handler);
        }
        _ => {}
    }

    // Apply funnel flag.
    if mode == ServeMode::Funnel {
        cfg.AllowFunnel.insert(host_port.clone(), true);
    } else {
        // For serve mode, ensure funnel is off for this port.
        cfg.AllowFunnel.insert(host_port.clone(), false);
    }

    // Set the config.
    lc.set_serve_config(&cfg, &etag).await?;

    // Print success message.
    let scheme = if serve_type == "http" {
        "http"
    } else {
        "https"
    };
    let port_part =
        if (scheme == "http" && serve_port == 80) || (scheme == "https" && serve_port == 443) {
            String::new()
        } else {
            format!(":{serve_port}")
        };

    if mode == ServeMode::Funnel {
        println!("Available on the internet:\n");
    } else {
        println!("Available within your tailnet:\n");
    }
    match serve_type {
        "https" | "http" => {
            println!("{scheme}://{dns_name}{port_part}{set_path}");
            println!("|-- proxy {target}");
        }
        "tcp" | "tls-terminated-tcp" => {
            let tls_status = if serve_type == "tls-terminated-tcp" {
                "TLS terminated"
            } else {
                "TLS over TCP"
            };
            println!("|-- tcp://{dns_name}:{serve_port} ({tls_status})");
            println!("|--> {target}");
        }
        _ => {}
    }
    println!();
    let cmd_name = if mode == ServeMode::Funnel {
        "funnel"
    } else {
        "serve"
    };
    let type_flag = match serve_type {
        "https" => "https",
        "http" => "http",
        "tcp" => "tcp",
        "tls-terminated-tcp" => "tls-terminated-tcp",
        _ => "https",
    };
    println!("To disable, run: rustscale {cmd_name} --{type_flag}={serve_port} off");

    Ok(())
}

/// Expand a proxy target string. Accepts:
/// - Port number (e.g. "3000") → "http://127.0.0.1:3000"
/// - host:port → "http://host:port"
/// - Full URL → as-is
fn expand_proxy_target(target: &str) -> String {
    if target.contains("://") {
        return target.to_string();
    }
    if target.parse::<u16>().is_ok() {
        return format!("http://127.0.0.1:{target}");
    }
    format!("http://{target}")
}

/// Expand a TCP forward target. Accepts port, host:port, or tcp://host:port.
fn expand_tcp_target(target: &str) -> String {
    if let Some(rest) = target.strip_prefix("tcp://") {
        return rest.to_string();
    }
    if target.parse::<u16>().is_ok() {
        return format!("127.0.0.1:{target}");
    }
    target.to_string()
}

/// Print serve config in human-readable format.
fn print_serve_config(cfg: &ServeConfig, _mode: ServeMode) {
    if cfg.is_empty() {
        println!("No serve config set.");
        return;
    }

    // Print TCP handlers.
    for (port, handler) in &cfg.TCP {
        if handler.HTTPS || handler.HTTP {
            let scheme = if handler.HTTPS { "https" } else { "http" };
            let port_part =
                if (scheme == "http" && *port == 80) || (scheme == "https" && *port == 443) {
                    String::new()
                } else {
                    format!(":{port}")
                };
            // Find the web config for this port.
            let hp_suffix = format!(":{port}");
            for (hp, web) in &cfg.Web {
                if hp.ends_with(&hp_suffix.as_str()) {
                    let host = hp.trim_end_matches(&hp_suffix.as_str());
                    let funnel_on = cfg.AllowFunnel.get(hp).copied().unwrap_or(false);
                    if funnel_on {
                        println!("Funnel (public internet):");
                    } else {
                        println!("Serve (tailnet):");
                    }
                    let mut mounts: Vec<&String> = web.Handlers.keys().collect();
                    mounts.sort_by_key(|m: &&String| m.len());
                    for mount in mounts {
                        let h = &web.Handlers[mount];
                        if !h.Proxy.is_empty() {
                            println!("{scheme}://{host}{port_part}{mount}");
                            println!("|-- proxy {}", h.Proxy);
                        } else if !h.Text.is_empty() {
                            println!("{scheme}://{host}{port_part}{mount}");
                            println!("|-- text \"{}\"", h.Text);
                        }
                    }
                }
            }
        } else if !handler.TCPForward.is_empty() {
            let tls_status = if handler.TerminateTLS.is_empty() {
                "TLS over TCP"
            } else {
                "TLS terminated"
            };
            println!("tcp://...:{port} ({tls_status})");
            println!("|--> {}", handler.TCPForward);
        }
        println!();
    }
}

fn serve_usage(_cmd: &str) {
    eprintln!("usage: rustscale serve [--bg] [--https=<port>|--http=<port>|--tcp=<port>|--tls-terminated-tcp=<port>] [--set-path <path>] <target>");
    eprintln!("       rustscale serve status [--json]");
    eprintln!("       rustscale serve reset");
}

/// Entry point for `rustscale funnel` — same as serve but with Funnel mode.
pub async fn run_funnel(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    if args.is_empty() {
        serve_usage("funnel");
        return Err(CliError("no subcommand".into()));
    }

    match args[0].as_str() {
        "status" => {
            let sub_args = args[1..].to_vec();
            return run_status(sub_args, socket, json, ServeMode::Funnel).await;
        }
        "reset" => {
            return run_reset(socket, ServeMode::Funnel).await;
        }
        _ => {}
    }

    run_set(args, socket, ServeMode::Funnel).await
}
