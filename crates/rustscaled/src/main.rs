//! rustscaled — the rustscale daemon binary.
//!
//! Subcommands:
//!   run                       — bring up a tsnet Server and wait for SIGINT/SIGTERM
//!   install-system-daemon     — install as a macOS launchd system daemon (macOS only)
//!   uninstall-system-daemon   — remove the launchd system daemon (macOS only)

#![forbid(unsafe_code)]

mod daemon;
#[cfg(target_os = "macos")]
mod launchd;

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Keep this ahead of all subcommand/log/runtime setup: version queries are
    // a side-effect-free identity probe for packaged and benchmarked daemons.
    if args
        .get(1)
        .is_some_and(|arg| matches!(arg.as_str(), "--version" | "-V"))
    {
        println!("{}", version_string());
        return;
    }
    if args.len() < 2 {
        usage(&args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "run" => {
            let mut statedir = None;
            let mut hostname = None;
            let mut socket = None;
            let mut tun = false;
            let mut port: Option<u16> = None;
            let mut socks5_server: Option<String> = None;
            let mut http_proxy_server: Option<String> = None;
            let mut config: Option<PathBuf> = None;
            let mut cleanup = false;
            let mut no_logs_no_support = false;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--statedir" | "--state" => {
                        i += 1;
                        if i >= args.len() {
                            log::error!("error: {} requires a value", args[i - 1]);
                            std::process::exit(1);
                        }
                        statedir = Some(PathBuf::from(&args[i]));
                    }
                    "--socket" => {
                        i += 1;
                        if i >= args.len() {
                            log::error!("error: --socket requires a value");
                            std::process::exit(1);
                        }
                        socket = Some(PathBuf::from(&args[i]));
                    }
                    "--hostname" => {
                        i += 1;
                        if i >= args.len() {
                            log::error!("error: --hostname requires a value");
                            std::process::exit(1);
                        }
                        hostname = Some(args[i].clone());
                    }
                    "--port" => {
                        i += 1;
                        if i >= args.len() {
                            log::error!("error: --port requires a value");
                            std::process::exit(1);
                        }
                        port = Some(args[i].parse().unwrap_or_else(|_| {
                            log::error!("error: invalid --port value: {}", args[i]);
                            std::process::exit(1);
                        }));
                    }
                    "--socks5-server" => {
                        i += 1;
                        if i >= args.len() {
                            log::error!("error: --socks5-server requires a value");
                            std::process::exit(1);
                        }
                        socks5_server = Some(args[i].clone());
                    }
                    "--http-proxy-server" => {
                        i += 1;
                        if i >= args.len() {
                            log::error!("error: --http-proxy-server requires a value");
                            std::process::exit(1);
                        }
                        http_proxy_server = Some(args[i].clone());
                    }
                    "--config" => {
                        i += 1;
                        if i >= args.len() {
                            log::error!("error: --config requires a value");
                            std::process::exit(1);
                        }
                        config = Some(PathBuf::from(&args[i]));
                    }
                    "--cleanup" => cleanup = true,
                    "--no-logs-no-support" => no_logs_no_support = true,
                    "--tun" => tun = true,
                    other => {
                        log::error!("error: unknown argument '{other}'");
                        std::process::exit(1);
                    }
                }
                i += 1;
            }

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime");
            rt.block_on(async {
                if let Err(e) = Box::pin(daemon::run(
                    statedir,
                    hostname,
                    tun,
                    socket,
                    port,
                    socks5_server,
                    http_proxy_server,
                    config,
                    cleanup,
                    no_logs_no_support,
                ))
                .await
                {
                    log::error!("rustscaled: {e}");
                    std::process::exit(1);
                }
            });
        }
        "install-system-daemon" => {
            #[cfg(target_os = "macos")]
            {
                if let Err(e) = launchd::install_system_daemon() {
                    log::error!("install-system-daemon: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                log::error!("install-system-daemon: not supported on this platform");
                std::process::exit(1);
            }
        }
        "uninstall-system-daemon" => {
            #[cfg(target_os = "macos")]
            {
                if let Err(e) = launchd::uninstall_system_daemon() {
                    log::error!("uninstall-system-daemon: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                log::error!("uninstall-system-daemon: not supported on this platform");
                std::process::exit(1);
            }
        }
        other => {
            log::error!("error: unknown subcommand '{other}'");
            usage(&args[0]);
            std::process::exit(1);
        }
    }
}

fn version_string() -> &'static str {
    concat!("rustscaled ", env!("CARGO_PKG_VERSION"))
}

fn usage(bin: &str) {
    log::info!(
        "usage: {bin} run [--statedir <dir>] [--state <dir>] [--socket <path>] \
         [--hostname <name>] [--port <port>] [--tun] \
         [--socks5-server <addr>] [--http-proxy-server <addr>] \
         [--config <path>] [--cleanup] [--no-logs-no-support]"
    );
    log::info!("       {bin} install-system-daemon");
    log::info!("       {bin} uninstall-system-daemon");
}

#[cfg(test)]
mod tests {
    use super::version_string;

    #[test]
    fn version_is_a_stable_daemon_identity() {
        assert_eq!(
            version_string(),
            concat!("rustscaled ", env!("CARGO_PKG_VERSION"))
        );
        assert!(!version_string().trim().is_empty());
    }
}
