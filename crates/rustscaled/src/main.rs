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
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--statedir" => {
                        i += 1;
                        if i >= args.len() {
                            eprintln!("error: --statedir requires a value");
                            std::process::exit(1);
                        }
                        statedir = Some(PathBuf::from(&args[i]));
                    }
                    "--socket" => {
                        i += 1;
                        if i >= args.len() {
                            eprintln!("error: --socket requires a value");
                            std::process::exit(1);
                        }
                        socket = Some(PathBuf::from(&args[i]));
                    }
                    "--hostname" => {
                        i += 1;
                        if i >= args.len() {
                            eprintln!("error: --hostname requires a value");
                            std::process::exit(1);
                        }
                        hostname = Some(args[i].clone());
                    }
                    "--tun" => tun = true,
                    other => {
                        eprintln!("error: unknown argument '{other}'");
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
                if let Err(e) = Box::pin(daemon::run(statedir, hostname, tun, socket)).await {
                    eprintln!("rustscaled: {e}");
                    std::process::exit(1);
                }
            });
        }
        "install-system-daemon" => {
            #[cfg(target_os = "macos")]
            {
                if let Err(e) = launchd::install_system_daemon() {
                    eprintln!("install-system-daemon: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                eprintln!("install-system-daemon: not supported on this platform");
                std::process::exit(1);
            }
        }
        "uninstall-system-daemon" => {
            #[cfg(target_os = "macos")]
            {
                if let Err(e) = launchd::uninstall_system_daemon() {
                    eprintln!("uninstall-system-daemon: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                eprintln!("uninstall-system-daemon: not supported on this platform");
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("error: unknown subcommand '{other}'");
            usage(&args[0]);
            std::process::exit(1);
        }
    }
}

fn usage(bin: &str) {
    eprintln!("usage: {bin} run [--statedir <dir>] [--socket <path>] [--hostname <name>] [--tun]");
    eprintln!("       {bin} install-system-daemon");
    eprintln!("       {bin} uninstall-system-daemon");
}
