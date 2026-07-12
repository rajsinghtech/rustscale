//! rustscale — the CLI binary. Talks to `rustscaled` over LocalAPI
//! (Unix domain socket via safesocket). This is the Rust equivalent of Go's
//! `cmd/tailscale` CLI.
//!
//! # Subcommands (Tier A — thin LocalAPI wrappers)
//!
//!   status       — show state of rustscaled and its connections
//!   ip           — show Tailscale IP addresses
//!   version      — print client and daemon version
//!   whois        — show the machine and user for a Tailscale IP
//!   netcheck     — print a network conditions analysis (client-side probe)
//!   metrics      — print Prometheus-format metrics
//!   health       — print active health warnings
//!   down         — disconnect (not yet supported by rustscaled)
//!   ping         — ping a peer (not yet supported by rustscaled)
//!
//! # Global flags
//!
//!   --socket <path>   override the daemon socket path
//!   --json            output in JSON format (where applicable)

#![forbid(unsafe_code)]

mod commands;
mod flags;
mod qrcode;
mod socket;
mod version;

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
        std::process::exit(1);
    }

    // Handle --help / -h / help as a top-level pseudo-subcommand.
    if matches!(args[1].as_str(), "--help" | "-h" | "help") {
        usage(&args[0]);
        return;
    }

    // Handle --version / -V as a top-level shortcut.
    if matches!(args[1].as_str(), "--version" | "-V") {
        println!("{}", version::client_version_string());
        return;
    }

    // Parse args: global flags (--socket, --json) can appear before or after
    // the subcommand. The first non-flag, non-value argument is the subcommand.
    let mut socket: Option<PathBuf> = None;
    let mut json = false;
    let mut subcommand: Option<String> = None;
    let mut sub_args: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --socket requires a value");
                    std::process::exit(1);
                }
                socket = Some(PathBuf::from(&args[i]));
            }
            s if s.starts_with("--socket=") => {
                socket = Some(PathBuf::from(&s["--socket=".len()..]));
            }
            "--json" => json = true,
            other => {
                if subcommand.is_none() {
                    // The first non-flag argument is the subcommand.
                    subcommand = Some(other.to_string());
                } else {
                    // Remaining args belong to the subcommand.
                    sub_args.push(other.to_string());
                }
            }
        }
        i += 1;
    }

    let Some(subcommand) = subcommand else {
        eprintln!("error: no subcommand specified");
        usage(&args[0]);
        std::process::exit(1);
    };

    let socket_path = socket::resolve_socket_path(socket);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let result = rt.block_on(dispatch(&subcommand, sub_args, socket_path, json));

    if let Err(e) = result {
        eprintln!("rustscale: {e}");
        std::process::exit(1);
    }
}

async fn dispatch(
    subcommand: &str,
    args: Vec<String>,
    socket_path: PathBuf,
    json: bool,
) -> Result<(), CliError> {
    match subcommand {
        "status" => commands::status::run(args, &socket_path, json).await,
        "ip" => commands::ip::run(args, &socket_path).await,
        "version" => commands::version::run(args, &socket_path, json).await,
        "whois" => commands::whois::run(args, &socket_path, json).await,
        "netcheck" => commands::netcheck::run(args, &socket_path).await,
        "metrics" => commands::metrics::run(args, &socket_path).await,
        "health" => commands::health::run(args, &socket_path, json).await,
        "up" => commands::up::run(args, &socket_path, json).await,
        "login" => commands::login::run(args, &socket_path, json).await,
        "logout" => commands::logout::run(args, &socket_path).await,
        "down" => commands::down::run(args, &socket_path).await,
        "set" => commands::set::run(args, &socket_path).await,
        "get" => commands::get::run(args, &socket_path).await,
        "serve" => commands::serve::run(args, &socket_path, json).await,
        "funnel" => commands::serve::run_funnel(args, &socket_path, json).await,
        "switch" => commands::switch::run(args, &socket_path, json).await,
        "cert" => commands::cert::run(args, &socket_path).await,
        "ping" => commands::ping::run(args, &socket_path).await,
        "file" => commands::file::run(args, &socket_path, json).await,
        "ssh" => commands::ssh::run(args, &socket_path).await,
        "web" => commands::web::run(args, &socket_path).await,
        "debug" => commands::debug::run(args, &socket_path, json).await,
        "bugreport" => commands::bugreport::run(args, &socket_path, json).await,
        "exit-node" => commands::exit_node::run(args, &socket_path, json).await,
        "dns" => commands::dns::run(args, &socket_path, json).await,
        "nc" => commands::nc::run(args, &socket_path, json).await,
        "id-token" => commands::id_token::run(args, &socket_path, json).await,
        "update" => commands::update::run(args, &socket_path, json).await,
        other => {
            eprintln!("error: unknown subcommand '{other}'");
            usage(&std::env::args().next().unwrap_or_default());
            std::process::exit(1);
        }
    }
}

fn usage(bin: &str) {
    eprintln!("usage: {bin} [global flags] <subcommand> [subcommand flags]");
    eprintln!();
    eprintln!("global flags:");
    eprintln!("  --socket <path>   path to the rustscaled LocalAPI socket");
    eprintln!("                     (default: /var/run/rustscaled.sock, fallback: <state_dir>/rustscaled.sock)");
    eprintln!("  --json             output in JSON format (where applicable)");
    eprintln!();
    eprintln!("subcommands:");
    eprintln!("  up [flags]                          connect to Tailscale (interactive auth if no auth key)");
    eprintln!("  login                               log in to Tailscale (interactive)");
    eprintln!("  logout                              disconnect and log out");
    eprintln!("  down                                disconnect from Tailscale");
    eprintln!("  set [flags]                         set preferences");
    eprintln!("  get                                 print preferences");
    eprintln!("  serve [--bg] [flags] <target>       serve content on the tailnet");
    eprintln!("  serve status [--json]               show current serve config");
    eprintln!("  serve reset                         clear serve config");
    eprintln!("  funnel [--bg] [flags] <target>      serve content on the internet");
    eprintln!("  funnel status [--json]              show current funnel config");
    eprintln!("  funnel reset                        clear funnel config");
    eprintln!("  switch [--list] [<profile>]         switch between accounts");
    eprintln!("  status [--peers=false] [--active]   show state of rustscaled and connections");
    eprintln!("  ip [-4] [-6] [peer]                 show Tailscale IP addresses");
    eprintln!("  version [--daemon]                  print client and daemon version");
    eprintln!("  whois [--json] ip[:port]            show machine and user for a Tailscale IP");
    eprintln!("  netcheck                            print network conditions analysis");
    eprintln!("  metrics                             print Prometheus-format metrics");
    eprintln!("  health                              print active health warnings");
    eprintln!("  cert [flags] <domain>               get TLS certs for a domain");
    eprintln!("  ping <ip>                           ping a peer (not yet supported)");
    eprintln!("  file cp <files...> <target>:        send file(s) to a host");
    eprintln!("  file get [--wait] [--conflict=...] <dir>  receive files from the inbox");
    eprintln!(
        "  ssh [user@]host [args...]            SSH to a Tailscale machine (execs system ssh)"
    );
    eprintln!("  web [--listen <addr>] [--readonly]   run a web UI for controlling rustscale");
    eprintln!("  debug [status|ipconfig|metrics]      call daemon debug endpoints");
    eprintln!("  bugreport                            print diagnostic summary for bug reports");
    eprintln!("  exit-node [--list] [--suggest]       list or select exit nodes");
    eprintln!("  dns [name] [--type <type>]           query the daemon DNS resolver");
    eprintln!("  nc <host:port>                       netcat via tailnet (not yet supported)");
    eprintln!("  id-token <audience>                  fetch OIDC ID token (not yet supported)");
    eprintln!(
        "  update                               check for client updates (not yet supported)"
    );
}

/// Error type for CLI subcommands.
#[derive(Debug)]
pub struct CliError(pub String);

impl From<rustscale_localclient::LocalClientError> for CliError {
    fn from(e: rustscale_localclient::LocalClientError) -> Self {
        CliError(e.to_string())
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError(e.to_string())
    }
}

impl From<String> for CliError {
    fn from(e: String) -> Self {
        CliError(e)
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}
