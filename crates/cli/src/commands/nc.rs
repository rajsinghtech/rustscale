//! `rustscale nc` — netcat-like connection via the daemon.
//!
//! Not yet fully supported. Prints a diagnostic message indicating
//! the feature is not implemented. The Go version connects to a
//! remote host:port via the tailnet and pipes stdin/stdout.

use std::path::Path;

use crate::CliError;

#[allow(clippy::unused_async)]
pub async fn run(args: Vec<String>, _socket: &Path, _json: bool) -> Result<(), CliError> {
    let host_port = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map_or("<host:port>", String::as_str);

    eprintln!("rustscale nc: not yet supported (would connect to {host_port})");
    eprintln!("Use 'rustscale debug' or the LocalAPI dial endpoint as a workaround.");
    Ok(())
}
