//! `rustscale drive` — share directories with the tailnet.
//!
//! Ports Go's `cmd/tailscale/cli/drive.go`. All subcommands are stubs:
//! Taildrive requires drive server and LocalAPI endpoints not yet ported
//! to rustscale.

use std::path::Path;

use crate::CliError;

#[allow(clippy::unused_async)]
pub async fn run(args: Vec<String>, _socket: &Path, _json: bool) -> Result<(), CliError> {
    let sub = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map_or("list", String::as_str);

    match sub {
        "list" => {
            eprintln!("rustscale drive list: not yet supported");
            eprintln!("Taildrive shares require drive server support not yet ported.");
        }
        "share" => {
            eprintln!("rustscale drive share: not yet supported");
            eprintln!("Creating Taildrive shares requires drive server support not yet ported.");
        }
        "unshare" => {
            eprintln!("rustscale drive unshare: not yet supported");
            eprintln!("Removing Taildrive shares requires drive server support not yet ported.");
        }
        other => {
            return Err(CliError(format!(
                "rustscale drive: unknown subcommand '{other}'"
            )));
        }
    }
    Ok(())
}
