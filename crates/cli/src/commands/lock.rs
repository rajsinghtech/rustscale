//! `rustscale lock` — manage tailnet lock.
//!
//! Ports Go's `cmd/tailscale/cli/tailnet-lock.go`. All subcommands are
//! stubs: tailnet lock (TKA) requires control protocol and crypto
//! support not yet ported to rustscale.

use std::path::Path;

use crate::CliError;

#[allow(clippy::unused_async)]
pub async fn run(args: Vec<String>, _socket: &Path, _json: bool) -> Result<(), CliError> {
    let sub = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map_or("status", String::as_str);

    match sub {
        "status" => {
            eprintln!("rustscale lock status: not yet supported");
            eprintln!(
                "Tailnet lock requires TKA crypto and control protocol support not yet ported."
            );
        }
        "init" => {
            eprintln!("rustscale lock init: not yet supported");
            eprintln!("Tailnet lock initialization requires TKA crypto and control protocol support not yet ported.");
        }
        "add" => {
            eprintln!("rustscale lock add: not yet supported");
            eprintln!("Adding trusted tailnet lock keys requires TKA support not yet ported.");
        }
        "remove" => {
            eprintln!("rustscale lock remove: not yet supported");
            eprintln!("Removing trusted tailnet lock keys requires TKA support not yet ported.");
        }
        "disable" => {
            eprintln!("rustscale lock disable: not yet supported");
            eprintln!("Disabling tailnet lock requires TKA support not yet ported.");
        }
        other => {
            return Err(CliError(format!(
                "rustscale lock: unknown subcommand '{other}'"
            )));
        }
    }
    Ok(())
}
