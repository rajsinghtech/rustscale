//! `rustscale update` — check for client updates.
//!
//! Not yet implemented. The Go version checks for a newer Tailscale
//! client version and offers to install it.

use std::path::Path;

use crate::CliError;

#[allow(clippy::unused_async)]
pub async fn run(_args: Vec<String>, _socket: &Path, _json: bool) -> Result<(), CliError> {
    eprintln!("rustscale update: not yet supported");
    eprintln!("Client update checking is not yet implemented.");
    Ok(())
}
