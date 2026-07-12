//! `rustscale id-token` — fetch an OIDC ID token from control.
//!
//! Not yet implemented. The Go version requests an OIDC ID token
//! from the control server for the given audience.

use std::path::Path;

use crate::CliError;

#[allow(clippy::unused_async)]
pub async fn run(args: Vec<String>, _socket: &Path, _json: bool) -> Result<(), CliError> {
    let audience = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map_or("<audience>", String::as_str);

    eprintln!("rustscale id-token: not yet supported (audience={audience})");
    eprintln!("OIDC ID token fetching requires control protocol support not yet ported.");
    Ok(())
}
