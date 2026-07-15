//! `rustscale id-token` — fetch an OIDC ID token from control.

use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    if args.len() != 1 || args[0].starts_with('-') {
        return Err(CliError("usage: rustscale id-token <audience>".into()));
    }

    let response = LocalClient::new(socket).id_token(&args[0]).await?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&response).map_err(|error| CliError(error.to_string()))?
        );
    } else {
        println!("{}", response.IDToken);
    }
    Ok(())
}
