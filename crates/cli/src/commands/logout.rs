use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::CliError;

pub async fn run(_args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let lc = LocalClient::new(socket);
    lc.logout().await?;
    println!("Logged out.");
    Ok(())
}
