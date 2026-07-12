use std::path::Path;

use rustscale_ipn::MaskedPrefs;
use rustscale_localclient::LocalClient;

use crate::CliError;

pub async fn run(_args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let lc = LocalClient::new(socket);
    let mask = MaskedPrefs {
        Prefs: rustscale_ipn::Prefs {
            WantRunning: false,
            ..Default::default()
        },
        WantRunningSet: true,
        ..Default::default()
    };
    lc.edit_prefs(&mask).await?;
    println!("Tailscale disconnected.");
    Ok(())
}
