use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::flags::parse_bool_flag;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let lc = LocalClient::new(socket);
    let want_json = json || parse_bool_flag(&args, "json").unwrap_or(false);

    let prefs = lc.get_prefs().await?;

    if want_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&prefs).unwrap_or_default()
        );
    } else {
        print_prefs(&prefs);
    }
    Ok(())
}

fn print_prefs(p: &rustscale_ipn::Prefs) {
    println!("ControlURL: {}", p.ControlURL);
    println!("WantRunning: {}", p.WantRunning);
    println!("LoggedOut: {}", p.LoggedOut);
    println!("Hostname: {}", p.Hostname);
    println!("RouteAll: {}", p.RouteAll);
    println!("ExitNodeID: {}", p.ExitNodeID);
    println!("ExitNodeIP: {}", p.ExitNodeIP);
    println!("CorpDNS: {}", p.CorpDNS);
    println!("ShieldsUp: {}", p.ShieldsUp);
    println!("AdvertiseRoutes: {:?}", p.AdvertiseRoutes);
    println!("AdvertiseTags: {:?}", p.AdvertiseTags);
    println!("AcceptRoutes: {}", p.AcceptRoutes);
    println!("AdvertiseExitNode: {}", p.AdvertiseExitNode);
    println!("Ephemeral: {}", p.Ephemeral);
}
