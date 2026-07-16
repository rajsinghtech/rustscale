use std::path::Path;

use rustscale_ipn::MaskedPrefs;
use rustscale_localclient::LocalClient;

use crate::flags::{parse_bool_flag, parse_str_flag};
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let lc = LocalClient::new(socket);

    let mut mask = MaskedPrefs::default();

    if let Some(h) = parse_str_flag(&args, "hostname") {
        mask.Prefs.Hostname = h;
        mask.HostnameSet = true;
    }
    if let Some(r) = parse_str_flag(&args, "advertise-routes") {
        mask.Prefs.AdvertiseRoutes = r.split(',').map(|s| s.trim().to_string()).collect();
        mask.AdvertiseRoutesSet = true;
    }
    if parse_bool_flag(&args, "advertise-exit-node").unwrap_or(false) {
        mask.Prefs.AdvertiseExitNode = true;
        mask.AdvertiseExitNodeSet = true;
    }
    if let Some(e) = parse_str_flag(&args, "exit-node") {
        mask.Prefs.ExitNodeIP = e;
        mask.ExitNodeIPSet = true;
    }
    if parse_bool_flag(&args, "shields-up").unwrap_or(false) {
        mask.Prefs.ShieldsUp = true;
        mask.ShieldsUpSet = true;
    }
    if parse_bool_flag(&args, "accept-routes").unwrap_or(false) {
        mask.Prefs.AcceptRoutes = true;
        mask.AcceptRoutesSet = true;
    }
    if parse_bool_flag(&args, "route-all").unwrap_or(false) {
        mask.Prefs.RouteAll = true;
        mask.RouteAllSet = true;
    }
    if let Some(tags) = parse_str_flag(&args, "advertise-tags") {
        mask.Prefs.AdvertiseTags = tags.split(',').map(|s| s.trim().to_string()).collect();
        mask.AdvertiseTagsSet = true;
    }
    // An absent flag preserves the configured operator; an empty value clears
    // it explicitly (`rustscale set --operator ""`).
    if let Some(operator) = parse_str_flag(&args, "operator") {
        mask.Prefs.OperatorUser = operator;
        mask.OperatorUserSet = true;
    }
    if parse_bool_flag(&args, "reset").unwrap_or(false) {
        mask.Prefs = rustscale_ipn::Prefs::default();
        mask.ControlURLSet = true;
        mask.WantRunningSet = true;
        mask.RouteAllSet = true;
        mask.CorpDNSSet = true;
    }

    if mask.is_empty() {
        eprintln!("set: no flags specified");
        return Err(CliError("no flags specified".into()));
    }

    let updated = lc.edit_prefs(&mask).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&updated).unwrap_or_default()
    );
    Ok(())
}
