use std::path::Path;

use rustscale_ipn::MaskedPrefs;
use rustscale_localclient::LocalClient;

use crate::flags::{parse_bool_flag, parse_csv_flag, parse_str_flag};
use crate::CliError;

const SET_HELP: &str = "Usage: rustscale set [flags]\n\nSet one or more preferences without changing unspecified preferences.\n\nFlags:\n  --hostname <name>                 hostname to use instead of the OS hostname\n  --accept-routes[=true|false]      accept routes advertised by other nodes\n  --accept-dns[=true|false]         accept DNS configuration from the admin panel\n  --shields-up[=true|false]         block incoming connections\n  --advertise-routes <routes>       comma-separated routes; empty clears routes\n  --advertise-exit-node[=true|false] offer this node as an exit node\n  --exit-node <node>                exit-node IP/name; empty clears selection\n  --route-all[=true|false]          route all traffic through the selected exit node\n  --advertise-tags <tags>           comma-separated tags; empty clears tags\n  --operator <user>                 Unix user allowed to operate the daemon\n  --reset                            reset supported preferences to defaults\n  -h, --help                        show this help";

fn wants_help(args: &[String]) -> bool {
    matches!(args, [arg] if matches!(arg.as_str(), "help" | "--help" | "-h" | "-help"))
}

pub async fn run(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    if wants_help(&args) {
        println!("{SET_HELP}");
        return Ok(());
    }

    let lc = LocalClient::new(socket);
    let mut mask = MaskedPrefs::default();

    if let Some(h) = parse_str_flag(&args, "hostname") {
        mask.Prefs.Hostname = h;
        mask.HostnameSet = true;
    }
    if let Some(routes) = parse_csv_flag(&args, "advertise-routes") {
        mask.Prefs.AdvertiseRoutes = routes;
        mask.AdvertiseRoutesSet = true;
    }
    if let Some(value) = parse_bool_flag(&args, "advertise-exit-node") {
        mask.Prefs.AdvertiseExitNode = value;
        mask.AdvertiseExitNodeSet = true;
    }
    if let Some(selector) = parse_str_flag(&args, "exit-node") {
        let status = lc.status_bounded().await?;
        super::exit_node::apply_exit_node_arg(&mut mask, &status, &selector, false)?;
    }
    if let Some(value) = parse_bool_flag(&args, "shields-up") {
        mask.Prefs.ShieldsUp = value;
        mask.ShieldsUpSet = true;
    }
    if let Some(value) = parse_bool_flag(&args, "accept-routes") {
        mask.Prefs.AcceptRoutes = value;
        mask.AcceptRoutesSet = true;
    }
    if let Some(value) = parse_bool_flag(&args, "accept-dns") {
        mask.Prefs.CorpDNS = value;
        mask.CorpDNSSet = true;
    }
    if let Some(value) = parse_bool_flag(&args, "route-all") {
        mask.Prefs.RouteAll = value;
        mask.RouteAllSet = true;
    }
    if let Some(tags) = parse_csv_flag(&args, "advertise-tags") {
        mask.Prefs.AdvertiseTags = tags;
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
        return Err(CliError(format!("no flags specified\n\n{SET_HELP}")));
    }

    let updated = lc.edit_prefs(&mask).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&updated).unwrap_or_default()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn recognizes_compatible_help_spellings() {
        for spelling in ["help", "--help", "-help", "-h"] {
            assert!(wants_help(&strings(&[spelling])));
        }
        assert!(!wants_help(&strings(&["--hostname", "help"])));
    }
}
