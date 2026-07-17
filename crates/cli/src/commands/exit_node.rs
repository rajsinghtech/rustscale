//! `rustscale exit-node` — list, select, or clear exit nodes.
//!
//! Selection follows the upstream `Prefs.SetExitNodeIP` rules for IP and
//! MagicDNS names. RustScale also accepts the stable node IDs exposed by
//! `ipnstate.PeerStatus.ID`, storing those in `Prefs.ExitNodeID` so the
//! daemon can keep the selection stable across key rotation.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;

use rustscale_ipn::MaskedPrefs;
use rustscale_localclient::LocalClient;
use serde_json::Value;

use crate::CliError;

const HELP: &str = "Show or change the exit node used for internet traffic.

Usage:
  rustscale exit-node [list]
  rustscale exit-node select <IP|hostname|stable-node-ID>
  rustscale exit-node clear
  rustscale exit-node suggest

The legacy forms `--list`, `--select <node>`, `--clear`, and `--suggest` are
also accepted.

Commands:
  list                 list available exit nodes (the default)
  select <node>        select an online exit node by IP, MagicDNS name, or ID
  clear                stop using an exit node
  suggest              show the control-suggested exit node

Flags:
  -h, --help           show this help
  --json               emit machine-readable list or suggestion output";
const LIST_HELP: &str = "Usage: rustscale exit-node list [--json]";
const SELECT_HELP: &str = "Usage: rustscale exit-node select <IP|hostname|stable-node-ID>";
const CLEAR_HELP: &str = "Usage: rustscale exit-node clear";
const SUGGEST_HELP: &str = "Usage: rustscale exit-node suggest [--json]";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HelpTopic {
    Root,
    List,
    Select,
    Clear,
    Suggest,
}

#[derive(Debug, Eq, PartialEq)]
enum ExitNodeCommand {
    Help(HelpTopic),
    List,
    Select(String),
    Clear,
    Suggest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExitNode {
    id: String,
    host_name: String,
    dns_name: String,
    ips: Vec<IpAddr>,
    online: bool,
    selected: bool,
    exit_option: bool,
    country: String,
    city: String,
}

impl ExitNode {
    fn display_name(&self) -> &str {
        if !self.dns_name.is_empty() {
            self.dns_name.trim_end_matches('.')
        } else if !self.host_name.is_empty() {
            &self.host_name
        } else {
            &self.id
        }
    }

    fn first_ip(&self) -> Option<IpAddr> {
        self.ips.first().copied()
    }

    fn status(&self) -> &'static str {
        match (self.selected, self.online) {
            (true, true) => "selected",
            (true, false) => "selected but offline",
            (false, false) => "offline",
            (false, true) => "-",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExitNodePreference {
    Ip(IpAddr),
    Id(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedExitNode {
    preference: ExitNodePreference,
}

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let command = parse_command(&args)?;
    match command {
        ExitNodeCommand::Help(topic) => {
            println!(
                "{}",
                match topic {
                    HelpTopic::Root => HELP,
                    HelpTopic::List => LIST_HELP,
                    HelpTopic::Select => SELECT_HELP,
                    HelpTopic::Clear => CLEAR_HELP,
                    HelpTopic::Suggest => SUGGEST_HELP,
                }
            );
            Ok(())
        }
        ExitNodeCommand::List => list(socket, json).await,
        ExitNodeCommand::Select(selector) => select(socket, &selector).await,
        ExitNodeCommand::Clear => clear(socket).await,
        ExitNodeCommand::Suggest => suggest(socket, json).await,
    }
}

fn parse_command(args: &[String]) -> Result<ExitNodeCommand, CliError> {
    let args = args
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .map(String::as_str)
        .collect::<Vec<_>>();

    match args.as_slice() {
        [] => Ok(ExitNodeCommand::List),
        ["help" | "--help" | "-help" | "-h"] => Ok(ExitNodeCommand::Help(HelpTopic::Root)),
        ["help", "list"] | ["list", "--help" | "-h" | "-help"] => {
            Ok(ExitNodeCommand::Help(HelpTopic::List))
        }
        ["help", "select"] | ["select", "--help" | "-h" | "-help"] => {
            Ok(ExitNodeCommand::Help(HelpTopic::Select))
        }
        ["help", "clear"] | ["clear", "--help" | "-h" | "-help"] => {
            Ok(ExitNodeCommand::Help(HelpTopic::Clear))
        }
        ["help", "suggest"] | ["suggest", "--help" | "-h" | "-help"] => {
            Ok(ExitNodeCommand::Help(HelpTopic::Suggest))
        }
        ["list" | "--list"] => Ok(ExitNodeCommand::List),
        ["clear" | "--clear"] => Ok(ExitNodeCommand::Clear),
        ["suggest" | "--suggest"] => Ok(ExitNodeCommand::Suggest),
        ["select" | "--select"] => Err(CliError(format!(
            "missing exit node selector\n{SELECT_HELP}"
        ))),
        ["select" | "--select", selector] if !selector.is_empty() => {
            Ok(ExitNodeCommand::Select((*selector).to_owned()))
        }
        [argument] if argument.starts_with("--select=") => {
            let selector = argument.trim_start_matches("--select=");
            if selector.is_empty() {
                Err(CliError(format!(
                    "missing exit node selector\n{SELECT_HELP}"
                )))
            } else {
                Ok(ExitNodeCommand::Select(selector.to_owned()))
            }
        }
        [selector] if !selector.starts_with('-') => {
            // Preserve the original RustScale positional selection spelling.
            Ok(ExitNodeCommand::Select((*selector).to_owned()))
        }
        [argument, ..] if argument.starts_with('-') => Err(CliError(format!(
            "unknown exit-node flag {argument:?}\n{HELP}"
        ))),
        _ => Err(CliError(format!(
            "unexpected exit-node arguments: {}\n{HELP}",
            args.join(" ")
        ))),
    }
}

async fn list(socket: &Path, json: bool) -> Result<(), CliError> {
    let status = LocalClient::new(socket).status_bounded().await?;
    let mut nodes = status_peers(&status)
        .into_iter()
        .filter(|node| node.exit_option)
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| {
        left.display_name()
            .to_ascii_lowercase()
            .cmp(&right.display_name().to_ascii_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });

    if nodes.is_empty() {
        return Err(CliError("no exit nodes found".into()));
    }

    if json {
        let output = nodes
            .iter()
            .map(|node| {
                serde_json::json!({
                    "id": node.id,
                    "ip": node.first_ip().map(|ip| ip.to_string()).unwrap_or_default(),
                    "hostname": node.display_name(),
                    "online": node.online,
                    "selected": node.selected,
                    "country": node.country,
                    "city": node.city,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|error| CliError(error.to_string()))?
        );
    } else {
        println!("{}", render_list(&nodes));
    }
    Ok(())
}

fn render_list(nodes: &[ExitNode]) -> String {
    let rows = nodes
        .iter()
        .map(|node| {
            [
                node.first_ip()
                    .map_or_else(|| "-".into(), |address| address.to_string()),
                node.display_name().to_owned(),
                if node.country.is_empty() {
                    "-".into()
                } else {
                    node.country.clone()
                },
                if node.city.is_empty() {
                    "-".into()
                } else {
                    node.city.clone()
                },
                node.status().into(),
            ]
        })
        .collect::<Vec<_>>();
    let headers = ["IP", "HOSTNAME", "COUNTRY", "CITY", "STATUS"];
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (index, value) in row.iter().enumerate() {
            widths[index] = widths[index].max(value.chars().count());
        }
    }

    let mut output = format!(
        "{:<ip_width$}  {:<host_width$}  {:<country_width$}  {:<city_width$}  {}",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
        headers[4],
        ip_width = widths[0],
        host_width = widths[1],
        country_width = widths[2],
        city_width = widths[3],
    );
    for row in rows {
        output.push('\n');
        write!(
            &mut output,
            "{:<ip_width$}  {:<host_width$}  {:<country_width$}  {:<city_width$}  {}",
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            ip_width = widths[0],
            host_width = widths[1],
            country_width = widths[2],
            city_width = widths[3],
        )
        .expect("writing an exit-node row to a String cannot fail");
    }
    output
}

async fn select(socket: &Path, selector: &str) -> Result<(), CliError> {
    let client = LocalClient::new(socket);
    let status = client.status_bounded().await?;
    let mut masked = MaskedPrefs::default();
    apply_exit_node_arg(&mut masked, &status, selector, true)?;
    client.edit_prefs(&masked).await?;
    Ok(())
}

async fn clear(socket: &Path) -> Result<(), CliError> {
    let mut masked = MaskedPrefs::default();
    clear_exit_node_fields(&mut masked);
    LocalClient::new(socket).edit_prefs(&masked).await?;
    Ok(())
}

async fn suggest(socket: &Path, json: bool) -> Result<(), CliError> {
    let status = LocalClient::new(socket).status_bounded().await?;
    let suggested = status
        .get("SuggestedExitNode")
        .and_then(Value::as_str)
        .unwrap_or("");
    if json {
        println!("{}", serde_json::json!({"suggestedExitNode": suggested}));
    } else if suggested.is_empty() {
        println!("No exit node suggestion is available.");
    } else {
        println!("Suggested exit node: {suggested}");
    }
    Ok(())
}

/// Apply an `up`/`set` exit-node argument to a partial preference update.
///
/// An empty argument clears both mutually exclusive fields. Names are resolved
/// to a Tailscale IP just as upstream `Prefs.SetExitNodeIP` does; an exact
/// stable ID uses `ExitNodeID`. `require_online` is enabled by the explicit
/// `exit-node select` operation, while `up` and `set` retain upstream's ability
/// to configure a known-but-offline node or a pending IP while stopped.
pub(crate) fn apply_exit_node_arg(
    masked: &mut MaskedPrefs,
    status: &Value,
    selector: &str,
    require_online: bool,
) -> Result<(), CliError> {
    if selector.is_empty() {
        clear_exit_node_fields(masked);
        return Ok(());
    }

    let resolved = resolve_exit_node_selector(status, selector, require_online)?;
    clear_exit_node_fields(masked);
    match resolved.preference {
        ExitNodePreference::Ip(ip) => masked.Prefs.ExitNodeIP = ip.to_string(),
        ExitNodePreference::Id(id) => masked.Prefs.ExitNodeID = id,
    }
    Ok(())
}

fn clear_exit_node_fields(masked: &mut MaskedPrefs) {
    masked.Prefs.ExitNodeID.clear();
    masked.Prefs.ExitNodeIP.clear();
    masked.ExitNodeIDSet = true;
    masked.ExitNodeIPSet = true;
}

fn resolve_exit_node_selector(
    status: &Value,
    selector: &str,
    require_online: bool,
) -> Result<ResolvedExitNode, CliError> {
    let peers = status_peers(status);

    if let Ok(ip) = selector.parse::<IpAddr>() {
        if status_ips(status).contains(&ip) {
            return Err(CliError(format!(
                "cannot use {selector} as an exit node as it is a local IP address to this machine"
            )));
        }

        let matches = peers
            .iter()
            .filter(|peer| peer.ips.contains(&ip))
            .collect::<Vec<_>>();
        if status_backend_running(status) || require_online {
            if matches.is_empty() {
                return Err(CliError(format!("no node found in netmap with IP {ip}")));
            }
            if matches.len() > 1 {
                return Err(CliError(format!("ambiguous exit node IP {ip}")));
            }
            validate_selectable_peer(matches[0], selector, true, require_online)?;
        }
        return Ok(ResolvedExitNode {
            preference: ExitNodePreference::Ip(ip),
        });
    }

    // Stable IDs are rotation-stable and are the daemon's canonical identity
    // for an explicitly ID-based selection. Keep matching case-sensitive.
    let id_matches = peers
        .iter()
        .filter(|peer| !peer.id.is_empty() && peer.id == selector)
        .collect::<Vec<_>>();
    if id_matches.len() > 1 {
        return Err(CliError(format!(
            "ambiguous exit node stable ID {selector:?}"
        )));
    }
    if let Some(peer) = id_matches.first() {
        validate_selectable_peer(peer, selector, false, require_online)?;
        return Ok(ResolvedExitNode {
            preference: ExitNodePreference::Id(peer.id.clone()),
        });
    }

    if peers.is_empty() {
        return Err(CliError(
            "cannot resolve exit node by hostname while Tailscale is starting up; please use its Tailscale IP address instead"
                .into(),
        ));
    }

    let suffix = magic_dns_suffix(status);
    let name_matches = peers
        .iter()
        .filter(|peer| peer_matches_name(peer, selector, &suffix))
        .collect::<Vec<_>>();
    match name_matches.as_slice() {
        [] => Err(CliError(format!(
            "invalid value {selector:?} for --exit-node; must be IP or peer hostname"
        ))),
        [_first, _second, ..] => Err(CliError(format!("ambiguous exit node name {selector:?}"))),
        [peer] => {
            validate_selectable_peer(peer, selector, false, require_online)?;
            let ip = peer
                .first_ip()
                .ok_or_else(|| CliError(format!("node {selector:?} has no Tailscale IP?")))?;
            Ok(ResolvedExitNode {
                preference: ExitNodePreference::Ip(ip),
            })
        }
    }
}

fn validate_selectable_peer(
    peer: &ExitNode,
    selector: &str,
    selector_is_ip: bool,
    require_online: bool,
) -> Result<(), CliError> {
    if !peer.exit_option {
        if selector_is_ip {
            return Err(CliError(format!(
                "node {selector} is not advertising an exit node"
            )));
        }
        return Err(CliError(format!(
            "node {selector:?} is not advertising an exit node"
        )));
    }
    if require_online && !peer.online {
        return Err(CliError(format!(
            "exit node {:?} is offline",
            peer.display_name()
        )));
    }
    Ok(())
}

fn status_peers(status: &Value) -> Vec<ExitNode> {
    let Some(peers) = status.get("Peer").and_then(Value::as_object) else {
        return Vec::new();
    };
    peers
        .values()
        .map(|peer| {
            let location = peer.get("Location");
            ExitNode {
                id: string_field(peer, "ID"),
                host_name: string_field(peer, "HostName"),
                dns_name: string_field(peer, "DNSName"),
                ips: peer
                    .get("TailscaleIPs")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter_map(|address| address.parse().ok())
                    .collect(),
                online: peer.get("Online").and_then(Value::as_bool).unwrap_or(false),
                selected: peer
                    .get("ExitNode")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                exit_option: peer
                    .get("ExitNodeOption")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                country: location
                    .and_then(|value| value.get("Country"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                city: location
                    .and_then(|value| value.get("City"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            }
        })
        .collect()
}

fn string_field(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn status_ips(status: &Value) -> Vec<IpAddr> {
    status
        .get("TailscaleIPs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|address| address.parse().ok())
        .collect()
}

fn status_backend_running(status: &Value) -> bool {
    status
        .get("BackendState")
        .and_then(Value::as_str)
        .is_some_and(|state| state == "Running")
}

fn magic_dns_suffix(status: &Value) -> String {
    status
        .get("MagicDNSSuffix")
        .and_then(Value::as_str)
        .filter(|suffix| !suffix.is_empty())
        .or_else(|| {
            status
                .get("CurrentTailnet")
                .and_then(|tailnet| tailnet.get("MagicDNSSuffix"))
                .and_then(Value::as_str)
                .filter(|suffix| !suffix.is_empty())
        })
        .unwrap_or("")
        .trim_matches('.')
        .to_owned()
}

fn peer_matches_name(peer: &ExitNode, selector: &str, suffix: &str) -> bool {
    let selector = selector.trim_end_matches('.');
    let dns_name = peer.dns_name.trim_end_matches('.');
    if selector.eq_ignore_ascii_case(dns_name)
        || (!peer.host_name.is_empty() && selector.eq_ignore_ascii_case(&peer.host_name))
    {
        return true;
    }

    let base_name = if suffix.is_empty() {
        dns_name.split('.').next().unwrap_or(dns_name)
    } else {
        dns_name
            .strip_suffix(suffix)
            .and_then(|prefix| prefix.strip_suffix('.'))
            .unwrap_or_else(|| dns_name.split('.').next().unwrap_or(dns_name))
    };
    selector.eq_ignore_ascii_case(base_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn peer(id: &str, dns_name: &str, ips: &[&str], exit_option: bool, online: bool) -> Value {
        serde_json::json!({
            "ID": id,
            "HostName": dns_name.split('.').next().unwrap_or(dns_name),
            "DNSName": dns_name,
            "TailscaleIPs": ips,
            "ExitNodeOption": exit_option,
            "Online": online,
        })
    }

    fn status(backend: &str, self_ips: &[&str], peers: Vec<Value>) -> Value {
        let peers = peers
            .into_iter()
            .enumerate()
            .map(|(index, peer)| (format!("nodekey:{index}"), peer))
            .collect::<serde_json::Map<_, _>>();
        serde_json::json!({
            "BackendState": backend,
            "TailscaleIPs": self_ips,
            "MagicDNSSuffix": ".foo",
            "Peer": peers,
        })
    }

    fn resolved_ip(status: &Value, selector: &str) -> Result<IpAddr, String> {
        resolve_exit_node_selector(status, selector, false)
            .map_err(|error| error.to_string())
            .and_then(|resolved| match resolved.preference {
                ExitNodePreference::Ip(ip) => Ok(ip),
                ExitNodePreference::Id(id) => Err(format!("resolved to ID {id}")),
            })
    }

    #[test]
    fn parses_list_select_clear_and_help_without_side_effects() {
        assert_eq!(parse_command(&[]).unwrap(), ExitNodeCommand::List);
        assert_eq!(
            parse_command(&strings(&["--list"])).unwrap(),
            ExitNodeCommand::List
        );
        assert_eq!(
            parse_command(&strings(&["select", "exit.foo"])).unwrap(),
            ExitNodeCommand::Select("exit.foo".into())
        );
        assert_eq!(
            parse_command(&strings(&["--select=node-id"])).unwrap(),
            ExitNodeCommand::Select("node-id".into())
        );
        assert_eq!(
            parse_command(&strings(&["exit.foo"])).unwrap(),
            ExitNodeCommand::Select("exit.foo".into())
        );
        assert_eq!(
            parse_command(&strings(&["clear"])).unwrap(),
            ExitNodeCommand::Clear
        );
        assert_eq!(
            parse_command(&strings(&["select", "--help"])).unwrap(),
            ExitNodeCommand::Help(HelpTopic::Select)
        );
        assert!(parse_command(&strings(&["select"])).is_err());
        assert!(parse_command(&strings(&["--unknown"])).is_err());
    }

    /// Differential cases copied from pinned Tailscale v1.100.0
    /// `ipn.TestExitNodeIPOfArg`. Exact successful IPs and error strings keep
    /// the Rust selector aligned with upstream's IP/base-name/FQDN contract.
    #[test]
    fn selector_matches_pinned_upstream_cases() {
        let stopped = status("Stopped", &[], vec![]);
        assert_eq!(
            resolved_ip(&stopped, "1.2.3.4").unwrap(),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );

        let running_empty = status("Running", &[], vec![]);
        assert_eq!(
            resolved_ip(&running_empty, "1.2.3.4").unwrap_err(),
            "no node found in netmap with IP 1.2.3.4"
        );
        assert_eq!(
            resolved_ip(&running_empty, "skippy.foo").unwrap_err(),
            "cannot resolve exit node by hostname while Tailscale is starting up; please use its Tailscale IP address instead"
        );

        let self_status = status("Running", &["1.2.3.4"], vec![]);
        assert_eq!(
            resolved_ip(&self_status, "1.2.3.4").unwrap_err(),
            "cannot use 1.2.3.4 as an exit node as it is a local IP address to this machine"
        );

        let not_exit = status(
            "Running",
            &[],
            vec![peer(
                "node-not-exit",
                "skippy.foo.",
                &["1.0.0.2"],
                false,
                true,
            )],
        );
        assert_eq!(
            resolved_ip(&not_exit, "skippy").unwrap_err(),
            "node \"skippy\" is not advertising an exit node"
        );
        assert_eq!(
            resolved_ip(&not_exit, "1.0.0.2").unwrap_err(),
            "node 1.0.0.2 is not advertising an exit node"
        );

        let available = status(
            "Running",
            &[],
            vec![peer("node-exit", "skippy.foo.", &["1.0.0.2"], true, true)],
        );
        for selector in ["skippy", "SKIPPY.FOO.", "skippy.foo"] {
            assert_eq!(
                resolved_ip(&available, selector).unwrap(),
                "1.0.0.2".parse::<IpAddr>().unwrap()
            );
        }
        assert_eq!(
            resolved_ip(&available, "unknown").unwrap_err(),
            "invalid value \"unknown\" for --exit-node; must be IP or peer hostname"
        );

        let ambiguous = status(
            "Running",
            &[],
            vec![
                peer("node-a", "skippy.foo.", &["1.0.0.2"], true, true),
                peer("node-b", "SKIPPY.foo.", &["1.0.0.3"], true, true),
            ],
        );
        assert_eq!(
            resolved_ip(&ambiguous, "skippy").unwrap_err(),
            "ambiguous exit node name \"skippy\""
        );
    }

    #[test]
    fn explicit_selection_accepts_ids_and_rejects_offline_nodes() {
        let status = status(
            "Running",
            &[],
            vec![peer(
                "node-stable-1",
                "offline.foo.",
                &["100.64.0.8"],
                true,
                false,
            )],
        );
        let error = resolve_exit_node_selector(&status, "node-stable-1", true).unwrap_err();
        assert_eq!(error.to_string(), "exit node \"offline.foo\" is offline");

        let resolved = resolve_exit_node_selector(&status, "node-stable-1", false).unwrap();
        assert_eq!(
            resolved.preference,
            ExitNodePreference::Id("node-stable-1".into())
        );
    }

    #[test]
    fn preference_masks_clear_the_mutually_exclusive_field() {
        let status = status(
            "Running",
            &[],
            vec![peer(
                "node-stable-1",
                "exit.foo.",
                &["100.64.0.8"],
                true,
                true,
            )],
        );
        let mut by_name = MaskedPrefs::default();
        apply_exit_node_arg(&mut by_name, &status, "exit", true).unwrap();
        assert_eq!(by_name.Prefs.ExitNodeIP, "100.64.0.8");
        assert!(by_name.Prefs.ExitNodeID.is_empty());
        assert!(by_name.ExitNodeIPSet && by_name.ExitNodeIDSet);

        let mut by_id = MaskedPrefs::default();
        apply_exit_node_arg(&mut by_id, &status, "node-stable-1", true).unwrap();
        assert_eq!(by_id.Prefs.ExitNodeID, "node-stable-1");
        assert!(by_id.Prefs.ExitNodeIP.is_empty());

        apply_exit_node_arg(&mut by_id, &status, "", true).unwrap();
        assert!(by_id.Prefs.ExitNodeID.is_empty());
        assert!(by_id.Prefs.ExitNodeIP.is_empty());
    }

    #[test]
    fn list_output_is_sorted_and_marks_offline_and_selected_nodes() {
        let nodes = vec![
            ExitNode {
                id: "node-b".into(),
                host_name: "zulu".into(),
                dns_name: "zulu.foo.".into(),
                ips: vec!["100.64.0.9".parse().unwrap()],
                online: false,
                selected: true,
                exit_option: true,
                country: String::new(),
                city: String::new(),
            },
            ExitNode {
                id: "node-a".into(),
                host_name: "alpha".into(),
                dns_name: "alpha.foo.".into(),
                ips: vec!["100.64.0.8".parse().unwrap()],
                online: true,
                selected: false,
                exit_option: true,
                country: String::new(),
                city: String::new(),
            },
        ];
        let rendered = render_list(&nodes);
        assert!(rendered.starts_with("IP"));
        assert!(rendered.contains("selected but offline"));
        assert!(rendered.contains("alpha.foo"));
    }
}
