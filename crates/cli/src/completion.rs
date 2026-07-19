//! Static shell completion support for the hand-written CLI parser.
//!
//! The hidden completion protocol normally only walks this command
//! description. `nc` host completion may perform one bounded, read-only status
//! lookup; it never invokes a mutating command and silently ignores failures.

use std::path::PathBuf;

use crate::CliError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlagValue {
    Bool,
    Value,
    OneOf(&'static [&'static str]),
}

#[derive(Clone, Copy, Debug)]
struct FlagSpec {
    name: &'static str,
    aliases: &'static [&'static str],
    value: FlagValue,
}

#[derive(Debug)]
struct CommandSpec {
    name: &'static str,
    flags: &'static [FlagSpec],
    subcommands: &'static [CommandSpec],
}

const fn flag(name: &'static str, value: FlagValue) -> FlagSpec {
    FlagSpec {
        name,
        aliases: &[],
        value,
    }
}

const fn flag_with_aliases(
    name: &'static str,
    aliases: &'static [&'static str],
    value: FlagValue,
) -> FlagSpec {
    FlagSpec {
        name,
        aliases,
        value,
    }
}

const fn command(
    name: &'static str,
    flags: &'static [FlagSpec],
    subcommands: &'static [CommandSpec],
) -> CommandSpec {
    CommandSpec {
        name,
        flags,
        subcommands,
    }
}

const NONE: &[CommandSpec] = &[];
const GLOBAL_FLAGS: &[FlagSpec] = &[
    flag("--socket", FlagValue::Value),
    flag("--json", FlagValue::Bool),
];
const BOOL_VALUES: &[&str] = &["true", "false"];

const SERVE_FLAGS: &[FlagSpec] = &[
    flag("--bg", FlagValue::Bool),
    flag("--https", FlagValue::Value),
    flag("--http", FlagValue::Value),
    flag("--tcp", FlagValue::Value),
    flag("--tls-terminated-tcp", FlagValue::Value),
    flag("--set-path", FlagValue::Value),
];
const SERVE_SUBCOMMANDS: &[CommandSpec] = &[
    command("status", &[flag("--json", FlagValue::Bool)], NONE),
    command("reset", &[], NONE),
];
const FILE_SUBCOMMANDS: &[CommandSpec] = &[
    command(
        "cp",
        &[
            flag("--name", FlagValue::Value),
            flag("--verbose", FlagValue::Bool),
            flag("--targets", FlagValue::Bool),
        ],
        NONE,
    ),
    command(
        "get",
        &[
            flag("--wait", FlagValue::Bool),
            flag(
                "--conflict",
                FlagValue::OneOf(&["skip", "overwrite", "rename"]),
            ),
            flag("--verbose", FlagValue::Bool),
        ],
        NONE,
    ),
];
const DEBUG_SUBCOMMANDS: &[CommandSpec] = &[
    command("status", &[flag("--json", FlagValue::Bool)], NONE),
    command("ipconfig", &[flag("--json", FlagValue::Bool)], NONE),
    command("metrics", &[flag("--json", FlagValue::Bool)], NONE),
    command("capture", &[flag("-o", FlagValue::Value)], NONE),
];
const LOCK_SUBCOMMANDS: &[CommandSpec] = &[
    command("status", &[], NONE),
    command(
        "init",
        &[
            flag("--confirm", FlagValue::Bool),
            flag("--resume", FlagValue::Bool),
            flag("--gen-disablements", FlagValue::Value),
        ],
        NONE,
    ),
    command("sign", &[], NONE),
    command("disable", &[], NONE),
    command("local-disable", &[], NONE),
];
const DRIVE_SUBCOMMANDS: &[CommandSpec] = &[
    command("status", &[], NONE),
    command("list", &[], NONE),
    command("share", &[], NONE),
    command("unshare", &[], NONE),
];
const DNS_SUBCOMMANDS: &[CommandSpec] =
    &[command("status", &[], NONE), command("query", &[], NONE)];
const EXIT_NODE_SUBCOMMANDS: &[CommandSpec] = &[
    command("list", &[], NONE),
    command("select", &[], NONE),
    command("clear", &[], NONE),
    command("suggest", &[], NONE),
];
const COMPLETION_SUBCOMMANDS: &[CommandSpec] = &[
    command("bash", &[], NONE),
    command("zsh", &[], NONE),
    command("fish", &[], NONE),
];

const COMMANDS: &[CommandSpec] = &[
    command(
        "up",
        &[
            flag("--auth-key", FlagValue::Value),
            flag("--hostname", FlagValue::Value),
            flag("--advertise-routes", FlagValue::Value),
            flag("--advertise-exit-node", FlagValue::Bool),
            flag("--exit-node", FlagValue::Value),
            flag("--shields-up", FlagValue::Bool),
            flag("--accept-routes", FlagValue::Bool),
            flag("--accept-dns", FlagValue::Bool),
            flag("--advertise-tags", FlagValue::Value),
            flag("--operator", FlagValue::Value),
            flag("--reset", FlagValue::Bool),
            flag("--force-reauth", FlagValue::Bool),
            flag("--timeout", FlagValue::Value),
            flag("--qr", FlagValue::Bool),
            flag("--qr-format", FlagValue::OneOf(&["auto", "small", "large"])),
        ],
        NONE,
    ),
    command(
        "login",
        &[
            flag("--timeout", FlagValue::Value),
            flag("--qr", FlagValue::Bool),
        ],
        NONE,
    ),
    command("logout", &[], NONE),
    command("down", &[], NONE),
    command(
        "set",
        &[
            flag("--hostname", FlagValue::Value),
            flag("--accept-routes", FlagValue::Bool),
            flag("--accept-dns", FlagValue::Bool),
            flag("--shields-up", FlagValue::Bool),
            flag("--advertise-routes", FlagValue::Value),
            flag("--advertise-exit-node", FlagValue::Bool),
            flag("--exit-node", FlagValue::Value),
            flag("--route-all", FlagValue::Bool),
            flag("--advertise-tags", FlagValue::Value),
            flag("--operator", FlagValue::Value),
            flag("--reset", FlagValue::Bool),
        ],
        NONE,
    ),
    command("get", &[flag("--json", FlagValue::Bool)], NONE),
    command("serve", SERVE_FLAGS, SERVE_SUBCOMMANDS),
    command("funnel", SERVE_FLAGS, SERVE_SUBCOMMANDS),
    command(
        "switch",
        &[
            flag("--list", FlagValue::Bool),
            flag("--json", FlagValue::Bool),
        ],
        NONE,
    ),
    command(
        "status",
        &[
            flag("--peers", FlagValue::Bool),
            flag("--active", FlagValue::Bool),
        ],
        NONE,
    ),
    command(
        "ip",
        &[
            flag("-1", FlagValue::Bool),
            flag("-4", FlagValue::Bool),
            flag("-6", FlagValue::Bool),
        ],
        NONE,
    ),
    command("version", &[flag("--daemon", FlagValue::Bool)], NONE),
    command("whois", &[], NONE),
    command("netcheck", &[], NONE),
    command("metrics", &[], NONE),
    command("health", &[], NONE),
    command(
        "cert",
        &[
            flag("--cert-file", FlagValue::Value),
            flag("--key-file", FlagValue::Value),
            flag("--min-validity", FlagValue::Value),
        ],
        NONE,
    ),
    command(
        "ping",
        &[
            flag("--tsmp", FlagValue::Bool),
            flag("--icmp", FlagValue::Bool),
            flag("--peerapi", FlagValue::Bool),
            flag_with_aliases("--size", &["-s"], FlagValue::Value),
            flag_with_aliases("--count", &["--c", "-c"], FlagValue::Value),
            flag("--timeout", FlagValue::Value),
            flag_with_aliases("--until-direct", &["-d"], FlagValue::Bool),
        ],
        NONE,
    ),
    command(
        "speedtest",
        &[
            flag_with_aliases("--host", &["-host"], FlagValue::Value),
            flag_with_aliases("--time", &["-t"], FlagValue::Value),
            flag_with_aliases("--server", &["-s"], FlagValue::Bool),
            flag_with_aliases("--reverse", &["-r"], FlagValue::Bool),
        ],
        NONE,
    ),
    command("file", &[], FILE_SUBCOMMANDS),
    command("ssh", &[], NONE),
    command(
        "web",
        &[
            flag("--listen", FlagValue::Value),
            flag("--browser", FlagValue::Bool),
            flag("--readonly", FlagValue::Bool),
            flag("--unsafe-any-addr", FlagValue::Bool),
        ],
        NONE,
    ),
    command("debug", &[], DEBUG_SUBCOMMANDS),
    command("bugreport", &[], NONE),
    command(
        "exit-node",
        &[
            flag("--list", FlagValue::Bool),
            flag("--select", FlagValue::Value),
            flag("--clear", FlagValue::Bool),
            flag("--suggest", FlagValue::Bool),
        ],
        EXIT_NODE_SUBCOMMANDS,
    ),
    command("dns", &[], DNS_SUBCOMMANDS),
    command("nc", &[], NONE),
    command("id-token", &[], NONE),
    command(
        "update",
        &[
            flag("--yes", FlagValue::Bool),
            flag("--dry-run", FlagValue::Bool),
            flag("--track", FlagValue::Value),
            flag("--version", FlagValue::Value),
        ],
        NONE,
    ),
    command(
        "wait",
        &[flag_with_aliases(
            "--timeout",
            &["-timeout"],
            FlagValue::Value,
        )],
        NONE,
    ),
    command("lock", &[], LOCK_SUBCOMMANDS),
    command("drive", &[], DRIVE_SUBCOMMANDS),
    command("completion", &[], COMPLETION_SUBCOMMANDS),
];

/// If completion is requesting the first `nc` positional, return its prefix
/// and any explicitly typed socket path. The caller may perform one bounded,
/// read-only status lookup; all other completion remains static.
pub fn nc_host_request(args: &[String]) -> Option<(Option<PathBuf>, String)> {
    let (current, completed) = args.split_last()?;
    if current.starts_with('-') {
        return None;
    }

    let mut socket = None;
    let mut saw_nc = false;
    let mut index = 0;
    while index < completed.len() {
        let token = completed[index].as_str();
        if token == "--socket" {
            let value = completed.get(index + 1)?;
            socket = Some(PathBuf::from(value));
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--socket=") {
            socket = Some(PathBuf::from(value));
            index += 1;
            continue;
        }
        if token == "--json" {
            index += 1;
            continue;
        }
        if !saw_nc && token == "nc" {
            saw_nc = true;
            index += 1;
            continue;
        }
        // A prior positional is the host, so the current word is the port.
        // Unknown flags and commands must never trigger daemon I/O.
        return None;
    }
    saw_nc.then(|| (socket, current.clone()))
}

/// Extract upstream-compatible `nc` host completion candidates from status.
pub fn nc_hosts_from_status(status: &serde_json::Value, prefix: &str) -> Vec<String> {
    let mut hosts = status
        .get("Peer")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(_, peer)| peer.get("DNSName").and_then(serde_json::Value::as_str))
        .map(|name| name.trim_end_matches('.').to_owned())
        .filter(|name| !name.is_empty() && name.starts_with(prefix))
        .collect::<Vec<_>>();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Print a completion script for a supported shell.
pub fn run_script(args: &[String]) -> Result<(), CliError> {
    let script = match args {
        [shell] if shell == "bash" => BASH_SCRIPT,
        [shell] if shell == "zsh" => ZSH_SCRIPT,
        [shell] if shell == "fish" => FISH_SCRIPT,
        _ => {
            return Err(CliError(
                "usage: rustscale completion <bash|zsh|fish>".into(),
            ))
        }
    };
    print!("{script}");
    Ok(())
}

/// Return the command model used by shell completion as normalized JSON.
///
/// This is consumed by the compatibility-contract generator through the
/// hidden, side-effect-free `__compat-contract` command. Keeping extraction on
/// the built binary makes the checked manifest follow the same command tree
/// that users' shells see.
pub fn contract_json() -> serde_json::Value {
    fn value_json(value: FlagValue) -> serde_json::Value {
        match value {
            FlagValue::Bool => serde_json::json!({"kind": "bool"}),
            FlagValue::Value => serde_json::json!({"kind": "value"}),
            FlagValue::OneOf(values) => {
                serde_json::json!({"kind": "one_of", "values": values})
            }
        }
    }

    fn flag_json(spec: &FlagSpec) -> serde_json::Value {
        serde_json::json!({
            "name": spec.name,
            "aliases": spec.aliases,
            "value": value_json(spec.value),
        })
    }

    fn command_json(spec: &CommandSpec) -> serde_json::Value {
        serde_json::json!({
            "name": spec.name,
            "aliases": [],
            "flags": spec.flags.iter().map(flag_json).collect::<Vec<_>>(),
            "subcommands": spec.subcommands.iter().map(command_json).collect::<Vec<_>>(),
        })
    }

    serde_json::json!({
        "name": "rustscale",
        "aliases": [],
        "flags": GLOBAL_FLAGS.iter().map(flag_json).collect::<Vec<_>>(),
        "commands": COMMANDS.iter().map(command_json).collect::<Vec<_>>(),
    })
}

/// Return newline-safe static candidates for the hidden shell protocol.
pub fn complete(args: &[String]) -> Vec<String> {
    let (completed, current) = args
        .split_last()
        .map_or((&[][..], ""), |(last, rest)| (rest, last.as_str()));

    let mut index = 0;
    while index < completed.len() {
        let token = completed[index].as_str();
        if token == "--" {
            return Vec::new();
        }
        if let Some(value) = flag_value(GLOBAL_FLAGS, token) {
            if token.contains('=') || value == FlagValue::Bool {
                index += 1;
            } else if index + 1 < completed.len() {
                index += 2;
            } else {
                return complete_flag_value("", value, current);
            }
            continue;
        }
        if token.starts_with('-') {
            return Vec::new();
        }
        let Some(spec) = COMMANDS.iter().find(|spec| spec.name == token) else {
            return Vec::new();
        };
        return complete_command(spec, &completed[index + 1..], current);
    }

    complete_names_and_flags(COMMANDS, GLOBAL_FLAGS, current)
}

fn complete_command(
    mut spec: &'static CommandSpec,
    mut completed: &[String],
    current: &str,
) -> Vec<String> {
    loop {
        let mut index = 0;
        let mut allow_subcommands = true;
        while index < completed.len() {
            let token = completed[index].as_str();
            if token == "--" {
                return Vec::new();
            }

            let local_value = flag_value(spec.flags, token);
            let global_value = flag_value(GLOBAL_FLAGS, token);
            if let Some(value) = local_value.or(global_value) {
                // Nested parsers require their subcommand to be the first
                // subcommand argument. Global flags are removed by main, but a
                // command-local flag means a later word is positional.
                allow_subcommands &= local_value.is_none();
                if token.contains('=') || value == FlagValue::Bool {
                    index += 1;
                } else if index + 1 < completed.len() {
                    index += 2;
                } else {
                    return complete_flag_value("", value, current);
                }
                continue;
            }
            if token.starts_with('-') {
                return Vec::new();
            }
            if allow_subcommands {
                if let Some(subcommand) = spec
                    .subcommands
                    .iter()
                    .find(|subcommand| subcommand.name == token)
                {
                    spec = subcommand;
                    completed = &completed[index + 1..];
                    break;
                }
            }

            // The hand-written parsers accept positionals, but completion must
            // not guess after one. This also makes `--` and unknown contexts
            // unable to trigger any runtime operation.
            return Vec::new();
        }

        if index == completed.len() {
            let subcommands = if allow_subcommands {
                spec.subcommands
            } else {
                NONE
            };
            return complete_names_and_flags(subcommands, spec.flags, current);
        }
    }
}

fn complete_names_and_flags(
    commands: &'static [CommandSpec],
    flags: &'static [FlagSpec],
    current: &str,
) -> Vec<String> {
    if current.starts_with('-') {
        if let Some((name, prefix)) = current.split_once('=') {
            if let Some(value) = flag_value(flags, name).or_else(|| flag_value(GLOBAL_FLAGS, name))
            {
                return complete_flag_value(name, value, prefix);
            }
            return Vec::new();
        }

        let mut candidates = Vec::new();
        for name in flags
            .iter()
            .chain(GLOBAL_FLAGS)
            .flat_map(|flag| std::iter::once(flag.name).chain(flag.aliases.iter().copied()))
            .filter(|name| name.starts_with(current))
        {
            if !candidates.iter().any(|candidate| candidate == name) {
                candidates.push(name.to_owned());
            }
        }
        return candidates;
    }

    commands
        .iter()
        .map(|command| command.name)
        .filter(|name| name.starts_with(current))
        .map(str::to_owned)
        .collect()
}

fn flag_value(flags: &[FlagSpec], token: &str) -> Option<FlagValue> {
    let name = token.split_once('=').map_or(token, |(name, _)| name);
    flags
        .iter()
        .find(|flag| flag.name == name || flag.aliases.contains(&name))
        .map(|flag| flag.value)
}

fn complete_flag_value(name: &str, value: FlagValue, prefix: &str) -> Vec<String> {
    let values = match value {
        FlagValue::Bool => BOOL_VALUES,
        FlagValue::OneOf(values) => values,
        FlagValue::Value => return Vec::new(),
    };

    values
        .iter()
        .copied()
        .filter(|candidate| candidate.starts_with(prefix))
        .map(|candidate| {
            if name.starts_with('-') {
                format!("{name}={candidate}")
            } else {
                candidate.to_owned()
            }
        })
        .collect()
}

const BASH_SCRIPT: &str = r#"# bash completion for rustscale
_rustscale_completion() {
    local candidate
    COMPREPLY=()
    while IFS= read -r candidate; do
        COMPREPLY+=("$candidate")
    done < <(command rustscale __complete -- "${COMP_WORDS[@]:1:$COMP_CWORD}")
}
complete -F _rustscale_completion rustscale
"#;

const ZSH_SCRIPT: &str = r#"#compdef rustscale
_rustscale_completion() {
    local -a suggestions
    suggestions=("${(@f)$(command rustscale __complete -- "${words[@]:1}")}")
    (( ${#suggestions} )) && compadd -- "${suggestions[@]}"
}
compdef _rustscale_completion rustscale
"#;

const FISH_SCRIPT: &str = r"# fish completion for rustscale
function __rustscale_completion
    command rustscale __complete -- (commandline -opc)[2..-1] (commandline -ct)
end
complete -c rustscale -f -a '(__rustscale_completion)'
";

#[cfg(test)]
mod tests {
    use super::*;

    fn words(input: &[&str]) -> Vec<String> {
        input.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn completes_top_level_prefixes() {
        assert_eq!(complete(&words(&["st"])), vec!["status"]);
        assert!(complete(&words(&[""]))
            .iter()
            .any(|word| word == "completion"));
    }

    #[test]
    fn requests_only_the_first_nc_positional_and_extracts_peer_names() {
        assert_eq!(
            nc_host_request(&words(&["--socket", "/tmp/test.sock", "nc", "pe"])),
            Some((Some(PathBuf::from("/tmp/test.sock")), "pe".into()))
        );
        assert!(nc_host_request(&words(&["nc", "peer", ""])).is_none());
        assert!(nc_host_request(&words(&["status", ""])).is_none());

        let status = serde_json::json!({
            "Peer": {
                "1": {"DNSName": "zebra.example.ts.net."},
                "2": {"DNSName": "peer.example.ts.net."},
                "3": {"DNSName": "peer-two.example.ts.net."}
            }
        });
        assert_eq!(
            nc_hosts_from_status(&status, "peer"),
            ["peer-two.example.ts.net", "peer.example.ts.net"]
        );
    }

    #[test]
    fn completes_nested_commands_and_flags() {
        assert_eq!(complete(&words(&["file", "g"])), vec!["get"]);
        assert_eq!(
            complete(&words(&["file", "get", "--conf"])),
            vec!["--conflict"]
        );
        assert_eq!(
            complete(&words(&["debug", ""])),
            vec!["status", "ipconfig", "metrics", "capture"]
        );
        assert_eq!(complete(&words(&["file", "--json", "g"])), vec!["get"]);
        assert_eq!(complete(&words(&["dns", ""])), vec!["status", "query"]);
        assert_eq!(complete(&words(&["dns", "q"])), vec!["query"]);
        assert!(complete(&words(&["serve", "--bg", "st"])).is_empty());
    }

    #[test]
    fn completes_flag_values() {
        assert_eq!(
            complete(&words(&["status", "--peers=f"])),
            vec!["--peers=false"]
        );
        assert_eq!(
            complete(&words(&["file", "get", "--conflict=o"])),
            vec!["--conflict=overwrite"]
        );
    }

    #[test]
    fn stops_after_positionals_or_double_dash() {
        assert!(complete(&words(&["ping", "100.64.0.1", "--"])).is_empty());
        assert!(complete(&words(&["ping", "--", ""])).is_empty());
        assert!(complete(&words(&["not-a-command", ""])).is_empty());
        assert!(complete(&words(&["file", "wat", ""])).is_empty());
    }

    #[test]
    fn scripts_use_only_hidden_completion_protocol() {
        for script in [BASH_SCRIPT, ZSH_SCRIPT, FISH_SCRIPT] {
            assert!(script.contains("rustscale __complete --"));
            assert!(!script.contains("rustscale status"));
        }
    }

    #[test]
    fn aliases_complete_and_are_exported_by_the_contract() {
        assert!(complete(&words(&["ping", "-"]))
            .iter()
            .any(|candidate| candidate == "-c"));
        assert_eq!(
            flag_value(
                COMMANDS
                    .iter()
                    .find(|command| command.name == "wait")
                    .unwrap()
                    .flags,
                "-timeout",
            ),
            Some(FlagValue::Value)
        );

        let contract = contract_json();
        let commands = contract["commands"].as_array().unwrap();
        let speedtest = commands
            .iter()
            .find(|command| command["name"] == "speedtest")
            .unwrap();
        assert!(speedtest["flags"].as_array().unwrap().iter().any(|flag| {
            flag["name"] == "--host"
                && flag["aliases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|alias| alias == "-host")
        }));
    }
}
