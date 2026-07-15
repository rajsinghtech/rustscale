//! Static shell completion support for the hand-written CLI parser.
//!
//! The hidden completion protocol only walks this command description. It must
//! never contact the daemon or invoke a command while an interactive shell is
//! completing input.

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
    value: FlagValue,
}

#[derive(Debug)]
struct CommandSpec {
    name: &'static str,
    flags: &'static [FlagSpec],
    subcommands: &'static [CommandSpec],
}

const fn flag(name: &'static str, value: FlagValue) -> FlagSpec {
    FlagSpec { name, value }
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
    command("init", &[], NONE),
    command("add", &[], NONE),
    command("remove", &[], NONE),
    command("disable", &[], NONE),
];
const DRIVE_SUBCOMMANDS: &[CommandSpec] = &[
    command("list", &[], NONE),
    command("share", &[], NONE),
    command("unshare", &[], NONE),
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
            flag("--shields-up", FlagValue::Bool),
            flag("--advertise-routes", FlagValue::Value),
            flag("--advertise-exit-node", FlagValue::Bool),
            flag("--exit-node", FlagValue::Value),
            flag("--route-all", FlagValue::Bool),
            flag("--advertise-tags", FlagValue::Value),
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
            flag("--size", FlagValue::Value),
            flag("-s", FlagValue::Value),
            flag("--count", FlagValue::Value),
            flag("--c", FlagValue::Value),
            flag("-c", FlagValue::Value),
            flag("--timeout", FlagValue::Value),
            flag("--until-direct", FlagValue::Bool),
            flag("-d", FlagValue::Bool),
        ],
        NONE,
    ),
    command(
        "speedtest",
        &[
            flag("--host", FlagValue::Value),
            flag("-host", FlagValue::Value),
            flag("--time", FlagValue::Value),
            flag("-t", FlagValue::Value),
            flag("--server", FlagValue::Bool),
            flag("-s", FlagValue::Bool),
            flag("--reverse", FlagValue::Bool),
            flag("-r", FlagValue::Bool),
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
            flag("--suggest", FlagValue::Bool),
        ],
        NONE,
    ),
    command(
        "dns",
        &[flag(
            "--type",
            FlagValue::OneOf(&["A", "AAAA", "CNAME", "MX", "PTR", "TXT"]),
        )],
        NONE,
    ),
    command("nc", &[], NONE),
    command("id-token", &[], NONE),
    command("update", &[], NONE),
    command("wait", &[flag("--timeout", FlagValue::Value)], NONE),
    command("lock", &[], LOCK_SUBCOMMANDS),
    command("drive", &[], DRIVE_SUBCOMMANDS),
    command("completion", &[], COMPLETION_SUBCOMMANDS),
];

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
            .map(|flag| flag.name)
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
        .find(|flag| flag.name == name)
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
}
