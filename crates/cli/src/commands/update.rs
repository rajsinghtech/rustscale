//! `rustscale update` — safely update from RustScale GitHub releases.

use std::io::{self, IsTerminal, Write};
use std::path::Path;

use rustscale_clientupdate::{
    detect_install_method, HttpClient, Platform, ReleaseUpdater, SystemCommandRunner,
    SystemFileSystem, Track, UpdateError, UpdateOutcome, VersionSelector, GITHUB_RELEASES_PAGE,
};

use crate::{version, CliError};

#[derive(Debug, PartialEq, Eq)]
struct UpdateFlags {
    yes: bool,
    dry_run: bool,
    track: Option<Track>,
    version: Option<String>,
}

fn parse_flags(args: &[String]) -> Result<Option<UpdateFlags>, CliError> {
    let mut flags = UpdateFlags {
        yes: false,
        dry_run: false,
        track: None,
        version: None,
    };
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        match argument.as_str() {
            "--help" | "-h" => return Ok(None),
            "--yes" => flags.yes = true,
            "--dry-run" => flags.dry_run = true,
            "--track" | "--version" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| CliError(format!("{argument} requires a non-empty value")))?;
                set_value(&mut flags, argument, value)?;
            }
            value if value.starts_with("--track=") => {
                set_value(&mut flags, "--track", &value["--track=".len()..])?;
            }
            value if value.starts_with("--version=") => {
                set_value(&mut flags, "--version", &value["--version=".len()..])?;
            }
            _ => {
                return Err(CliError(format!(
                    "unknown update argument {argument:?}; try 'rustscale update --help'"
                )));
            }
        }
        index += 1;
    }

    if flags.track.is_some() && flags.version.is_some() {
        return Err(CliError("cannot specify both --track and --version".into()));
    }
    if flags.yes && flags.dry_run {
        return Err(CliError("cannot specify both --yes and --dry-run".into()));
    }
    Ok(Some(flags))
}

fn set_value(flags: &mut UpdateFlags, name: &str, value: &str) -> Result<(), CliError> {
    if value.is_empty() {
        return Err(CliError(format!("{name} requires a non-empty value")));
    }
    match name {
        "--track" => {
            if flags.track.is_some() {
                return Err(CliError("--track may only be specified once".into()));
            }
            flags.track = Some(
                value
                    .parse()
                    .map_err(|error: UpdateError| CliError(error.to_string()))?,
            );
        }
        "--version" => {
            if flags.version.is_some() {
                return Err(CliError("--version may only be specified once".into()));
            }
            flags.version = Some(value.to_owned());
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_interaction(flags: &UpdateFlags, stdin_is_terminal: bool) -> Result<(), CliError> {
    if !flags.yes && !flags.dry_run && !stdin_is_terminal {
        return Err(CliError(
            "refusing a noninteractive update without --yes (use --dry-run to inspect the plan)"
                .into(),
        ));
    }
    Ok(())
}

fn usage() {
    eprintln!(
        "usage: rustscale update [--yes | --dry-run] [--track <track> | --version <version>]"
    );
    eprintln!();
    eprintln!("flags:");
    eprintln!("  --yes             update without an interactive prompt");
    eprintln!("  --dry-run         print the selected release and plan without changing files");
    eprintln!("  --track <track>   stable, release-candidate, or unstable");
    eprintln!("  --version <ver>   install an explicit GitHub release version");
}

pub async fn run(args: Vec<String>, _socket: &Path, json: bool) -> Result<(), CliError> {
    let stdin_is_terminal = io::stdin().is_terminal();
    tokio::task::spawn_blocking(move || run_blocking(args, json, stdin_is_terminal))
        .await
        .map_err(|error| CliError(format!("update worker failed: {error}")))?
}

fn run_blocking(args: Vec<String>, json: bool, stdin_is_terminal: bool) -> Result<(), CliError> {
    let Some(flags) = parse_flags(&args)? else {
        usage();
        return Ok(());
    };
    validate_interaction(&flags, stdin_is_terminal)?;

    let selector = if let Some(version) = flags.version.clone() {
        VersionSelector::Version(version)
    } else {
        VersionSelector::Track(flags.track.unwrap_or_else(|| {
            rustscale_clientupdate::version_to_track(version::CLIENT_VERSION)
                .unwrap_or(Track::Stable)
        }))
    };

    let executable = std::env::current_exe()
        .map_err(|error| CliError(format!("cannot locate the rustscale executable: {error}")))?;
    let filesystem = SystemFileSystem;
    let install_method = detect_install_method(&executable, Platform::current(), &filesystem);
    let http = HttpClient::new().map_err(update_error)?;
    let commands = SystemCommandRunner;
    let updater = ReleaseUpdater::new(
        version::CLIENT_VERSION,
        Platform::current(),
        install_method,
        &http,
        &http,
        &commands,
        &filesystem,
    );

    let yes = flags.yes;
    let (plan, outcome) = updater
        .execute(selector, flags.dry_run, |plan| {
            yes || confirm(plan.current_version.as_str(), plan.target_version.as_str())
        })
        .map_err(update_error)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "currentVersion": plan.current_version,
                "targetVersion": plan.target_version,
                "track": plan.track.as_str(),
                "dryRun": flags.dry_run,
                "plan": plan.description(),
                "outcome": match outcome {
                    UpdateOutcome::AlreadyCurrent => "already-current",
                    UpdateOutcome::NewerLocal => "newer-local",
                    UpdateOutcome::DryRun => "dry-run",
                    UpdateOutcome::Declined => "declined",
                    UpdateOutcome::Applied => "applied",
                },
            })
        );
        return Ok(());
    }

    match outcome {
        UpdateOutcome::AlreadyCurrent => println!(
            "RustScale {} is already the latest {} release.",
            plan.current_version,
            plan.track.as_str()
        ),
        UpdateOutcome::NewerLocal => {
            println!(
                "Local RustScale {} is newer than the selected {} release {}.",
                plan.current_version,
                plan.track.as_str(),
                plan.target_version
            );
            if flags.dry_run {
                println!("No files or commands were changed (dry run).");
            }
        }
        UpdateOutcome::DryRun => {
            println!("Current: {}", plan.current_version);
            println!(
                "Selected: {} ({})",
                plan.target_version,
                plan.track.as_str()
            );
            println!("Plan: {}", plan.description());
            println!("No files or commands were changed (dry run).");
        }
        UpdateOutcome::Declined => {
            println!("Update cancelled; the current installation was not changed.");
        }
        UpdateOutcome::Applied => println!(
            "RustScale {} update applied and version-verified. Restart rustscaled to run the new daemon.",
            plan.target_version
        ),
    }
    Ok(())
}

fn confirm(current: &str, target: &str) -> bool {
    eprint!("This will update RustScale from {current} to {target}. Continue? [y/N] ");
    if io::stderr().flush().is_err() {
        return false;
    }
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .is_ok_and(|_| matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn update_error(error: UpdateError) -> CliError {
    match error {
        UpdateError::Unsupported(reason) => CliError(format!(
            "update is not supported for this installation: {reason}. See {GITHUB_RELEASES_PAGE}"
        )),
        other => CliError(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_update_flags() {
        assert_eq!(
            parse_flags(&args(&["--yes", "--track=unstable"]))
                .unwrap()
                .unwrap(),
            UpdateFlags {
                yes: true,
                dry_run: false,
                track: Some(Track::Unstable),
                version: None,
            }
        );
        assert_eq!(
            parse_flags(&args(&["--dry-run", "--version", "v1.2.3"]))
                .unwrap()
                .unwrap()
                .version
                .as_deref(),
            Some("v1.2.3")
        );
    }

    #[test]
    fn rejects_mutually_exclusive_flags() {
        assert!(parse_flags(&args(&["--track", "stable", "--version", "1.2.3"])).is_err());
        assert!(parse_flags(&args(&["--yes", "--dry-run"])).is_err());
    }

    #[test]
    fn rejects_invalid_and_missing_values() {
        assert!(parse_flags(&args(&["--track", "nightly"])).is_err());
        assert!(parse_flags(&args(&["--version"])).is_err());
        assert!(parse_flags(&args(&["--version="])).is_err());
        assert!(parse_flags(&args(&["positional"])).is_err());
    }

    #[test]
    fn noninteractive_updates_require_yes_but_dry_runs_do_not() {
        let plain = parse_flags(&[]).unwrap().unwrap();
        assert!(validate_interaction(&plain, false).is_err());
        let yes = parse_flags(&args(&["--yes"])).unwrap().unwrap();
        assert!(validate_interaction(&yes, false).is_ok());
        let dry_run = parse_flags(&args(&["--dry-run"])).unwrap().unwrap();
        assert!(validate_interaction(&dry_run, false).is_ok());
    }
}
