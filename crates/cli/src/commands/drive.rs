//! `rustscale drive` — the safely supported local Taildrive share slice.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustscale_drive::{normalize_share_name, validate_share_root};
use rustscale_localclient::{DriveShare, LocalClient, LocalClientError};

use crate::CliError;

const PATH_VALIDATION_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let operation = run_inner(&args, socket, json);
    tokio::pin!(operation);
    tokio::select! {
        result = &mut operation => result,
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|error| CliError(format!("drive: failed to listen for cancellation: {error}")))?;
            if args.first().is_some_and(|subcommand| matches!(subcommand.as_str(), "share" | "unshare")) {
                Err(CliError("drive: canceled; the mutation may have committed, so run `rustscale drive list` before retrying".into()))
            } else {
                Err(CliError("drive: canceled".into()))
            }
        }
    }
}

async fn run_inner(args: &[String], socket: &Path, json: bool) -> Result<(), CliError> {
    let subcommand = args.first().map_or("list", String::as_str);
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = LocalClient::new(socket);

    match subcommand {
        "status" => status(&client, rest, json).await,
        "list" => list(&client, rest, json).await,
        "share" => share(&client, rest, json).await,
        "unshare" => unshare(&client, rest, json).await,
        "mount" | "unmount" | "remote" | "bookmark" | "bookmarks" => Err(CliError(
            "remote Taildrive mounts and macOS security-scoped bookmarks are not supported".into(),
        )),
        "rename" => Err(CliError(
            "drive rename is not supported by this first CLI parity slice".into(),
        )),
        other => Err(CliError(format!(
            "drive: unsupported subcommand '{other}' (supported: status, list, share, unshare)"
        ))),
    }
}

async fn status(client: &LocalClient, args: &[String], json: bool) -> Result<(), CliError> {
    if !args.is_empty() {
        return Err(CliError("usage: rustscale drive status".into()));
    }
    let status = client.drive_status().await?;
    if json {
        print_json(&status)?;
        return Ok(());
    }

    println!(
        "Taildrive sharing is {}.",
        if status.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "Sharing is {} by the signed netmap.",
        if status.sharing_allowed {
            "allowed"
        } else {
            "not allowed"
        }
    );
    println!("Configuration generation: {}", status.generation);
    print_share_table(&status.shares);
    Ok(())
}

async fn list(client: &LocalClient, args: &[String], json: bool) -> Result<(), CliError> {
    if !args.is_empty() {
        return Err(CliError("usage: rustscale drive list".into()));
    }
    let (config, _) = client.get_drive_config().await?;
    if json {
        print_json(&config.shares)?;
    } else {
        print_share_table(&config.shares);
    }
    Ok(())
}

async fn share(client: &LocalClient, args: &[String], json: bool) -> Result<(), CliError> {
    if args.iter().any(|arg| {
        arg == "--bookmark"
            || arg == "--bookmark-data"
            || arg.starts_with("--bookmark=")
            || arg.starts_with("--bookmark-data=")
    }) {
        return Err(CliError(
            "macOS security-scoped Taildrive bookmarks are not supported".into(),
        ));
    }
    if args.len() != 2 {
        return Err(CliError(
            "usage: rustscale drive share <name> <path>".into(),
        ));
    }

    let name = validated_name(&args[0])?;
    let path = absolute_validated_path(&args[1]).await?;
    let (mut config, etag) = client.get_drive_config().await?;
    config.shares.retain(|share| share.name != name);
    config.shares.push(DriveShare::new(name, path));
    config
        .shares
        .sort_by(|left, right| left.name.cmp(&right.name));
    config.enabled = true;
    let status = mutation_result(client.set_drive_config(&config, &etag).await)?;

    if json {
        print_json(&status)?;
    } else {
        println!("Sharing {:?} as {:?}", args[1], args[0]);
    }
    Ok(())
}

async fn unshare(client: &LocalClient, args: &[String], json: bool) -> Result<(), CliError> {
    if args.len() != 1 {
        return Err(CliError("usage: rustscale drive unshare <name>".into()));
    }
    let name = validated_name(&args[0])?;
    let (mut config, etag) = client.get_drive_config().await?;
    let old_len = config.shares.len();
    config.shares.retain(|share| share.name != name);
    if config.shares.len() == old_len {
        return Err(CliError(format!("Taildrive share {:?} not found", args[0])));
    }
    config.enabled = !config.shares.is_empty();
    let status = mutation_result(client.set_drive_config(&config, &etag).await)?;

    if json {
        print_json(&status)?;
    } else {
        println!("No longer sharing {:?}", args[0]);
    }
    Ok(())
}

fn mutation_result(
    result: Result<rustscale_localclient::DriveStatus, LocalClientError>,
) -> Result<rustscale_localclient::DriveStatus, CliError> {
    match result {
        Ok(status) => Ok(status),
        Err(
            error
            @ (LocalClientError::Timeout(_)
            | LocalClientError::Io(_)
            | LocalClientError::Json(_)),
        ) => Err(CliError(
            format!(
                "Taildrive mutation outcome is unknown ({error}); run `rustscale drive list` before retrying"
            ),
        )),
        Err(error) => Err(error.into()),
    }
}

fn validated_name(name: &str) -> Result<String, CliError> {
    normalize_share_name(name).map_err(|_| {
        CliError(
            "invalid share name: use only letters a-z, digits, underscore, parentheses, and spaces"
                .into(),
        )
    })
}

async fn absolute_validated_path(path: &str) -> Result<PathBuf, CliError> {
    let input = PathBuf::from(path);
    let absolute = if input.is_absolute() {
        input
    } else {
        std::env::current_dir()?.join(input)
    };
    let checked = absolute.clone();
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("rustscale-drive-path".into())
        .spawn(move || {
            let _ = result_tx.send(validate_share_root(&checked));
        })
        .map_err(|error| {
            CliError(format!(
                "failed to start Taildrive path validation: {error}"
            ))
        })?;
    tokio::time::timeout(PATH_VALIDATION_TIMEOUT, result_rx)
        .await
        .map_err(|_| CliError("Taildrive path validation timed out".into()))?
        .map_err(|_| CliError("Taildrive path validation worker stopped".into()))?
        .map_err(|error| CliError(error.to_string()))?;
    Ok(absolute)
}

fn print_share_table(shares: &[DriveShare]) {
    let longest_name = shares
        .iter()
        .map(|share| share.name.len())
        .max()
        .unwrap_or(0)
        .max("name".len());
    let longest_path = shares
        .iter()
        .map(|share| share.path.to_string_lossy().len())
        .max()
        .unwrap_or(0)
        .max("path".len());
    let longest_as = shares
        .iter()
        .map(|share| share.as_user.len())
        .max()
        .unwrap_or(0)
        .max("as".len());

    println!(
        "{:<longest_name$}    {:<longest_path$}    as",
        "name", "path"
    );
    println!(
        "{:-<longest_name$}    {:-<longest_path$}    {:-<longest_as$}",
        "", "", ""
    );
    for share in shares {
        println!(
            "{:<longest_name$}    {:<longest_path$}    {}",
            share.name,
            share.path.display(),
            share.as_user
        );
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<(), CliError> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| CliError(error.to_string()))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_table_matches_upstream_columns() {
        let shares = [DriveShare::new("docs", "/srv/documents")];
        let longest_name = shares[0].name.len().max("name".len());
        let longest_path = shares[0].path.to_string_lossy().len().max("path".len());
        assert_eq!(longest_name, 4);
        assert_eq!(longest_path, 14);
    }

    #[test]
    fn names_are_normalized_before_compare_and_swap() {
        assert_eq!(validated_name(" My Docs (2) ").unwrap(), "my docs (2)");
        assert!(validated_name("../docs").is_err());
    }
}
