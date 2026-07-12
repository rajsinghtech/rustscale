//! `rustscale file` subcommand — Taildrop file transfer.
//!
//! Ports Go's `cmd/tailscale/cli/file.go`:
//! - `file cp [--name=<name>] [--verbose] <files...> <target>:` — send files.
//! - `file get [--wait] [--conflict=skip|overwrite|rename] [--verbose] <dir>` —
//!   receive files from the inbox.
//! - `file cp --targets` — list possible file cp targets.

use std::path::Path;

use rustscale_localclient::LocalClient;
use rustscale_tsnet::{resolve_conflict, ConflictMode};

use crate::flags::{parse_bool_flag, parse_str_flag};
use crate::CliError;

/// Entry point for `rustscale file <cp|get> ...`.
pub async fn run(args: Vec<String>, socket: &Path, _json: bool) -> Result<(), CliError> {
    if args.is_empty() {
        file_usage();
        return Err(CliError("no subcommand".into()));
    }

    match args[0].as_str() {
        "cp" => {
            let sub_args = args[1..].to_vec();
            run_cp(sub_args, socket).await
        }
        "get" => {
            let sub_args = args[1..].to_vec();
            run_get(sub_args, socket).await
        }
        other => {
            eprintln!("error: unknown file subcommand '{other}'");
            file_usage();
            Err(CliError(format!("unknown file subcommand: {other}")))
        }
    }
}

/// `file cp [--name=<name>] [--verbose] [--targets] <files...> <target>:`
async fn run_cp(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let verbose = parse_bool_flag(&args, "verbose").unwrap_or(false);
    let name_override = parse_str_flag(&args, "name");
    let targets_mode = parse_bool_flag(&args, "targets").unwrap_or(false);

    if targets_mode {
        let lc = LocalClient::new(socket);
        let targets = lc.file_targets().await?;
        if targets.is_empty() {
            println!("No file targets available.");
            return Ok(());
        }
        for t in &targets {
            let detail = if t.Online { "" } else { "\toffline" };
            let ip = t
                .TailscaleIPs
                .first()
                .map(std::string::ToString::to_string)
                .unwrap_or_default();
            println!("{ip}\t{}{detail}", t.Name);
        }
        return Ok(());
    }

    // Parse positional args (filter out flags).
    let positional: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .collect();
    if positional.len() < 2 {
        return Err(CliError(
            "usage: rustscale file cp <files...> <target>:".into(),
        ));
    }

    let (files, target_arg) = positional.split_at(positional.len() - 1);
    let target_raw = &target_arg[0];

    // Target must end with a colon.
    let target = target_raw
        .strip_suffix(':')
        .ok_or_else(|| CliError("final argument to 'file cp' must end in colon".into()))?;

    if files.len() > 1 && name_override.is_some() {
        return Err(CliError("can't use --name= with multiple files".into()));
    }

    let lc = LocalClient::new(socket);

    // Resolve the target to a stable node ID via file-targets.
    let targets = lc.file_targets().await?;
    let target_entry = targets.iter().find(|t| {
        t.Name.trim_end_matches('.') == target.trim_end_matches('.')
            || t.StableID == *target
            || t.TailscaleIPs.iter().any(|ip| ip.to_string() == *target)
    });

    let Some(target_entry) = target_entry else {
        return Err(CliError(format!(
            "can't send to {target}: not found in file targets"
        )));
    };

    for file_arg in files {
        let (filename, body) = if file_arg == "-" {
            let name = name_override
                .clone()
                .unwrap_or_else(|| "stdin.txt".to_string());
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
                .map_err(|e| CliError(format!("failed to read stdin: {e}")))?;
            (name, buf)
        } else {
            let path = std::path::Path::new(file_arg);
            if path.is_dir() {
                return Err(CliError("directories not supported".into()));
            }
            let body = std::fs::read(path)
                .map_err(|e| CliError(format!("failed to read {file_arg}: {e}")))?;
            let name = name_override
                .clone()
                .or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_else(|| file_arg.clone());
            (name, body)
        };

        if verbose {
            eprintln!("sending {filename} ({} bytes) to {target}...", body.len());
        }

        lc.push_file(&target_entry.StableID, &filename, &body)
            .await?;

        if verbose {
            eprintln!("sent {filename}");
        }
    }

    Ok(())
}

/// `file get [--wait] [--conflict=skip|overwrite|rename] [--verbose] <dir>`
async fn run_get(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let wait = parse_bool_flag(&args, "wait").unwrap_or(false);
    let verbose = parse_bool_flag(&args, "verbose").unwrap_or(false);
    let conflict_str = parse_str_flag(&args, "conflict").unwrap_or_else(|| "skip".to_string());
    let conflict = ConflictMode::parse(&conflict_str).map_err(CliError)?;

    let positional: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .collect();
    if positional.len() != 1 {
        return Err(CliError(
            "usage: rustscale file get [--wait] [--conflict=...] <target-directory>".into(),
        ));
    }
    let dir = &positional[0];

    let dir_path = std::path::Path::new(dir);
    if !dir_path.is_dir() {
        return Err(CliError(format!("{dir:?} is not a directory")));
    }

    let lc = LocalClient::new(socket);

    // Optionally wait for files to arrive.
    let files = if wait {
        // Poll with a long timeout.
        loop {
            let files = lc.waiting_files().await?;
            if !files.is_empty() {
                break files;
            }
            if verbose {
                eprintln!("waiting for file...");
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    } else {
        lc.waiting_files().await?
    };

    if files.is_empty() {
        if verbose {
            println!("No files waiting.");
        }
        return Ok(());
    }

    let mut downloaded = 0usize;
    let mut errors = Vec::new();

    for wf in &files {
        match receive_file(&lc, wf, dir_path, conflict, verbose).await {
            Ok(()) => downloaded += 1,
            Err(e) => errors.push(e),
        }
    }

    for e in &errors {
        eprintln!("{e}");
    }

    if downloaded == 0 && !files.is_empty() {
        return Err(CliError(format!(
            "moved {downloaded}/{} files",
            files.len()
        )));
    }

    if verbose {
        println!("moved {downloaded}/{} files", files.len());
    }

    Ok(())
}

/// Download a single file from the inbox, write it to the target directory
/// (honoring the conflict mode), and delete it from the inbox.
async fn receive_file(
    lc: &LocalClient,
    wf: &rustscale_ipn::WaitingFile,
    dir: &std::path::Path,
    conflict: ConflictMode,
    verbose: bool,
) -> Result<(), CliError> {
    let (bytes, _size) = lc.get_waiting_file(&wf.Name).await?;

    let target_path = resolve_conflict(dir, &wf.Name, conflict).map_err(CliError)?;

    std::fs::write(&target_path, &bytes)
        .map_err(|e| CliError(format!("failed to write {}: {e}", target_path.display())))?;

    if verbose {
        println!(
            "wrote {} as {} ({} bytes)",
            wf.Name,
            target_path.display(),
            bytes.len()
        );
    }

    lc.delete_waiting_file(&wf.Name).await?;

    Ok(())
}

fn file_usage() {
    eprintln!("usage: rustscale file <cp|get> ...");
    eprintln!();
    eprintln!("  file cp [--name=<name>] [--verbose] [--targets] <files...> <target>:");
    eprintln!("      Send file(s) to a host. Use --targets to list possible targets.");
    eprintln!("      Use '-' for stdin (requires --name=).");
    eprintln!();
    eprintln!("  file get [--wait] [--conflict=skip|overwrite|rename] [--verbose] <dir>");
    eprintln!("      Move files from the Tailscale inbox to <dir>.");
}
