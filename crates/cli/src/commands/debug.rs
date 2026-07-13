//! `rustscale debug` — call daemon debug endpoints.
//!
//! Ports a subset of Go's `cmd/tailscale/cli/debug.go`. Supports
//! `debug status`, `debug ipconfig`, and `debug metrics` sub-commands.

use std::io::Write;
use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::flags;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    if args.first().is_some_and(|arg| arg == "capture") {
        return run_capture(&args[1..], socket).await;
    }

    let want_json = json || flags::parse_bool_flag(&args, "json").unwrap_or(false);

    // The first positional arg selects the debug action.
    let action = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map_or("status", String::as_str);

    let client = LocalClient::new(socket);
    let result = client.debug(action).await?;

    if want_json {
        let pretty = serde_json::to_string_pretty(&result).map_err(|e| CliError(e.to_string()))?;
        println!("{pretty}");
    } else {
        println!("{result}");
    }
    Ok(())
}

async fn run_capture(args: &[String], socket: &Path) -> Result<(), CliError> {
    let mut output_path = "-";
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" => {
                i += 1;
                output_path = args
                    .get(i)
                    .ok_or_else(|| CliError("debug capture: -o requires a path".into()))?;
            }
            arg if arg.starts_with("-o") && arg.len() > 2 => output_path = &arg[2..],
            arg => {
                return Err(CliError(format!(
                    "debug capture: unexpected argument {arg}"
                )))
            }
        }
        i += 1;
    }

    let mut output: Box<dyn Write> = if output_path == "-" {
        Box::new(std::io::stdout())
    } else {
        Box::new(std::fs::File::create(output_path)?)
    };
    let client = LocalClient::new(socket);
    let mut capture = client.debug_capture().await?;
    let mut buf = [0u8; 8192];
    loop {
        let count = capture.read(&mut buf).await?;
        if count == 0 {
            break;
        }
        output.write_all(&buf[..count])?;
    }
    output.flush()?;
    Ok(())
}
