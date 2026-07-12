use std::path::Path;
use std::time::Duration;

use rustscale_ipn::NOTIFY_INITIAL_STATE;
use rustscale_localclient::LocalClient;

use crate::flags::{parse_bool_flag, parse_str_flag};
use crate::qrcode;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let lc = LocalClient::new(socket);
    let json = parse_bool_flag(&args, "json").unwrap_or(json);
    let timeout = parse_str_flag(&args, "timeout")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);
    let qr = parse_bool_flag(&args, "qr").unwrap_or(false);

    let status = lc.status().await?;
    let backend_state = status
        .get("BackendState")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");

    if backend_state == "Running" {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&status).unwrap_or_default()
            );
        } else {
            println!("Already running.");
        }
        return Ok(());
    }

    let mut watch = lc.watch_ipn_bus(NOTIFY_INITIAL_STATE).await?;

    lc.login_interactive().await?;

    let deadline = std::time::Instant::now() + Duration::from_secs(timeout);
    loop {
        let msg = match tokio::time::timeout(
            deadline.saturating_duration_since(std::time::Instant::now()),
            watch.next(),
        )
        .await
        {
            Ok(Ok(Some(n))) => n,
            Ok(Ok(None)) => return Err(CliError("connection closed".into())),
            Ok(Err(e)) => return Err(CliError(e.to_string())),
            Err(_) => return Err(CliError("timeout waiting for login".into())),
        };

        if let Some(ref url) = msg.BrowseToURL {
            if json {
                let qr_field = qrcode::render_png_data_url(url).ok();
                let mut out = serde_json::json!({
                    "AuthURL": url,
                    "BackendState": "NeedsLogin",
                });
                if let Some(qr) = qr_field {
                    out["QR"] = serde_json::Value::String(qr);
                }
                println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            } else {
                println!("\nTo authenticate, visit:\n  {url}\n");
                if qr {
                    match qrcode::render_terminal(url) {
                        Ok(rendered) => eprint!("{rendered}"),
                        Err(e) => eprintln!("QR code error: {e}"),
                    }
                }
            }
        }
        if let Some(true) = msg.LoginFinished {
            if !json {
                println!("Login finished.");
            }
        }
        if let Some(state) = msg.State {
            if state == rustscale_ipn::State::Running {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&status).unwrap_or_default()
                    );
                } else {
                    println!("Tailscale is running.");
                }
                return Ok(());
            }
            if !json {
                println!("State: {state}");
            }
        }
    }
}
