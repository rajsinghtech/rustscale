use std::path::Path;
use std::time::Duration;

use rustscale_ipn::{MaskedPrefs, StartOptions, NOTIFY_INITIAL_STATE};
use rustscale_localclient::LocalClient;

use crate::flags::{parse_bool_flag, parse_csv_flag, parse_str_flag};
use crate::qrcode;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let lc = LocalClient::new(socket);
    let json = parse_bool_flag(&args, "json").unwrap_or(json);
    let timeout = parse_str_flag(&args, "timeout")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);
    let auth_key = parse_str_flag(&args, "auth-key");
    let force_reauth = parse_bool_flag(&args, "force-reauth").unwrap_or(false);
    let qr = parse_bool_flag(&args, "qr").unwrap_or(false);
    let qr_format = parse_str_flag(&args, "qr-format").unwrap_or_else(|| "auto".into());

    let status = lc.status().await?;
    let backend_state = status
        .get("BackendState")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let mut update = MaskedPrefs::default();
    update.Prefs.WantRunning = true;
    update.WantRunningSet = true;

    if let Some(h) = parse_str_flag(&args, "hostname") {
        update.Prefs.Hostname = h;
        update.HostnameSet = true;
    }
    if let Some(routes) = parse_csv_flag(&args, "advertise-routes") {
        update.Prefs.AdvertiseRoutes = routes;
        update.AdvertiseRoutesSet = true;
    }
    if let Some(value) = parse_bool_flag(&args, "advertise-exit-node") {
        update.Prefs.AdvertiseExitNode = value;
        update.AdvertiseExitNodeSet = true;
    }
    if let Some(selector) = parse_str_flag(&args, "exit-node") {
        super::exit_node::apply_exit_node_arg(&mut update, &status, &selector, false)?;
    }
    if let Some(value) = parse_bool_flag(&args, "shields-up") {
        update.Prefs.ShieldsUp = value;
        update.ShieldsUpSet = true;
    }
    if let Some(value) = parse_bool_flag(&args, "accept-routes") {
        update.Prefs.AcceptRoutes = value;
        update.AcceptRoutesSet = true;
    }
    if let Some(value) = parse_bool_flag(&args, "accept-dns") {
        update.Prefs.CorpDNS = value;
        update.CorpDNSSet = true;
    } else if backend_state == "NeedsLogin" {
        // Tailscale's first-run `up` defaults to accepting control-plane DNS.
        // Preserve an established node's explicit choice, but do not make a
        // fresh replacement install silently opt out of MagicDNS.
        update.Prefs.CorpDNS = true;
        update.CorpDNSSet = true;
    }
    if let Some(tags) = parse_csv_flag(&args, "advertise-tags") {
        update.Prefs.AdvertiseTags = tags;
        update.AdvertiseTagsSet = true;
    }
    // Omitted preserves the persisted operator. `--operator ""` explicitly
    // clears it, matching Tailscale's persisted Prefs.OperatorUser behavior.
    if let Some(operator) = parse_str_flag(&args, "operator") {
        update.Prefs.OperatorUser = operator;
        update.OperatorUserSet = true;
    }
    if parse_bool_flag(&args, "reset").unwrap_or(false) {
        update.Prefs = rustscale_ipn::Prefs::default();
        update.Prefs.WantRunning = true;
        update.WantRunningSet = true;
        update.RouteAllSet = true;
        update.CorpDNSSet = true;
    }

    if backend_state == "Running" && !force_reauth {
        // `up` is also the declarative container entrypoint surface. Apply
        // supplied preferences even when the node is already online instead
        // of returning with stale routes/DNS/hostname settings.
        lc.edit_prefs(&update).await?;
        if json {
            let updated_status = lc.status().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&updated_status).unwrap_or_default()
            );
        } else {
            println!("Tailscale is already running; preferences updated.");
        }
        return Ok(());
    }

    let mut watch = lc.watch_ipn_bus(NOTIFY_INITIAL_STATE).await?;

    let opts = StartOptions {
        AuthKey: auth_key.clone().unwrap_or_default(),
        UpdatePrefs: Some(update.clone()),
        ..Default::default()
    };
    lc.start(&opts).await?;

    // An auth key is itself the non-interactive login mechanism. Do not queue
    // a browser login behind it; that can race a successful key registration
    // and leave container bootstrap waiting on an unrelated auth URL.
    let needs_interactive_login =
        should_start_interactive_login(backend_state, force_reauth, auth_key.as_deref());
    if needs_interactive_login {
        lc.login_interactive().await?;
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(timeout);
    let mut last_url: Option<String> = None;
    loop {
        let msg = match tokio::time::timeout(
            deadline.saturating_duration_since(std::time::Instant::now()),
            watch.next(),
        )
        .await
        {
            Ok(Ok(Some(n))) => n,
            Ok(Ok(None) | Err(_)) => {
                // Starting a stopped/pre-login daemon atomically replaces its
                // LocalAPI generation. Several already-accepted watches can
                // close while the listener ownership transfer drains. First
                // accept an authoritative Running status from the replacement;
                // otherwise keep reconnecting within the caller's one deadline.
                // A reconnect count is not a valid generation boundary.
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(CliError("timeout waiting for up".into()));
                }
                if let Ok(Ok(status)) = tokio::time::timeout(remaining, lc.status()).await {
                    if status.get("BackendState").and_then(|v| v.as_str()) == Some("Running") {
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
                }

                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(CliError("timeout waiting for up".into()));
                }
                tokio::time::sleep(remaining.min(Duration::from_millis(25))).await;
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(CliError("timeout waiting for up".into()));
                }
                if let Ok(Ok(next_watch)) =
                    tokio::time::timeout(remaining, lc.watch_ipn_bus(NOTIFY_INITIAL_STATE)).await
                {
                    watch = next_watch;
                }
                continue;
            }
            Err(_) => return Err(CliError("timeout waiting for up".into())),
        };

        if let Some(ref url) = msg.BrowseToURL {
            if last_url.as_deref() != Some(url.as_str()) {
                last_url = Some(url.clone());
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
                        let _ = qr_format; // terminal always uses half-blocks
                    }
                }
            }
        }
        if let Some(true) = msg.LoginFinished {
            if !json {
                println!("Login finished.");
            }
        }
        if let Some(ref err) = msg.ErrMessage {
            if !json {
                eprintln!("Error: {err}");
            }
        }
        if let Some(state) = msg.State {
            if state == rustscale_ipn::State::Running {
                if json {
                    let st = lc.status().await?;
                    println!("{}", serde_json::to_string_pretty(&st).unwrap_or_default());
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

fn should_start_interactive_login(
    backend_state: &str,
    force_reauth: bool,
    auth_key: Option<&str>,
) -> bool {
    auth_key.is_none() && (backend_state == "NeedsLogin" || force_reauth)
}

#[cfg(test)]
mod tests {
    use super::should_start_interactive_login;

    #[test]
    fn needs_login_uses_browser_even_when_generated_node_key_exists() {
        assert!(should_start_interactive_login("NeedsLogin", false, None));
        assert!(!should_start_interactive_login(
            "NeedsLogin",
            false,
            Some("tskey-test")
        ));
        assert!(!should_start_interactive_login("Stopped", false, None));
        assert!(should_start_interactive_login("Running", true, None));
    }
}
