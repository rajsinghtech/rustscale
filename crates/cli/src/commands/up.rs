use std::path::Path;
use std::time::Duration;

use rustscale_ipn::{MaskedPrefs, StartOptions, NOTIFY_INITIAL_STATE};
use rustscale_localclient::LocalClient;

use crate::flags::{parse_bool_flag, parse_str_flag};
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let lc = LocalClient::new(socket);
    let json = parse_bool_flag(&args, "json").unwrap_or(json);
    let timeout = parse_str_flag(&args, "timeout")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);
    let auth_key = parse_str_flag(&args, "auth-key");
    let force_reauth = parse_bool_flag(&args, "force-reauth").unwrap_or(false);

    let status = lc.status().await?;
    let backend_state = status
        .get("BackendState")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let have_node_key = status
        .get("HaveNodeKey")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if backend_state == "Running" && !force_reauth {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&status).unwrap_or_default()
            );
        } else {
            println!("Tailscale is already running.");
        }
        return Ok(());
    }

    let mut update = MaskedPrefs::default();
    update.Prefs.WantRunning = true;
    update.WantRunningSet = true;

    if let Some(h) = parse_str_flag(&args, "hostname") {
        update.Prefs.Hostname = h;
        update.HostnameSet = true;
    }
    if let Some(r) = parse_str_flag(&args, "advertise-routes") {
        update.Prefs.AdvertiseRoutes = r.split(',').map(|s| s.trim().to_string()).collect();
        update.AdvertiseRoutesSet = true;
    }
    if parse_bool_flag(&args, "advertise-exit-node").unwrap_or(false) {
        update.Prefs.AdvertiseExitNode = true;
        update.AdvertiseExitNodeSet = true;
    }
    if let Some(e) = parse_str_flag(&args, "exit-node") {
        update.Prefs.ExitNodeIP = e;
        update.ExitNodeIPSet = true;
    }
    if parse_bool_flag(&args, "shields-up").unwrap_or(false) {
        update.Prefs.ShieldsUp = true;
        update.ShieldsUpSet = true;
    }
    if parse_bool_flag(&args, "accept-routes").unwrap_or(false) {
        update.Prefs.AcceptRoutes = true;
        update.AcceptRoutesSet = true;
    }
    if parse_bool_flag(&args, "accept-dns").unwrap_or(false) {
        update.Prefs.CorpDNS = true;
        update.CorpDNSSet = true;
    }
    if parse_bool_flag(&args, "reset").unwrap_or(false) {
        update.Prefs = rustscale_ipn::Prefs::default();
        update.Prefs.WantRunning = true;
        update.WantRunningSet = true;
        update.RouteAllSet = true;
        update.CorpDNSSet = true;
    }

    let mut watch = lc.watch_ipn_bus(NOTIFY_INITIAL_STATE).await?;

    let opts = StartOptions {
        AuthKey: auth_key.clone().unwrap_or_default(),
        UpdatePrefs: Some(update.clone()),
        ..Default::default()
    };
    lc.start(&opts).await?;

    let needs_login = !have_node_key || force_reauth || auth_key.is_none();
    if needs_login {
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
            Ok(Ok(None)) => return Err(CliError("connection closed".into())),
            Ok(Err(e)) => return Err(CliError(e.to_string())),
            Err(_) => return Err(CliError("timeout waiting for up".into())),
        };

        if let Some(ref url) = msg.BrowseToURL {
            if last_url.as_deref() != Some(url.as_str()) {
                last_url = Some(url.clone());
                if !json {
                    println!("\nTo authenticate, visit:\n  {url}\n");
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
