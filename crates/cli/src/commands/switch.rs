use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::flags::parse_bool_flag;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, _json: bool) -> Result<(), CliError> {
    let list = parse_bool_flag(&args, "list").unwrap_or(false);
    let json = parse_bool_flag(&args, "json").unwrap_or(false);

    let lc = LocalClient::new(socket);

    if list {
        let profiles = lc.list_profiles().await?;
        let current = lc.current_profile().await?;

        if json {
            let entries: Vec<serde_json::Value> = profiles
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "id": p.ID,
                        "name": p.Name,
                        "tailnet": p.NetworkProfile.DomainName,
                        "control_url": p.ControlURL,
                        "selected": p.ID == current.ID,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).unwrap_or_default()
            );
        } else {
            if profiles.is_empty() {
                println!("No profiles found.");
                return Ok(());
            }
            println!("{:<24} {:<20} {:<20}", "ID", "Tailnet", "Account");
            for p in &profiles {
                let mut name = p.Name.clone();
                if p.ID == current.ID {
                    name.push('*');
                }
                let tailnet = if p.NetworkProfile.DisplayName.is_empty() {
                    p.NetworkProfile.DomainName.clone()
                } else {
                    p.NetworkProfile.DisplayName.clone()
                };
                println!("{:<24} {:<20} {:<20}", p.ID, tailnet, name);
            }
        }
        return Ok(());
    }

    // Switch to a profile.
    let positional: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .collect();
    if positional.is_empty() {
        return Err(CliError("usage: rustscale switch <profile-id|name>".into()));
    }
    let target = &positional[0];

    // Find the profile by ID or name.
    let profiles = lc.list_profiles().await?;
    let current = lc.current_profile().await?;

    let profile_id = profiles
        .iter()
        .find(|p| p.ID == *target || p.Name == *target)
        .map(|p| p.ID.clone())
        .ok_or_else(|| CliError(format!("no profile named \"{target}\"")))?;

    if profile_id == current.ID {
        println!("Already on account \"{target}\"");
        return Ok(());
    }

    lc.switch_profile(&profile_id).await?;
    println!("Switching to account \"{target}\"...");

    // Poll for the switch to complete.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > deadline {
            return Err(CliError("timeout waiting for switch to complete".into()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let status = lc.status().await?;
        let state = status
            .get("BackendState")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        match state {
            "Running" => {
                println!("Success.");
                return Ok(());
            }
            "NeedsLogin" => {
                println!("Logged out. To log in, run: rustscale up");
                return Ok(());
            }
            "NoState" | "Starting" => continue,
            _ => {
                println!("State: {state}");
                continue;
            }
        }
    }
}
