//! `rustscale dns` — query the daemon's DNS resolver.
//!
//! With a name argument, resolves it via the daemon. Without arguments,
//! prints the DNS resolver status (MagicDNS enabled, nameservers).

use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::flags;
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let want_json = json || flags::parse_bool_flag(&args, "json").unwrap_or(false);

    let client = LocalClient::new(socket);

    // If a name argument is provided, query it.
    if let Some(name) = args.iter().find(|a| !a.starts_with("--")) {
        let qtype = flags::parse_str_flag(&args, "type").unwrap_or_else(|| "A".to_string());
        let result = client.dns_query(name, &qtype).await?;

        if want_json {
            let pretty =
                serde_json::to_string_pretty(&result).map_err(|e| CliError(e.to_string()))?;
            println!("{pretty}");
        } else {
            let results = result
                .get("results")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if results.is_empty() {
                println!("No results for {name}.");
            } else {
                for ip in &results {
                    println!("{ip}");
                }
            }
        }
        return Ok(());
    }

    // No name argument — print DNS status.
    let status = client.status().await?;
    let magicdns = status
        .get("CurrentTailnet")
        .and_then(|v| v.get("MagicDNSEnabled"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let suffix = status
        .get("CurrentTailnet")
        .and_then(|v| v.get("MagicDNSSuffix"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let cert_domains = status
        .get("CertDomains")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if want_json {
        println!(
            "{}",
            serde_json::json!({
                "magicdns_enabled": magicdns,
                "magicdns_suffix": suffix,
                "cert_domains": cert_domains,
            })
        );
    } else {
        println!(
            "MagicDNS: {}",
            if magicdns { "enabled" } else { "disabled" }
        );
        if !suffix.is_empty() {
            println!("MagicDNS suffix: {suffix}");
        }
        if !cert_domains.is_empty() {
            println!("Cert domains: {}", cert_domains.join(", "));
        }
    }

    Ok(())
}
