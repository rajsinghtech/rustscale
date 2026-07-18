//! `rustscale lock` — the safely supported Tailnet Lock administration slice.

use std::path::Path;

use rand::RngCore as _;
use rustscale_key::{NLPublic, NodePublic};
use rustscale_localclient::LocalClient;
use rustscale_tka::{disablement_kdf, Key, KeyKind};

use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let subcommand = args.first().map_or("status", String::as_str);
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let client = LocalClient::new(socket);
    match subcommand {
        "status" => status(&client, rest, json).await,
        "init" => init(&client, rest, json).await,
        "sign" => sign(&client, rest).await,
        "disable" => disable(&client, rest).await,
        "local-disable" => local_disable(&client, rest).await,
        other => Err(CliError(format!(
            "lock: unsupported subcommand '{other}' (supported: status, init, sign, disable, local-disable)"
        ))),
    }
}

async fn status(client: &LocalClient, args: &[String], json: bool) -> Result<(), CliError> {
    if !args.is_empty() {
        return Err(CliError("usage: rustscale lock status".into()));
    }
    let status = client.tailnet_lock_status().await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).map_err(|error| CliError(error.to_string()))?
        );
        return Ok(());
    }
    let enabled = status["Enabled"].as_bool().unwrap_or(false);
    let local_disabled = status["LocalDisabled"].as_bool().unwrap_or(false);
    let local_disable_pending = status["LocalDisablePending"].as_bool().unwrap_or(false);
    if local_disabled || local_disable_pending {
        if local_disabled {
            println!("Tailnet Lock enforcement is LOCALLY DISABLED for this node.");
        } else {
            println!("Tailnet Lock local-disable state is awaiting fresh control confirmation.");
        }
        if !status["StateConsistent"].as_bool().unwrap_or(false) {
            println!("Peer access is withdrawn until a fresh authenticated map confirms the denylisted authority.");
        }
        if status["LocalDisableCleanupPending"]
            .as_bool()
            .unwrap_or(false)
        {
            println!(
                "Retired authority cleanup is incomplete; retry `rustscale lock local-disable`."
            );
        }
    } else {
        println!(
            "Tailnet Lock is {}.",
            if enabled { "ENABLED" } else { "NOT enabled" }
        );
    }
    if enabled && !status["StateConsistent"].as_bool().unwrap_or(false) {
        println!("Authority state is not synchronized; peer access is failing closed.");
    }
    if let Some(public) = status["PublicKey"].as_str() {
        println!("This node's Tailnet Lock key: {public}");
    }
    if enabled {
        if status["NodeKeySigned"].as_bool().unwrap_or(false) {
            println!("This node is authorized by Tailnet Lock.");
        } else if let Some(node) = status["NodeKey"].as_str() {
            println!("This node is not currently authorized.");
            println!("On a trusted signing node, run: rustscale lock sign {node}");
        }
        if let Some(keys) = status["TrustedKeys"].as_array() {
            if !keys.is_empty() {
                println!("Trusted signing keys:");
                for key in keys {
                    println!(
                        "  {}\t{} votes",
                        key["Key"].as_str().unwrap_or("<unknown>"),
                        key["Votes"].as_u64().unwrap_or(0)
                    );
                }
            }
        }
        if let Some(peers) = status["FilteredPeers"].as_array() {
            if !peers.is_empty() {
                println!("Filtered peers:");
                for peer in peers {
                    println!(
                        "  {}\t{}\t{}",
                        peer["Name"].as_str().unwrap_or("<unnamed>"),
                        peer["NodeKey"].as_str().unwrap_or("<unknown>"),
                        peer["Reason"].as_str().unwrap_or("unauthorized")
                    );
                }
            }
        }
    }
    Ok(())
}

async fn init(client: &LocalClient, args: &[String], json: bool) -> Result<(), CliError> {
    let mut confirm = false;
    let mut resume = false;
    let mut count = 1usize;
    let mut key_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--confirm" {
            confirm = true;
        } else if argument == "--resume" {
            resume = true;
        } else if let Some(value) = argument.strip_prefix("--gen-disablements=") {
            count = parse_count(value)?;
        } else if argument == "--gen-disablements" {
            index += 1;
            count = parse_count(
                args.get(index)
                    .ok_or_else(|| CliError("--gen-disablements requires a value".into()))?,
            )?;
        } else if argument.starts_with("--") {
            return Err(CliError(format!("unknown lock init flag: {argument}")));
        } else {
            key_args.push(argument.clone());
        }
        index += 1;
    }

    let current = client.tailnet_lock_status().await?;
    let receipt_pending = !current["InitReceipt"].is_null();
    if resume {
        if !confirm {
            return Err(CliError(
                "resuming returns stored disablement secrets; re-run with --resume --confirm"
                    .into(),
            ));
        }
        if !receipt_pending {
            return Err(CliError(
                "there is no durable Tailnet Lock initialization receipt".into(),
            ));
        }
        let response = client
            .tailnet_lock_init(&serde_json::json!({"Resume": true}))
            .await?;
        return print_init_result(client, response, json).await;
    }
    if receipt_pending {
        return Err(CliError(
            "a durable initialization receipt already exists; use lock status and lock init --resume --confirm, never generate replacements"
                .into(),
        ));
    }
    if current["Enabled"].as_bool().unwrap_or(false) {
        return Err(CliError("Tailnet Lock is already enabled".into()));
    }
    let self_public: NLPublic = current["PublicKey"]
        .as_str()
        .ok_or_else(|| CliError("daemon did not report a Tailnet Lock key".into()))?
        .parse()
        .map_err(|_| CliError("daemon reported an invalid Tailnet Lock key".into()))?;

    let mut keys = if key_args.is_empty() {
        vec![trusted_key(&self_public, 1)]
    } else {
        key_args
            .iter()
            .map(|argument| parse_trusted_key(argument))
            .collect::<Result<Vec<_>, _>>()?
    };
    if !keys.iter().any(|key| key.public == self_public.raw32()) {
        return Err(CliError(
            "the current node's Tailnet Lock key must be trusted during initialization".into(),
        ));
    }
    // Keep the request deterministic and reject duplicate key IDs locally.
    keys.sort_by(|left, right| left.public.cmp(&right.public));
    if keys.windows(2).any(|pair| pair[0].public == pair[1].public) {
        return Err(CliError("duplicate trusted Tailnet Lock key".into()));
    }

    if !confirm {
        println!(
            "This will enable Tailnet Lock with {} trusted key(s).",
            keys.len()
        );
        println!("It will generate {count} one-time disablement secret(s).");
        println!("Re-run with --confirm after verifying every trusted key.");
        return Ok(());
    }

    let mut secrets = Vec::with_capacity(count);
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let mut secret = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        values.push(disablement_kdf(&secret));
        secrets.push(secret);
    }
    let request = serde_json::json!({
        "Keys": keys,
        "DisablementValues": values,
        "DisablementSecrets": secrets,
        "SupportDisablement": [],
        "Resume": false,
    });
    let response = match client.tailnet_lock_init(&request).await {
        Ok(response) => response,
        Err(error) => {
            eprintln!(
                "Tailnet Lock initialization may be ambiguous. The original secrets were durably receipted before control was contacted; run `rustscale lock status` and `rustscale lock init --resume --confirm`. Do not generate replacements."
            );
            return Err(error.into());
        }
    };
    print_init_result(client, response, json).await
}

async fn print_init_result(
    client: &LocalClient,
    response: serde_json::Value,
    json: bool,
) -> Result<(), CliError> {
    let secrets = response["DisablementSecrets"]
        .as_array()
        .ok_or_else(|| CliError("daemon did not return the durable disablement receipt".into()))?
        .iter()
        .map(|secret| {
            let bytes = secret
                .as_array()
                .ok_or_else(|| CliError("daemon returned an invalid disablement receipt".into()))?
                .iter()
                .map(|byte| {
                    byte.as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or_else(|| {
                            CliError("daemon returned an invalid disablement receipt".into())
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("disablement-secret:{}", hex::encode_upper(bytes)))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).map_err(|error| CliError(error.to_string()))?
        );
    } else {
        println!("Tailnet Lock initialization complete or recovered.");
        println!("Store these secrets now; the owner-only recovery receipt will be acknowledged after this output:");
        for secret in secrets {
            println!("  {secret}");
        }
    }
    if let Some(transaction_id) = response["InitReceipt"]["TransactionID"].as_str() {
        client.tailnet_lock_ack_init(transaction_id).await?;
    }
    Ok(())
}

fn parse_count(value: &str) -> Result<usize, CliError> {
    let count = value
        .parse::<usize>()
        .map_err(|_| CliError("--gen-disablements must be an integer".into()))?;
    if !(1..=32).contains(&count) {
        return Err(CliError(
            "--gen-disablements must be between 1 and 32".into(),
        ));
    }
    Ok(count)
}

fn parse_trusted_key(argument: &str) -> Result<Key, CliError> {
    let (key, votes) = argument
        .split_once('?')
        .map_or((argument, "1"), |(key, votes)| (key, votes));
    let public: NLPublic = key
        .parse()
        .map_err(|_| CliError("invalid Tailnet Lock public key".into()))?;
    let votes = votes
        .parse::<u64>()
        .map_err(|_| CliError("invalid Tailnet Lock vote count".into()))?;
    if !(1..=4096).contains(&votes) {
        return Err(CliError("vote count must be between 1 and 4096".into()));
    }
    Ok(trusted_key(&public, votes))
}

fn trusted_key(public: &NLPublic, votes: u64) -> Key {
    Key {
        kind: KeyKind::Key25519,
        votes,
        public: public.raw32().to_vec(),
        meta: None,
    }
}

async fn sign(client: &LocalClient, args: &[String]) -> Result<(), CliError> {
    if args.is_empty() || args.len() > 2 {
        return Err(CliError(
            "usage: rustscale lock sign <node-key> [<rotation-key>]".into(),
        ));
    }
    let node: NodePublic = args[0]
        .parse()
        .map_err(|_| CliError("invalid node public key".into()))?;
    let rotation = if let Some(value) = args.get(1) {
        value
            .parse::<NLPublic>()
            .map_err(|_| CliError("invalid rotation public key".into()))?
            .raw32()
            .to_vec()
    } else {
        Vec::new()
    };
    client
        .tailnet_lock_sign(&serde_json::json!({
            "NodeKey": node,
            "RotationPublic": rotation,
        }))
        .await?;
    println!("Node signature submitted.");
    Ok(())
}

async fn disable(client: &LocalClient, args: &[String]) -> Result<(), CliError> {
    if args.len() != 1 {
        return Err(CliError(
            "usage: rustscale lock disable <disablement-secret:HEX>".into(),
        ));
    }
    let encoded = args[0]
        .strip_prefix("disablement-secret:")
        .ok_or_else(|| CliError("disablement secret must use disablement-secret:HEX".into()))?;
    let secret = hex::decode(encoded).map_err(|_| CliError("invalid disablement secret".into()))?;
    client.tailnet_lock_disable(&secret).await?;
    println!(
        "Disablement accepted; local enforcement remains until control confirms it in a netmap."
    );
    Ok(())
}

async fn local_disable(client: &LocalClient, args: &[String]) -> Result<(), CliError> {
    if !args.is_empty() {
        return Err(CliError("usage: rustscale lock local-disable".into()));
    }
    client.tailnet_lock_force_local_disable().await?;
    println!(
        "Tailnet Lock enforcement is locally disabled for this node only; the authority state ID is durably denylisted."
    );
    println!("This does not disable Tailnet Lock for any other node in the tailnet.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_key_parser_accepts_cli_prefix_and_votes() {
        let public = NLPublic::from_raw32([3; 32]);
        let key = parse_trusted_key(&format!("{}?7", public.cli_string())).unwrap();
        assert_eq!(key.public, vec![3; 32]);
        assert_eq!(key.votes, 7);
    }

    #[test]
    fn disablement_count_is_bounded() {
        assert!(parse_count("1").is_ok());
        assert!(parse_count("32").is_ok());
        assert!(parse_count("0").is_err());
        assert!(parse_count("33").is_err());
    }
}
