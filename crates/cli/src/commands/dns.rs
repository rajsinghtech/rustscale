//! `rustscale dns` — inspect and query the daemon's DNS resolver.
//!
//! The current LocalAPI DNS query response contains peer IP address strings,
//! not a DNS wire response. The CLI therefore supports A and AAAA queries and
//! filters that address list to the requested family.

use std::net::IpAddr;
use std::path::Path;

use rustscale_localclient::LocalClient;
use serde_json::Value;

use crate::CliError;

const DNS_USAGE: &str =
    "usage:\n  rustscale dns status [--json]\n  rustscale dns query [--json] <name> [A|AAAA]";
const DNS_STATUS_USAGE: &str = "usage: rustscale dns status [--json]";
const DNS_QUERY_USAGE: &str = "usage: rustscale dns query [--json] <name> [A|AAAA]";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueryType {
    A,
    Aaaa,
}

impl QueryType {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            _ => Err(CliError(format!(
                "unsupported DNS query type {value:?}; the current LocalAPI result supports only A and AAAA"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
        }
    }

    const fn matches(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::A, IpAddr::V4(_)) | (Self::Aaaa, IpAddr::V6(_))
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
enum DnsCommand {
    Help,
    Status,
    StatusHelp,
    Query { name: String, qtype: QueryType },
    QueryHelp,
}

pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    match parse_command(&args)? {
        DnsCommand::Help => {
            eprintln!("{DNS_USAGE}");
            Ok(())
        }
        DnsCommand::StatusHelp => {
            eprintln!("{DNS_STATUS_USAGE}");
            Ok(())
        }
        DnsCommand::QueryHelp => {
            eprintln!("{DNS_QUERY_USAGE}");
            Ok(())
        }
        DnsCommand::Status => run_status(socket, json).await,
        DnsCommand::Query { name, qtype } => run_query(socket, json, &name, qtype).await,
    }
}

fn parse_command(args: &[String]) -> Result<DnsCommand, CliError> {
    let Some((subcommand, args)) = args.split_first() else {
        return Err(CliError(format!("missing DNS subcommand\n{DNS_USAGE}")));
    };

    match subcommand.as_str() {
        "help" | "--help" | "-h" if args.is_empty() => Ok(DnsCommand::Help),
        "status" => match args {
            [] => Ok(DnsCommand::Status),
            [help] if matches!(help.as_str(), "--help" | "-h") => Ok(DnsCommand::StatusHelp),
            [argument, ..] => Err(CliError(format!(
                "unexpected argument for 'dns status': {argument:?}\n{DNS_STATUS_USAGE}"
            ))),
        },
        "query" => parse_query_command(args),
        other => Err(CliError(format!(
            "unknown DNS subcommand {other:?}; use 'rustscale dns query <name> [A|AAAA]' to query a name\n{DNS_USAGE}"
        ))),
    }
}

fn parse_query_command(args: &[String]) -> Result<DnsCommand, CliError> {
    if matches!(args, [help] if matches!(help.as_str(), "--help" | "-h")) {
        return Ok(DnsCommand::QueryHelp);
    }

    let Some(name) = args.first() else {
        return Err(CliError(format!(
            "missing required argument: name\n{DNS_QUERY_USAGE}"
        )));
    };
    if name.is_empty() {
        return Err(CliError(format!(
            "DNS query name must not be empty\n{DNS_QUERY_USAGE}"
        )));
    }
    if name.starts_with('-') {
        return Err(CliError(format!(
            "unexpected flag before DNS query name: {name}\n{DNS_QUERY_USAGE}"
        )));
    }
    if args.len() > 2 {
        return Err(CliError(format!(
            "unexpected extra arguments: {}\n{DNS_QUERY_USAGE}",
            args[2..].join(" ")
        )));
    }

    let qtype = match args.get(1) {
        Some(value) if value.starts_with('-') => {
            return Err(CliError(format!(
                "unexpected flag after DNS query name: {value}\n{DNS_QUERY_USAGE}"
            )));
        }
        Some(value) => QueryType::parse(value)?,
        None => QueryType::A,
    };

    Ok(DnsCommand::Query {
        name: name.clone(),
        qtype,
    })
}

async fn run_query(
    socket: &Path,
    json: bool,
    name: &str,
    qtype: QueryType,
) -> Result<(), CliError> {
    let client = LocalClient::new(socket);
    let mut result = client.dns_query(name, qtype.as_str()).await?;
    filter_results(&mut result, qtype);

    if json {
        let pretty = serde_json::to_string_pretty(&result).map_err(|e| CliError(e.to_string()))?;
        println!("{pretty}");
    } else {
        let results = result
            .get("results")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if results.is_empty() {
            println!("No results for {name}.");
        } else {
            for address in results {
                println!("{address}");
            }
        }
    }

    Ok(())
}

fn filter_results(result: &mut Value, qtype: QueryType) {
    let Some(results) = result.get_mut("results").and_then(Value::as_array_mut) else {
        return;
    };
    results.retain(|value| {
        value
            .as_str()
            .and_then(|address| address.parse::<IpAddr>().ok())
            .is_some_and(|address| qtype.matches(address))
    });
}

async fn run_status(socket: &Path, json: bool) -> Result<(), CliError> {
    let status = LocalClient::new(socket).status().await?;
    let magicdns = status
        .get("CurrentTailnet")
        .and_then(|v| v.get("MagicDNSEnabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let suffix = status
        .get("CurrentTailnet")
        .and_then(|v| v.get("MagicDNSSuffix"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let cert_domains = status
        .get("CertDomains")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();

    if json {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_only_explicit_status_and_query_subcommands() {
        assert_eq!(
            parse_command(&strings(&["status"])).unwrap(),
            DnsCommand::Status
        );
        assert_eq!(
            parse_command(&strings(&["query", "status.tailnet.ts.net", "aaaa"])).unwrap(),
            DnsCommand::Query {
                name: "status.tailnet.ts.net".into(),
                qtype: QueryType::Aaaa,
            }
        );

        let error = parse_command(&strings(&["peer.tailnet.ts.net"])).unwrap_err();
        assert!(error.to_string().contains("unknown DNS subcommand"));
    }

    #[test]
    fn validates_query_arguments_before_dispatch() {
        for (args, message) in [
            (&["query"][..], "missing required argument: name"),
            (&["query", ""][..], "must not be empty"),
            (&["query", "--type"][..], "unexpected flag before"),
            (&["query", "peer", "--type"][..], "unexpected flag after"),
            (&["query", "peer", "AAAA", "extra"][..], "unexpected extra"),
            (&["query", "peer", "TXT"][..], "supports only A and AAAA"),
        ] {
            let error = parse_command(&strings(args)).unwrap_err();
            assert!(
                error.to_string().contains(message),
                "error {error:?} did not contain {message:?}"
            );
        }
    }

    #[test]
    fn filters_current_localapi_results_by_address_family() {
        let original = serde_json::json!({
            "results": ["100.64.0.8", "fd7a:115c:a1e0::8", "not-an-ip", 7]
        });

        let mut a = original.clone();
        filter_results(&mut a, QueryType::A);
        assert_eq!(a["results"], serde_json::json!(["100.64.0.8"]));

        let mut aaaa = original;
        filter_results(&mut aaaa, QueryType::Aaaa);
        assert_eq!(aaaa["results"], serde_json::json!(["fd7a:115c:a1e0::8"]));
    }
}
