//! `rustscale cert` — fetch TLS certificates for a domain.
//!
//! Ports Go's `cmd/tailscale/cli/cert.go` → `runCert`. Talks to the daemon
//! over LocalAPI (`GET /localapi/v0/cert/<domain>`), writes the cert and/or
//! key to files (or stdout with `-`), and prints the node's cert domain from
//! status when no domain is given.
//!
//! # Flags
//!
//!   --cert-file <path>   output cert file or `-` for stdout;
//!                         defaults to `<domain>.crt` if both --cert-file
//!                         and --key-file are unset
//!   --key-file <path>    output key file or `-` for stdout;
//!                         defaults to `<domain>.key` if both --cert-file
//!                         and --key-file are unset
//!   --min-validity <dur> ensure the cert is valid for at least this Go-style
//!                         duration (e.g. `720h`); 0/empty = just don't expire

use std::path::Path;

use rustscale_localclient::LocalClient;

use crate::flags::{parse_bool_flag, parse_str_flag};
use crate::CliError;

pub async fn run(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let lc = LocalClient::new(socket);
    let cert_file = parse_str_flag(&args, "cert-file");
    let key_file = parse_str_flag(&args, "key-file");
    let min_validity = parse_str_flag(&args, "min-validity").unwrap_or_default();
    let _ = parse_bool_flag(&args, "json"); // cert doesn't use --json

    // Positional domain argument (first non-flag arg).
    let domain = positional_domain(&args);

    let Some(domain) = domain else {
        // No domain given: print the node's cert domain from status,
        // or a hint if HTTPS isn't enabled / Tailscale isn't running.
        let status = lc.status().await?;
        let backend_state = status
            .get("BackendState")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        if backend_state == "Running" {
            let domains = status
                .get("CertDomains")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|d| d.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if domains.is_empty() {
                eprintln!("\nHTTPS cert support is not enabled/configured for your tailnet.");
            } else if domains.len() == 1 {
                eprintln!("\nFor domain, use \"{}\".", domains[0]);
            } else {
                eprintln!("\nValid domain options: {:?}.", domains);
            }
        } else {
            eprintln!("\nTailscale is not running.");
        }
        return Err(CliError("Usage: rustscale cert [flags] <domain>".into()));
    };

    // Determine output paths (matching Go's defaults).
    let (cert_path, key_path) = resolve_paths(&domain, cert_file.as_deref(), key_file.as_deref());

    // Fetch the cert pair.
    let mv_secs: u64 = parse_min_validity_secs(&min_validity)?;
    let (cert_pem, key_pem) = lc.cert_pair(&domain, mv_secs).await?;

    // Write cert file.
    if let Some(ref cp) = cert_path {
        if cp == "-" {
            // stdout
            use std::io::Write;
            let mut stdout = std::io::stdout();
            stdout.write_all(&cert_pem)?;
        } else {
            write_if_changed(cp, &cert_pem, 0o644)?;
            eprintln!("Wrote public cert to {cp}");
        }
    }

    // Write key file.
    if let Some(ref kp) = key_path {
        if kp == "-" {
            use std::io::Write;
            let mut stdout = std::io::stdout();
            stdout.write_all(&key_pem)?;
        } else {
            write_if_changed(kp, &key_pem, 0o600)?;
            eprintln!("Wrote private key to {kp}");
        }
    }

    Ok(())
}

/// Extract the positional domain argument (first non-flag, non-flag-value arg).
fn positional_domain(args: &[String]) -> Option<String> {
    let value_flags = ["cert-file", "key-file", "min-validity"];
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-" {
            // "-" is not a domain.
            i += 1;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--") {
            // --flag=value → skip
            if rest.contains('=') {
                i += 1;
                continue;
            }
            // --flag value → skip both (if it's a value-taking flag)
            if value_flags.contains(&rest) {
                i += 2;
                continue;
            }
            // boolean flag → skip just this
            i += 1;
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            // short flag, skip
            i += 1;
            continue;
        }
        // Positional argument.
        return Some(arg.clone());
    }
    None
}

/// Resolve the cert and key output paths from the flags + domain, matching
/// Go's defaults: if both --cert-file and --key-file are unset, derive
/// `<domain>.crt` and `<domain>.key`. If either is set, only write the one(s
/// that are set.
fn resolve_paths(
    domain: &str,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> (Option<String>, Option<String>) {
    let (cert, key) = if cert_file.is_none() && key_file.is_none() {
        let base = domain.replacen("*.", "wildcard_.", 1);
        (Some(format!("{base}.crt")), Some(format!("{base}.key")))
    } else {
        (cert_file.map(String::from), key_file.map(String::from))
    };
    (cert, key)
}

/// Parse a Go-style min-validity duration string to seconds. `0`/empty = 0.
fn parse_min_validity_secs(s: &str) -> Result<u64, CliError> {
    let s = s.trim();
    if s.is_empty() || s == "0" {
        return Ok(0);
    }
    let mut total: u64 = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let num_end = rest
            .bytes()
            .position(|b| !b.is_ascii_digit() && b != b'.')
            .unwrap_or(rest.len());
        if num_end == 0 {
            return Err(CliError(format!("invalid --min-validity: '{s}'")));
        }
        let n: f64 = rest[..num_end]
            .parse()
            .map_err(|e| CliError(format!("invalid --min-validity number: {e}")))?;
        rest = &rest[num_end..];
        let unit_end = rest
            .bytes()
            .position(|b| b.is_ascii_digit() || b == b'.')
            .unwrap_or(rest.len());
        if unit_end == 0 {
            return Err(CliError(format!("invalid --min-validity: '{s}'")));
        }
        let unit = rest[..unit_end].to_ascii_lowercase();
        rest = &rest[unit_end..];
        let secs = match unit.as_str() {
            "h" => n * 3600.0,
            "m" => n * 60.0,
            "s" => n,
            "ms" => n / 1000.0,
            other => {
                return Err(CliError(format!("invalid --min-validity unit '{other}'")));
            }
        };
        total = total.saturating_add(secs.round() as u64);
    }
    Ok(total)
}

/// Write `contents` to `path` only if the content changed (avoids touching
/// mtime on identical writes, matching Go's `writeIfChanged`).
fn write_if_changed(path: &str, contents: &[u8], mode: u32) -> Result<(), CliError> {
    if std::fs::read(path).is_ok_and(|old| old == contents) {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(contents)
            })?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::write(path, contents)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positional_domain_simple() {
        let args = vec!["test.ts.net".to_string()];
        assert_eq!(positional_domain(&args), Some("test.ts.net".into()));
    }

    #[test]
    fn positional_domain_with_flags() {
        let args = vec![
            "--cert-file".to_string(),
            "out.crt".to_string(),
            "test.ts.net".to_string(),
        ];
        assert_eq!(positional_domain(&args), Some("test.ts.net".into()));
    }

    #[test]
    fn positional_domain_with_equals_flags() {
        let args = vec![
            "--cert-file=out.crt".to_string(),
            "--key-file=-".to_string(),
            "test.ts.net".to_string(),
        ];
        assert_eq!(positional_domain(&args), Some("test.ts.net".into()));
    }

    #[test]
    fn positional_domain_none() {
        let args = vec!["--json".to_string()];
        assert_eq!(positional_domain(&args), None);
    }

    #[test]
    fn resolve_paths_defaults() {
        let (c, k) = resolve_paths("test.ts.net", None, None);
        assert_eq!(c, Some("test.ts.net.crt".into()));
        assert_eq!(k, Some("test.ts.net.key".into()));
    }

    #[test]
    fn resolve_paths_wildcard() {
        let (c, k) = resolve_paths("*.ts.net", None, None);
        assert_eq!(c, Some("wildcard_.ts.net.crt".into()));
        assert_eq!(k, Some("wildcard_.ts.net.key".into()));
    }

    #[test]
    fn resolve_paths_explicit() {
        let (c, k) = resolve_paths("test.ts.net", Some("out.crt"), Some("-"));
        assert_eq!(c, Some("out.crt".into()));
        assert_eq!(k, Some("-".into()));
    }

    #[test]
    fn resolve_paths_only_cert() {
        let (c, k) = resolve_paths("test.ts.net", Some("out.crt"), None);
        assert_eq!(c, Some("out.crt".into()));
        assert_eq!(k, None);
    }

    #[test]
    fn parse_min_validity_zero() {
        assert_eq!(parse_min_validity_secs("").unwrap(), 0);
        assert_eq!(parse_min_validity_secs("0").unwrap(), 0);
    }

    #[test]
    fn parse_min_validity_hours() {
        assert_eq!(parse_min_validity_secs("720h").unwrap(), 720 * 3600);
    }

    #[test]
    fn parse_min_validity_combined() {
        assert_eq!(parse_min_validity_secs("1h30m").unwrap(), 5400);
    }

    #[test]
    fn parse_min_validity_invalid() {
        assert!(parse_min_validity_secs("xyz").is_err());
        assert!(parse_min_validity_secs("12").is_err());
    }
}
