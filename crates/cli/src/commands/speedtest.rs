//! `rustscale speedtest` — measure TCP throughput to another endpoint.

use std::path::Path;
use std::time::Duration;

use rustscale_speedtest::{self as speedtest, Direction, Result as SpeedtestResult};
use tokio::net::{TcpListener, TcpStream};

use crate::CliError;

#[derive(Debug, PartialEq, Eq)]
struct SpeedtestArgs {
    host: String,
    duration: Duration,
    server: bool,
    reverse: bool,
}

fn parse_duration(value: &str) -> Result<Duration, CliError> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 0.001)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1.0)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60.0)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3_600.0)
    } else {
        return Err(CliError(format!("invalid --time value: {value}")));
    };
    if number.is_empty() || number.starts_with('-') {
        return Err(CliError(format!("invalid --time value: {value}")));
    }
    let number: f64 = number
        .parse()
        .map_err(|_| CliError(format!("invalid --time value: {value}")))?;
    if !number.is_finite() || number < 0.0 {
        return Err(CliError(format!("invalid --time value: {value}")));
    }
    Duration::try_from_secs_f64(number * multiplier)
        .map_err(|_| CliError(format!("invalid --time value: {value}")))
}

fn parse_speedtest_args(args: &[String]) -> Result<SpeedtestArgs, CliError> {
    let mut host = format!(":{}", speedtest::DEFAULT_PORT);
    let mut duration = speedtest::DEFAULT_DURATION;
    let mut server = false;
    let mut reverse = false;
    let mut index = 0;

    while index < args.len() {
        let argument = &args[index];
        let value = |flag: &str, index: &mut usize| -> Result<String, CliError> {
            *index += 1;
            args.get(*index)
                .cloned()
                .filter(|value| !value.starts_with('-'))
                .ok_or_else(|| CliError(format!("{flag} requires a value")))
        };
        match argument.as_str() {
            "--host" | "-host" => host = value(argument, &mut index)?,
            "--time" | "-t" => duration = parse_duration(&value(argument, &mut index)?)?,
            "--server" | "-s" => server = true,
            "--reverse" | "-r" => reverse = true,
            value if value.starts_with("--host=") || value.starts_with("-host=") => {
                host = value
                    .split_once('=')
                    .map_or_else(String::new, |(_, value)| value.to_owned());
                if host.is_empty() {
                    return Err(CliError("--host requires a value".into()));
                }
            }
            value if value.starts_with("--time=") => {
                duration = parse_duration(&value["--time=".len()..])?;
            }
            value if value.starts_with("-t=") => duration = parse_duration(&value["-t=".len()..])?,
            value if value.starts_with('-') => {
                return Err(CliError(format!("unknown flag: {value}")))
            }
            value => return Err(CliError(format!("unexpected argument: {value}"))),
        }
        index += 1;
    }

    Ok(SpeedtestArgs {
        host: normalize_host(&host)?,
        duration,
        server,
        reverse,
    })
}

/// Add speedtest's default port when `host` has none, following Go's
/// `SplitHostPort`/`JoinHostPort` behavior. Explicit service-name ports are
/// preserved for Tokio's downstream address resolution.
fn normalize_host(host: &str) -> Result<String, CliError> {
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return Err(CliError(format!("invalid --host value: {host}")));
    }
    if let Some(bracketed) = host.strip_prefix('[') {
        let Some((ip, port)) = bracketed.split_once("]:") else {
            return Err(CliError(format!("invalid --host value: {host}")));
        };
        if ip.parse::<std::net::Ipv6Addr>().is_err() || port.is_empty() || port.contains(']') {
            return Err(CliError(format!("invalid --host value: {host}")));
        }
        return Ok(host.into());
    }

    let colon_count = host.bytes().filter(|byte| *byte == b':').count();
    match colon_count {
        0 => {
            if host.contains(['[', ']']) {
                return Err(CliError(format!("invalid --host value: {host}")));
            }
            Ok(format!("{host}:{}", speedtest::DEFAULT_PORT))
        }
        1 => {
            let (name, port) = host.split_once(':').expect("one colon");
            if port.is_empty() || name.contains(['[', ']']) {
                return Err(CliError(format!("invalid --host value: {host}")));
            }
            Ok(host.into())
        }
        _ => match host.parse::<std::net::Ipv6Addr>() {
            Ok(ip) => Ok(format!("[{ip}]:{}", speedtest::DEFAULT_PORT)),
            Err(_) => Err(CliError(format!("invalid --host value: {host}"))),
        },
    }
}

fn print_help() {
    println!("Usage: rustscale speedtest [flags]");
    println!();
    println!("Flags:");
    println!("  --host, -host <host:port>  Remote address or listen address (default :20333)");
    println!("  --time, -t <duration>      Test duration (default 5s)");
    println!("  --server, -s               Run as a server");
    println!("  --reverse, -r              Upload instead of download");
}

fn print_results(results: &[SpeedtestResult]) {
    println!("Results:");
    println!("Interval            Transfer            Bandwidth");
    for result in results.iter().filter(|result| !result.is_total) {
        let start = result
            .interval_start
            .duration_since(results[0].interval_start)
            .as_secs_f64();
        let end = result
            .interval_end
            .duration_since(results[0].interval_start)
            .as_secs_f64();
        println!(
            "{start:>4.2}-{end:<4.2}    sec    {:<10.4} MBits   {:<10.4} Mbits/sec",
            result.megabits(),
            result.mbits_per_sec()
        );
    }
    if let Some(total) = results.iter().find(|result| result.is_total) {
        println!("-------------------------------------------------------------------------");
        println!(
            "{:>4.2}-{: <4.2}    sec    {:<10.4} MBits   {:<10.4} Mbits/sec",
            0.0,
            total.interval_secs(),
            total.megabits(),
            total.mbits_per_sec()
        );
    }
}

/// Run the speedtest command.
pub async fn run(args: Vec<String>, _socket: &Path) -> Result<(), CliError> {
    if args
        .iter()
        .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
    {
        print_help();
        return Ok(());
    }
    let parsed = parse_speedtest_args(&args)?;

    if parsed.server {
        let listener = TcpListener::bind(&parsed.host).await?;
        println!("listening on {}", listener.local_addr()?);

        let server = speedtest::Server::default();
        let cancellation = speedtest::CancellationToken::new();
        let serving = server.serve(listener, cancellation.clone());
        tokio::pin!(serving);
        return tokio::select! {
            result = &mut serving => result.map_err(|error| CliError(error.to_string())),
            signal = tokio::signal::ctrl_c() => {
                cancellation.cancel();
                let server_result = serving.await.map_err(|error| CliError(error.to_string()));
                signal?;
                server_result
            }
        };
    }

    if !(speedtest::MIN_DURATION..=speedtest::MAX_DURATION).contains(&parsed.duration) {
        return Err(CliError(format!(
            "test duration must be between {:?} and {:?}",
            speedtest::MIN_DURATION,
            speedtest::MAX_DURATION
        )));
    }

    let mut stream = TcpStream::connect(&parsed.host).await?;
    let direction = if parsed.reverse {
        Direction::Upload
    } else {
        Direction::Download
    };
    let results = speedtest::run(&mut stream, direction, parsed.duration)
        .await
        .map_err(|error| CliError(error.to_string()))?;
    print_results(&results);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_speedtest_flags() {
        let parsed =
            parse_speedtest_args(&args(&["--host=127.0.0.1:20333", "-t", "10s", "-s", "-r"]))
                .unwrap();
        assert_eq!(parsed.host, "127.0.0.1:20333");
        assert_eq!(parsed.duration, Duration::from_secs(10));
        assert!(parsed.server);
        assert!(parsed.reverse);
    }

    #[test]
    fn normalizes_speedtest_hosts() {
        let default_host = format!(":{}", speedtest::DEFAULT_PORT);
        for (input, want) in [
            (
                "example.test",
                format!("example.test:{}", speedtest::DEFAULT_PORT),
            ),
            (
                "192.0.2.1",
                format!("192.0.2.1:{}", speedtest::DEFAULT_PORT),
            ),
            ("[2001:db8::1]:4444", "[2001:db8::1]:4444".into()),
            (
                "2001:db8::1",
                format!("[2001:db8::1]:{}", speedtest::DEFAULT_PORT),
            ),
            ("example.test:4444", "example.test:4444".into()),
            ("example.test:http", "example.test:http".into()),
            (&default_host, default_host.clone()),
        ] {
            assert_eq!(normalize_host(input).unwrap(), want);
        }
        for malformed in ["", "[2001:db8::1]", "example.test:", "bad host"] {
            assert!(normalize_host(malformed).is_err(), "{malformed}");
        }
    }
}
