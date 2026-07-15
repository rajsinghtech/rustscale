#[cfg(target_os = "macos")]
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    run_supervised, Endpoint, Entry, Error, OsMetadata, ProcessAssociation, SnapshotContext,
    SnapshotOptions, State, Table,
};

#[cfg(target_os = "macos")]
const NETSTAT_ARGS: [&str; 5] = ["-W", "-a", "-n", "-p", "tcp"];

/// Injectable source of numeric macOS `netstat` output.
pub trait NetstatReader: Send + Sync {
    fn read_netstat(&self, context: &SnapshotContext, max_bytes: usize) -> Result<Vec<u8>, Error>;
}

/// Build a supervised macOS TCP table using an injected command-output reader.
pub fn snapshot_macos_with_reader<R: NetstatReader + 'static>(
    reader: R,
    options: &SnapshotOptions,
    cancellation: &crate::CancellationToken,
) -> Result<Table, Error> {
    let options_for_worker = options.clone();
    run_supervised(options, cancellation, move |context| {
        snapshot_macos_inner(&reader, &options_for_worker, &context)
    })
}

fn snapshot_macos_inner<R: NetstatReader>(
    reader: &R,
    options: &SnapshotOptions,
    context: &SnapshotContext,
) -> Result<Table, Error> {
    context.check()?;
    let bytes = reader.read_netstat(context, options.limits.max_netstat_bytes)?;
    context.check()?;
    if bytes.len() > options.limits.max_netstat_bytes {
        return Err(Error::LimitExceeded {
            resource: "macOS netstat output bytes",
            limit: options.limits.max_netstat_bytes,
        });
    }
    let entries = parse_netstat(&bytes, options, context)?;
    Ok(Table {
        entries,
        process_association: if options.associate_processes {
            ProcessAssociation::Unavailable
        } else {
            ProcessAssociation::NotRequested
        },
    })
}

/// Parse numeric macOS `netstat -an -p tcp` output.
pub fn parse_netstat(
    bytes: &[u8],
    options: &SnapshotOptions,
    context: &SnapshotContext,
) -> Result<Vec<Entry>, Error> {
    const SOURCE: &str = "macOS netstat";
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8 {
        source_name: SOURCE,
    })?;
    let mut entries = Vec::new();
    for (index, raw_line) in text.split('\n').enumerate() {
        context.check()?;
        let line_number = index + 1;
        if raw_line.len() > options.limits.max_line_bytes {
            return Err(Error::LimitExceeded {
                resource: "macOS netstat line bytes",
                limit: options.limits.max_line_bytes,
            });
        }
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        let family = match first {
            "tcp4" => Family::V4,
            "tcp6" | "tcp46" => Family::V6,
            // Headers and non-TCP protocols are intentionally ignored.
            value if !value.starts_with("tcp") => continue,
            _ => {
                return Err(Error::Malformed {
                    source_name: SOURCE,
                    line: line_number,
                    reason: "unsupported TCP family",
                });
            }
        };
        if entries.len() == options.limits.max_entries {
            return Err(Error::LimitExceeded {
                resource: "TCP connection entries",
                limit: options.limits.max_entries,
            });
        }
        entries.push(parse_netstat_line(line, family, line_number)?);
    }
    entries.sort_unstable();
    Ok(entries)
}

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

fn parse_netstat_line(line: &str, family: Family, line_number: usize) -> Result<Entry, Error> {
    const SOURCE: &str = "macOS netstat";
    let malformed = |reason| Error::Malformed {
        source_name: SOURCE,
        line: line_number,
        reason,
    };
    let mut fields = line.split_whitespace();
    fields.next();
    fields
        .next()
        .ok_or_else(|| malformed("missing receive queue"))?
        .parse::<u64>()
        .map_err(|_| malformed("invalid receive queue"))?;
    fields
        .next()
        .ok_or_else(|| malformed("missing send queue"))?
        .parse::<u64>()
        .map_err(|_| malformed("invalid send queue"))?;
    let local = fields
        .next()
        .ok_or_else(|| malformed("missing local endpoint"))?;
    let remote = fields
        .next()
        .ok_or_else(|| malformed("missing remote endpoint"))?;
    let state = fields.next().ok_or_else(|| malformed("missing state"))?;

    Ok(Entry {
        local: parse_netstat_endpoint(local, family)
            .ok_or_else(|| malformed("invalid local endpoint"))?,
        remote: parse_netstat_endpoint(remote, family)
            .ok_or_else(|| malformed("invalid remote endpoint"))?,
        pid: None,
        process: None,
        state: parse_macos_state(state).ok_or_else(|| malformed("invalid state"))?,
        os_metadata: OsMetadata::Macos,
    })
}

fn parse_netstat_endpoint(value: &str, family: Family) -> Option<Endpoint> {
    let (address, port) = value.rsplit_once('.')?;
    let port = if port == "*" {
        0
    } else {
        port.parse::<u16>().ok()?
    };
    match family {
        Family::V4 => {
            let address = if address == "*" {
                Ipv4Addr::UNSPECIFIED
            } else {
                address.parse().ok()?
            };
            Some(Endpoint::new(IpAddr::V4(address), port))
        }
        Family::V6 => {
            let address = address
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(address);
            let (address, zone) = address
                .split_once('%')
                .map_or((address, None), |(address, zone)| (address, Some(zone)));
            let address = if address == "*" {
                Ipv6Addr::UNSPECIFIED
            } else {
                // Only standard, complete IPv6 text is accepted. Never repair
                // Darwin's shortened or truncated presentation.
                if address.contains("...") {
                    return None;
                }
                address.parse().ok()?
            };
            let zone = match zone {
                Some(zone) if valid_zone(zone) => Some(zone.to_owned()),
                Some(_) => return None,
                None => None,
            };
            Some(Endpoint::with_zone(IpAddr::V6(address), port, zone))
        }
    }
}

fn valid_zone(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 64
        && zone
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn parse_macos_state(value: &str) -> Option<State> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    let canonical = value.to_ascii_uppercase().replace('_', "-");
    Some(match canonical.as_str() {
        "CLOSED" => State::Closed,
        "LISTEN" => State::Listen,
        "SYN-SENT" => State::SynSent,
        "SYN-RECEIVED" | "SYN-RCVD" => State::SynReceived,
        "ESTABLISHED" => State::Established,
        "FIN-WAIT-1" | "FIN-WAIT1" => State::FinWait1,
        "FIN-WAIT-2" | "FIN-WAIT2" => State::FinWait2,
        "CLOSE-WAIT" => State::CloseWait,
        "CLOSING" => State::Closing,
        "LAST-ACK" => State::LastAck,
        "TIME-WAIT" => State::TimeWait,
        "DELETE-TCB" => State::DeleteTcb,
        _ => State::Other(canonical),
    })
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemNetstatReader;

#[cfg(target_os = "macos")]
impl NetstatReader for SystemNetstatReader {
    fn read_netstat(&self, context: &SnapshotContext, max_bytes: usize) -> Result<Vec<u8>, Error> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::Duration;

        context.check()?;
        let mut child = Command::new("/usr/sbin/netstat")
            .args(NETSTAT_ARGS)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Error::io("starting /usr/sbin/netstat", error))?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::io(
                "capturing /usr/sbin/netstat output",
                io::Error::other("stdout pipe unavailable"),
            ));
        };
        let read_limit = u64::try_from(max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let reader = thread::spawn(move || {
            let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
            stdout.take(read_limit).read_to_end(&mut bytes)?;
            Ok::<_, io::Error>(bytes)
        });

        let status = loop {
            if let Err(error) = context.check() {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(error);
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(Error::io("waiting for /usr/sbin/netstat", error));
                }
            }
        };
        let bytes = reader
            .join()
            .map_err(|_| {
                Error::io(
                    "reading /usr/sbin/netstat output",
                    io::Error::other("reader thread panicked"),
                )
            })?
            .map_err(|error| Error::io("reading /usr/sbin/netstat output", error))?;
        if bytes.len() > max_bytes {
            return Ok(bytes);
        }
        if !status.success() {
            return Err(Error::NetstatFailed(status.to_string()));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CancellationToken, Limits};

    struct FakeNetstat(Vec<u8>);

    impl NetstatReader for FakeNetstat {
        fn read_netstat(
            &self,
            _context: &SnapshotContext,
            max_bytes: usize,
        ) -> Result<Vec<u8>, Error> {
            Ok(self.0[..self.0.len().min(max_bytes.saturating_add(1))].to_vec())
        }
    }

    fn options() -> SnapshotOptions {
        SnapshotOptions {
            deadline: None,
            limits: Limits::default(),
            associate_processes: true,
        }
    }

    fn context() -> SnapshotContext {
        SnapshotContext::new(None, CancellationToken::new())
    }

    fn snapshot(output: Vec<u8>, options: &SnapshotOptions) -> Result<Table, Error> {
        snapshot_macos_inner(&FakeNetstat(output), options, &context())
    }

    #[test]
    fn parses_macos_numeric_vectors() {
        let output = b"Active Internet connections\nProto Recv-Q Send-Q Local Address Foreign Address (state)\ntcp4 0 0 127.0.0.1.8080 10.0.0.2.443 ESTABLISHED\ntcp6 0 0 fe80::1%lo0.22 *.* LISTEN\ntcp6 0 0 ::ffff:127.0.0.1.9000 ::1.1234 FIN_WAIT_1\ntcp46 0 0 *.3033 *.* LISTEN\nudp4 0 0 *.53 *.*\n";
        let table = snapshot(output.to_vec(), &options()).unwrap();
        assert_eq!(table.entries.len(), 4);
        assert_eq!(table.process_association, ProcessAssociation::Unavailable);
        let established = table
            .entries
            .iter()
            .find(|entry| entry.state == State::Established)
            .unwrap();
        assert_eq!(established.local.to_string(), "127.0.0.1:8080");
        assert_eq!(established.remote.to_string(), "10.0.0.2:443");
        let listening = table
            .listening()
            .find(|entry| entry.local.zone.as_deref() == Some("lo0"))
            .unwrap();
        assert_eq!(listening.local.to_string(), "[fe80::1%lo0]:22");
        assert_eq!(listening.remote.to_string(), "[::]:0");
        let mapped = table
            .entries
            .iter()
            .find(|entry| entry.state == State::FinWait1)
            .unwrap();
        assert_eq!(mapped.local.to_string(), "127.0.0.1:9000");
    }

    #[test]
    fn normalizes_macos_state_aliases() {
        assert_eq!(parse_macos_state("SYN_RCVD"), Some(State::SynReceived));
        assert_eq!(parse_macos_state("TIME_WAIT"), Some(State::TimeWait));
        assert_eq!(parse_macos_state("FIN_WAIT_2"), Some(State::FinWait2));
        assert_eq!(
            parse_macos_state("future_state"),
            Some(State::Other("FUTURE-STATE".into()))
        );
    }

    #[test]
    fn supervised_macos_reader_returns_before_blocking_reader_finishes() {
        struct BlockingNetstat;
        impl NetstatReader for BlockingNetstat {
            fn read_netstat(
                &self,
                _context: &SnapshotContext,
                _max_bytes: usize,
            ) -> Result<Vec<u8>, Error> {
                std::thread::sleep(std::time::Duration::from_millis(200));
                Ok(Vec::new())
            }
        }

        let bounded = SnapshotOptions {
            deadline: Some(std::time::Instant::now() + std::time::Duration::from_millis(25)),
            ..options()
        };
        let started = std::time::Instant::now();
        assert!(matches!(
            snapshot_macos_with_reader(BlockingNetstat, &bounded, &CancellationToken::new()),
            Err(Error::DeadlineExceeded)
        ));
        assert!(started.elapsed() < std::time::Duration::from_millis(150));
    }

    #[test]
    fn rejects_malformed_tcp_line() {
        let error =
            snapshot(b"tcp4 0 bad 127.0.0.1.80 *.* LISTEN\n".to_vec(), &options()).unwrap_err();
        assert!(matches!(error, Error::Malformed { line: 1, .. }));
    }

    #[test]
    fn rejects_large_output_and_too_many_entries() {
        let mut constrained = options();
        constrained.limits.max_netstat_bytes = 16;
        assert!(matches!(
            snapshot(vec![b'x'; 17], &constrained),
            Err(Error::LimitExceeded { .. })
        ));

        constrained.limits.max_netstat_bytes = 4096;
        constrained.limits.max_entries = 1;
        let rows = b"tcp4 0 0 *.80 *.* LISTEN\ntcp4 0 0 *.81 *.* LISTEN\n";
        assert!(matches!(
            snapshot(rows.to_vec(), &constrained),
            Err(Error::LimitExceeded { .. })
        ));
    }

    #[test]
    fn rejects_truncated_ellipsis_and_ambiguous_ipv6() {
        for endpoint in [
            "fd4d:4a27:29aa:4.80",
            "fe80::7563:4198:.80",
            "2001:db8:...:1.80",
        ] {
            let row = format!("tcp6 0 0 {endpoint} *.* LISTEN\n");
            assert!(matches!(
                snapshot(row.into_bytes(), &options()),
                Err(Error::Malformed { .. })
            ));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_command_requests_wide_numeric_output() {
        assert_eq!(NETSTAT_ARGS, ["-W", "-a", "-n", "-p", "tcp"]);
    }

    #[test]
    fn rejects_invalid_zone_and_overlong_line() {
        let invalid_zone = b"tcp6 0 0 fe80::1%bad/zone.80 *.* LISTEN\n";
        assert!(matches!(
            snapshot(invalid_zone.to_vec(), &options()),
            Err(Error::Malformed { .. })
        ));

        let mut constrained = options();
        constrained.limits.max_line_bytes = 8;
        assert!(matches!(
            snapshot(b"tcp4 0 0 *.80 *.* LISTEN\n".to_vec(), &constrained),
            Err(Error::LimitExceeded { .. })
        ));
    }
}
