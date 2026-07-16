use std::net::{IpAddr, Ipv6Addr};

use crate::{
    run_supervised, Endpoint, Entry, Error, OsMetadata, ProcessAssociation, SnapshotContext,
    SnapshotOptions, State, Table,
};

const SOURCE: &str = "Windows TCP table";
const PROTOCOL_HEADER: &str = "RUSTSCALE-NETSTAT\t1";

/// Injectable source of bounded, numeric Windows TCP table output.
///
/// The output protocol is intentionally strict and locale-independent. It
/// starts with `RUSTSCALE-NETSTAT<TAB>1`, contains zero or more rows of the
/// form `ROW<TAB>family<TAB>local-address<TAB>local-port<TAB>remote-address`
/// followed by `<TAB>remote-port<TAB>numeric-state<TAB>pid`, and ends with
/// `END<TAB>4<TAB>ipv4-count<TAB>6<TAB>ipv6-count`.
///
/// Implementations must return at most `max_bytes + 1` bytes. A complete
/// footer for both address families is required, so callers never receive a
/// successful partial-family snapshot.
pub trait WindowsTcpTableReader: Send + Sync {
    fn read_tcp_table(&self, context: &SnapshotContext, max_bytes: usize)
        -> Result<Vec<u8>, Error>;
}

/// Build a supervised Windows TCP table using an injected output reader.
pub fn snapshot_windows_with_reader<R: WindowsTcpTableReader + 'static>(
    reader: R,
    options: &SnapshotOptions,
    cancellation: &crate::CancellationToken,
) -> Result<Table, Error> {
    let options_for_worker = options.clone();
    run_supervised(options, cancellation, move |context| {
        snapshot_windows_inner(&reader, &options_for_worker, &context)
    })
}

fn snapshot_windows_inner<R: WindowsTcpTableReader>(
    reader: &R,
    options: &SnapshotOptions,
    context: &SnapshotContext,
) -> Result<Table, Error> {
    context.check()?;
    let bytes = reader.read_tcp_table(context, options.limits.max_netstat_bytes)?;
    context.check()?;
    if bytes.len() > options.limits.max_netstat_bytes {
        return Err(Error::LimitExceeded {
            resource: "Windows TCP table output bytes",
            limit: options.limits.max_netstat_bytes,
        });
    }
    let mut entries = parse_windows_tcp_table(&bytes, options, context)?;
    if !options.associate_processes {
        for entry in &mut entries {
            entry.pid = None;
        }
    }
    Ok(Table {
        entries,
        process_association: if options.associate_processes {
            ProcessAssociation::Complete
        } else {
            ProcessAssociation::NotRequested
        },
    })
}

/// Parse the bounded, numeric protocol emitted by the Windows system reader.
pub fn parse_windows_tcp_table(
    bytes: &[u8],
    options: &SnapshotOptions,
    context: &SnapshotContext,
) -> Result<Vec<Entry>, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8 {
        source_name: SOURCE,
    })?;
    let mut lines = text.split_terminator('\n').enumerate();
    let Some((header_index, raw_header)) = lines.next() else {
        return Err(malformed(1, "missing protocol header"));
    };
    debug_assert_eq!(header_index, 0);
    let header = checked_line(raw_header, 1, options)?;
    if header != PROTOCOL_HEADER {
        return Err(malformed(1, "invalid protocol header"));
    }

    let mut entries = Vec::new();
    let mut family_counts = [0_usize; 2];
    let mut saw_footer = false;
    for (index, raw_line) in lines {
        context.check()?;
        let line_number = index + 1;
        let line = checked_line(raw_line, line_number, options)?;
        if line.is_empty() {
            return Err(malformed(line_number, "unexpected empty line"));
        }
        if saw_footer {
            return Err(malformed(line_number, "output after protocol footer"));
        }

        let fields = checked_fields(line, line_number, options)?;
        match fields.first().copied() {
            Some("ROW") => {
                if fields.len() != 8 {
                    return Err(malformed(line_number, "invalid row field count"));
                }
                if entries.len() == options.limits.max_entries {
                    return Err(Error::LimitExceeded {
                        resource: "TCP connection entries",
                        limit: options.limits.max_entries,
                    });
                }
                let (entry, family_index) = parse_row(&fields, line_number)?;
                family_counts[family_index] = family_counts[family_index]
                    .checked_add(1)
                    .ok_or_else(|| malformed(line_number, "family row count overflow"))?;
                entries.push(entry);
            }
            Some("END") => {
                if fields.len() != 5 || fields[1] != "4" || fields[3] != "6" {
                    return Err(malformed(line_number, "invalid protocol footer"));
                }
                let ipv4_count = parse_usize(fields[2])
                    .ok_or_else(|| malformed(line_number, "invalid IPv4 row count"))?;
                let ipv6_count = parse_usize(fields[4])
                    .ok_or_else(|| malformed(line_number, "invalid IPv6 row count"))?;
                if [ipv4_count, ipv6_count] != family_counts {
                    return Err(malformed(line_number, "family row count mismatch"));
                }
                saw_footer = true;
            }
            _ => return Err(malformed(line_number, "unknown protocol record")),
        }
    }
    if !saw_footer {
        return Err(malformed(
            text.split_terminator('\n').count().saturating_add(1),
            "missing protocol footer",
        ));
    }

    entries.sort_unstable();
    Ok(entries)
}

fn checked_line<'a>(
    raw_line: &'a str,
    _line_number: usize,
    options: &SnapshotOptions,
) -> Result<&'a str, Error> {
    let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
    if line.len() > options.limits.max_line_bytes {
        return Err(Error::LimitExceeded {
            resource: "Windows TCP table line bytes",
            limit: options.limits.max_line_bytes,
        });
    }
    Ok(line)
}

fn checked_fields<'a>(
    line: &'a str,
    _line_number: usize,
    options: &SnapshotOptions,
) -> Result<Vec<&'a str>, Error> {
    const MAX_FIELDS: usize = 8;
    let fields: Vec<_> = line.split('\t').take(MAX_FIELDS + 1).collect();
    if fields.len() > MAX_FIELDS {
        return Err(Error::LimitExceeded {
            resource: "Windows TCP table fields per line",
            limit: MAX_FIELDS,
        });
    }
    if fields
        .iter()
        .any(|field| field.len() > options.limits.max_windows_token_bytes)
    {
        return Err(Error::LimitExceeded {
            resource: "Windows TCP table token bytes",
            limit: options.limits.max_windows_token_bytes,
        });
    }
    Ok(fields)
}

fn parse_row(fields: &[&str], line_number: usize) -> Result<(Entry, usize), Error> {
    let (family, family_index) = match fields[1] {
        "4" => (Family::V4, 0),
        "6" => (Family::V6, 1),
        _ => return Err(malformed(line_number, "invalid address family")),
    };
    let local = parse_endpoint(fields[2], fields[3], family)
        .ok_or_else(|| malformed(line_number, "invalid local endpoint"))?;
    let remote = parse_endpoint(fields[4], fields[5], family)
        .ok_or_else(|| malformed(line_number, "invalid remote endpoint"))?;
    let state_number =
        parse_u32(fields[6]).ok_or_else(|| malformed(line_number, "invalid numeric TCP state"))?;
    let pid = parse_u32(fields[7]).ok_or_else(|| malformed(line_number, "invalid PID"))?;
    Ok((
        Entry {
            local,
            remote,
            pid: Some(pid),
            process: None,
            state: windows_state(state_number),
            os_metadata: OsMetadata::Windows,
        },
        family_index,
    ))
}

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

fn parse_endpoint(address: &str, port: &str, family: Family) -> Option<Endpoint> {
    let port = parse_u16(port)?;
    match family {
        Family::V4 => Some(Endpoint::new(IpAddr::V4(address.parse().ok()?), port)),
        Family::V6 => {
            let (address, zone) = match address.rsplit_once('%') {
                Some((address, zone)) => {
                    if zone.is_empty()
                        || zone.len() > 10
                        || !zone.bytes().all(|byte| byte.is_ascii_digit())
                        || parse_u32(zone)? == 0
                    {
                        return None;
                    }
                    (address, Some(zone.to_owned()))
                }
                None => (address, None),
            };
            let address: Ipv6Addr = address.parse().ok()?;
            Some(Endpoint::with_zone(IpAddr::V6(address), port, zone))
        }
    }
}

fn parse_u16(value: &str) -> Option<u16> {
    if !decimal_token(value) {
        return None;
    }
    value.parse().ok()
}

fn parse_u32(value: &str) -> Option<u32> {
    if !decimal_token(value) {
        return None;
    }
    value.parse().ok()
}

fn parse_usize(value: &str) -> Option<usize> {
    if !decimal_token(value) {
        return None;
    }
    value.parse().ok()
}

fn decimal_token(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn windows_state(value: u32) -> State {
    match value {
        1 => State::Closed,
        2 => State::Listen,
        3 => State::SynSent,
        4 => State::SynReceived,
        5 => State::Established,
        6 => State::FinWait1,
        7 => State::FinWait2,
        8 => State::CloseWait,
        9 => State::Closing,
        10 => State::LastAck,
        11 => State::TimeWait,
        12 => State::DeleteTcb,
        other => State::Unknown(other),
    }
}

fn malformed(line: usize, reason: &'static str) -> Error {
    Error::Malformed {
        source_name: SOURCE,
        line,
        reason,
    }
}

#[cfg(target_os = "windows")]
const POWERSHELL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$culture = [System.Globalization.CultureInfo]::InvariantCulture
$output = [System.Console]::Out
$ipv4Count = [uint64]0
$ipv6Count = [uint64]0
$output.WriteLine("RUSTSCALE-NETSTAT`t1")
$modulePath = [System.IO.Path]::Combine(
    $env:SystemRoot,
    'System32\WindowsPowerShell\v1.0\Modules\NetTCPIP\NetTCPIP.psd1'
)
Microsoft.PowerShell.Core\Import-Module -Name $modulePath -ErrorAction Stop
NetTCPIP\Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
    $local = [System.Net.IPAddress]::Parse([string]$_.LocalAddress)
    $remote = [System.Net.IPAddress]::Parse([string]$_.RemoteAddress)
    if ($local.AddressFamily -ne $remote.AddressFamily) {
        throw 'mixed address families'
    }
    if ($local.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $family = 4
        $ipv4Count++
    } elseif ($local.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        $family = 6
        $ipv6Count++
    } else {
        throw 'unsupported address family'
    }
    $fields = [string[]]@(
        'ROW',
        $family.ToString($culture),
        $local.ToString(),
        ([uint32]$_.LocalPort).ToString($culture),
        $remote.ToString(),
        ([uint32]$_.RemotePort).ToString($culture),
        ([uint32]$_.State).ToString($culture),
        ([uint32]$_.OwningProcess).ToString($culture)
    )
    $output.WriteLine([string]::Join("`t", $fields))
}
$footer = [string[]]@(
    'END',
    '4',
    $ipv4Count.ToString($culture),
    '6',
    $ipv6Count.ToString($culture)
)
$output.WriteLine([string]::Join("`t", $footer))
"#;

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemWindowsTcpTableReader;

#[cfg(target_os = "windows")]
impl WindowsTcpTableReader for SystemWindowsTcpTableReader {
    fn read_tcp_table(
        &self,
        context: &SnapshotContext,
        max_bytes: usize,
    ) -> Result<Vec<u8>, Error> {
        use std::io::{self, Read};
        use std::path::{Component, Path, PathBuf, Prefix};
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::Duration;

        use base64::Engine as _;

        context.check()?;
        let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
            Error::io(
                "locating Windows PowerShell",
                io::Error::new(io::ErrorKind::NotFound, "SystemRoot is not set"),
            )
        })?;
        let system_root = Path::new(&system_root);
        let mut components = system_root.components();
        let trusted_drive_path = matches!(
            components.next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        ) && matches!(components.next(), Some(Component::RootDir))
            && components.all(|component| matches!(component, Component::Normal(_)));
        if !trusted_drive_path {
            return Err(Error::io(
                "locating Windows PowerShell",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SystemRoot is not an absolute local drive path",
                ),
            ));
        }
        let powershell: PathBuf = system_root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let encoded_script = base64::engine::general_purpose::STANDARD.encode(
            POWERSHELL_SCRIPT
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        let mut child = Command::new(&powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encoded_script,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Error::io("starting Windows TCP table command", error))?;
        let Some(stdout) = child.stdout.take() else {
            terminate_and_reap(&mut child);
            return Err(Error::io(
                "capturing Windows TCP table output",
                io::Error::other("stdout pipe unavailable"),
            ));
        };
        let read_limit = u64::try_from(max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let reader = match thread::Builder::new()
            .name("rustscale-netstat-windows-output".into())
            .spawn(move || {
                let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
                stdout.take(read_limit).read_to_end(&mut bytes)?;
                Ok::<_, io::Error>(bytes)
            }) {
            Ok(reader) => reader,
            Err(error) => {
                terminate_and_reap(&mut child);
                return Err(Error::io("starting Windows TCP table output reader", error));
            }
        };

        let status = loop {
            if let Err(error) = context.check() {
                terminate_and_reap(&mut child);
                let _ = reader.join();
                return Err(error);
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(error) => {
                    terminate_and_reap(&mut child);
                    let _ = reader.join();
                    return Err(Error::io("waiting for Windows TCP table command", error));
                }
            }
        };
        let bytes = reader
            .join()
            .map_err(|_| {
                Error::io(
                    "reading Windows TCP table output",
                    io::Error::other("reader thread panicked"),
                )
            })?
            .map_err(|error| Error::io("reading Windows TCP table output", error))?;
        if bytes.len() > max_bytes {
            return Ok(bytes);
        }
        if !status.success() {
            return Err(Error::WindowsCommandFailed(status.to_string()));
        }
        Ok(bytes)
    }
}

#[cfg(target_os = "windows")]
fn terminate_and_reap(child: &mut std::process::Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::{run_supervised_with_limiter, CancellationToken, Limits, WorkerLimiter};

    const FIXTURE: &str = "RUSTSCALE-NETSTAT\t1\nROW\t4\t127.0.0.1\t8080\t10.0.0.2\t443\t5\t42\nROW\t6\tfe80::1%12\t22\t::\t0\t2\t9001\nEND\t4\t1\t6\t1\n";

    struct FixtureReader(Vec<u8>);

    impl WindowsTcpTableReader for FixtureReader {
        fn read_tcp_table(
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

    fn snapshot(output: &str, options: &SnapshotOptions) -> Result<Table, Error> {
        snapshot_windows_inner(
            &FixtureReader(output.as_bytes().to_vec()),
            options,
            &context(),
        )
    }

    #[test]
    fn parses_ipv4_ipv6_pid_and_numeric_states() {
        let table = snapshot(FIXTURE, &options()).unwrap();
        assert_eq!(table.entries.len(), 2);
        assert_eq!(table.process_association, ProcessAssociation::Complete);
        let established = table
            .entries
            .iter()
            .find(|entry| entry.state == State::Established)
            .unwrap();
        assert_eq!(established.local.to_string(), "127.0.0.1:8080");
        assert_eq!(established.remote.to_string(), "10.0.0.2:443");
        assert_eq!(established.pid, Some(42));
        assert_eq!(established.os_metadata, OsMetadata::Windows);
        let listening = table.listening().next().unwrap();
        assert_eq!(listening.local.to_string(), "[fe80::1%12]:22");
        assert_eq!(listening.remote.to_string(), "[::]:0");
        assert_eq!(listening.pid, Some(9001));
    }

    #[test]
    fn maps_every_windows_state_and_preserves_unknown_values() {
        let expected = [
            State::Closed,
            State::Listen,
            State::SynSent,
            State::SynReceived,
            State::Established,
            State::FinWait1,
            State::FinWait2,
            State::CloseWait,
            State::Closing,
            State::LastAck,
            State::TimeWait,
            State::DeleteTcb,
        ];
        for (index, expected) in expected.into_iter().enumerate() {
            assert_eq!(windows_state(u32::try_from(index + 1).unwrap()), expected);
        }
        assert_eq!(windows_state(99), State::Unknown(99));
    }

    #[test]
    fn process_metadata_can_be_disabled() {
        let mut unassociated = options();
        unassociated.associate_processes = false;
        let table = snapshot(FIXTURE, &unassociated).unwrap();
        assert_eq!(table.process_association, ProcessAssociation::NotRequested);
        assert!(table.entries.iter().all(|entry| entry.pid.is_none()));
    }

    #[test]
    fn rejects_malformed_rows_and_ambiguous_tokens() {
        for output in [
            "RUSTSCALE-NETSTAT\t1\nROW\t4\t127.0.0.1\t80\t0.0.0.0\t0\tLISTEN\t1\nEND\t4\t1\t6\t0\n",
            "RUSTSCALE-NETSTAT\t1\nROW\t4\t127.0.0.1\t80\t::\t0\t2\t1\nEND\t4\t1\t6\t0\n",
            "RUSTSCALE-NETSTAT\t1\nROW\t6\tfe80::1%eth0\t80\t::\t0\t2\t1\nEND\t4\t0\t6\t1\n",
            "RUSTSCALE-NETSTAT\t1\nROW\t4\t127.0.0.1\t080\t0.0.0.0\t0\t2\t1\nEND\t4\t1\t6\t0\n",
            "RUSTSCALE-NETSTAT\t1\nROW\t4\t127.0.0.1\t80\t0.0.0.0\t0\t2\t1\textra\nEND\t4\t1\t6\t0\n",
        ] {
            assert!(matches!(
                snapshot(output, &options()),
                Err(Error::Malformed { .. } | Error::LimitExceeded { .. })
            ));
        }
    }

    #[test]
    fn rejects_truncation_and_all_partial_family_forms() {
        for output in [
            "RUSTSCALE-NETSTAT\t1\nROW\t4\t127.0.0.1\t80\t0.0.0.0\t0\t2\t1\n",
            "RUSTSCALE-NETSTAT\t1\nROW\t4\t127.0.0.1\t80\t0.0.0.0\t0\t2\t1\nEND\t4\t1\t6\t1\n",
            "RUSTSCALE-NETSTAT\t1\nEND\t4\t0\t6\n",
            "RUSTSCALE-NETSTAT\t1\nEND\t4\t0\t6\t0\nROW\t6\t::1\t80\t::\t0\t2\t1\n",
            "RUSTSCALE-NETSTAT\t1\nRUSTSCALE-NETSTAT\t1\nEND\t4\t0\t6\t0\n",
        ] {
            assert!(matches!(
                snapshot(output, &options()),
                Err(Error::Malformed { .. })
            ));
        }
    }

    #[test]
    fn enforces_output_line_token_and_entry_limits() {
        let mut constrained = options();
        constrained.limits.max_netstat_bytes = 16;
        assert!(matches!(
            snapshot(FIXTURE, &constrained),
            Err(Error::LimitExceeded { .. })
        ));

        constrained.limits.max_netstat_bytes = 4096;
        constrained.limits.max_line_bytes = 20;
        assert!(matches!(
            snapshot(FIXTURE, &constrained),
            Err(Error::LimitExceeded { .. })
        ));

        constrained.limits.max_line_bytes = 4096;
        constrained.limits.max_windows_token_bytes = 3;
        assert!(matches!(
            snapshot(FIXTURE, &constrained),
            Err(Error::LimitExceeded { .. })
        ));

        constrained.limits.max_windows_token_bytes = 256;
        constrained.limits.max_entries = 1;
        assert!(matches!(
            snapshot(FIXTURE, &constrained),
            Err(Error::LimitExceeded { .. })
        ));
    }

    struct BlockingReader {
        release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
    }

    impl WindowsTcpTableReader for BlockingReader {
        fn read_tcp_table(
            &self,
            _context: &SnapshotContext,
            _max_bytes: usize,
        ) -> Result<Vec<u8>, Error> {
            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2));
            Ok(b"RUSTSCALE-NETSTAT\t1\nEND\t4\t0\t6\t0\n".to_vec())
        }
    }

    #[test]
    fn deadline_cancellation_and_worker_bound_are_preserved() {
        let limiter = Arc::new(WorkerLimiter::new(1));
        let (release_sender, blocked) = std::sync::mpsc::channel();
        let release = Arc::new(Mutex::new(blocked));
        let bounded = SnapshotOptions {
            deadline: Some(Instant::now() + Duration::from_millis(30)),
            ..options()
        };
        let worker_options = bounded.clone();
        let first_release = release.clone();
        let started = Instant::now();
        let result = run_supervised_with_limiter(
            &bounded,
            &CancellationToken::new(),
            limiter.clone(),
            move |context| {
                snapshot_windows_inner(
                    &BlockingReader {
                        release: first_release,
                    },
                    &worker_options,
                    &context,
                )
            },
        );
        assert!(matches!(result, Err(Error::DeadlineExceeded)));
        assert!(started.elapsed() < Duration::from_millis(200));

        let second = SnapshotOptions {
            deadline: Some(Instant::now() + Duration::from_millis(100)),
            ..options()
        };
        assert!(matches!(
            run_supervised_with_limiter(
                &second,
                &CancellationToken::new(),
                limiter.clone(),
                |_| Ok(())
            ),
            Err(Error::WorkerCapacity)
        ));
        release_sender.send(()).unwrap();
        let cleanup_deadline = Instant::now() + Duration::from_secs(1);
        while limiter.active.load(std::sync::atomic::Ordering::Acquire) != 0
            && Instant::now() < cleanup_deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(limiter.active.load(std::sync::atomic::Ordering::Acquire), 0);

        struct CancellingReader(CancellationToken);
        impl WindowsTcpTableReader for CancellingReader {
            fn read_tcp_table(
                &self,
                _context: &SnapshotContext,
                _max_bytes: usize,
            ) -> Result<Vec<u8>, Error> {
                self.0.cancel();
                Ok(FIXTURE.as_bytes().to_vec())
            }
        }
        let cancellation = CancellationToken::new();
        assert!(matches!(
            snapshot_windows_with_reader(
                CancellingReader(cancellation.clone()),
                &options(),
                &cancellation
            ),
            Err(Error::Cancelled)
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn system_transport_is_fixed_numeric_and_has_no_intermediary_shell() {
        assert!(POWERSHELL_SCRIPT.contains("Get-NetTCPConnection"));
        assert!(POWERSHELL_SCRIPT.contains("InvariantCulture"));
        assert!(POWERSHELL_SCRIPT.contains("([uint32]$_.State)"));
        assert!(!POWERSHELL_SCRIPT.contains("cmd.exe"));
    }
}
