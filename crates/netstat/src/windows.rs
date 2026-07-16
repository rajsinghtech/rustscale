use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    parse_hex_array, run_supervised, Endpoint, Entry, Error, OsMetadata, ProcessAssociation,
    SnapshotContext, SnapshotOptions, State, Table,
};

const SOURCE: &str = "Windows TCP table";
const PROTOCOL_HEADER: &str = "RUSTSCALE-NETSTAT\t1";

/// Injectable source of bounded, numeric Windows TCP table output.
///
/// The output protocol is intentionally strict and locale-independent. It
/// starts with `RUSTSCALE-NETSTAT<TAB>1`. Each address family must then have
/// an ordered `BEGIN<TAB>family`, zero or more numeric `ROW` records, and an
/// `END-FAMILY<TAB>family<TAB>count` success record. A family can instead end
/// with `ERROR<TAB>family<TAB>numeric-code`, which always fails the snapshot.
/// A final `END` is required after successful IPv4 and IPv6 sections.
///
/// Implementations must return at most `max_bytes + 1` bytes. Both family
/// success records and the final footer are mandatory, so callers never
/// receive a successful partial-family snapshot.
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
    let mut phase = ParsePhase::ExpectBegin(Family::V4);
    let mut family_count = 0_usize;
    for (index, raw_line) in lines {
        context.check()?;
        let line_number = index + 1;
        let line = checked_line(raw_line, line_number, options)?;
        if line.is_empty() {
            return Err(malformed(line_number, "unexpected empty line"));
        }
        if phase == ParsePhase::Complete {
            return Err(malformed(line_number, "output after protocol footer"));
        }

        let fields = checked_fields(line, line_number, options)?;
        match phase {
            ParsePhase::ExpectBegin(family) => {
                if fields.as_slice() != ["BEGIN", family.token()] {
                    return Err(malformed(line_number, family.missing_reason()));
                }
                family_count = 0;
                phase = ParsePhase::Rows(family);
            }
            ParsePhase::Rows(family) => match fields.first().copied() {
                Some("ROW") => {
                    if fields.len() != 10 || fields[1] != family.token() {
                        return Err(malformed(line_number, "invalid family row"));
                    }
                    if entries.len() == options.limits.max_entries {
                        return Err(Error::LimitExceeded {
                            resource: "TCP connection entries",
                            limit: options.limits.max_entries,
                        });
                    }
                    let entry = parse_row(&fields, line_number, family)?;
                    family_count = family_count
                        .checked_add(1)
                        .ok_or_else(|| malformed(line_number, "family row count overflow"))?;
                    entries.push(entry);
                }
                Some("END-FAMILY") => {
                    if fields.len() != 3 || fields[1] != family.token() {
                        return Err(malformed(line_number, "invalid family success footer"));
                    }
                    let reported = parse_usize(fields[2])
                        .ok_or_else(|| malformed(line_number, "invalid family row count"))?;
                    if reported != family_count {
                        return Err(malformed(line_number, "family row count mismatch"));
                    }
                    phase = match family {
                        Family::V4 => ParsePhase::ExpectBegin(Family::V6),
                        Family::V6 => ParsePhase::ExpectFinal,
                    };
                }
                Some("ERROR") => {
                    if fields.len() != 3 || fields[1] != family.token() {
                        return Err(malformed(line_number, "invalid family error record"));
                    }
                    let code = parse_u32(fields[2])
                        .ok_or_else(|| malformed(line_number, "invalid family error code"))?;
                    return Err(Error::WindowsFamilyFailed {
                        family: family.name(),
                        code,
                    });
                }
                _ => return Err(malformed(line_number, "unknown family record")),
            },
            ParsePhase::ExpectFinal => {
                if fields.as_slice() != ["END"] {
                    return Err(malformed(line_number, "missing protocol footer"));
                }
                phase = ParsePhase::Complete;
            }
            ParsePhase::Complete => unreachable!(),
        }
    }
    if phase != ParsePhase::Complete {
        return Err(malformed(
            text.split_terminator('\n').count().saturating_add(1),
            phase.incomplete_reason(),
        ));
    }

    entries.sort_unstable();
    Ok(entries)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParsePhase {
    ExpectBegin(Family),
    Rows(Family),
    ExpectFinal,
    Complete,
}

impl ParsePhase {
    fn incomplete_reason(self) -> &'static str {
        match self {
            Self::ExpectBegin(family) => family.missing_reason(),
            Self::Rows(Family::V4) => "missing IPv4 success footer",
            Self::Rows(Family::V6) => "missing IPv6 success footer",
            Self::ExpectFinal => "missing protocol footer",
            Self::Complete => "output after protocol footer",
        }
    }
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
    const MAX_FIELDS: usize = 10;
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

fn parse_row(fields: &[&str], line_number: usize, family: Family) -> Result<Entry, Error> {
    let local = parse_endpoint(fields[2], fields[3], fields[4], family)
        .ok_or_else(|| malformed(line_number, "invalid local endpoint"))?;
    let remote = parse_endpoint(fields[5], fields[6], fields[7], family)
        .ok_or_else(|| malformed(line_number, "invalid remote endpoint"))?;
    let state_number =
        parse_u32(fields[8]).ok_or_else(|| malformed(line_number, "invalid numeric TCP state"))?;
    let pid = parse_u32(fields[9]).ok_or_else(|| malformed(line_number, "invalid PID"))?;
    Ok(Entry {
        local,
        remote,
        pid: Some(pid),
        process: None,
        state: windows_state(state_number),
        os_metadata: OsMetadata::Windows,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn token(self) -> &'static str {
        match self {
            Self::V4 => "4",
            Self::V6 => "6",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }

    fn missing_reason(self) -> &'static str {
        match self {
            Self::V4 => "missing IPv4 family section",
            Self::V6 => "missing IPv6 family section",
        }
    }
}

fn parse_endpoint(address: &str, scope: &str, port: &str, family: Family) -> Option<Endpoint> {
    let port = parse_u16(port)?;
    let scope = parse_u32(scope)?;
    match family {
        Family::V4 => {
            if scope != 0 {
                return None;
            }
            let address = Ipv4Addr::from(parse_hex_array::<4>(address)?);
            Some(Endpoint::new(IpAddr::V4(address), port))
        }
        Family::V6 => {
            let address = Ipv6Addr::from(parse_hex_array::<16>(address)?);
            let zone = (scope != 0).then(|| scope.to_string());
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

// Deliberately do not derive either path from SystemRoot, PATH, PSModulePath,
// or any other process environment. Standard-root Windows is the documented
// compatibility boundary; spawning fails closed everywhere else.
#[cfg(any(target_os = "windows", test))]
const TRUSTED_POWERSHELL_PATH: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

// Reflection.Emit creates only an in-memory P/Invoke method. Unlike Add-Type,
// this does not invoke a compiler or create a compiler cache/temp artifact.
#[cfg(any(target_os = "windows", test))]
const POWERSHELL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$culture = [System.Globalization.CultureInfo]::InvariantCulture
$output = [System.Console]::Out
$maxNativeTableBytes = [uint32](8 * 1024 * 1024)
$maxRows = [uint32]65536
$errorInvalidSize = [uint32]4294967295
$errorRetryLimit = [uint32]4294967294
$errorMalformedTable = [uint32]4294967293
$errorUnexpected = [uint32]4294967292

$assemblyName = [System.Reflection.AssemblyName]::new('Rustscale.Netstat.Native')
$assembly = [System.AppDomain]::CurrentDomain.DefineDynamicAssembly(
    $assemblyName,
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run
)
$module = $assembly.DefineDynamicModule('Rustscale.Netstat.Native')
$typeAttributes = [System.Reflection.TypeAttributes](
    [System.Reflection.TypeAttributes]::Public -bor
    [System.Reflection.TypeAttributes]::Abstract -bor
    [System.Reflection.TypeAttributes]::Sealed
)
$typeBuilder = $module.DefineType('RustscaleNetstatNative', $typeAttributes)
$methodAttributes = [System.Reflection.MethodAttributes](
    [System.Reflection.MethodAttributes]::Public -bor
    [System.Reflection.MethodAttributes]::Static -bor
    [System.Reflection.MethodAttributes]::PinvokeImpl
)
$parameterTypes = [Type[]]@(
    [IntPtr],
    [uint32].MakeByRefType(),
    [int32],
    [uint32],
    [int32],
    [uint32]
)
$methodBuilder = $typeBuilder.DefinePInvokeMethod(
    'GetExtendedTcpTable',
    'C:\Windows\System32\iphlpapi.dll',
    $methodAttributes,
    [System.Reflection.CallingConventions]::Standard,
    [uint32],
    $parameterTypes,
    [System.Runtime.InteropServices.CallingConvention]::Winapi,
    [System.Runtime.InteropServices.CharSet]::None
)
$methodBuilder.SetImplementationFlags(
    $methodBuilder.GetMethodImplementationFlags() -bor
    [System.Reflection.MethodImplAttributes]::PreserveSig
)
$nativeType = $typeBuilder.CreateType()
$getTcpTable = $nativeType.GetMethod('GetExtendedTcpTable')

function Invoke-TcpTable {
    param(
        [IntPtr]$Buffer,
        [uint32]$Size,
        [uint32]$AddressFamily
    )
    [object[]]$arguments = @(
        $Buffer,
        $Size,
        [int32]1,
        $AddressFamily,
        [int32]5,
        [uint32]0
    )
    [uint32]$code = $script:getTcpTable.Invoke($null, $arguments)
    [object[]]$result = @($code, [uint32]$arguments[1])
    return ,$result
}

function Read-U32 {
    param([IntPtr]$Buffer, [int32]$Offset)
    [int64]$value = [System.Runtime.InteropServices.Marshal]::ReadInt32($Buffer, $Offset)
    if ($value -lt 0) {
        $value += [int64]4294967296
    }
    return [uint32]$value
}

function Read-NetworkPort {
    param([IntPtr]$Buffer, [int32]$Offset)
    [uint32]$high = [System.Runtime.InteropServices.Marshal]::ReadByte($Buffer, $Offset)
    [uint32]$low = [System.Runtime.InteropServices.Marshal]::ReadByte($Buffer, $Offset + 1)
    return [uint16](($high * 256) + $low)
}

function Read-Hex {
    param([IntPtr]$Buffer, [int32]$Offset, [int32]$Length)
    [byte[]]$bytes = [byte[]]::new($Length)
    [System.Runtime.InteropServices.Marshal]::Copy(
        [IntPtr]::Add($Buffer, $Offset),
        $bytes,
        0,
        $Length
    )
    return [System.BitConverter]::ToString($bytes).Replace('-', '')
}

function Write-FamilyError {
    param([uint32]$Family, [uint32]$Code)
    [string[]]$fields = @(
        'ERROR',
        $Family.ToString($script:culture),
        $Code.ToString($script:culture)
    )
    $script:output.WriteLine([string]::Join("`t", $fields))
}

function Write-Family {
    param(
        [uint32]$Family,
        [uint32]$AddressFamily,
        [uint32]$RowSize
    )
    $script:output.WriteLine(
        [string]::Join("`t", [string[]]@('BEGIN', $Family.ToString($script:culture)))
    )

    try {
        [object[]]$probe = Invoke-TcpTable ([IntPtr]::Zero) 0 $AddressFamily
    } catch {
        Write-FamilyError $Family $script:errorUnexpected
        return $false
    }
    [uint32]$code = $probe[0]
    [uint32]$nextSize = $probe[1]
    if ($code -ne 122) {
        Write-FamilyError $Family $code
        return $false
    }

    for ([int32]$attempt = 0; $attempt -lt 3; $attempt++) {
        if ($nextSize -lt 4 -or $nextSize -gt $script:maxNativeTableBytes) {
            Write-FamilyError $Family $script:errorInvalidSize
            return $false
        }
        [uint32]$capacity = $nextSize
        [IntPtr]$buffer = [IntPtr]::Zero
        try {
            $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int32]$capacity)
            [object[]]$result = Invoke-TcpTable $buffer $capacity $AddressFamily
            $code = $result[0]
            [uint32]$used = $result[1]
            if ($code -eq 122) {
                $nextSize = $used
                continue
            }
            if ($code -ne 0) {
                Write-FamilyError $Family $code
                return $false
            }
            if ($used -lt 4 -or $used -gt $capacity) {
                Write-FamilyError $Family $script:errorInvalidSize
                return $false
            }

            [uint32]$rowCount = Read-U32 $buffer 0
            [uint64]$required = [uint64]4 + ([uint64]$rowCount * [uint64]$RowSize)
            if ($rowCount -gt $script:maxRows -or $required -gt [uint64]$used) {
                Write-FamilyError $Family $script:errorMalformedTable
                return $false
            }

            for ([uint32]$index = 0; $index -lt $rowCount; $index++) {
                [int32]$row = [int32](4 + ([uint64]$index * [uint64]$RowSize))
                if ($Family -eq 4) {
                    [string]$localAddress = Read-Hex $buffer ($row + 4) 4
                    [uint32]$localScope = 0
                    [uint16]$localPort = Read-NetworkPort $buffer ($row + 8)
                    [string]$remoteAddress = Read-Hex $buffer ($row + 12) 4
                    [uint32]$remoteScope = 0
                    [uint16]$remotePort = Read-NetworkPort $buffer ($row + 16)
                    [uint32]$state = Read-U32 $buffer $row
                    [uint32]$pid = Read-U32 $buffer ($row + 20)
                } else {
                    [string]$localAddress = Read-Hex $buffer $row 16
                    [uint32]$localScope = Read-U32 $buffer ($row + 16)
                    [uint16]$localPort = Read-NetworkPort $buffer ($row + 20)
                    [string]$remoteAddress = Read-Hex $buffer ($row + 24) 16
                    [uint32]$remoteScope = Read-U32 $buffer ($row + 40)
                    [uint16]$remotePort = Read-NetworkPort $buffer ($row + 44)
                    [uint32]$state = Read-U32 $buffer ($row + 48)
                    [uint32]$pid = Read-U32 $buffer ($row + 52)
                }
                [string[]]$fields = @(
                    'ROW',
                    $Family.ToString($script:culture),
                    $localAddress,
                    $localScope.ToString($script:culture),
                    $localPort.ToString($script:culture),
                    $remoteAddress,
                    $remoteScope.ToString($script:culture),
                    $remotePort.ToString($script:culture),
                    $state.ToString($script:culture),
                    $pid.ToString($script:culture)
                )
                $script:output.WriteLine([string]::Join("`t", $fields))
            }
            [string[]]$footer = @(
                'END-FAMILY',
                $Family.ToString($script:culture),
                $rowCount.ToString($script:culture)
            )
            $script:output.WriteLine([string]::Join("`t", $footer))
            return $true
        } catch {
            Write-FamilyError $Family $script:errorUnexpected
            return $false
        } finally {
            if ($buffer -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
            }
        }
    }

    Write-FamilyError $Family $script:errorRetryLimit
    return $false
}

$output.WriteLine("RUSTSCALE-NETSTAT`t1")
if (-not (Write-Family 4 2 24)) {
    exit 0
}
if (-not (Write-Family 6 23 56)) {
    exit 0
}
$output.WriteLine('END')
"#;

#[cfg(any(target_os = "windows", test))]
fn windows_command(encoded_script: &str) -> std::process::Command {
    let mut command = std::process::Command::new(TRUSTED_POWERSHELL_PATH);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded_script,
        ])
        // Do not inherit attacker-selected executable or module lookup paths.
        // PowerShell still receives its fixed standard root for CLR internals.
        .env("SystemRoot", r"C:\Windows")
        .env("WINDIR", r"C:\Windows")
        .env_remove("PATH")
        .env_remove("PSModulePath");
    command
}

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
        use std::process::Stdio;
        use std::thread;
        use std::time::Duration;

        use base64::Engine as _;

        context.check()?;
        let encoded_script = base64::engine::general_purpose::STANDARD.encode(
            POWERSHELL_SCRIPT
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        let mut child = windows_command(&encoded_script)
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

    const FIXTURE: &str = "RUSTSCALE-NETSTAT\t1\nBEGIN\t4\nROW\t4\t7F000001\t0\t8080\t0A000002\t0\t443\t5\t42\nEND-FAMILY\t4\t1\nBEGIN\t6\nROW\t6\tFE800000000000000000000000000001\t12\t22\t00000000000000000000000000000000\t0\t0\t2\t9001\nEND-FAMILY\t6\t1\nEND\n";
    const EMPTY_FIXTURE: &str =
        "RUSTSCALE-NETSTAT\t1\nBEGIN\t4\nEND-FAMILY\t4\t0\nBEGIN\t6\nEND-FAMILY\t6\t0\nEND\n";

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
        let suffix = "END-FAMILY\t4\t1\nBEGIN\t6\nEND-FAMILY\t6\t0\nEND\n";
        for row in [
            "ROW\t4\t7F000001\t0\t80\t00000000\t0\t0\tLISTEN\t1\n",
            "ROW\t6\t7F000001\t0\t80\t00000000\t0\t0\t2\t1\n",
            "ROW\t4\tnot-hex!\t0\t80\t00000000\t0\t0\t2\t1\n",
            "ROW\t4\t7F000001\t0\t080\t00000000\t0\t0\t2\t1\n",
            "ROW\t4\t7F000001\t0\t80\t00000000\t0\t0\t2\t1\textra\n",
        ] {
            let output = format!("RUSTSCALE-NETSTAT\t1\nBEGIN\t4\n{row}{suffix}");
            assert!(matches!(
                snapshot(&output, &options()),
                Err(Error::Malformed { .. } | Error::LimitExceeded { .. })
            ));
        }
    }

    #[test]
    fn rejects_truncation_and_all_partial_family_forms() {
        for output in [
            "RUSTSCALE-NETSTAT\t1\n",
            "RUSTSCALE-NETSTAT\t1\nBEGIN\t4\nROW\t4\t7F000001\t0\t80\t00000000\t0\t0\t2\t1\n",
            // A successful IPv4 section never permits omission of IPv6.
            "RUSTSCALE-NETSTAT\t1\nBEGIN\t4\nEND-FAMILY\t4\t0\nEND\n",
            "RUSTSCALE-NETSTAT\t1\nBEGIN\t4\nEND-FAMILY\t4\t0\nBEGIN\t6\nEND-FAMILY\t6\t0\n",
            "RUSTSCALE-NETSTAT\t1\nBEGIN\t4\nEND-FAMILY\t4\t0\nBEGIN\t6\nEND-FAMILY\t6\t1\nEND\n",
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
            Ok(EMPTY_FIXTURE.as_bytes().to_vec())
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

    #[test]
    fn family_error_is_explicit_and_fatal() {
        let output = "RUSTSCALE-NETSTAT\t1\nBEGIN\t4\nERROR\t4\t5\n";
        assert!(matches!(
            snapshot(output, &options()),
            Err(Error::WindowsFamilyFailed {
                family: "IPv4",
                code: 5
            })
        ));
    }

    #[test]
    fn system_transport_ignores_systemroot_path_and_module_resolution() {
        assert_eq!(
            TRUSTED_POWERSHELL_PATH,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
        let command = windows_command("fixed-script");
        assert_eq!(
            command.get_program(),
            std::ffi::OsStr::new(TRUSTED_POWERSHELL_PATH)
        );
        let environment: std::collections::HashMap<_, _> = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().to_ascii_uppercase(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            environment.get("SYSTEMROOT"),
            Some(&Some(r"C:\Windows".into()))
        );
        assert_eq!(environment.get("WINDIR"), Some(&Some(r"C:\Windows".into())));
        assert_eq!(environment.get("PATH"), Some(&None));
        assert_eq!(environment.get("PSMODULEPATH"), Some(&None));
        assert!(POWERSHELL_SCRIPT.contains("C:\\Windows\\System32\\iphlpapi.dll"));
        assert!(POWERSHELL_SCRIPT.contains("GetExtendedTcpTable"));
        assert!(POWERSHELL_SCRIPT.contains("Write-Family 4 2 24"));
        assert!(POWERSHELL_SCRIPT.contains("Write-Family 6 23 56"));
        assert!(POWERSHELL_SCRIPT.contains("BEGIN"));
        assert!(POWERSHELL_SCRIPT.contains("END-FAMILY"));
        assert!(!POWERSHELL_SCRIPT.contains("$env:"));
        assert!(!POWERSHELL_SCRIPT.contains("Get-NetTCPConnection"));
        assert!(!POWERSHELL_SCRIPT.contains("Import-Module"));
        assert!(!POWERSHELL_SCRIPT.contains("Add-Type"));
        assert!(!POWERSHELL_SCRIPT.contains("New-Object"));
        assert!(!POWERSHELL_SCRIPT.contains("cmd.exe"));
    }
}
