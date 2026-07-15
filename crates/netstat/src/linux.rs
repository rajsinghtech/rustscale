use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crate::{
    parse_hex_array, path_for_proc, read_file_limited, run_supervised, sorted_directory, Endpoint,
    Entry, Error, OsMetadata, ProcessAssociation, SnapshotContext, SnapshotOptions, State, Table,
};

const PROC_ROOT: &str = "/proc";
const TCP4_PATH: &str = "/proc/net/tcp";
const TCP6_PATH: &str = "/proc/net/tcp6";

/// A bounded directory listing returned by an injectable Linux reader.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Directory {
    pub names: Vec<OsString>,
    pub truncated: bool,
}

/// Injectable access to Linux procfs.
///
/// Implementations must return at most `limit + 1` file bytes and at most
/// `limit` directory names. `truncated` must be set when more names existed.
/// `read_link` reads the symlink itself and must not open its target.
pub trait LinuxReader: Send + Sync {
    fn read_file(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>>;
    fn read_directory(&self, path: &Path, limit: usize) -> io::Result<Directory>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
}

/// Host procfs reader. All reads and directory listings are bounded.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLinuxReader;

impl LinuxReader for SystemLinuxReader {
    fn read_file(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
        read_file_limited(path, limit)
    }

    fn read_directory(&self, path: &Path, limit: usize) -> io::Result<Directory> {
        sorted_directory(path, limit)
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::read_link(path)
    }
}

/// Byte order used for each kernel-rendered `/proc/net` address lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcEndian {
    Little,
    Big,
}

/// Injectable decoder for Linux `/proc/net/tcp{,6}` address vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcAddressDecoder {
    endian: ProcEndian,
}

impl ProcAddressDecoder {
    pub const fn new(endian: ProcEndian) -> Self {
        Self { endian }
    }

    pub const fn native() -> Self {
        #[cfg(target_endian = "little")]
        {
            Self::new(ProcEndian::Little)
        }
        #[cfg(target_endian = "big")]
        {
            Self::new(ProcEndian::Big)
        }
    }

    fn decode_v4(self, value: &str) -> Option<Ipv4Addr> {
        let mut bytes = parse_hex_array::<4>(value)?;
        if self.endian == ProcEndian::Little {
            bytes.reverse();
        }
        Some(Ipv4Addr::from(bytes))
    }

    fn decode_v6(self, value: &str) -> Option<Ipv6Addr> {
        let mut bytes = parse_hex_array::<16>(value)?;
        if self.endian == ProcEndian::Little {
            for lane in bytes.chunks_exact_mut(4) {
                lane.reverse();
            }
        }
        Some(Ipv6Addr::from(bytes))
    }
}

/// Build a supervised Linux TCP table using an injected procfs reader.
pub fn snapshot_linux_with_reader<R: LinuxReader + 'static>(
    reader: R,
    options: &SnapshotOptions,
    cancellation: &crate::CancellationToken,
) -> Result<Table, Error> {
    snapshot_linux_with_reader_and_decoder(
        reader,
        ProcAddressDecoder::native(),
        options,
        cancellation,
    )
}

/// Build a supervised Linux TCP table using injected procfs and address readers.
pub fn snapshot_linux_with_reader_and_decoder<R: LinuxReader + 'static>(
    reader: R,
    decoder: ProcAddressDecoder,
    options: &SnapshotOptions,
    cancellation: &crate::CancellationToken,
) -> Result<Table, Error> {
    let options_for_worker = options.clone();
    run_supervised(options, cancellation, move |context| {
        snapshot_linux_inner(&reader, decoder, &options_for_worker, &context)
    })
}

fn snapshot_linux_inner<R: LinuxReader>(
    reader: &R,
    decoder: ProcAddressDecoder,
    options: &SnapshotOptions,
    context: &SnapshotContext,
) -> Result<Table, Error> {
    context.check()?;
    let mut entries = Vec::new();
    let mut successful_tables = 0_usize;

    for (path, family, operation) in [
        (TCP4_PATH, Family::V4, "reading /proc/net/tcp"),
        (TCP6_PATH, Family::V6, "reading /proc/net/tcp6"),
    ] {
        context.check()?;
        match reader.read_file(Path::new(path), options.limits.max_table_bytes) {
            Ok(bytes) => {
                successful_tables += 1;
                if bytes.len() > options.limits.max_table_bytes {
                    return Err(Error::LimitExceeded {
                        resource: "Linux TCP table bytes",
                        limit: options.limits.max_table_bytes,
                    });
                }
                parse_proc_table(
                    &bytes,
                    family,
                    decoder,
                    path,
                    &options.limits,
                    context,
                    &mut entries,
                )?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::io(operation, error)),
        }
    }

    if successful_tables == 0 {
        return Err(Error::io(
            "reading Linux TCP tables",
            io::Error::new(io::ErrorKind::NotFound, "/proc TCP tables are absent"),
        ));
    }

    let process_association = if options.associate_processes {
        associate_processes(reader, &mut entries, options, context)?
    } else {
        ProcessAssociation::NotRequested
    };

    entries.sort_unstable();
    Ok(Table {
        entries,
        process_association,
    })
}

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

fn parse_proc_table(
    bytes: &[u8],
    family: Family,
    decoder: ProcAddressDecoder,
    source_name: &'static str,
    limits: &crate::Limits,
    context: &SnapshotContext,
    entries: &mut Vec<Entry>,
) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8 { source_name })?;
    for (index, raw_line) in text.split('\n').enumerate() {
        context.check()?;
        let line_number = index + 1;
        if raw_line.len() > limits.max_line_bytes {
            return Err(Error::LimitExceeded {
                resource: "Linux TCP table line bytes",
                limit: limits.max_line_bytes,
            });
        }
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line).trim();
        if line.is_empty() || line.starts_with("sl ") || line.starts_with("sl\t") {
            continue;
        }
        if entries.len() == limits.max_entries {
            return Err(Error::LimitExceeded {
                resource: "TCP connection entries",
                limit: limits.max_entries,
            });
        }
        entries.push(parse_proc_line(
            line,
            family,
            decoder,
            source_name,
            line_number,
        )?);
    }
    Ok(())
}

fn parse_proc_line(
    line: &str,
    family: Family,
    decoder: ProcAddressDecoder,
    source_name: &'static str,
    line_number: usize,
) -> Result<Entry, Error> {
    let malformed = |reason| Error::Malformed {
        source_name,
        line: line_number,
        reason,
    };
    let mut fields = line.split_whitespace();
    let slot = fields.next().ok_or_else(|| malformed("missing slot"))?;
    if !slot.ends_with(':') || slot[..slot.len() - 1].parse::<u32>().is_err() {
        return Err(malformed("invalid slot"));
    }
    let local = fields
        .next()
        .ok_or_else(|| malformed("missing local endpoint"))?;
    let remote = fields
        .next()
        .ok_or_else(|| malformed("missing remote endpoint"))?;
    let state = fields.next().ok_or_else(|| malformed("missing state"))?;
    let queue = fields.next().ok_or_else(|| malformed("missing queue"))?;
    if !valid_hex_pair(queue, 16) {
        return Err(malformed("invalid queue"));
    }
    let timer = fields.next().ok_or_else(|| malformed("missing timer"))?;
    if !valid_hex_pair(timer, 16) {
        return Err(malformed("invalid timer"));
    }
    let retransmits = fields
        .next()
        .ok_or_else(|| malformed("missing retransmit count"))?;
    if !valid_hex(retransmits, 16) {
        return Err(malformed("invalid retransmit count"));
    }
    let uid = fields
        .next()
        .ok_or_else(|| malformed("missing uid"))?
        .parse::<u32>()
        .map_err(|_| malformed("invalid uid"))?;
    fields
        .next()
        .ok_or_else(|| malformed("missing timeout"))?
        .parse::<u64>()
        .map_err(|_| malformed("invalid timeout"))?;
    let inode = fields
        .next()
        .ok_or_else(|| malformed("missing inode"))?
        .parse::<u64>()
        .map_err(|_| malformed("invalid inode"))?;

    let state_number = parse_fixed_hex_u8(state).ok_or_else(|| malformed("invalid state"))?;
    Ok(Entry {
        local: parse_proc_endpoint(local, family, decoder)
            .ok_or_else(|| malformed("invalid local endpoint"))?,
        remote: parse_proc_endpoint(remote, family, decoder)
            .ok_or_else(|| malformed("invalid remote endpoint"))?,
        pid: None,
        process: None,
        state: linux_state(state_number),
        os_metadata: OsMetadata::Linux { inode, uid },
    })
}

fn parse_proc_endpoint(
    value: &str,
    family: Family,
    decoder: ProcAddressDecoder,
) -> Option<Endpoint> {
    let (address, port) = value.split_once(':')?;
    if port.len() != 4 {
        return None;
    }
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = match family {
        Family::V4 => IpAddr::V4(decoder.decode_v4(address)?),
        Family::V6 => IpAddr::V6(decoder.decode_v6(address)?),
    };
    Some(Endpoint::new(address, port))
}

fn valid_hex_pair(value: &str, max_digits: usize) -> bool {
    value
        .split_once(':')
        .is_some_and(|(left, right)| valid_hex(left, max_digits) && valid_hex(right, max_digits))
}

fn valid_hex(value: &str, max_digits: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_digits
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_fixed_hex_u8(value: &str) -> Option<u8> {
    if value.len() != 2 {
        return None;
    }
    u8::from_str_radix(value, 16).ok()
}

fn linux_state(value: u8) -> State {
    match value {
        0x01 => State::Established,
        0x02 => State::SynSent,
        0x03 => State::SynReceived,
        0x04 => State::FinWait1,
        0x05 => State::FinWait2,
        0x06 => State::TimeWait,
        0x07 => State::Closed,
        0x08 => State::CloseWait,
        0x09 => State::LastAck,
        0x0a => State::Listen,
        0x0b => State::Closing,
        0x0c => State::NewSynReceived,
        other => State::Unknown(u32::from(other)),
    }
}

fn associate_processes<R: LinuxReader>(
    reader: &R,
    entries: &mut [Entry],
    options: &SnapshotOptions,
    context: &SnapshotContext,
) -> Result<ProcessAssociation, Error> {
    let wanted: HashSet<u64> = entries
        .iter()
        .filter_map(|entry| match entry.os_metadata {
            OsMetadata::Linux { inode, .. } if inode != 0 => Some(inode),
            _ => None,
        })
        .collect();
    if wanted.is_empty() {
        return Ok(ProcessAssociation::Complete);
    }

    let proc_root = Path::new(PROC_ROOT);
    let process_directory = match reader.read_directory(proc_root, options.limits.max_processes) {
        Ok(directory) => directory,
        Err(_) => return Ok(ProcessAssociation::Partial),
    };
    if process_directory.names.len() > options.limits.max_processes {
        return Err(Error::LimitExceeded {
            resource: "Linux process directory entries",
            limit: options.limits.max_processes,
        });
    }
    let mut partial = process_directory.truncated;
    let mut pids: Vec<u32> = process_directory
        .names
        .iter()
        .filter_map(|name| name.to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    pids.dedup();

    let mut owners: HashMap<u64, (u32, Option<String>)> = HashMap::new();
    let mut total_fds = 0_usize;
    'processes: for pid in pids {
        context.check()?;
        if owners.len() == wanted.len() {
            break;
        }
        let Some(identity_before) = read_process_start_time(reader, proc_root, pid, options) else {
            partial = true;
            continue;
        };
        let fd_path = path_for_proc(proc_root, pid, "fd");
        let fd_directory = if let Ok(directory) =
            reader.read_directory(&fd_path, options.limits.max_fds_per_process)
        {
            directory
        } else {
            partial = true;
            continue;
        };
        if fd_directory.names.len() > options.limits.max_fds_per_process {
            return Err(Error::LimitExceeded {
                resource: "Linux process FD directory entries",
                limit: options.limits.max_fds_per_process,
            });
        }
        partial |= fd_directory.truncated;
        let mut matched_inodes = HashSet::new();

        for fd_name in fd_directory.names {
            context.check()?;
            if total_fds == options.limits.max_total_fds {
                partial = true;
                break 'processes;
            }
            total_fds += 1;
            let link = if let Ok(link) = reader.read_link(&fd_path.join(fd_name)) {
                link
            } else {
                partial = true;
                continue;
            };
            let Some(inode) = socket_inode(&link) else {
                continue;
            };
            if wanted.contains(&inode) && !owners.contains_key(&inode) {
                matched_inodes.insert(inode);
            }
        }
        if matched_inodes.is_empty() {
            continue;
        }

        let (process, name_partial) = read_process_name(reader, proc_root, pid, options);
        partial |= name_partial;
        context.check()?;
        let Some(identity_after) = read_process_start_time(reader, proc_root, pid, options) else {
            partial = true;
            continue;
        };
        if identity_before != identity_after {
            partial = true;
            continue;
        }
        for inode in matched_inodes {
            owners.insert(inode, (pid, process.clone()));
        }
    }

    if owners.len() != wanted.len() {
        partial = true;
    }
    for entry in entries {
        let OsMetadata::Linux { inode, .. } = entry.os_metadata else {
            continue;
        };
        if let Some((pid, process)) = owners.get(&inode) {
            entry.pid = Some(*pid);
            entry.process.clone_from(process);
        }
    }

    Ok(if partial {
        ProcessAssociation::Partial
    } else {
        ProcessAssociation::Complete
    })
}

fn socket_inode(link: &Path) -> Option<u64> {
    let value = link.to_str()?;
    value
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn read_process_start_time<R: LinuxReader>(
    reader: &R,
    proc_root: &Path,
    pid: u32,
    options: &SnapshotOptions,
) -> Option<u64> {
    let path = path_for_proc(proc_root, pid, "stat");
    let bytes = reader
        .read_file(&path, options.limits.max_process_stat_bytes)
        .ok()?;
    if bytes.len() > options.limits.max_process_stat_bytes {
        return None;
    }
    parse_process_start_time(&bytes)
}

fn parse_process_start_time(bytes: &[u8]) -> Option<u64> {
    let value = std::str::from_utf8(bytes).ok()?.trim_end();
    let command_end = value.rfind(')')?;
    let mut fields = value.get(command_end + 1..)?.split_whitespace();
    // `/proc/<pid>/stat` field 22 is starttime. The suffix starts at field 3.
    fields.nth(19)?.parse().ok()
}

fn read_process_name<R: LinuxReader>(
    reader: &R,
    proc_root: &Path,
    pid: u32,
    options: &SnapshotOptions,
) -> (Option<String>, bool) {
    let path = path_for_proc(proc_root, pid, "comm");
    let Ok(bytes) = reader.read_file(&path, options.limits.max_process_name_bytes) else {
        return (None, true);
    };
    if bytes.len() > options.limits.max_process_name_bytes {
        return (None, true);
    }
    let Ok(value) = std::str::from_utf8(&bytes) else {
        return (None, true);
    };
    let value = value.trim_end_matches(['\n', '\r']);
    if value.is_empty() {
        (None, false)
    } else {
        (Some(value.to_owned()), false)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::{CancellationToken, Limits};

    const HEADER: &str =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
    const V4_ROW: &str = "  0: 0100007F:1F90 0200000A:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000\n";
    const V6_ROW: &str = "  1: 00000000000000000000000001000000:0035 0000000000000000FFFF00000100007F:14E9 0A 00000000:00000000 00:00000000 00000000 0 0 54321 1\n";

    #[derive(Default)]
    struct FakeReader {
        files: HashMap<PathBuf, Vec<u8>>,
        directories: HashMap<PathBuf, Directory>,
        links: HashMap<PathBuf, PathBuf>,
        failures: HashMap<PathBuf, io::ErrorKind>,
        raw_failures: HashMap<PathBuf, i32>,
        file_sequences: Mutex<HashMap<PathBuf, VecDeque<Vec<u8>>>>,
        reads: Mutex<Vec<PathBuf>>,
        cancel_on_read: Option<crate::CancellationToken>,
    }

    impl LinuxReader for FakeReader {
        fn read_file(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
            self.reads.lock().unwrap().push(path.to_owned());
            if let Some(cancellation) = &self.cancel_on_read {
                cancellation.cancel();
            }
            if let Some(raw_error) = self.raw_failures.get(path) {
                return Err(io::Error::from_raw_os_error(*raw_error));
            }
            if let Some(kind) = self.failures.get(path) {
                return Err(io::Error::new(*kind, "injected failure"));
            }
            if let Some(bytes) = self
                .file_sequences
                .lock()
                .unwrap()
                .get_mut(path)
                .and_then(VecDeque::pop_front)
            {
                return Ok(bytes[..bytes.len().min(limit.saturating_add(1))].to_vec());
            }
            self.files
                .get(path)
                .map(|bytes| bytes[..bytes.len().min(limit.saturating_add(1))].to_vec())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))
        }

        fn read_directory(&self, path: &Path, limit: usize) -> io::Result<Directory> {
            self.reads.lock().unwrap().push(path.to_owned());
            if let Some(kind) = self.failures.get(path) {
                return Err(io::Error::new(*kind, "injected failure"));
            }
            let directory = self
                .directories
                .get(path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))?;
            Ok(Directory {
                names: directory.names.iter().take(limit).cloned().collect(),
                truncated: directory.truncated || directory.names.len() > limit,
            })
        }

        fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
            self.reads.lock().unwrap().push(path.to_owned());
            if let Some(kind) = self.failures.get(path) {
                return Err(io::Error::new(*kind, "injected failure"));
            }
            self.links
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))
        }
    }

    fn options() -> SnapshotOptions {
        SnapshotOptions {
            deadline: None,
            limits: Limits::default(),
            associate_processes: false,
        }
    }

    fn context() -> SnapshotContext {
        SnapshotContext::new(None, CancellationToken::new())
    }

    fn snapshot(reader: &FakeReader, options: &SnapshotOptions) -> Result<Table, Error> {
        snapshot_linux_inner(
            reader,
            ProcAddressDecoder::new(ProcEndian::Little),
            options,
            &context(),
        )
    }

    fn proc_stat(pid: u32, start_time: u64) -> Vec<u8> {
        format!(
            "{pid} (demo process) S {} {start_time}\n",
            vec!["0"; 18].join(" ")
        )
        .into_bytes()
    }

    fn snapshot_with_decoder(
        reader: &FakeReader,
        decoder: ProcAddressDecoder,
    ) -> Result<Table, Error> {
        snapshot_linux_inner(reader, decoder, &options(), &context())
    }

    #[test]
    fn parses_little_and_big_endian_table_vectors() {
        for (decoder, v4_row, v6_row) in [
            (
                ProcAddressDecoder::new(ProcEndian::Little),
                V4_ROW,
                V6_ROW,
            ),
            (
                ProcAddressDecoder::new(ProcEndian::Big),
                "  0: 7F000001:1F90 0A000002:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1\n",
                "  1: 00000000000000000000000000000001:0035 00000000000000000000FFFF7F000001:14E9 0A 00000000:00000000 00:00000000 00000000 0 0 54321 1\n",
            ),
        ] {
            let mut reader = FakeReader::default();
            reader.files.insert(
                PathBuf::from(TCP4_PATH),
                format!("{HEADER}{v4_row}").into_bytes(),
            );
            reader.files.insert(
                PathBuf::from(TCP6_PATH),
                format!("{HEADER}{v6_row}").into_bytes(),
            );
            let table = snapshot_with_decoder(&reader, decoder).unwrap();
            assert_eq!(table.entries.len(), 2);
            let established = table
                .entries
                .iter()
                .find(|entry| entry.state == State::Established)
                .unwrap();
            assert_eq!(established.local.to_string(), "127.0.0.1:8080");
            assert_eq!(established.remote.to_string(), "10.0.0.2:443");
            let listening = table.listening().next().unwrap();
            assert_eq!(listening.local.to_string(), "[::1]:53");
            assert_eq!(listening.remote.to_string(), "127.0.0.1:5353");
        }
    }

    #[test]
    fn normalizes_all_linux_states() {
        let expected = [
            State::Established,
            State::SynSent,
            State::SynReceived,
            State::FinWait1,
            State::FinWait2,
            State::TimeWait,
            State::Closed,
            State::CloseWait,
            State::LastAck,
            State::Listen,
            State::Closing,
            State::NewSynReceived,
            State::Unknown(13),
        ];
        for (index, expected) in expected.into_iter().enumerate() {
            assert_eq!(linux_state(u8::try_from(index + 1).unwrap()), expected);
        }
    }

    #[test]
    fn only_not_found_family_absence_is_tolerated() {
        let mut reader = FakeReader::default();
        reader.files.insert(
            PathBuf::from(TCP4_PATH),
            format!("{HEADER}{V4_ROW}").into_bytes(),
        );
        reader
            .failures
            .insert(PathBuf::from(TCP6_PATH), io::ErrorKind::NotFound);
        let table = snapshot(&reader, &options()).unwrap();
        assert_eq!(table.entries.len(), 1);

        reader
            .failures
            .insert(PathBuf::from(TCP6_PATH), io::ErrorKind::PermissionDenied);
        assert!(matches!(
            snapshot(&reader, &options()),
            Err(Error::Io { .. })
        ));

        reader.failures.remove(Path::new(TCP6_PATH));
        // EIO is raw OS error 5 on Linux.
        reader.raw_failures.insert(PathBuf::from(TCP6_PATH), 5);
        assert!(matches!(
            snapshot(&reader, &options()),
            Err(Error::Io { .. })
        ));
    }

    #[test]
    fn rejects_malformed_recognized_row() {
        let mut reader = FakeReader::default();
        reader.files.insert(
            PathBuf::from(TCP4_PATH),
            format!("{HEADER}  0: not-an-endpoint\n").into_bytes(),
        );
        reader
            .files
            .insert(PathBuf::from(TCP6_PATH), HEADER.as_bytes().to_vec());
        let error = snapshot(&reader, &options()).unwrap_err();
        assert!(matches!(error, Error::Malformed { line: 2, .. }));
    }

    #[test]
    fn rejects_large_table_and_entry_count() {
        let mut reader = FakeReader::default();
        reader
            .files
            .insert(PathBuf::from(TCP4_PATH), vec![b'x'; 33]);
        reader
            .files
            .insert(PathBuf::from(TCP6_PATH), HEADER.as_bytes().to_vec());
        let mut constrained = options();
        constrained.limits.max_table_bytes = 32;
        assert!(matches!(
            snapshot(&reader, &constrained),
            Err(Error::LimitExceeded { .. })
        ));

        reader.files.insert(
            PathBuf::from(TCP4_PATH),
            format!("{HEADER}{V4_ROW}{V4_ROW}").into_bytes(),
        );
        constrained.limits.max_table_bytes = 4096;
        constrained.limits.max_entries = 1;
        assert!(matches!(
            snapshot(&reader, &constrained),
            Err(Error::LimitExceeded { .. })
        ));
    }

    fn add_process_fixture(reader: &mut FakeReader, start_time: u64) {
        reader.directories.insert(
            PathBuf::from(PROC_ROOT),
            Directory {
                names: vec![OsString::from("42")],
                truncated: false,
            },
        );
        reader.directories.insert(
            PathBuf::from("/proc/42/fd"),
            Directory {
                names: vec![OsString::from("7")],
                truncated: false,
            },
        );
        reader.links.insert(
            PathBuf::from("/proc/42/fd/7"),
            PathBuf::from("socket:[12345]"),
        );
        reader
            .files
            .insert(PathBuf::from("/proc/42/comm"), b"demo\n".to_vec());
        reader
            .files
            .insert(PathBuf::from("/proc/42/stat"), proc_stat(42, start_time));
    }

    fn reader_with_connection() -> FakeReader {
        let mut reader = FakeReader::default();
        reader.files.insert(
            PathBuf::from(TCP4_PATH),
            format!("{HEADER}{V4_ROW}").into_bytes(),
        );
        reader
            .files
            .insert(PathBuf::from(TCP6_PATH), HEADER.as_bytes().to_vec());
        reader
    }

    #[test]
    fn stable_identity_is_required_for_complete_pid_association() {
        let mut reader = reader_with_connection();
        add_process_fixture(&mut reader, 9001);
        let mut associated = options();
        associated.associate_processes = true;
        let table = snapshot(&reader, &associated).unwrap();
        assert_eq!(table.process_association, ProcessAssociation::Complete);
        assert_eq!(table.entries[0].pid, Some(42));
        assert_eq!(table.entries[0].process.as_deref(), Some("demo"));
        assert!(!reader
            .reads
            .lock()
            .unwrap()
            .iter()
            .any(|path| path == Path::new("socket:[12345]")));
    }

    #[test]
    fn pid_reuse_race_omits_association_and_marks_partial() {
        let mut reader = reader_with_connection();
        add_process_fixture(&mut reader, 9001);
        reader.file_sequences.lock().unwrap().insert(
            PathBuf::from("/proc/42/stat"),
            VecDeque::from([proc_stat(42, 9001), proc_stat(42, 9002)]),
        );
        let mut associated = options();
        associated.associate_processes = true;
        let table = snapshot(&reader, &associated).unwrap();
        assert_eq!(table.process_association, ProcessAssociation::Partial);
        assert_eq!(table.entries[0].pid, None);
        assert_eq!(table.entries[0].process, None);
    }

    #[test]
    fn process_exit_race_preserves_rows_as_partial() {
        let mut reader = reader_with_connection();
        add_process_fixture(&mut reader, 9001);
        reader
            .failures
            .insert(PathBuf::from("/proc/42/fd"), io::ErrorKind::NotFound);
        let mut associated = options();
        associated.associate_processes = true;
        let table = snapshot(&reader, &associated).unwrap();
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries[0].pid, None);
        assert_eq!(table.process_association, ProcessAssociation::Partial);
    }

    #[test]
    fn process_and_fd_limits_produce_partial_snapshot() {
        let mut reader = reader_with_connection();
        reader.directories.insert(
            PathBuf::from(PROC_ROOT),
            Directory {
                names: vec![OsString::from("1"), OsString::from("2")],
                truncated: false,
            },
        );
        let mut associated = options();
        associated.associate_processes = true;
        associated.limits.max_processes = 1;
        associated.limits.max_fds_per_process = 1;
        associated.limits.max_total_fds = 1;
        let table = snapshot(&reader, &associated).unwrap();
        assert_eq!(table.process_association, ProcessAssociation::Partial);
    }

    #[test]
    fn parses_start_time_after_parenthesized_command() {
        assert_eq!(
            parse_process_start_time(&proc_stat(42, 123_456)),
            Some(123_456)
        );
        assert_eq!(
            parse_process_start_time(b"42 (name with ) chars) S 0 0\n"),
            None
        );
    }

    #[test]
    fn supervised_linux_reader_returns_before_blocking_read_finishes() {
        struct BlockingReader;
        impl LinuxReader for BlockingReader {
            fn read_file(&self, _path: &Path, _limit: usize) -> io::Result<Vec<u8>> {
                std::thread::sleep(std::time::Duration::from_millis(200));
                Err(io::Error::new(io::ErrorKind::NotFound, "late"))
            }

            fn read_directory(&self, _path: &Path, _limit: usize) -> io::Result<Directory> {
                unreachable!()
            }

            fn read_link(&self, _path: &Path) -> io::Result<PathBuf> {
                unreachable!()
            }
        }

        let bounded = SnapshotOptions {
            deadline: Some(std::time::Instant::now() + std::time::Duration::from_millis(25)),
            ..options()
        };
        let started = std::time::Instant::now();
        assert!(matches!(
            snapshot_linux_with_reader(BlockingReader, &bounded, &CancellationToken::new()),
            Err(Error::DeadlineExceeded)
        ));
        assert!(started.elapsed() < std::time::Duration::from_millis(150));
    }

    #[test]
    fn cancellation_is_observed_between_reader_and_parse() {
        let cancellation = CancellationToken::new();
        let mut reader = FakeReader {
            cancel_on_read: Some(cancellation.clone()),
            ..FakeReader::default()
        };
        reader.files.insert(
            PathBuf::from(TCP4_PATH),
            format!("{HEADER}{V4_ROW}").into_bytes(),
        );
        let context = SnapshotContext::new(None, cancellation);
        assert!(matches!(
            snapshot_linux_inner(
                &reader,
                ProcAddressDecoder::new(ProcEndian::Little),
                &options(),
                &context
            ),
            Err(Error::Cancelled)
        ));
    }
}
