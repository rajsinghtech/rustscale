//! SSH session recording in asciicast v2 format.

use crate::recording_upload::UploadAbort;
use rustscale_tailcfg::{SSHRecorderFailureAction, StableNodeID, UserID};
use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MAX_EVENT_DATA: usize = 64 * 1024;
const MAX_RECORDING_FRAME: usize = 512 * 1024;
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug)]
pub enum RecordDir {
    Input,
    Output,
}

impl RecordDir {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Input => "i",
            Self::Output => "o",
        }
    }
}

/// Configuration derived from a matched SSH action.
#[derive(Clone, Debug, Default)]
pub struct RecordingConfig {
    pub recorders: Vec<std::net::SocketAddr>,
    pub on_failure: Option<SSHRecorderFailureAction>,
    pub local_path: Option<PathBuf>,
    pub fail_open: bool,
}

/// The first line of a recording upload.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CastHeader {
    pub version: u32,
    pub width: u32,
    pub height: u32,
    pub timestamp: u64,
    pub command: String,
    pub src_node: String,
    #[serde(rename = "srcNodeID")]
    pub src_node_id: StableNodeID,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub src_node_tags: Vec<String>,
    #[serde(rename = "srcNodeUserID", skip_serializing_if = "Option::is_none")]
    pub src_node_user_id: Option<UserID>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_node_user: Option<String>,
    pub env: HashMap<String, String>,
    pub ssh_user: String,
    pub local_user: String,
    #[serde(rename = "connectionID")]
    pub connection_id: String,
}

impl CastHeader {
    pub fn new(
        pty_size: (u32, u32),
        command: String,
        env: HashMap<String, String>,
        ssh_user: String,
        local_user: String,
        connection_id: String,
    ) -> Self {
        Self {
            version: 2,
            width: pty_size.0,
            height: pty_size.1,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            command,
            src_node: String::new(),
            src_node_id: String::new(),
            src_node_tags: Vec::new(),
            src_node_user_id: None,
            src_node_user: None,
            env,
            ssh_user,
            local_user,
            connection_id,
        }
    }
}

#[derive(serde::Serialize)]
struct CastEvent<'a>(f64, &'a str, &'a str);

enum RecordingOutput {
    File(File),
    Upload(Box<dyn Write + Send>),
}

impl Write for RecordingOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::File(out) => out.write(buf),
            Self::Upload(out) => out.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::File(out) => out.flush(),
            Self::Upload(out) => out.flush(),
        }
    }
}

/// Thread-safe recorder used by the session output pumps.
pub struct SessionRecorder {
    inner: Mutex<RecorderInner>,
    result_rx: Mutex<Option<oneshot::Receiver<io::Result<()>>>>,
    upload_abort: Option<UploadAbort>,
    start: Instant,
}

struct RecorderInner {
    out: Option<RecordingOutput>,
    failed: bool,
}

#[derive(Debug)]
pub enum RecordResult {
    Ok,
    Failed,
}

impl SessionRecorder {
    pub fn new(
        path: &Path,
        pty_size: (u32, u32),
        _title: &str,
        env: &BTreeMap<String, String>,
        fail_open: bool,
    ) -> io::Result<Self> {
        let file = open_recording_file(path)?;
        let header = CastHeader::new(
            pty_size,
            String::new(),
            env.clone().into_iter().collect(),
            String::new(),
            String::new(),
            String::new(),
        );
        Self::with_output(RecordingOutput::File(file), header, fail_open, None, None)
    }

    pub(crate) fn with_file(path: &Path, header: CastHeader, fail_open: bool) -> io::Result<Self> {
        Self::with_output(
            RecordingOutput::File(open_recording_file(path)?),
            header,
            fail_open,
            None,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_test_writer(
        writer: Box<dyn Write + Send>,
        header: CastHeader,
        fail_open: bool,
    ) -> io::Result<Self> {
        Self::with_output(
            RecordingOutput::Upload(writer),
            header,
            fail_open,
            None,
            None,
        )
    }

    pub(crate) fn with_upload(
        writer: Box<dyn Write + Send>,
        result_rx: oneshot::Receiver<io::Result<()>>,
        upload_abort: UploadAbort,
        header: CastHeader,
        fail_open: bool,
    ) -> io::Result<Self> {
        Self::with_output(
            RecordingOutput::Upload(writer),
            header,
            fail_open,
            Some(result_rx),
            Some(upload_abort),
        )
    }

    fn with_output(
        mut out: RecordingOutput,
        header: CastHeader,
        _fail_open: bool,
        result_rx: Option<oneshot::Receiver<io::Result<()>>>,
        upload_abort: Option<UploadAbort>,
    ) -> io::Result<Self> {
        let mut encoded = serde_json::to_vec(&header).map_err(io::Error::other)?;
        if encoded.len() >= MAX_RECORDING_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recording header is too large",
            ));
        }
        encoded.push(b'\n');
        out.write_all(&encoded)?;
        out.flush()?;
        Ok(Self {
            inner: Mutex::new(RecorderInner {
                out: Some(out),
                failed: false,
            }),
            result_rx: Mutex::new(result_rx),
            upload_abort,
            start: Instant::now(),
        })
    }

    pub fn write(&self, dir: RecordDir, data: &[u8]) -> RecordResult {
        if matches!(dir, RecordDir::Input) {
            return RecordResult::Ok;
        }
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return RecordResult::Failed,
        };
        if inner.failed {
            // Report a failure only once. Fail-open sessions disable their
            // sink after the first error instead of logging every output chunk.
            return RecordResult::Ok;
        }
        let Some(mut out) = inner.out.take() else {
            return RecordResult::Ok;
        };
        // Go converts each output byte slice to one string event before JSON
        // encoding. Invalid UTF-8 is therefore replaced, not base64 encoded.
        let result = if data.len() > MAX_EVENT_DATA {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recording event is too large",
            ))
        } else {
            let text = String::from_utf8_lossy(data);
            let event = CastEvent(self.start.elapsed().as_secs_f64(), dir.as_str(), &text);
            serde_json::to_vec(&event)
                .map_err(io::Error::other)
                .and_then(|mut encoded| {
                    if encoded.len() >= MAX_RECORDING_FRAME {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "recording event is too large",
                        ));
                    }
                    encoded.push(b'\n');
                    out.write_all(&encoded)
                })
        };
        if result.and_then(|()| out.flush()).is_ok() {
            inner.out = Some(out);
            RecordResult::Ok
        } else {
            inner.failed = true;
            // Drop the sink for both policies. Fail-closed orchestration
            // terminates the process; fail-open stops recording.
            RecordResult::Failed
        }
    }

    pub fn close(&self) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        if let Some(mut out) = inner.out.take() {
            out.flush()?;
        }
        Ok(())
    }

    pub fn take_result_rx(&self) -> Option<oneshot::Receiver<io::Result<()>>> {
        self.result_rx.lock().ok()?.take()
    }

    pub fn has_failed(&self) -> bool {
        self.inner.lock().map_or(true, |g| g.failed)
    }

    pub fn abort_upload(&self) {
        if let Some(abort) = &self.upload_abort {
            abort.abort();
        }
    }
}

fn open_recording_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

impl Drop for SessionRecorder {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub fn default_recording_path(var_root: &Path) -> io::Result<PathBuf> {
    let dir = var_root.join("ssh-sessions");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    Ok(dir.join(format!("ssh-session-{ts}.cast")))
}

pub fn should_record_locally(config: &RecordingConfig) -> bool {
    config.recorders.is_empty() && config.local_path.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn cast_header_uses_upstream_field_names() {
        let mut header = CastHeader::new(
            (80, 24),
            "printf hello".into(),
            HashMap::from([("TERM".into(), "xterm-256color".into())]),
            "alice".into(),
            "root".into(),
            "connection".into(),
        );
        header.src_node = "client.tailnet.ts.net".into();
        header.src_node_id = "node-client".into();
        header.src_node_user_id = Some(42);
        header.src_node_user = Some("alice@example.com".into());
        let value = serde_json::to_value(header).unwrap();
        assert_eq!(value["version"], 2);
        assert_eq!(value["srcNode"], "client.tailnet.ts.net");
        assert_eq!(value["srcNodeID"], "node-client");
        assert_eq!(value["srcNodeUserID"], 42);
        assert_eq!(value["sshUser"], "alice");
        assert_eq!(value["localUser"], "root");
        assert_eq!(value["connectionID"], "connection");
        assert!(value.get("src_node").is_none());
    }

    #[test]
    fn recorder_writes_header_and_events() {
        let tmp = std::env::temp_dir().join(format!("rs-ssh-rec-{}.cast", uuid()));
        let env = BTreeMap::from([("SHELL".to_string(), "/bin/sh".to_string())]);
        let rec = SessionRecorder::new(&tmp, (80, 24), "test", &env, false).unwrap();
        assert!(matches!(
            rec.write(RecordDir::Output, b"hello world\r\n"),
            RecordResult::Ok
        ));
        rec.close().unwrap();
        let mut content = String::new();
        File::open(&tmp)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.lines().next().unwrap().contains("\"version\":2"));
        assert!(content.contains("\"o\",\"hello world\\r\\n\""));
        assert!(!content.contains("aGVsbG8="));
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn default_path_creates_dir() {
        let root = std::env::temp_dir().join(format!("rs-ssh-varroot-{}", uuid()));
        assert!(default_recording_path(&root)
            .unwrap()
            .to_string_lossy()
            .contains("ssh-sessions"));
        let _ = std::fs::remove_dir_all(root);
    }

    fn uuid() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
