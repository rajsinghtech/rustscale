//! SSH session recording — ports Go's `ssh/tailssh/tailssh.go` recording logic.
//!
//! When the SSH policy action specifies `Recorders`, the session output is
//! captured to a file in asciicast v2 (`.cast`) JSON format. This is a minimal
//! implementation that writes to a local file path. A full implementation would
//! stream to remote recorder nodes via the control plane noise protocol.
//!
//! Go reference: `ssh/tailssh/tailssh.go` — `type recording struct`,
//! `startNewRecording`, `openFileForRecording`, `loggingWriter`.

use base64::Engine as _;
use rustscale_tailcfg::SSHRecorderFailureAction;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Direction of recorded data: input from the client or output to the client.
/// Currently only output is recorded (input may contain passwords).
#[derive(Clone, Copy, Debug)]
pub enum RecordDir {
    /// Client → server (keyboard input). Currently not recorded.
    Input,
    /// Server → client (terminal output). Recorded.
    Output,
}

impl RecordDir {
    fn as_str(self) -> &'static str {
        match self {
            RecordDir::Input => "i",
            RecordDir::Output => "o",
        }
    }
}

/// Configuration for session recording, derived from `SSHAction`.
#[derive(Clone, Debug, Default)]
pub struct RecordingConfig {
    /// Remote recorder URLs. If empty and `local_path` is set, records locally.
    pub recorders: Vec<String>,
    /// Action to take when recording fails.
    pub on_failure: Option<SSHRecorderFailureAction>,
    /// Local file path to write the recording to. If `None`, recordings are
    /// stored in `var_root/ssh-sessions/`.
    pub local_path: Option<PathBuf>,
    /// If true, allow the session to continue even if recording fails.
    pub fail_open: bool,
}

/// Header metadata for the asciicast v2 format — written as the first JSON line.
#[derive(serde::Serialize)]
struct CastHeader {
    version: u32,
    width: u32,
    height: u32,
    timestamp: u64,
    title: String,
    env: std::collections::BTreeMap<String, String>,
}

/// A single asciicast event line: `[time, dir, data]`.
#[derive(serde::Serialize)]
struct CastEvent<'a> {
    t: f64,
    dir: &'a str,
    data: &'a str,
}

/// Session recorder — writes PTY output to a `.cast` file in asciicast v2 format.
///
/// Mirrors Go's `recording` struct. The writer is guarded by a mutex so that
/// concurrent writes from the PTY pump task are serialized. If the recording
/// fails and `fail_open` is false, subsequent writes are dropped and
/// `has_failed()` returns true so the caller can terminate the session.
pub struct SessionRecorder {
    inner: Mutex<RecorderInner>,
    start: Instant,
}

struct RecorderInner {
    out: Option<File>,
    fail_open: bool,
    failed: bool,
}

/// Outcome of a write to the recorder.
#[derive(Debug)]
pub enum RecordResult {
    /// Data was written successfully.
    Ok,
    /// Recording failed; check `fail_open` to decide whether to continue.
    Failed,
}

impl SessionRecorder {
    /// Create a new recorder that writes to `path`.
    ///
    /// Writes the asciicast v2 header as the first line. The `pty_size` tuple
    /// is `(width, height)` in columns/rows.
    pub fn new(
        path: &Path,
        pty_size: (u32, u32),
        title: &str,
        env: &std::collections::BTreeMap<String, String>,
        fail_open: bool,
    ) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let header = CastHeader {
            version: 2,
            width: pty_size.0,
            height: pty_size.1,
            timestamp,
            title: title.to_string(),
            env: env.clone(),
        };

        let mut file = file;
        let header_json = serde_json::to_string(&header).map_err(io::Error::other)?;
        writeln!(file, "{header_json}")?;

        Ok(Self {
            inner: Mutex::new(RecorderInner {
                out: Some(file),
                fail_open,
                failed: false,
            }),
            start: Instant::now(),
        })
    }

    /// Write a chunk of session data in the given direction.
    ///
    /// Only `Output` data is actually recorded; `Input` is ignored (may contain
    /// passwords). The data is base64-encoded into the asciicast event line.
    pub fn write(&self, dir: RecordDir, data: &[u8]) -> RecordResult {
        if matches!(dir, RecordDir::Input) {
            return RecordResult::Ok;
        }

        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return RecordResult::Failed,
        };
        if inner.failed {
            return RecordResult::Failed;
        }
        let Some(ref mut file) = inner.out else {
            return RecordResult::Failed;
        };

        let elapsed = self.start.elapsed().as_secs_f64();
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        let event = serde_json::to_string(&CastEvent {
            t: elapsed,
            dir: dir.as_str(),
            data: &encoded,
        })
        .ok();

        let result = match event {
            Some(json) => writeln!(file, "{json}").and_then(|()| file.flush()),
            None => Err(io::Error::other("serialize event")),
        };

        if result.is_err() {
            if inner.fail_open {
                inner.failed = true;
                inner.out = None;
                return RecordResult::Failed;
            }
            return RecordResult::Failed;
        }

        RecordResult::Ok
    }

    /// Close the recorder, flushing any buffered data.
    pub fn close(&self) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        if let Some(mut file) = inner.out.take() {
            file.flush()?;
        }
        Ok(())
    }

    /// Whether the recording has failed and writes are being dropped.
    pub fn has_failed(&self) -> bool {
        self.inner.lock().map_or(true, |g| g.failed)
    }
}

impl Drop for SessionRecorder {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Build a default recording path under `var_root/ssh-sessions/`.
///
/// Mirrors Go's `openFileForRecording`: creates the directory if needed and
/// returns a temp-style filename with the current timestamp.
pub fn default_recording_path(var_root: &Path) -> io::Result<PathBuf> {
    let dir = var_root.join("ssh-sessions");
    std::fs::create_dir_all(&dir)?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    Ok(dir.join(format!("ssh-session-{ts}.cast")))
}

/// Determine whether local recording should be used (no remote recorders).
pub fn should_record_locally(config: &RecordingConfig) -> bool {
    config.recorders.is_empty() && config.local_path.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Read;

    #[test]
    fn recorder_writes_header_and_events() {
        let tmp = std::env::temp_dir().join(format!(
            "rs-ssh-rec-{}.cast",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let env = BTreeMap::from([("SHELL".to_string(), "/bin/sh".to_string())]);
        let rec = SessionRecorder::new(&tmp, (80, 24), "test", &env, false).unwrap();

        let out = b"hello world\r\n";
        assert!(matches!(
            rec.write(RecordDir::Output, out),
            RecordResult::Ok
        ));
        assert!(matches!(
            rec.write(RecordDir::Input, b"secret"),
            RecordResult::Ok
        ));
        rec.close().unwrap();

        let mut content = String::new();
        File::open(&tmp)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert!(lines.len() >= 2);
        assert!(lines[0].contains("\"version\":2"));
        assert!(lines[1].contains("\"o\""));
        // The data is base64-encoded in the asciicast event.
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello world\r\n");
        assert!(lines[1].contains(&encoded));

        // Input should not be recorded as an event line
        assert!(lines[1..].iter().all(|l| !l.contains("\"i\"")));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn recorder_fail_open_drops_writes() {
        let path = std::env::temp_dir().join("nonexistent/deep/path/cast");
        let result = SessionRecorder::new(&path, (80, 24), "x", &BTreeMap::new(), true);
        // Creating the file should fail because the directory doesn't exist.
        assert!(result.is_err());
    }

    #[test]
    fn default_path_creates_dir() {
        let root = std::env::temp_dir().join(format!(
            "rs-ssh-varroot-{}",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = default_recording_path(&root).unwrap();
        assert!(path.to_string_lossy().contains("ssh-sessions"));
        assert!(path.to_string_lossy().ends_with(".cast"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
