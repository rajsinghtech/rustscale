//! Logtail log streaming client — ports Go's `logtail/` package.
//!
//! Buffers log entries and uploads them to a log server. This is a minimal
//! implementation: the `LogTail` struct buffers entries in memory and provides
//! a `send` method that would POST them to the configured server. The actual
//! HTTP upload is a stub (TODO: wire up to the control plane noise protocol or
//! a direct HTTPS POST).
//!
//! Go reference: `logtail/logtail.go` — `type Logtail`, `type Logger`,
//! `logtail/config.go` — `type Config`.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default log server host.
pub const DEFAULT_HOST: &str = "log.tailscale.com";

/// Collection name for tailscaled-style node logs.
pub const COLLECTION_NODE: &str = "tailnode.log.tailscale.io";

/// Configuration for the logtail client — mirrors Go's `logtail.Config`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Collection name (a domain name, e.g. `tailnode.log.tailscale.io`).
    pub collection: String,
    /// Private ID for the primary log stream.
    pub private_id: String,
    /// Private ID for a copy log stream (superset of the primary).
    pub copy_private_id: String,
    /// Base URL for the log server. If empty, defaults to `https://DEFAULT_HOST`.
    pub base_url: String,
    /// Whether to compress log uploads.
    pub compress_logs: bool,
    /// Maximum upload size in bytes (0 = default).
    pub max_upload_size: usize,
    /// Whether to include client timestamps.
    pub skip_client_time: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            collection: COLLECTION_NODE.to_string(),
            private_id: String::new(),
            copy_private_id: String::new(),
            base_url: String::new(),
            compress_logs: false,
            max_upload_size: 0,
            skip_client_time: false,
        }
    }
}

/// Metadata attached to each log entry — mirrors Go's `Logtail` struct.
#[derive(Clone, Debug, Default, serde::Serialize)]
struct LogtailMeta {
    /// Epoch seconds when the entry was generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_time: Option<u64>,
    /// Ephemeral process ID (if enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    proc_id: Option<u32>,
    /// Ephemeral per-process sequence number.
    #[serde(skip_serializing_if = "Option::is_none")]
    proc_seq: Option<u64>,
}

/// A single log entry — the `logtail` metadata is inlined alongside the
/// caller's JSON value.
#[derive(Clone, Debug, serde::Serialize)]
pub struct LogEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    logtail: Option<LogtailMeta>,
    /// The log message text.
    pub text: String,
    /// Verbosity level (0 = info, higher = more verbose).
    #[serde(skip_serializing_if = "skip_zero")]
    pub v: i32,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn skip_zero(v: &i32) -> bool {
    *v == 0
}

/// The logtail client — buffers log entries and provides a `send` method.
///
/// In Go, `Logger` runs a background goroutine that periodically flushes the
/// buffer to the server. Here, we provide an explicit `send` method that the
/// caller can invoke (or wire up to a tokio task). The actual HTTP upload is
/// a stub that logs and discards.
///
/// ```
/// use rustscale_logtail::{Config, LogTail};
/// let lt = LogTail::new(Config::default());
/// lt.write("hello world");
/// assert_eq!(lt.buffered_count(), 1);
/// ```
pub struct LogTail {
    config: Config,
    buffer: Mutex<VecDeque<LogEntry>>,
    proc_id: u32,
    proc_seq: Mutex<u64>,
}

impl LogTail {
    /// Create a new logtail client with the given config.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            buffer: Mutex::new(VecDeque::new()),
            proc_id: rand_u32(),
            proc_seq: Mutex::new(0),
        }
    }

    /// The configured base URL (or the default host if empty).
    pub fn base_url(&self) -> String {
        if self.config.base_url.is_empty() {
            format!("https://{DEFAULT_HOST}")
        } else {
            self.config.base_url.clone()
        }
    }

    /// Buffer a log entry with the given text.
    pub fn write(&self, text: &str) {
        self.write_entry(LogEntry {
            logtail: Some(self.make_meta()),
            text: text.to_string(),
            v: 0,
        });
    }

    /// Buffer a verbose log entry (level > 0).
    pub fn write_verbose(&self, text: &str, v: i32) {
        self.write_entry(LogEntry {
            logtail: Some(self.make_meta()),
            text: text.to_string(),
            v,
        });
    }

    /// Buffer a raw log entry.
    fn write_entry(&self, entry: LogEntry) {
        let mut buf = self.buffer.lock().unwrap();
        buf.push_back(entry);
    }

    /// Build the `logtail` metadata for a new entry.
    fn make_meta(&self) -> LogtailMeta {
        let mut seq = self.proc_seq.lock().unwrap();
        *seq += 1;
        let seq_val = *seq;

        let client_time = if self.config.skip_client_time {
            None
        } else {
            Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            )
        };

        LogtailMeta {
            client_time,
            proc_id: Some(self.proc_id),
            proc_seq: Some(seq_val),
        }
    }

    /// Drain and upload buffered entries to the log server.
    ///
    /// Returns the number of entries that were "sent" (in this stub, always
    /// the buffer count — the actual HTTP POST is a TODO).
    pub fn send(&self) -> usize {
        let entries: Vec<LogEntry> = {
            let mut buf = self.buffer.lock().unwrap();
            buf.drain(..).collect()
        };
        let count = entries.len();
        if count == 0 {
            return 0;
        }

        // Serialize entries as a JSON array.
        let json = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string());

        // TODO: POST json to {base_url}/c/{collection}?pri={private_id}
        // using the control plane noise protocol or direct HTTPS.
        // For now, log the intent and discard the payload.
        log::debug!(
            "logtail: would upload {} bytes ({} entries) to {}",
            json.len(),
            count,
            self.base_url()
        );

        count
    }

    /// Number of buffered entries waiting to be sent.
    pub fn buffered_count(&self) -> usize {
        self.buffer.lock().unwrap().len()
    }

    /// The collection name.
    pub fn collection(&self) -> &str {
        &self.config.collection
    }
}

/// Generate a random u32 for the process ID.
fn rand_u32() -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    std::process::id().hash(&mut h);
    (h.finish() & 0xFFFF_FFFF) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_and_count() {
        let lt = LogTail::new(Config::default());
        lt.write("hello");
        lt.write("world");
        assert_eq!(lt.buffered_count(), 2);
    }

    #[test]
    fn send_drains_buffer() {
        let lt = LogTail::new(Config::default());
        lt.write("test1");
        lt.write("test2");
        let n = lt.send();
        assert_eq!(n, 2);
        assert_eq!(lt.buffered_count(), 0);
    }

    #[test]
    fn send_empty_buffer() {
        let lt = LogTail::new(Config::default());
        let n = lt.send();
        assert_eq!(n, 0);
    }

    #[test]
    fn base_url_defaults() {
        let lt = LogTail::new(Config::default());
        assert!(lt.base_url().starts_with("https://log.tailscale.com"));
    }

    #[test]
    fn base_url_custom() {
        let cfg = Config {
            base_url: "https://custom.example.com".to_string(),
            ..Default::default()
        };
        let lt = LogTail::new(cfg);
        assert_eq!(lt.base_url(), "https://custom.example.com");
    }

    #[test]
    fn entry_serializes_to_json() {
        let lt = LogTail::new(Config::default());
        lt.write("test message");
        let entries: Vec<LogEntry> = lt.buffer.lock().unwrap().drain(..).collect();
        let json = serde_json::to_string(&entries).unwrap();
        assert!(json.contains("test message"));
        assert!(json.contains("logtail"));
    }

    #[test]
    fn proc_seq_increments() {
        let lt = LogTail::new(Config::default());
        lt.write("a");
        lt.write("b");
        let entries: Vec<LogEntry> = lt.buffer.lock().unwrap().drain(..).collect();
        let seq1 = entries[0].logtail.as_ref().unwrap().proc_seq.unwrap();
        let seq2 = entries[1].logtail.as_ref().unwrap().proc_seq.unwrap();
        assert_eq!(seq2, seq1 + 1);
    }
}
