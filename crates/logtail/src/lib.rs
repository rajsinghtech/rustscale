//! Logtail log streaming client — ports Go's `logtail/` package.
//!
//! Buffers log entries and uploads them to a log server via HTTP POST.
//! A background tokio task drains the buffer, serializes entries as a JSON
//! array, optionally compresses with zstd, and POSTs to
//! `{base_url}/c/{collection}/{private_id}[?copyId={copy_private_id}]`.
//! Failed uploads retry with random 30–60s backoff (or the server's
//! `Retry-After` header, capped at 5 minutes).
//!
//! Go reference: `logtail/logtail.go` — `type Logger`, `type Config`,
//! `logtail/config.go` — `type Config`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, Notify};

pub mod log;

pub use log::LogtailLogger;

pub const DEFAULT_HOST: &str = "log.tailscale.com";

pub const COLLECTION_NODE: &str = "tailnode.log.tailscale.io";

const MAX_UPLOAD_SIZE: usize = 256 << 10;
const MAX_BUFFER_ENTRIES: usize = 10_000;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_RETRY: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub struct Config {
    pub collection: String,
    pub private_id: String,
    pub copy_private_id: String,
    pub base_url: String,
    pub compress_logs: bool,
    pub max_upload_size: usize,
    pub skip_client_time: bool,
    /// Whether this client accepts log entries. Environment opt-out still
    /// takes precedence over this setting.
    pub enabled: bool,
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
            enabled: true,
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize)]
struct LogtailMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    client_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proc_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proc_seq: Option<u64>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LogEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    logtail: Option<LogtailMeta>,
    pub text: String,
    #[serde(skip_serializing_if = "skip_zero")]
    pub v: i32,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn skip_zero(v: &i32) -> bool {
    *v == 0
}

#[derive(Default)]
struct Metrics {
    upload_calls: AtomicU64,
    upload_errors: AtomicU64,
    uploaded_bytes: AtomicU64,
}

struct LogTailInner {
    config: Config,
    buffer: Mutex<VecDeque<LogEntry>>,
    proc_id: u32,
    proc_seq: Mutex<u64>,
    flush_notify: Notify,
    enabled: AtomicBool,
    environment_disabled: bool,
    drop_count: AtomicU64,
    metrics: Metrics,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    done_rx: Mutex<Option<oneshot::Receiver<()>>>,
}

/// The logtail client — buffers log entries and uploads them via a
/// background task started with [`LogTail::start_upload`].
///
/// ```
/// use rustscale_logtail::{Config, LogTail};
/// let lt = LogTail::new(Config::default());
/// lt.write("hello world");
/// assert_eq!(lt.buffered_count(), 1);
/// ```
#[derive(Clone)]
pub struct LogTail {
    inner: Arc<LogTailInner>,
}

impl LogTail {
    pub fn new(config: Config) -> Self {
        let environment_disabled =
            rustscale_envknob::bool("TS_NO_LOGS_NO_SUPPORT").unwrap_or(false);
        Self {
            inner: Arc::new(LogTailInner {
                enabled: AtomicBool::new(config.enabled),
                environment_disabled,
                config,
                buffer: Mutex::new(VecDeque::new()),
                proc_id: proc_id(),
                proc_seq: Mutex::new(0),
                flush_notify: Notify::new(),
                drop_count: AtomicU64::new(0),
                metrics: Metrics::default(),
                shutdown_tx: Mutex::new(None),
                done_rx: Mutex::new(None),
            }),
        }
    }

    pub fn base_url(&self) -> String {
        if self.inner.config.base_url.is_empty() {
            format!("https://{DEFAULT_HOST}")
        } else {
            self.inner.config.base_url.clone()
        }
    }

    pub fn upload_url(&self) -> String {
        upload_url_for(&self.inner.config)
    }

    pub fn write(&self, text: &str) {
        self.write_entry(LogEntry {
            logtail: Some(self.make_meta()),
            text: text.to_string(),
            v: 0,
        });
    }

    pub fn write_verbose(&self, text: &str, v: i32) {
        self.write_entry(LogEntry {
            logtail: Some(self.make_meta()),
            text: text.to_string(),
            v,
        });
    }

    fn write_entry(&self, entry: LogEntry) {
        if self.disabled() {
            return;
        }
        let mut buf = self.inner.buffer.lock().unwrap();
        if buf.len() >= MAX_BUFFER_ENTRIES {
            buf.pop_front();
            self.inner.drop_count.fetch_add(1, Ordering::Relaxed);
        }
        buf.push_back(entry);
        drop(buf);
        self.inner.flush_notify.notify_waiters();
    }

    fn make_meta(&self) -> LogtailMeta {
        let mut seq = self.inner.proc_seq.lock().unwrap();
        *seq += 1;
        let seq_val = *seq;
        let client_time = if self.inner.config.skip_client_time {
            None
        } else {
            Some(chrono::Utc::now())
        };
        LogtailMeta {
            client_time,
            proc_id: Some(self.inner.proc_id),
            proc_seq: Some(seq_val),
        }
    }

    pub fn start_upload(&self) -> UploadHandle {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        *self.inner.shutdown_tx.lock().unwrap() = Some(shutdown_tx);
        *self.inner.done_rx.lock().unwrap() = Some(done_rx);
        let inner = Arc::clone(&self.inner);
        tokio::spawn(upload_loop(inner, shutdown_rx, done_tx));
        UploadHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn flush(&self) {
        self.inner.flush_notify.notify_waiters();
    }

    /// Enable or disable accepting log entries for this client. The
    /// `TS_NO_LOGS_NO_SUPPORT` environment opt-out always remains effective.
    pub fn set_enabled(&self, enabled: bool) {
        self.inner.enabled.store(enabled, Ordering::Relaxed);
        if enabled {
            self.flush();
        }
    }

    /// Whether this client is disabled, either explicitly or by environment.
    pub fn disabled(&self) -> bool {
        self.inner.environment_disabled || !self.inner.enabled.load(Ordering::Relaxed)
    }

    pub async fn shutdown(&self) {
        let tx_opt = self.inner.shutdown_tx.lock().unwrap().take();
        if let Some(tx) = tx_opt {
            let _ = tx.send(());
        }
        let rx_opt = self.inner.done_rx.lock().unwrap().take();
        if let Some(rx) = rx_opt {
            let _ = rx.await;
        }
    }

    pub fn buffered_count(&self) -> usize {
        self.inner.buffer.lock().unwrap().len()
    }

    pub fn dropped_count(&self) -> u64 {
        self.inner.drop_count.load(Ordering::Relaxed)
    }

    pub fn collection(&self) -> &str {
        &self.inner.config.collection
    }

    pub fn upload_calls(&self) -> u64 {
        self.inner.metrics.upload_calls.load(Ordering::Relaxed)
    }

    pub fn upload_errors(&self) -> u64 {
        self.inner.metrics.upload_errors.load(Ordering::Relaxed)
    }

    pub fn uploaded_bytes(&self) -> u64 {
        self.inner.metrics.uploaded_bytes.load(Ordering::Relaxed)
    }
}

impl std::io::Write for LogTail {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LogTail::write(self, &String::from_utf8_lossy(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        LogTail::flush(self);
        Ok(())
    }
}

/// Handle to the background upload task. Drop or call [`UploadHandle::shutdown`]
/// to stop the uploader and wait for in-flight uploads to complete.
pub struct UploadHandle {
    inner: Arc<LogTailInner>,
}

impl UploadHandle {
    pub async fn shutdown(self) {
        let tx_opt = self.inner.shutdown_tx.lock().unwrap().take();
        if let Some(tx) = tx_opt {
            let _ = tx.send(());
        }
        let rx_opt = self.inner.done_rx.lock().unwrap().take();
        if let Some(rx) = rx_opt {
            let _ = rx.await;
        }
    }
}

impl Drop for UploadHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.inner.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }
}

fn upload_url_for(config: &Config) -> String {
    let base = if config.base_url.is_empty() {
        format!("https://{DEFAULT_HOST}")
    } else {
        config.base_url.clone()
    };
    let mut url = format!("{base}/c/{}/{}", config.collection, config.private_id);
    if !config.copy_private_id.is_empty() {
        url.push_str("?copyId=");
        url.push_str(&config.copy_private_id);
    }
    url
}

fn drain_buffer(buffer: &Mutex<VecDeque<LogEntry>>) -> Vec<LogEntry> {
    buffer.lock().unwrap().drain(..).collect()
}

fn maybe_compress(body: &[u8], compress_logs: bool) -> (Vec<u8>, Option<usize>) {
    if compress_logs && body.len() > 256 {
        if let Ok(zbody) = zstd::encode_all(body, 1) {
            if body.len().saturating_sub(zbody.len()) > 64 {
                return (zbody, Some(body.len()));
            }
        }
    }
    (body.to_vec(), None)
}

async fn upload_loop(
    inner: Arc<LogTailInner>,
    mut shutdown_rx: oneshot::Receiver<()>,
    done_tx: oneshot::Sender<()>,
) {
    let client = reqwest::Client::builder()
        .user_agent("")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    loop {
        let entries = drain_buffer(&inner.buffer);
        if entries.is_empty() {
            tokio::select! {
                () = inner.flush_notify.notified() => continue,
                _ = &mut shutdown_rx => break,
            }
        }

        let max_len = if inner.config.max_upload_size > 0 {
            inner.config.max_upload_size
        } else {
            MAX_UPLOAD_SIZE
        };
        let body = serialize_bounded(&entries, max_len);
        let (body, origlen) = maybe_compress(&body, inner.config.compress_logs);

        let mut last_error = String::new();
        let mut failures: u32 = 0;
        let mut first_failure: Option<Instant> = None;

        loop {
            inner.metrics.upload_calls.fetch_add(1, Ordering::Relaxed);
            match upload_single(&client, &inner.config, &body, origlen).await {
                Ok(n) => {
                    inner.metrics.uploaded_bytes.fetch_add(n, Ordering::Relaxed);
                    if failures > 0 {
                        let elapsed = first_failure.map(|t| t.elapsed()).unwrap_or_default();
                        ::log::info!(
                            "logtail: upload succeeded after {failures} failures, {elapsed:?}"
                        );
                    }
                    break;
                }
                Err((retry_after, err_str)) => {
                    failures += 1;
                    first_failure.get_or_insert_with(Instant::now);
                    inner.metrics.upload_errors.fetch_add(1, Ordering::Relaxed);

                    if last_error != err_str {
                        ::log::warn!("logtail: upload: {err_str}");
                        last_error = err_str;
                    }

                    let delay = if retry_after > Duration::ZERO {
                        std::cmp::min(retry_after, MAX_RETRY)
                    } else {
                        Duration::from_secs(30 + (rand::random::<u64>() % 31))
                    };

                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        _ = &mut shutdown_rx => break,
                    }
                }
            }
        }

        match shutdown_rx.try_recv() {
            Ok(()) | Err(oneshot::error::TryRecvError::Closed) => break,
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
    }

    let _ = done_tx.send(());
}

fn serialize_bounded(entries: &[LogEntry], max_len: usize) -> Vec<u8> {
    if entries.is_empty() {
        return b"[]".to_vec();
    }
    let mut body = Vec::with_capacity(256.min(max_len));
    body.push(b'[');
    let mut first = true;
    for entry in entries {
        let encoded = match serde_json::to_vec(entry) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !first && body.len() + encoded.len() + 1 > max_len {
            break;
        }
        if !first {
            body.push(b',');
        }
        body.extend_from_slice(&encoded);
        first = false;
    }
    body.push(b']');
    body
}

async fn upload_single(
    client: &reqwest::Client,
    config: &Config,
    body: &[u8],
    origlen: Option<usize>,
) -> Result<u64, (Duration, String)> {
    let url = upload_url_for(config);
    let mut req = client.post(&url).timeout(UPLOAD_TIMEOUT);
    if let Some(orig) = origlen {
        req = req
            .header("Content-Encoding", "zstd")
            .header("Orig-Content-Length", orig.to_string());
    }
    let resp = req.body(body.to_vec()).send().await.map_err(|e| {
        (
            Duration::ZERO,
            format!("log upload of {} bytes failed: {e}", body.len()),
        )
    })?;
    let status = resp.status();
    if status != reqwest::StatusCode::OK {
        let retry_after = resp
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let body_text = resp.text().await.unwrap_or_default();
        return Err((
            Duration::from_secs(retry_after),
            format!(
                "log upload of {} bytes failed {status}: {body_text}",
                body.len()
            ),
        ));
    }
    Ok(body.len() as u64)
}

fn proc_id() -> u32 {
    let id = rand::random::<u32>();
    if id == 0 {
        7
    } else {
        id
    }
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
    fn disabled_client_drops_entries() {
        let lt = LogTail::new(Config::default());
        lt.set_enabled(false);
        lt.write("not buffered");
        assert!(lt.disabled());
        assert_eq!(lt.buffered_count(), 0);
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
    fn upload_url_format() {
        let cfg = Config {
            collection: "tailnode.log.tailscale.io".to_string(),
            private_id: "ab".repeat(32),
            base_url: "https://log.example.com".to_string(),
            ..Default::default()
        };
        let lt = LogTail::new(cfg);
        let expected = format!(
            "https://log.example.com/c/tailnode.log.tailscale.io/{}",
            "ab".repeat(32)
        );
        assert_eq!(lt.upload_url(), expected);
    }

    #[test]
    fn upload_url_with_copy_id() {
        let cfg = Config {
            collection: "col".to_string(),
            private_id: "p".to_string(),
            copy_private_id: "c".to_string(),
            base_url: "https://x".to_string(),
            ..Default::default()
        };
        let lt = LogTail::new(cfg);
        assert_eq!(lt.upload_url(), "https://x/c/col/p?copyId=c");
    }

    #[test]
    fn upload_url_default_base() {
        let cfg = Config {
            collection: "col".to_string(),
            private_id: "p".to_string(),
            ..Default::default()
        };
        let lt = LogTail::new(cfg);
        assert_eq!(lt.upload_url(), "https://log.tailscale.com/c/col/p");
    }

    #[test]
    fn entry_serializes_to_json() {
        let lt = LogTail::new(Config::default());
        lt.write("test message");
        let entries: Vec<LogEntry> = lt.inner.buffer.lock().unwrap().drain(..).collect();
        let json = serde_json::to_string(&entries).unwrap();
        assert!(json.contains("test message"));
        assert!(json.contains("logtail"));
    }

    #[test]
    fn proc_seq_increments() {
        let lt = LogTail::new(Config::default());
        lt.write("a");
        lt.write("b");
        let entries: Vec<LogEntry> = lt.inner.buffer.lock().unwrap().drain(..).collect();
        let seq1 = entries[0].logtail.as_ref().unwrap().proc_seq.unwrap();
        let seq2 = entries[1].logtail.as_ref().unwrap().proc_seq.unwrap();
        assert_eq!(seq2, seq1 + 1);
    }

    #[test]
    fn client_time_is_rfc3339() {
        let lt = LogTail::new(Config::default());
        lt.write("test");
        let entries: Vec<LogEntry> = lt.inner.buffer.lock().unwrap().drain(..).collect();
        let json = serde_json::to_string(&entries).unwrap();
        assert!(json.contains("\"client_time\":\""));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let ct = v[0]["logtail"]["client_time"].as_str().unwrap();
        assert!(ct.contains('T'));
        assert!(ct.ends_with('Z'));
    }

    #[test]
    fn client_time_skipped_when_configured() {
        let cfg = Config {
            skip_client_time: true,
            ..Default::default()
        };
        let lt = LogTail::new(cfg);
        lt.write("test");
        let entries: Vec<LogEntry> = lt.inner.buffer.lock().unwrap().drain(..).collect();
        let json = serde_json::to_string(&entries).unwrap();
        assert!(!json.contains("client_time"));
    }

    #[test]
    fn compress_only_when_worth_it() {
        let body = vec![b'x'; 500];
        let (out, orig) = maybe_compress(&body, true);
        assert!(orig.is_some());
        assert!(out.len() < body.len());

        let small = vec![b'x'; 100];
        let (out, orig) = maybe_compress(&small, true);
        assert!(orig.is_none());
        assert_eq!(out, small);
    }

    #[test]
    fn compress_disabled() {
        let body = vec![b'x'; 500];
        let (out, orig) = maybe_compress(&body, false);
        assert!(orig.is_none());
        assert_eq!(out, body);
    }

    #[test]
    fn buffer_cap_drops_oldest() {
        let lt = LogTail::new(Config::default());
        for _ in 0..(MAX_BUFFER_ENTRIES + 10) {
            lt.write("x");
        }
        assert_eq!(lt.buffered_count(), MAX_BUFFER_ENTRIES);
        assert_eq!(lt.dropped_count(), 10);
    }

    #[tokio::test]
    async fn upload_posts_to_local_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = Config {
            collection: "test.collection".to_string(),
            private_id: "ab".repeat(32),
            base_url: format!("http://{addr}"),
            compress_logs: false,
            ..Default::default()
        };
        let lt = LogTail::new(cfg);
        lt.write("hello logtail");
        let handle = lt.start_upload();

        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16384];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let _ = tx.send(req);
        });

        let req = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .unwrap()
            .unwrap();
        handle.shutdown().await;

        assert!(req.starts_with("POST /c/test.collection/"));
        assert!(req.contains("hello logtail"));
        assert_eq!(lt.upload_calls(), 1);
        assert_eq!(lt.upload_errors(), 0);
    }

    #[tokio::test]
    async fn upload_compressed_headers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = Config {
            collection: "test.collection".to_string(),
            private_id: "ab".repeat(32),
            base_url: format!("http://{addr}"),
            compress_logs: true,
            ..Default::default()
        };
        let lt = LogTail::new(cfg);
        for i in 0..50 {
            lt.write(&format!(
                "log line number {i} with some padding text here aaa"
            ));
        }
        let handle = lt.start_upload();

        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 32768];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let _ = tx.send(req);
        });

        let req = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .unwrap()
            .unwrap();
        handle.shutdown().await;

        assert!(
            req.to_ascii_lowercase().contains("content-encoding: zstd"),
            "missing zstd header: {req}"
        );
        assert!(
            req.to_ascii_lowercase().contains("orig-content-length:"),
            "missing orig-length header: {req}"
        );
    }

    #[tokio::test]
    async fn upload_retries_on_server_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = Config {
            collection: "test.collection".to_string(),
            private_id: "ab".repeat(32),
            base_url: format!("http://{addr}"),
            compress_logs: false,
            ..Default::default()
        };
        let lt = LogTail::new(cfg);
        lt.write("retry me");
        let handle = lt.start_upload();

        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16384];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 1\r\n\r\n",
            )
            .await
            .unwrap();
            let _ = tx.send(());
        });

        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        handle.shutdown().await;

        assert!(lt.upload_errors() >= 1);
    }

    #[tokio::test]
    async fn shutdown_drains_and_stops() {
        let cfg = Config {
            collection: "c".to_string(),
            private_id: "p".to_string(),
            base_url: "http://127.0.0.1:1".to_string(),
            ..Default::default()
        };
        let lt = LogTail::new(cfg);
        lt.write("entry");
        let handle = lt.start_upload();
        handle.shutdown().await;
    }
}
