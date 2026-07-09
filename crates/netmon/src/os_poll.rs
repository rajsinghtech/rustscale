//! Non-macOS OS event source: polling fallback.
//!
//! On platforms without an AF_ROUTE equivalent (Linux, etc.), we poll the
//! interface state every `poll_interval` (default 10s). This matches Go's
//! `net/netmon/polling.go` (`pollingMon`).

use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Spawn the polling OS event source as an async task.
pub(crate) fn spawn_os_source(
    signal_tx: mpsc::Sender<()>,
    stopped: Arc<AtomicBool>,
    poll_interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if stopped.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(poll_interval).await;
            if stopped.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let _ = signal_tx.try_send(());
        }
    })
}
