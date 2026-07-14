//! Packet capture sink and pcap encoder.
//!
//! The custom payload metadata uses Tailscale's LINKTYPE_USER0 format.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// The capture point at which a plaintext packet was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum CapturePath {
    FromLocal = 0,
    FromPeer = 1,
    SynthesizedToLocal = 2,
    SynthesizedToPeer = 3,
    #[allow(dead_code)]
    PathDisco = 254,
}

/// Original addresses saved by NAT rewriting, if any.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CaptureMeta {
    pub(crate) original_src: Option<IpAddr>,
    pub(crate) original_dst: Option<IpAddr>,
}

/// A destination for encoded pcap bytes.
pub(crate) trait CaptureOutput: Send {
    fn write(&mut self, buf: &[u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

impl<T: Write + Send> CaptureOutput for T {
    fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_all(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Write::flush(self)
    }
}

/// A nonblocking capture output for a LocalAPI client.
///
/// A slow client is dropped when its bounded queue is full. Packet processing
/// must never wait for an HTTP peer to consume a capture record.
pub(crate) struct ChannelOutput {
    tx: mpsc::Sender<Vec<u8>>,
}

impl ChannelOutput {
    pub(crate) fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl CaptureOutput for ChannelOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.tx.try_send(buf.to_vec()).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "capture client is too slow")
            }
            mpsc::error::TrySendError::Closed(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "capture client disconnected")
            }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Shared optional capture sink. Pumps retain this slot and only acquire its
/// read lock when deciding whether a packet needs capture work.
pub(crate) type CaptureSlot = Arc<RwLock<Option<Arc<Sink>>>>;

pub(crate) fn new_slot() -> CaptureSlot {
    Arc::new(RwLock::new(None))
}

pub(crate) fn get_or_set(slot: &CaptureSlot) -> Arc<Sink> {
    let mut guard = slot.write().expect("capture slot lock poisoned");
    if let Some(sink) = guard.as_ref() {
        return sink.clone();
    }
    let sink = Arc::new(Sink::new());
    *guard = Some(sink.clone());
    sink
}

pub(crate) fn clear(slot: &CaptureSlot) {
    if let Some(sink) = slot.write().expect("capture slot lock poisoned").take() {
        sink.close();
    }
}

pub(crate) fn log_packet(slot: &CaptureSlot, path: CapturePath, data: &[u8]) {
    // This is the disabled-capture hot path: one read-lock/Option check.
    let sink = slot
        .read()
        .expect("capture slot lock poisoned")
        .as_ref()
        .cloned();
    if let Some(sink) = sink {
        sink.log_packet(path, SystemTime::now(), data, CaptureMeta::default());
    }
}

/// Fanout sink for pcap records.
pub(crate) struct Sink {
    closed: AtomicBool,
    next_output: AtomicU64,
    flush_pending: AtomicBool,
    outputs: Mutex<HashMap<u64, Box<dyn CaptureOutput>>>,
    closed_token: CancellationToken,
}

impl Sink {
    pub(crate) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            next_output: AtomicU64::new(0),
            flush_pending: AtomicBool::new(false),
            outputs: Mutex::new(HashMap::new()),
            closed_token: CancellationToken::new(),
        }
    }

    /// Register an output and immediately write its pcap global header.
    pub(crate) fn register_output<O: CaptureOutput + 'static>(
        self: &Arc<Self>,
        mut output: O,
    ) -> io::Result<CaptureHandle> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(CaptureHandle::empty());
        }
        output.write(&pcap_header())?;
        let id = self.next_output.fetch_add(1, Ordering::Relaxed);
        self.outputs
            .lock()
            .expect("capture outputs lock poisoned")
            .insert(id, Box::new(output));
        Ok(CaptureHandle {
            sink: Arc::downgrade(self),
            id: Some(id),
        })
    }

    pub(crate) fn log_packet(
        self: &Arc<Self>,
        path: CapturePath,
        when: SystemTime,
        data: &[u8],
        meta: CaptureMeta,
    ) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let record = pcap_record(path, when, data, meta);
        let mut outputs = self.outputs.lock().expect("capture outputs lock poisoned");
        outputs.retain(|_, output| output.write(&record).is_ok());
        drop(outputs);
        self.schedule_flush();
    }

    pub(crate) fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.outputs
            .lock()
            .expect("capture outputs lock poisoned")
            .clear();
        self.closed_token.cancel();
    }

    pub(crate) async fn wait(&self) {
        self.closed_token.cancelled().await;
    }

    #[cfg(test)]
    fn output_count(&self) -> usize {
        self.outputs.lock().unwrap().len()
    }

    fn unregister(&self, id: u64) {
        self.outputs
            .lock()
            .expect("capture outputs lock poisoned")
            .remove(&id);
    }

    fn schedule_flush(self: &Arc<Self>) {
        if self
            .flush_pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // A dedicated short-lived thread keeps the packet path independent of
        // a Tokio runtime and coalesces file/HTTP flushes like the Go sink.
        let sink = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            if !sink.closed.load(Ordering::Acquire) {
                let mut outputs = sink.outputs.lock().expect("capture outputs lock poisoned");
                outputs.retain(|_, output| output.flush().is_ok());
            }
            sink.flush_pending.store(false, Ordering::Release);
        });
    }
}

/// Removes one registered output when dropped.
pub(crate) struct CaptureHandle {
    sink: Weak<Sink>,
    id: Option<u64>,
}

impl CaptureHandle {
    fn empty() -> Self {
        Self {
            sink: Weak::new(),
            id: None,
        }
    }

    pub(crate) fn unregister(mut self) {
        self.remove();
    }

    fn remove(&mut self) {
        if let Some(id) = self.id.take() {
            if let Some(sink) = self.sink.upgrade() {
                sink.unregister(id);
            }
        }
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.remove();
    }
}

fn pcap_header() -> [u8; 24] {
    let mut out = [0; 24];
    out[0..4].copy_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    out[4..6].copy_from_slice(&2u16.to_le_bytes());
    out[6..8].copy_from_slice(&4u16.to_le_bytes());
    out[16..20].copy_from_slice(&65535u32.to_le_bytes());
    out[20..24].copy_from_slice(&147u32.to_le_bytes());
    out
}

fn pcap_record(path: CapturePath, when: SystemTime, data: &[u8], meta: CaptureMeta) -> Vec<u8> {
    let src = meta.original_src.map(ip_bytes).unwrap_or_default();
    let dst = meta.original_dst.map(ip_bytes).unwrap_or_default();
    let extra = 4 + src.len() + dst.len();
    let len = data.len() + extra;
    let elapsed = when.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = elapsed.as_secs() as u32;
    let micros = elapsed.subsec_micros();
    let mut out = Vec::with_capacity(16 + len);
    out.extend_from_slice(&seconds.to_le_bytes());
    out.extend_from_slice(&micros.to_le_bytes());
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(&(path as u16).to_le_bytes());
    out.push(src.len() as u8);
    out.extend_from_slice(&src);
    out.push(dst.len() as u8);
    out.extend_from_slice(&dst);
    out.extend_from_slice(data);
    out
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn global_header_is_byte_exact() {
        assert_eq!(
            pcap_header(),
            [
                0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
                0, 0, 0x93, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn record_encodes_no_nat_metadata() {
        let record = pcap_record(
            CapturePath::FromPeer,
            UNIX_EPOCH + Duration::from_micros(1_234_567),
            &[1, 2, 3],
            CaptureMeta::default(),
        );
        assert_eq!(
            record,
            [1, 0, 0, 0, 0x47, 0x94, 0x03, 0, 7, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 1, 2, 3,]
        );
    }

    #[test]
    fn fans_out_to_multiple_outputs() {
        let sink = Arc::new(Sink::new());
        let first = SharedWriter::default();
        let second = SharedWriter::default();
        let _first = sink.register_output(first.clone()).unwrap();
        let _second = sink.register_output(second.clone()).unwrap();
        sink.log_packet(
            CapturePath::FromLocal,
            UNIX_EPOCH,
            &[42],
            CaptureMeta::default(),
        );
        assert_eq!(*first.0.lock().unwrap(), *second.0.lock().unwrap());
        assert_eq!(first.0.lock().unwrap().len(), 24 + 21);
    }

    #[test]
    fn removes_erroring_output() {
        let sink = Arc::new(Sink::new());
        // Header writes too, so register a writer that only starts failing
        // after the immediate global-header write.
        struct FailsAfterHeader(bool);
        impl Write for FailsAfterHeader {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.0 {
                    Err(io::Error::other("nope"))
                } else {
                    self.0 = true;
                    Ok(buf.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let _handle = sink.register_output(FailsAfterHeader(false)).unwrap();
        sink.log_packet(
            CapturePath::FromLocal,
            UNIX_EPOCH,
            &[],
            CaptureMeta::default(),
        );
        assert_eq!(sink.output_count(), 0);
    }

    #[tokio::test]
    async fn close_stops_logging_and_wakes_waiters() {
        let sink = Arc::new(Sink::new());
        let writer = SharedWriter::default();
        let _handle = sink.register_output(writer.clone()).unwrap();
        let waiter = sink.clone();
        let wait = tokio::spawn(async move { waiter.wait().await });
        sink.close();
        wait.await.unwrap();
        let before = writer.0.lock().unwrap().len();
        sink.log_packet(
            CapturePath::FromLocal,
            UNIX_EPOCH,
            &[1],
            CaptureMeta::default(),
        );
        assert_eq!(writer.0.lock().unwrap().len(), before);
    }
}
