//! In-memory smoltcp `Device` impl bridging the WireGuard data plane.
//!
//! Incoming IP packets (from `WgTunn::decapsulate`) are pushed into a shared
//! rx queue; the smoltcp interface reads them via `Device::receive`. Outbound
//! packets produced by smoltcp go into a shared tx queue; the caller drains
//! them via [`Netstack::pop_tx`] for WireGuard encapsulation.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::Notify;

/// Shared packet queues for the loopback device.
type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;
type RecycleQueue = Arc<Mutex<Vec<Vec<u8>>>>;

const RX_RECYCLE_CAPACITY: usize = 256;

/// A smoltcp `Device` backed by in-memory rx/tx queues.
pub struct LoopbackDevice {
    rx: Queue,
    tx: Queue,
    rx_depth: Arc<AtomicUsize>,
    tx_depth: Arc<AtomicUsize>,
    rx_ready: VecDeque<Vec<u8>>,
    rx_recycle: RecycleQueue,
    rx_recycle_ready: Vec<Vec<u8>>,
    mtu: usize,
    tx_capacity: usize,
    tx_notify: Arc<Notify>,
}

impl LoopbackDevice {
    #[cfg(test)]
    pub fn new(
        rx: Queue,
        tx: Queue,
        rx_depth: Arc<AtomicUsize>,
        tx_depth: Arc<AtomicUsize>,
        mtu: usize,
        tx_capacity: usize,
        tx_notify: Arc<Notify>,
    ) -> Self {
        Self::new_with_recycle(
            rx,
            tx,
            rx_depth,
            tx_depth,
            Arc::new(Mutex::new(Vec::new())),
            mtu,
            tx_capacity,
            tx_notify,
        )
    }

    pub(crate) fn new_with_recycle(
        rx: Queue,
        tx: Queue,
        rx_depth: Arc<AtomicUsize>,
        tx_depth: Arc<AtomicUsize>,
        rx_recycle: RecycleQueue,
        mtu: usize,
        tx_capacity: usize,
        tx_notify: Arc<Notify>,
    ) -> Self {
        assert!(tx_capacity > 0, "netstack tx capacity must be non-zero");
        Self {
            rx,
            tx,
            rx_depth,
            tx_depth,
            rx_ready: VecDeque::new(),
            rx_recycle,
            rx_recycle_ready: Vec::new(),
            mtu,
            tx_capacity,
            tx_notify,
        }
    }

    fn tx_token(&mut self) -> Option<OwnedTxToken> {
        if self.tx_depth.load(Ordering::Relaxed) >= self.tx_capacity {
            return None;
        }
        Some(OwnedTxToken {
            tx: self.tx.clone(),
            tx_depth: self.tx_depth.clone(),
            tx_capacity: self.tx_capacity,
            tx_notify: self.tx_notify.clone(),
        })
    }

    fn reply_tx_token(&self) -> Option<OwnedTxToken> {
        if self.tx_depth.load(Ordering::Relaxed) >= self.tx_capacity {
            return None;
        }
        Some(OwnedTxToken {
            tx: self.tx.clone(),
            tx_depth: self.tx_depth.clone(),
            tx_capacity: self.tx_capacity,
            tx_notify: self.tx_notify.clone(),
        })
    }

    fn pop_rx(&mut self) -> Option<Vec<u8>> {
        if self.rx_ready.is_empty() {
            let mut queue = self.rx.lock().ok()?;
            std::mem::swap(&mut *queue, &mut self.rx_ready);
        }
        let packet = self.rx_ready.pop_front();
        if packet.is_some() {
            let previous = self.rx_depth.fetch_sub(1, Ordering::Relaxed);
            assert!(previous > 0, "netstack rx depth underflow");
        }
        packet
    }

    /// Publish buffers consumed by smoltcp with one shared-pool lock per poll
    /// turn. The bounded pool keeps idle memory independent of traffic volume.
    pub(crate) fn publish_rx_recycled(&mut self) {
        if self.rx_recycle_ready.is_empty() {
            return;
        }
        if let Ok(mut recycled) = self.rx_recycle.lock() {
            while recycled.len() < RX_RECYCLE_CAPACITY {
                let Some(buffer) = self.rx_recycle_ready.pop() else {
                    break;
                };
                recycled.push(buffer);
            }
        }
        self.rx_recycle_ready.clear();
    }
}

impl Device for LoopbackDevice {
    type RxToken<'a> = OwnedRxToken<'a>;
    type TxToken<'a> = OwnedTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // smoltcp requires a transmit token alongside every receive token so
        // it can emit an immediate reply. Leave the inbound packet queued
        // while the outbound side is full instead of accepting it and then
        // dropping that reply.
        // The egress cursor keeps one-slot refills fair, while free queue
        // space still admits the reply token required to process ingress.
        let tx = self.reply_tx_token()?;
        let pkt = self.pop_rx();
        pkt.map(|buf| {
            (
                OwnedRxToken {
                    buf: Some(buf),
                    recycled: &mut self.rx_recycle_ready,
                },
                tx,
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.tx_token()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }
}

/// An rx token that owns its packet data.
pub struct OwnedRxToken<'a> {
    buf: Option<Vec<u8>>,
    recycled: &'a mut Vec<Vec<u8>>,
}

impl RxToken for OwnedRxToken<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(mut self, f: F) -> R {
        let result = f(self.buf.as_deref().expect("rx token buffer missing"));
        self.recycle();
        result
    }
}

impl OwnedRxToken<'_> {
    fn recycle(&mut self) {
        if let Some(mut buffer) = self.buf.take() {
            buffer.clear();
            self.recycled.push(buffer);
        }
    }
}

impl Drop for OwnedRxToken<'_> {
    fn drop(&mut self) {
        self.recycle();
    }
}

/// A tx token that pushes the transmitted packet into the shared tx queue.
pub struct OwnedTxToken {
    tx: Queue,
    tx_depth: Arc<AtomicUsize>,
    tx_capacity: usize,
    tx_notify: Arc<Notify>,
}

impl TxToken for OwnedTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        if let Ok(mut q) = self.tx.lock() {
            // The device is the sole producer and smoltcp consumes a token
            // synchronously, so a reserved slot cannot be stolen between
            // `transmit` and `consume`. The pump may only make more room.
            assert!(
                q.len() < self.tx_capacity,
                "netstack tx token overcommitted"
            );
            q.push_back(buf);
            self.tx_depth.fetch_add(1, Ordering::Relaxed);
        }
        self.tx_notify.notify_one();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturated_transmit_resumes_after_one_slot_is_drained() {
        let rx = Arc::new(Mutex::new(VecDeque::new()));
        let tx = Arc::new(Mutex::new(VecDeque::new()));
        let rx_depth = Arc::new(AtomicUsize::new(0));
        let tx_depth = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(Notify::new());
        let mut device =
            LoopbackDevice::new(rx, tx.clone(), rx_depth, tx_depth.clone(), 1280, 2, notify);
        let now = Instant::from_millis(0);

        device
            .transmit(now)
            .expect("first slot")
            .consume(1, |packet| packet[0] = 1);
        device
            .transmit(now)
            .expect("second slot")
            .consume(1, |packet| packet[0] = 2);
        assert!(
            device.transmit(now).is_none(),
            "full queue must backpressure"
        );

        assert_eq!(tx.lock().unwrap().pop_front(), Some(vec![1]));
        tx_depth.fetch_sub(1, Ordering::Relaxed);
        device
            .transmit(now)
            .expect("freed slot")
            .consume(1, |packet| packet[0] = 3);
        assert_eq!(
            tx.lock().unwrap().iter().cloned().collect::<Vec<_>>(),
            vec![vec![2], vec![3]]
        );
    }

    #[test]
    fn receive_and_transmit_resume_after_partial_drain() {
        let rx = Arc::new(Mutex::new(VecDeque::from([vec![9]])));
        let tx = Arc::new(Mutex::new(VecDeque::from([vec![1], vec![2]])));
        let rx_depth = Arc::new(AtomicUsize::new(1));
        let tx_depth = Arc::new(AtomicUsize::new(2));
        let notify = Arc::new(Notify::new());
        let mut device = LoopbackDevice::new(
            rx.clone(),
            tx.clone(),
            rx_depth.clone(),
            tx_depth.clone(),
            1280,
            2,
            notify,
        );
        let now = Instant::from_millis(0);

        assert!(device.receive(now).is_none());
        assert_eq!(rx.lock().unwrap().front(), Some(&vec![9]));
        assert!(
            device.transmit(now).is_none(),
            "full egress must backpressure"
        );

        tx.lock().unwrap().pop_front();
        tx_depth.fetch_sub(1, Ordering::Relaxed);
        assert!(device.receive(now).is_some());
        assert!(rx.lock().unwrap().is_empty());
        assert_eq!(rx_depth.load(Ordering::Relaxed), 0);
        assert!(device.transmit(now).is_some());
    }

    #[test]
    fn receive_cache_preserves_packets_published_during_a_drain() {
        let rx = Arc::new(Mutex::new(VecDeque::from([vec![1], vec![2]])));
        let tx = Arc::new(Mutex::new(VecDeque::new()));
        let rx_depth = Arc::new(AtomicUsize::new(2));
        let tx_depth = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(Notify::new());
        let mut device =
            LoopbackDevice::new(rx.clone(), tx, rx_depth.clone(), tx_depth, 1280, 4, notify);
        let now = Instant::from_millis(0);

        let first = device
            .receive(now)
            .expect("first packet")
            .0
            .consume(<[u8]>::to_vec);
        {
            let mut queue = rx.lock().unwrap();
            queue.push_back(vec![3]);
            rx_depth.fetch_add(1, Ordering::Relaxed);
        }
        let second = device
            .receive(now)
            .expect("cached second packet")
            .0
            .consume(<[u8]>::to_vec);
        let third = device
            .receive(now)
            .expect("newly published third packet")
            .0
            .consume(<[u8]>::to_vec);

        assert_eq!([first, second, third], [vec![1], vec![2], vec![3]]);
        assert_eq!(rx_depth.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn consumed_rx_buffers_publish_once_per_poll_turn() {
        let mut packet = Vec::with_capacity(2048);
        packet.extend_from_slice(&[1, 2, 3]);
        let allocation = packet.as_ptr();
        let rx = Arc::new(Mutex::new(VecDeque::from([packet])));
        let tx = Arc::new(Mutex::new(VecDeque::new()));
        let rx_depth = Arc::new(AtomicUsize::new(1));
        let tx_depth = Arc::new(AtomicUsize::new(0));
        let recycled = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let mut device = LoopbackDevice::new_with_recycle(
            rx,
            tx,
            rx_depth,
            tx_depth,
            Arc::clone(&recycled),
            1280,
            4,
            notify,
        );

        device
            .receive(Instant::from_millis(0))
            .expect("rx token")
            .0
            .consume(|body| assert_eq!(body, &[1, 2, 3]));
        assert!(recycled.lock().unwrap().is_empty());

        device.publish_rx_recycled();
        let recycled = recycled.lock().unwrap();
        assert_eq!(recycled.len(), 1);
        assert!(recycled[0].is_empty());
        assert_eq!(recycled[0].as_ptr(), allocation);
    }
}
