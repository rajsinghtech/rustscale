//! In-memory smoltcp `Device` impl bridging the WireGuard data plane.
//!
//! Incoming IP packets (from `WgTunn::decapsulate`) are pushed into a shared
//! rx queue; the smoltcp interface reads them via `Device::receive`. Outbound
//! packets produced by smoltcp go into a shared tx queue; the caller drains
//! them via [`Netstack::pop_tx`] for WireGuard encapsulation.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::Notify;

/// Shared packet queues for the loopback device.
type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;

/// A smoltcp `Device` backed by in-memory rx/tx queues.
pub struct LoopbackDevice {
    rx: Queue,
    tx: Queue,
    mtu: usize,
    tx_notify: Arc<Notify>,
}

impl LoopbackDevice {
    pub fn new(rx: Queue, tx: Queue, mtu: usize, tx_notify: Arc<Notify>) -> Self {
        Self {
            rx,
            tx,
            mtu,
            tx_notify,
        }
    }
}

impl Device for LoopbackDevice {
    type RxToken<'a> = OwnedRxToken;
    type TxToken<'a> = OwnedTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.lock().ok()?.pop_front();
        pkt.map(|p| {
            (
                OwnedRxToken { buf: p },
                OwnedTxToken {
                    tx: self.tx.clone(),
                    tx_notify: self.tx_notify.clone(),
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(OwnedTxToken {
            tx: self.tx.clone(),
            tx_notify: self.tx_notify.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }
}

/// An rx token that owns its packet data.
pub struct OwnedRxToken {
    buf: Vec<u8>,
}

impl RxToken for OwnedRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buf)
    }
}

/// A tx token that pushes the transmitted packet into the shared tx queue.
pub struct OwnedTxToken {
    tx: Queue,
    tx_notify: Arc<Notify>,
}

impl TxToken for OwnedTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        if let Ok(mut q) = self.tx.lock() {
            q.push_back(buf);
        }
        self.tx_notify.notify_one();
        result
    }
}
