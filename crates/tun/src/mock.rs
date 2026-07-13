//! An in-memory [`Tun`] implementation for unit tests.
//!
//! `MockTun::new` returns a device plus a sender to inject packets that
//! `read_batch` will surface. Anything written via `write_packet` is captured
//! and retrievable through `written()`.

use std::io;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};

use crate::{Tun, TunPacketBatch};

/// A mock TUN device for tests.
pub struct MockTun {
    name: String,
    mtu: usize,
    read_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    writes: Mutex<Vec<Vec<u8>>>,
}

impl MockTun {
    /// Create a mock device and a sender for injecting inbound packets.
    pub fn new(name: &str, mtu: usize) -> (Self, mpsc::Sender<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(64);
        (
            Self {
                name: name.to_string(),
                mtu,
                read_rx: Mutex::new(rx),
                writes: Mutex::new(Vec::new()),
            },
            tx,
        )
    }

    /// Return all packets written to the device so far.
    pub async fn written(&self) -> Vec<Vec<u8>> {
        self.writes.lock().await.clone()
    }
}

#[async_trait]
impl Tun for MockTun {
    async fn read_batch(&self, batch: &mut TunPacketBatch) -> io::Result<()> {
        batch.clear();
        match self.read_rx.lock().await.recv().await {
            Some(pkt) => {
                let out = batch.packet_mut(0)?;
                out.clear();
                out.reserve(self.mtu);
                out.extend_from_slice(&pkt);
                batch.set_len(1);
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "mock closed")),
        }
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        self.writes.lock().await.push(packet.to_vec());
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}
