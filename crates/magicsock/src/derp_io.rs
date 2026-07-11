//! DERP client actor: splits the `DerpClient` stream into read and write
//! halves for concurrent I/O from separate tasks.

use rand::RngCore;
use rustscale_derp::{decode_frame_header, encode_frame_header, frame_type};
use rustscale_key::NodePublic;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Command sent to the DERP write task.
enum DerpCmd {
    SendPacket { dst: NodePublic, data: Vec<u8> },
    Ping { data: [u8; 8] },
    Pong { data: [u8; 8] },
}

/// Channel-based wrapper around a DERP connection.
///
/// Uses `DerpClient::into_split` to separate read and write halves, avoiding
/// the stream-corruption problem that occurs when `select!` cancels a
/// `recv()` future mid-read. Stores the reader/writer task handles so
/// [`DerpIo::close`] can abort them (dropping the socket halves and closing
/// the connection).
pub struct DerpIo {
    cmd_tx: mpsc::Sender<DerpCmd>,
    recv_rx: tokio::sync::Mutex<mpsc::Receiver<(NodePublic, Vec<u8>)>>,
    reader_task: tokio::task::JoinHandle<()>,
    writer_task: tokio::task::JoinHandle<()>,
    keepalive_task: tokio::task::JoinHandle<()>,
}

impl DerpIo {
    /// Split a `DerpClient` into reader/writer tasks and return a channel handle.
    pub fn spawn(client: rustscale_derp::DerpClient) -> Self {
        let private_key = client.private_key();
        let (read_half, write_half, _server_key) = client.into_split();

        let (cmd_tx, mut cmd_rx) = mpsc::channel(128);
        let (recv_tx, recv_rx) = mpsc::channel(128);
        let pong_tx = cmd_tx.clone();
        let keepalive_tx = cmd_tx.clone();

        let writer_task = tokio::spawn(async move {
            let mut writer = write_half;
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    DerpCmd::SendPacket { dst, data } => {
                        let mut body = Vec::with_capacity(32 + data.len());
                        body.extend_from_slice(&dst.raw32());
                        body.extend_from_slice(&data);
                        let header =
                            encode_frame_header(frame_type::SEND_PACKET, body.len() as u32);
                        if writer.write_all(&header).await.is_err() {
                            break;
                        }
                        if writer.write_all(&body).await.is_err() {
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                    DerpCmd::Ping { data } => {
                        let header = encode_frame_header(frame_type::PING, 8);
                        if writer.write_all(&header).await.is_err() {
                            break;
                        }
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                    DerpCmd::Pong { data } => {
                        let header = encode_frame_header(frame_type::PONG, 8);
                        if writer.write_all(&header).await.is_err() {
                            break;
                        }
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let reader_task = tokio::spawn(async move {
            let mut reader = read_half;
            loop {
                let mut header = [0u8; rustscale_derp::FRAME_HEADER_LEN];
                if reader.read_exact(&mut header).await.is_err() {
                    break;
                }
                let (typ, len) = decode_frame_header(&header);
                if len > (rustscale_derp::MAX_PACKET_SIZE as u32) * 2 {
                    break;
                }
                let mut body = vec![0u8; len as usize];
                if reader.read_exact(&mut body).await.is_err() {
                    break;
                }

                if typ == frame_type::RECV_PACKET && body.len() >= 32 {
                    let mut src = [0u8; 32];
                    src.copy_from_slice(&body[..32]);
                    let source = NodePublic::from_raw32(src);
                    let data = body[32..].to_vec();
                    if recv_tx.send((source, data)).await.is_err() {
                        break;
                    }
                } else if typ == frame_type::PING && body.len() >= 8 {
                    let mut data = [0u8; 8];
                    data.copy_from_slice(&body[..8]);
                    if pong_tx.send(DerpCmd::Pong { data }).await.is_err() {
                        break;
                    }
                }
            }
        });

        let keepalive_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let mut data = [0u8; 8];
                rand::rngs::OsRng.fill_bytes(&mut data);
                if keepalive_tx.send(DerpCmd::Ping { data }).await.is_err() {
                    break;
                }
            }
        });

        drop(private_key);

        Self {
            cmd_tx,
            recv_rx: tokio::sync::Mutex::new(recv_rx),
            reader_task,
            writer_task,
            keepalive_task,
        }
    }

    pub fn close(&self) {
        self.reader_task.abort();
        self.writer_task.abort();
        self.keepalive_task.abort();
    }

    /// Send a data packet to `dst` via DERP.
    pub async fn send_packet(&self, dst: NodePublic, data: Vec<u8>) {
        let _ = self.cmd_tx.send(DerpCmd::SendPacket { dst, data }).await;
    }

    /// Try to receive the next packet from DERP (blocks until one is ready).
    pub async fn try_recv(&self) -> Option<(NodePublic, Vec<u8>)> {
        self.recv_rx.lock().await.recv().await
    }
}
