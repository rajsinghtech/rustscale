//! Wire protocol between rustscale-bench client and server.
//!
//! Header (client -> server, 14 bytes):
//!   magic [4]          = b"RSB1"
//!   mode  u8           = 0=throughput, 1=latency
//!   dir   u8           = 0=up, 1=down, 2=bidir (throughput only)
//!   duration_secs u32  = BE (throughput only)
//!   count u32          = BE (latency only)
//!
//! Ack (server -> client, 4 bytes):
//!   magic [4]          = b"RSB1"

pub const MAGIC: [u8; 4] = *b"RSB1";
pub const HEADER_LEN: usize = 14;
pub const ACK_LEN: usize = 4;

pub const MODE_THROUGHPUT: u8 = 0;
pub const MODE_LATENCY: u8 = 1;

pub const DIR_UP: u8 = 0;
pub const DIR_DOWN: u8 = 1;
pub const DIR_BIDIR: u8 = 2;

/// Buffer size for firehose writes — kept at MTU (1280) to avoid overflowing
/// the netstack's per-connection channel (64 items × 1280 < 128KB send window).
/// The netstack's pump_connection drains the channel in one pass and drops
/// data that doesn't fit in the smoltcp send buffer; smaller chunks mean
/// more of each drain batch reaches the socket.
pub const FIREHOSE_BUF_SIZE: usize = 1280;

/// Read buffer size — can be large since the netstack delivers whole TCP
/// segments into the app channel.
pub const READ_BUF_SIZE: usize = 65_535;

/// Ping message size for latency mode.
pub const PING_SIZE: usize = 8;

use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use rustscale_netstack::NetstackStream;

pub struct Header {
    pub mode: u8,
    pub direction: u8,
    pub duration_secs: u32,
    pub count: u32,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[..4].copy_from_slice(&MAGIC);
        buf[4] = self.mode;
        buf[5] = self.direction;
        buf[6..10].copy_from_slice(&self.duration_secs.to_be_bytes());
        buf[10..14].copy_from_slice(&self.count.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8; HEADER_LEN]) -> Result<Self, &'static str> {
        if buf[..4] != MAGIC {
            return Err("bad magic");
        }
        Ok(Self {
            mode: buf[4],
            direction: buf[5],
            duration_secs: u32::from_be_bytes(buf[6..10].try_into().unwrap()),
            count: u32::from_be_bytes(buf[10..14].try_into().unwrap()),
        })
    }
}

pub async fn write_header(stream: &mut NetstackStream, hdr: &Header) -> Result<(), Box<dyn Error>> {
    stream.write_all(&hdr.encode()).await?;
    Ok(())
}

pub async fn read_header(stream: &mut NetstackStream) -> Result<Header, Box<dyn Error>> {
    let mut buf = [0u8; HEADER_LEN];
    stream.read_exact(&mut buf).await?;
    Header::decode(&buf).map_err(Into::into)
}

pub async fn write_ack(stream: &mut NetstackStream) -> Result<(), Box<dyn Error>> {
    stream.write_all(&MAGIC).await?;
    Ok(())
}

pub async fn read_ack(stream: &mut NetstackStream) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; ACK_LEN];
    stream.read_exact(&mut buf).await?;
    if buf != MAGIC {
        return Err("bad ack magic".into());
    }
    Ok(())
}
