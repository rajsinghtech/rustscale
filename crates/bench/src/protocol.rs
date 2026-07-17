//! Wire protocol shared by the userspace-tsnet and kernel-TCP transports.
//!
//! Header (client -> server, 14 bytes):
//!   magic [4]          = b"RSB1"
//!   mode  u8           = 0=throughput, 1=latency
//!   dir   u8           = 0=up, 1=down, 2=bidir (throughput only)
//!   duration_secs u32  = BE (throughput only)
//!   count u32          = BE (latency only)
//!
//! Ready (server -> client, 4 bytes): magic [4] = b"RSB1"
//! Go (client -> server, 1 byte): b'G'. Throughput workers send this only
//! after every stream is ready, so connection setup is outside the trial.

pub const MAGIC: [u8; 4] = *b"RSB1";
pub const HEADER_LEN: usize = 14;
pub const ACK_LEN: usize = 4;
pub const GO: u8 = b'G';
pub const MODE_THROUGHPUT: u8 = 0;
pub const MODE_LATENCY: u8 = 1;
pub const DIR_UP: u8 = 0;
pub const DIR_DOWN: u8 = 1;
pub const DIR_BIDIR: u8 = 2;
pub const FIREHOSE_BUF_SIZE: usize = 1280;
pub const READ_BUF_SIZE: usize = 65_535;
pub const PING_SIZE: usize = 8;

use std::error::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy)]
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

pub async fn write_header<S: AsyncWrite + Unpin>(
    stream: &mut S,
    hdr: &Header,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    stream.write_all(&hdr.encode()).await?;
    Ok(())
}

pub async fn read_header<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Header, Box<dyn Error + Send + Sync>> {
    let mut buf = [0u8; HEADER_LEN];
    stream.read_exact(&mut buf).await?;
    Header::decode(&buf).map_err(Into::into)
}

pub async fn write_ack<S: AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    stream.write_all(&MAGIC).await?;
    Ok(())
}

pub async fn read_ack<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut buf = [0u8; ACK_LEN];
    stream.read_exact(&mut buf).await?;
    if buf != MAGIC {
        return Err("bad ack magic".into());
    }
    Ok(())
}

pub async fn write_go<S: AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    stream.write_all(&[GO]).await?;
    Ok(())
}

pub async fn read_go<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut byte = [0];
    stream.read_exact(&mut byte).await?;
    if byte[0] != GO {
        return Err("bad go byte".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip_is_transport_independent() {
        let header = Header {
            mode: MODE_THROUGHPUT,
            direction: DIR_DOWN,
            duration_secs: 10,
            count: 0,
        };
        let decoded = Header::decode(&header.encode()).unwrap();
        assert_eq!(
            (
                decoded.mode,
                decoded.direction,
                decoded.duration_secs,
                decoded.count
            ),
            (MODE_THROUGHPUT, DIR_DOWN, 10, 0)
        );
    }
}
