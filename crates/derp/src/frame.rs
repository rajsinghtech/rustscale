//! DERP frame codec — pure sync, independently testable.
//!
//! Frame layout: 1-byte type + 4-byte big-endian length (not including the
//! 5-byte header) + body.

use std::io::{self, Read, Write};

/// 1-byte frame type + 4-byte length = 5 bytes.
pub const FRAME_HEADER_LEN: usize = 1 + 4;

/// Maximum packet data size (64 KiB).
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// Maximum info frame length.
pub const MAX_INFO_LEN: usize = 1 << 20;

/// Public key length.
pub const KEY_LEN: usize = 32;

/// NaCl box nonce length.
pub const NONCE_LEN: usize = 24;

/// Current DERP protocol version.
pub const PROTOCOL_VERSION: u32 = 2;

/// DERP magic: UTF-8 of "DERP🔑".
pub const MAGIC: [u8; 8] = [0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91];

/// Frame type byte values (match Go's derp.go exactly).
pub mod frame_type {
    pub const SERVER_KEY: u8 = 0x01;
    pub const CLIENT_INFO: u8 = 0x02;
    pub const SERVER_INFO: u8 = 0x03;
    pub const SEND_PACKET: u8 = 0x04;
    pub const RECV_PACKET: u8 = 0x05;
    pub const KEEP_ALIVE: u8 = 0x06;
    pub const NOTE_PREFERRED: u8 = 0x07;
    pub const PEER_GONE: u8 = 0x08;
    pub const PEER_PRESENT: u8 = 0x09;
    pub const FORWARD_PACKET: u8 = 0x0a;
    pub const WATCH_CONNS: u8 = 0x10;
    pub const CLOSE_PEER: u8 = 0x11;
    pub const PING: u8 = 0x12;
    pub const PONG: u8 = 0x13;
    pub const HEALTH: u8 = 0x14;
    pub const RESTARTING: u8 = 0x15;
}

/// HTTP header names.
pub mod headers {
    pub const IDEAL_NODE: &str = "Ideal-Node";
    pub const FAST_START: &str = "Derp-Fast-Start";
}

/// Encode a frame header into a 5-byte array.
pub fn encode_frame_header(typ: u8, len: u32) -> [u8; FRAME_HEADER_LEN] {
    let mut buf = [0u8; FRAME_HEADER_LEN];
    buf[0] = typ;
    buf[1..5].copy_from_slice(&len.to_be_bytes());
    buf
}

/// Decode a 5-byte frame header.
pub fn decode_frame_header(buf: &[u8; FRAME_HEADER_LEN]) -> (u8, u32) {
    let typ = buf[0];
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    (typ, len)
}

/// Write a frame header to `w`.
pub fn write_frame_header<W: Write>(w: &mut W, typ: u8, len: u32) -> io::Result<()> {
    w.write_all(&encode_frame_header(typ, len))
}

/// Write a complete frame (header + body) and flush.
pub fn write_frame<W: Write>(w: &mut W, typ: u8, body: &[u8]) -> io::Result<()> {
    if body.len() > 10 << 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unreasonably large frame write",
        ));
    }
    write_frame_header(w, typ, body.len() as u32)?;
    w.write_all(body)?;
    w.flush()
}

/// Read a 5-byte frame header from `r`.
pub fn read_frame_header<R: Read>(r: &mut R) -> io::Result<(u8, u32)> {
    let mut buf = [0u8; FRAME_HEADER_LEN];
    r.read_exact(&mut buf)?;
    Ok(decode_frame_header(&buf))
}

/// Read a frame (header + body) into `buf`, returning (type, declared_len).
///
/// `buf` is resized to fit the body. If the declared length exceeds
/// `max_size`, an error is returned.
pub fn read_frame<R: Read>(r: &mut R, max_size: u32, buf: &mut Vec<u8>) -> io::Result<(u8, u32)> {
    let (typ, len) = read_frame_header(r)?;
    if len > max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame size {len} exceeds max {max_size}"),
        ));
    }
    buf.resize(len as usize, 0);
    r.read_exact(buf)?;
    Ok((typ, len))
}

/// PeerGone reason codes.
pub mod peer_gone_reason {
    pub const DISCONNECTED: u8 = 0x00;
    pub const NOT_HERE: u8 = 0x01;
    pub const MESH_CONN_BROKE: u8 = 0xf0;
}

/// PeerPresent flag bits.
pub mod peer_present_flags {
    pub const IS_REGULAR: u8 = 1 << 0;
    pub const IS_MESH_PEER: u8 = 1 << 1;
    pub const IS_PROBER: u8 = 1 << 2;
    pub const NOT_IDEAL: u8 = 1 << 3;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_frame_header_golden() {
        // SendPacket len 1024
        let mut buf = Vec::new();
        write_frame_header(&mut buf, frame_type::SEND_PACKET, 1024).unwrap();
        assert_eq!(
            buf,
            vec![frame_type::SEND_PACKET, 0x00, 0x00, 0x04, 0x00]
        );

        // KeepAlive len 0
        let mut buf = Vec::new();
        write_frame_header(&mut buf, frame_type::KEEP_ALIVE, 0).unwrap();
        assert_eq!(buf, vec![frame_type::KEEP_ALIVE, 0x00, 0x00, 0x00, 0x00]);

        // RecvPacket max len
        let mut buf = Vec::new();
        write_frame_header(&mut buf, frame_type::RECV_PACKET, 0xffff_ffff).unwrap();
        assert_eq!(
            buf,
            vec![frame_type::RECV_PACKET, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn read_frame_header_golden() {
        let input = [frame_type::SEND_PACKET, 0x00, 0x00, 0x04, 0x00];
        let (typ, len) = read_frame_header(&mut Cursor::new(&input[..])).unwrap();
        assert_eq!(typ, frame_type::SEND_PACKET);
        assert_eq!(len, 1024);

        let input = [frame_type::KEEP_ALIVE, 0, 0, 0, 0];
        let (typ, len) = read_frame_header(&mut Cursor::new(&input[..])).unwrap();
        assert_eq!(typ, frame_type::KEEP_ALIVE);
        assert_eq!(len, 0);

        let input = [frame_type::RECV_PACKET, 0xff, 0xff, 0xff, 0xff];
        let (typ, len) = read_frame_header(&mut Cursor::new(&input[..])).unwrap();
        assert_eq!(typ, frame_type::RECV_PACKET);
        assert_eq!(len, 0xffff_ffff);
    }

    #[test]
    fn frame_roundtrip_all_types() {
        for &typ in &[
            frame_type::SERVER_KEY,
            frame_type::CLIENT_INFO,
            frame_type::SERVER_INFO,
            frame_type::SEND_PACKET,
            frame_type::RECV_PACKET,
            frame_type::KEEP_ALIVE,
            frame_type::NOTE_PREFERRED,
            frame_type::PEER_GONE,
            frame_type::PEER_PRESENT,
            frame_type::FORWARD_PACKET,
            frame_type::WATCH_CONNS,
            frame_type::CLOSE_PEER,
            frame_type::PING,
            frame_type::PONG,
            frame_type::HEALTH,
            frame_type::RESTARTING,
        ] {
            let body = vec![0xde, 0xad, 0xbe, 0xef];
            let mut out = Vec::new();
            write_frame(&mut out, typ, &body).unwrap();

            let mut cursor = Cursor::new(&out[..]);
            let mut buf = Vec::new();
            let (got_typ, got_len) = read_frame(&mut cursor, MAX_PACKET_SIZE as u32, &mut buf).unwrap();
            assert_eq!(got_typ, typ);
            assert_eq!(got_len as usize, body.len());
            assert_eq!(buf, body);
        }
    }

    #[test]
    fn read_frame_rejects_oversize() {
        // Write a header claiming a huge length.
        let mut out = Vec::new();
        write_frame_header(&mut out, frame_type::SEND_PACKET, 0xffff_ffff).unwrap();
        let mut cursor = Cursor::new(&out[..]);
        let mut buf = Vec::new();
        let err = read_frame(&mut cursor, 1024, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
