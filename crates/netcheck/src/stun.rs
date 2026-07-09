//! STUN binding request/response codec — an RFC 5389 subset, ported from
//! Tailscale's Go `net/stun` package.
//!
//! Implements:
//! - binding request generation with a random 12-byte transaction ID and a
//!   `SOFTWARE` attribute set to `"tailnode"`, plus a trailing `FINGERPRINT`.
//! - binding response generation (`XOR-MAPPED-ADDRESS`, IPv4 and IPv6).
//! - parsing of binding responses, preferring `XOR-MAPPED-ADDRESS`
//!   (`0x0020` and the alt `0x8020`) and falling back to `MAPPED-ADDRESS`.
//! - `is_stun` quick check.
//! - binding-request parsing (used by the netcheck hairpin/varies checks and
//!   by in-process fake STUN servers in tests).

#![allow(clippy::cast_possible_truncation)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use rand::RngCore;

/// A STUN transaction ID: the 12 bytes following the 4-byte magic cookie.
pub type TxID = [u8; TX_ID_LEN];
/// Length of the STUN message header (RFC 5389 §6).
pub const HEADER_LEN: usize = 20;

/// Length of a transaction ID.
pub const TX_ID_LEN: usize = 12;

/// The RFC 5389 magic cookie: `0x2112A442`.
pub const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// First half of the magic cookie, XOR'd into the port in `XOR-MAPPED-ADDRESS`.
const MAGIC_COOKIE_PORT_XOR: u16 = 0x2112;

/// The value XOR'd into the CRC-32 for the `FINGERPRINT` attribute.
const FINGERPRINT_XOR: u32 = 0x5354_554e;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// An alternate attribute type some servers emit (comprehension-optional range).
const ATTR_XOR_MAPPED_ADDRESS_ALT: u16 = 0x8020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;

/// The `SOFTWARE` value Tailscale clients advertise. Eight bytes long, so it
/// needs no padding.
const SOFTWARE: &[u8] = b"tailnode";

/// Length of a `FINGERPRINT` attribute on the wire (type + length + u32).
const FINGERPRINT_LEN: usize = 8;

/// Errors produced by STUN parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    #[error("response is not a STUN packet")]
    NotStun,
    #[error("STUN packet is not a success response")]
    NotSuccessResponse,
    #[error("STUN packet is not a binding request")]
    NotBindingRequest,
    #[error("STUN response has malformed attributes")]
    MalformedAttrs,
    #[error("STUN request came from non-Tailscale software")]
    WrongSoftware,
    #[error("STUN request didn't end in fingerprint")]
    NoFingerprint,
    #[error("STUN request had bogus fingerprint")]
    WrongFingerprint,
}

/// Generate a new cryptographically random transaction ID.
pub fn new_tx_id() -> TxID {
    let mut tx = [0u8; TX_ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut tx);
    tx
}

/// Build a STUN binding request for `tx_id`, carrying a `SOFTWARE` attribute
/// (`"tailnode"`) and a trailing `FINGERPRINT`.
pub fn request(tx_id: &TxID) -> Vec<u8> {
    // SOFTWARE attribute: 4-byte header + 8-byte value (no padding).
    const SOFTWARE_ATTR_LEN: usize = 4 + SOFTWARE.len();
    let attrs_len = SOFTWARE_ATTR_LEN + FINGERPRINT_LEN;

    let mut b = Vec::with_capacity(HEADER_LEN + attrs_len);
    // Type: binding request.
    b.extend_from_slice(&[0x00, 0x01]);
    // Length of everything after the 20-byte header.
    b.extend_from_slice(&(attrs_len as u16).to_be_bytes());
    // Magic cookie + transaction ID.
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(tx_id);

    // SOFTWARE attribute.
    b.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    b.extend_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    b.extend_from_slice(SOFTWARE);

    // FINGERPRINT attribute, computed over the packet so far.
    let fp = fingerprint(&b);
    b.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&fp.to_be_bytes());
    b
}

/// Build a STUN binding response for `tx_id` reporting `addr` as the
/// `XOR-MAPPED-ADDRESS`. Returns an empty vec for a non-IPv4/v6 address
/// (never happens for `SocketAddr` in practice).
pub fn response(tx_id: &TxID, addr: SocketAddr) -> Vec<u8> {
    let (fam, addr_bytes, port) = match addr {
        SocketAddr::V4(v4) => (0x01u8, v4.ip().octets().to_vec(), v4.port()),
        SocketAddr::V6(v6) => (0x02u8, v6.ip().octets().to_vec(), v6.port()),
    };
    let attrs_len = 8 + addr_bytes.len();
    let mut b = Vec::with_capacity(HEADER_LEN + attrs_len);

    // Type: success response.
    b.extend_from_slice(&[0x01, 0x01]);
    b.extend_from_slice(&(attrs_len as u16).to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(tx_id);

    // XOR-MAPPED-ADDRESS attribute.
    b.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    b.extend_from_slice(&((4 + addr_bytes.len()) as u16).to_be_bytes());
    b.push(0); // unused
    b.push(fam);
    b.extend_from_slice(&(port ^ MAGIC_COOKIE_PORT_XOR).to_be_bytes());

    // The address bytes: first 4 XOR'd with the magic cookie, the remainder
    // (IPv6 only) XOR'd with the transaction ID.
    for (i, &o) in addr_bytes.iter().enumerate() {
        if i < MAGIC_COOKIE.len() {
            b.push(o ^ MAGIC_COOKIE[i]);
        } else {
            b.push(o ^ tx_id[i - MAGIC_COOKIE.len()]);
        }
    }
    b
}

/// Parse a STUN binding response, returning the transaction ID and the
/// `XOR-MAPPED-ADDRESS` (or `MAPPED-ADDRESS` fallback) as a `SocketAddr`.
pub fn parse_response(b: &[u8]) -> Result<(TxID, SocketAddr), StunError> {
    if !is_stun(b) {
        return Err(StunError::NotStun);
    }
    let mut tx_id = [0u8; TX_ID_LEN];
    tx_id.copy_from_slice(&b[8..8 + TX_ID_LEN]);
    if b[0] != 0x01 || b[1] != 0x01 {
        return Err(StunError::NotSuccessResponse);
    }
    let attrs_len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let body = &b[HEADER_LEN..];
    if attrs_len > body.len() {
        return Err(StunError::MalformedAttrs);
    }
    let body = &body[..attrs_len];

    let mut xor_addr: Option<SocketAddr> = None;
    let mut fallback_addr: Option<SocketAddr> = None;

    foreach_attr(body, |attr_type, attr| match attr_type {
        ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS_ALT => {
            if let Some(ap) = xor_mapped_address(&tx_id, attr) {
                xor_addr = Some(ap);
            }
        }
        ATTR_MAPPED_ADDRESS => {
            if let Some(ap) = mapped_address(attr) {
                fallback_addr = Some(ap);
            }
        }
        _ => {}
    })?;

    xor_addr
        .or(fallback_addr)
        .map(|ap| (tx_id, ap))
        .ok_or(StunError::MalformedAttrs)
}

/// Parse a STUN binding request, verifying it came from a Tailscale client
/// (`SOFTWARE == "tailnode"`) and that it ends in a valid `FINGERPRINT`.
pub fn parse_binding_request(b: &[u8]) -> Result<TxID, StunError> {
    if !is_stun(b) {
        return Err(StunError::NotStun);
    }
    if b[0] != 0x00 || b[1] != 0x01 {
        return Err(StunError::NotBindingRequest);
    }
    let mut tx_id = [0u8; TX_ID_LEN];
    tx_id.copy_from_slice(&b[8..8 + TX_ID_LEN]);

    let mut software_ok = false;
    let mut last_attr = 0u16;
    let mut got_fp: Option<u32> = None;
    foreach_attr(&b[HEADER_LEN..], |attr_type, attr| {
        last_attr = attr_type;
        if attr_type == ATTR_SOFTWARE && attr == SOFTWARE {
            software_ok = true;
        }
        if attr_type == ATTR_FINGERPRINT && attr.len() == 4 {
            got_fp = Some(u32::from_be_bytes([attr[0], attr[1], attr[2], attr[3]]));
        }
    })?;

    if !software_ok {
        return Err(StunError::WrongSoftware);
    }
    if last_attr != ATTR_FINGERPRINT {
        return Err(StunError::NoFingerprint);
    }
    let want_fp = fingerprint(&b[..b.len() - FINGERPRINT_LEN]);
    if got_fp != Some(want_fp) {
        return Err(StunError::WrongFingerprint);
    }
    Ok(tx_id)
}

/// Quick check: does `b` look like a STUN message? (RFC 5389 §6: the top two
/// bits of the first byte are zero and bytes 4..8 are the magic cookie.)
#[must_use]
pub fn is_stun(b: &[u8]) -> bool {
    b.len() >= HEADER_LEN && b[0] & 0b1100_0000 == 0 && b[4..8] == MAGIC_COOKIE
}

/// CRC-32/IEEE over `b`, XOR'd with the STUN fingerprint constant.
fn fingerprint(b: &[u8]) -> u32 {
    crc32fast::hash(b) ^ FINGERPRINT_XOR
}

/// Walk the STUN attribute list in `b`, calling `f` with each attribute's type
/// and its (unpadded) value slice. Returns the first malformation error.
fn foreach_attr(mut b: &[u8], mut f: impl FnMut(u16, &[u8])) -> Result<(), StunError> {
    while !b.is_empty() {
        if b.len() < 4 {
            return Err(StunError::MalformedAttrs);
        }
        let attr_type = u16::from_be_bytes([b[0], b[1]]);
        let attr_len = u16::from_be_bytes([b[2], b[3]]) as usize;
        // Attributes are padded to a 4-byte boundary.
        let attr_len_padded = (attr_len + 3) & !3;
        b = &b[4..];
        if attr_len_padded > b.len() {
            return Err(StunError::MalformedAttrs);
        }
        f(attr_type, &b[..attr_len]);
        b = &b[attr_len_padded..];
    }
    Ok(())
}

/// Decode an `XOR-MAPPED-ADDRESS` attribute body into a `SocketAddr`.
/// Returns `None` on any malformation.
fn xor_mapped_address(tx_id: &TxID, b: &[u8]) -> Option<SocketAddr> {
    if b.len() < 4 {
        return None;
    }
    let xor_port = u16::from_be_bytes([b[2], b[3]]);
    let port = xor_port ^ MAGIC_COOKIE_PORT_XOR;
    let addr_field = &b[4..];
    let addr_len = family_addr_len(b[1])?;
    if addr_field.len() < addr_len {
        return None;
    }
    let xor_addr = &addr_field[..addr_len];
    let mut addr = vec![0u8; addr_len];
    for (i, &o) in xor_addr.iter().enumerate() {
        if i < MAGIC_COOKIE.len() {
            addr[i] = o ^ MAGIC_COOKIE[i];
        } else {
            addr[i] = o ^ tx_id[i - MAGIC_COOKIE.len()];
        }
    }
    build_socket_addr(b[1], &addr, port)
}

/// Decode a (non-XOR'd) `MAPPED-ADDRESS` attribute body into a `SocketAddr`.
fn mapped_address(b: &[u8]) -> Option<SocketAddr> {
    if b.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([b[2], b[3]]);
    let addr_field = &b[4..];
    let addr_len = family_addr_len(b[1])?;
    if addr_field.len() < addr_len {
        return None;
    }
    build_socket_addr(b[1], &addr_field[..addr_len], port)
}

/// The address length for a STUN address family byte, or `None` if unknown.
fn family_addr_len(fam: u8) -> Option<usize> {
    match fam {
        0x01 => Some(4),  // IPv4
        0x02 => Some(16), // IPv6
        _ => None,
    }
}

/// Build a `SocketAddr` from a family byte and decoded address bytes. Mirrors
/// Go's `netip.AddrFromSlice(...).Unmap()`: a v4-mapped v6 address (family 2
/// with `::ffff:a.b.c.d`) is returned as IPv4.
fn build_socket_addr(fam: u8, addr: &[u8], port: u16) -> Option<SocketAddr> {
    match fam {
        0x01 if addr.len() == 4 => {
            let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        0x02 if addr.len() == 16 => {
            // Unmap v4-in-v6 (`::ffff:a.b.c.d`) the way Go's Addr.Unmap does.
            let is_v4_mapped =
                addr[0..10].iter().all(|&x| x == 0) && addr[10] == 0xff && addr[11] == 0xff;
            if is_v4_mapped {
                let ip = Ipv4Addr::new(addr[12], addr[13], addr[14], addr[15]);
                Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
            } else {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(addr);
                let ip = Ipv6Addr::from(octets);
                Some(SocketAddr::new(std::net::IpAddr::V6(ip), port))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
