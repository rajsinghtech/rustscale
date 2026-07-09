//! Minimal DNS wire codec: parse a question and build A/AAAA/NXDOMAIN
//! responses. Only the subset needed by the MagicDNS responder is
//! implemented (single-question queries, name compression via pointers).

#![allow(clippy::cast_possible_truncation)]

use std::net::{Ipv4Addr, Ipv6Addr};

/// Decode a DNS name at `pos`, following compression pointers. Returns the
/// dotted name (without trailing dot) and the offset immediately after the
/// name *in the original message* (i.e. after the terminating 0 byte, or
/// after a 2-byte pointer when one is encountered).
fn parse_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut after = None; // position after the name in the original stream
    let mut jumped = false;
    let mut hops = 0;
    loop {
        if pos >= buf.len() || hops > 64 {
            return None;
        }
        let len = buf[pos];
        if len == 0 {
            // End of name.
            if !jumped && after.is_none() {
                after = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes).
            if pos + 1 >= buf.len() {
                return None;
            }
            if !jumped && after.is_none() {
                after = Some(pos + 2);
            }
            let offset = ((len as usize & 0x3F) << 8) | buf[pos + 1] as usize;
            pos = offset;
            jumped = true;
            hops += 1;
            continue;
        }
        let label_len = len as usize;
        if pos + 1 + label_len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[pos + 1..pos + 1 + label_len]).ok()?;
        labels.push(label.to_string());
        pos += 1 + label_len;
    }
    Some((labels.join("."), after.unwrap_or(pos)))
}

/// Parse the single question from a DNS query. Returns
/// `(name, qtype, qclass)`.
pub fn parse_question(buf: &[u8]) -> Option<(String, u16, u16)> {
    if buf.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    if qd != 1 {
        return None;
    }
    let (name, after_name) = parse_name(buf, 12)?;
    if after_name + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[after_name], buf[after_name + 1]]);
    let qclass = u16::from_be_bytes([buf[after_name + 2], buf[after_name + 3]]);
    Some((name, qtype, qclass))
}

/// The byte offset where the question section ends (header + QNAME + 4).
fn question_end(buf: &[u8]) -> Option<usize> {
    let (_, after_name) = parse_name(buf, 12)?;
    Some(after_name + 4)
}

/// Build the response header from a query: QR=1, copy RD, set RA, given
/// `rcode` and `ancount`.
fn response_header(query: &[u8], rcode: u8, ancount: u16) -> [u8; 12] {
    let id = [query[0], query[1]];
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let opcode = (flags >> 11) & 0b1111;
    let rd = (flags >> 8) & 0b1;
    let new_flags: u16 = 0x8000 // QR
        | (opcode << 11)
        | (rd << 8)
        | 0x0080 // RA
        | u16::from(rcode & 0b1111);
    [
        id[0],
        id[1],
        (new_flags >> 8) as u8,
        (new_flags & 0xFF) as u8,
        0,
        1, // QDCOUNT = 1
        (ancount >> 8) as u8,
        (ancount & 0xFF) as u8,
        0,
        0, // NSCOUNT
        0,
        0, // ARCOUNT
    ]
}

/// Build an A record response with the given IPv4 addresses.
pub fn build_a_response(query: &[u8], ips: &[Ipv4Addr]) -> Option<Vec<u8>> {
    build_addr_response(query, ips.len(), |out, idx| {
        let oct = ips[idx].octets();
        out.extend_from_slice(&oct);
    })
}

/// Build an AAAA record response with the given IPv6 addresses.
pub fn build_aaaa_response(query: &[u8], ips: &[Ipv6Addr]) -> Option<Vec<u8>> {
    build_addr_response(query, ips.len(), |out, idx| {
        let oct = ips[idx].octets();
        out.extend_from_slice(&oct);
    })
}

/// Shared builder for A (rdata 4) / AAAA (rdata 16) responses. `rdlen` is
/// inferred from `count`; `write_rdata` appends each record's rdata.
fn build_addr_response<F>(query: &[u8], count: usize, write_rdata: F) -> Option<Vec<u8>>
where
    F: Fn(&mut Vec<u8>, usize),
{
    if query.len() < 12 {
        return None;
    }
    let qend = question_end(query)?;
    let is_aaaa = {
        let (_, qtype, _) = parse_question(query)?;
        qtype == 28
    };
    let rtype: u16 = if is_aaaa { 28 } else { 1 };
    let rdlen: u16 = if is_aaaa { 16 } else { 4 };

    let mut resp = Vec::with_capacity(qend + count * (2 + 2 + 2 + 4 + 2 + rdlen as usize));
    resp.extend_from_slice(&response_header(query, 0, count as u16));
    // Echo the question section verbatim.
    resp.extend_from_slice(&query[12..qend]);
    for i in 0..count {
        // Name: compression pointer to offset 12 (start of QNAME).
        resp.push(0xC0);
        resp.push(0x0C);
        resp.extend_from_slice(&rtype.to_be_bytes()); // TYPE
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&rdlen.to_be_bytes()); // RDLENGTH
        write_rdata(&mut resp, i);
    }
    Some(resp)
}

/// Build an NXDOMAIN response (RCODE=3, 0 answers) echoing the question.
pub fn build_nxdomain(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qend = question_end(query)?;
    let mut resp = Vec::with_capacity(qend);
    resp.extend_from_slice(&response_header(query, 3, 0));
    resp.extend_from_slice(&query[12..qend]);
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS A query for `name`.
    fn make_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0xABCDu16.to_be_bytes()); // ID
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0); // name terminator
        q.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        q
    }

    #[test]
    fn parse_question_decodes_name_and_type() {
        let q = make_query("host.tailnet.ts.net", 1);
        let (name, qtype, qclass) = parse_question(&q).expect("parse");
        assert_eq!(name, "host.tailnet.ts.net");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 1);
    }

    #[test]
    fn build_a_response_has_answer() {
        let q = make_query("host.tailnet.ts.net", 1);
        let resp = build_a_response(&q, &[Ipv4Addr::new(100, 64, 0, 1)]).expect("build");
        // QR bit set in flags.
        assert_eq!(resp[2] & 0x80, 0x80);
        // ANCOUNT = 1.
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        // RCODE = 0.
        assert_eq!(resp[3] & 0x0F, 0);
        // Find the rdata (last 4 bytes) == 100.64.0.1.
        let rdata = &resp[resp.len() - 4..];
        assert_eq!(rdata, &[100, 64, 0, 1]);
    }

    #[test]
    fn build_aaaa_response_has_answer() {
        let q = make_query("host.tailnet.ts.net", 28);
        let ip = "fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap();
        let resp = build_aaaa_response(&q, &[ip]).expect("build");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        let rdata = &resp[resp.len() - 16..];
        assert_eq!(rdata, &ip.octets());
    }

    #[test]
    fn build_nxdomain_sets_rcode3() {
        let q = make_query("nope.tailnet.ts.net", 1);
        let resp = build_nxdomain(&q).expect("build");
        assert_eq!(resp[3] & 0x0F, 3, "RCODE should be NXDOMAIN(3)");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "ANCOUNT=0");
        assert_eq!(resp[2] & 0x80, 0x80, "QR set");
    }

    #[test]
    fn build_a_response_zero_ips_is_noerror_empty() {
        let q = make_query("host.tailnet.ts.net", 1);
        // Empty A answer list => NOERROR with 0 answers (not NXDOMAIN).
        let resp = build_a_response(&q, &[]).expect("build");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
        assert_eq!(resp[3] & 0x0F, 0);
    }
}
