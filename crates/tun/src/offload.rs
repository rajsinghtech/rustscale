//! Safe, platform-neutral virtio-net GSO receive splitting.

use std::io;

use crate::TunPacketBatch;

pub(crate) const VIRTIO_NET_HDR_LEN: usize = 10;
pub(crate) const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub(crate) const GSO_NONE: u8 = 0;
pub(crate) const GSO_TCPV4: u8 = 1;
pub(crate) const GSO_UDP_L4: u8 = 3;
pub(crate) const GSO_TCPV6: u8 = 4;

#[derive(Clone, Copy)]
pub(crate) struct VirtioHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

pub(crate) fn virtio_header(raw: &[u8]) -> io::Result<VirtioHdr> {
    if raw.len() < VIRTIO_NET_HDR_LEN {
        return invalid("short virtio header");
    }
    Ok(VirtioHdr {
        flags: raw[0],
        gso_type: raw[1],
        hdr_len: u16::from_ne_bytes([raw[2], raw[3]]),
        gso_size: u16::from_ne_bytes([raw[4], raw[5]]),
        csum_start: u16::from_ne_bytes([raw[6], raw[7]]),
        csum_offset: u16::from_ne_bytes([raw[8], raw[9]]),
    })
}

fn invalid<T>(message: &'static str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}
fn add(a: usize, b: usize) -> io::Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "packet offset overflow"))
}
fn range(data: &[u8], offset: usize, len: usize) -> io::Result<&[u8]> {
    data.get(offset..add(offset, len)?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short packet"))
}
fn put16(data: &mut [u8], offset: usize, value: u16) -> io::Result<()> {
    let dst = data
        .get_mut(offset..add(offset, 2)?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short packet"))?;
    dst.copy_from_slice(&value.to_be_bytes());
    Ok(())
}
fn put32(data: &mut [u8], offset: usize, value: u32) -> io::Result<()> {
    let dst = data
        .get_mut(offset..add(offset, 4)?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short packet"))?;
    dst.copy_from_slice(&value.to_be_bytes());
    Ok(())
}
fn be16(data: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_be_bytes(
        range(data, offset, 2)?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "short packet"))?,
    ))
}
fn be32(data: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        range(data, offset, 4)?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "short packet"))?,
    ))
}

/// Return a non-complemented Internet checksum sum.
fn checksum(data: &[u8], initial: u16) -> u16 {
    // Accumulate native-endian words, as wireguard-go does. Converting the
    // accumulator at each boundary retains Internet checksum byte order on
    // both little- and big-endian targets.
    let mut sum = u64::from_be_bytes(u64::from(initial).to_ne_bytes());
    let mut data = data;

    macro_rules! add_words {
        ($sum:expr, $carry:expr; $($offset:literal),+ $(,)?) => {
            $(add_with_carry($sum, native_u64(&data[$offset..$offset + 8]), $carry);)+
        };
    }

    while data.len() >= 128 {
        let mut carry = 0;
        add_words!(&mut sum, &mut carry; 0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120);
        sum = sum.wrapping_add(carry);
        data = &data[128..];
    }
    if data.len() >= 64 {
        let mut carry = 0;
        add_words!(&mut sum, &mut carry; 0, 8, 16, 24, 32, 40, 48, 56);
        sum = sum.wrapping_add(carry);
        data = &data[64..];
    }
    if data.len() >= 32 {
        let mut carry = 0;
        add_words!(&mut sum, &mut carry; 0, 8, 16, 24);
        sum = sum.wrapping_add(carry);
        data = &data[32..];
    }
    if data.len() >= 16 {
        let mut carry = 0;
        add_words!(&mut sum, &mut carry; 0, 8);
        sum = sum.wrapping_add(carry);
        data = &data[16..];
    }
    if data.len() >= 8 {
        let (next, carry) = sum.overflowing_add(native_u64(&data[..8]));
        sum = next.wrapping_add(u64::from(carry));
        data = &data[8..];
    }
    if data.len() >= 4 {
        let word = u32::from_ne_bytes(data[..4].try_into().expect("four-byte tail"));
        let (next, carry) = sum.overflowing_add(u64::from(word));
        sum = next.wrapping_add(u64::from(carry));
        data = &data[4..];
    }
    if data.len() >= 2 {
        let word = u16::from_ne_bytes(data[..2].try_into().expect("two-byte tail"));
        let (next, carry) = sum.overflowing_add(u64::from(word));
        sum = next.wrapping_add(u64::from(carry));
        data = &data[2..];
    }
    if let [byte] = data {
        let word = u16::from_ne_bytes([*byte, 0]);
        let (next, carry) = sum.overflowing_add(u64::from(word));
        sum = next.wrapping_add(u64::from(carry));
    }

    let mut sum = u64::from_ne_bytes(sum.to_be_bytes());
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn native_u64(data: &[u8]) -> u64 {
    u64::from_ne_bytes(data[..8].try_into().expect("eight-byte word"))
}

fn add_with_carry(sum: &mut u64, word: u64, carry: &mut u64) {
    let (next, first_carry) = sum.overflowing_add(word);
    let (next, second_carry) = next.overflowing_add(*carry);
    *sum = next;
    *carry = u64::from(first_carry || second_carry);
}
fn pseudo(protocol: u8, src: &[u8], dst: &[u8], len: u16) -> u16 {
    let sum = checksum(src, 0);
    let sum = checksum(dst, sum);
    let sum = checksum(&[0, protocol], sum);
    checksum(&len.to_be_bytes(), sum)
}

/// Split one virtio-net frame. On every error `batch` is empty and may be
/// reused, even if output storage was changed while constructing a segment.
pub(crate) fn split_virtio(raw: &[u8], batch: &mut TunPacketBatch) -> io::Result<()> {
    batch.clear();
    let result = split_virtio_inner(raw, batch);
    if result.is_err() {
        batch.clear();
    }
    result
}

fn split_virtio_inner(raw: &[u8], batch: &mut TunPacketBatch) -> io::Result<()> {
    let header = virtio_header(raw)?;
    let input = raw
        .get(VIRTIO_NET_HDR_LEN..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short virtio frame"))?;
    if !matches!(
        header.gso_type,
        GSO_NONE | GSO_TCPV4 | GSO_UDP_L4 | GSO_TCPV6
    ) {
        return invalid("unsupported virtio GSO type");
    }
    if header.gso_type != GSO_NONE && header.gso_size == 0 {
        return invalid("zero GSO size");
    }
    let cs = usize::from(header.csum_start);
    let csum_at = add(cs, usize::from(header.csum_offset))?;
    if add(csum_at, 2)? > input.len() {
        return invalid("checksum offset out of bounds");
    }
    if header.gso_type == GSO_NONE {
        return split_none(input, header, cs, csum_at, batch);
    }

    // hdr_len is kernel metadata and is deliberately ignored for GSO frames.
    let transport_header_len = if header.gso_type == GSO_UDP_L4 {
        8
    } else {
        let offset = add(cs, 12)?;
        let byte = *input
            .get(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short TCP header"))?;
        let len = usize::from(byte >> 4) * 4;
        if !(20..=60).contains(&len) {
            return invalid("invalid TCP header length");
        }
        len
    };
    let header_len = add(cs, transport_header_len)?;
    if header_len > input.len() {
        return invalid("packet shorter than headers");
    }
    split_gso(
        input,
        header,
        cs,
        csum_at,
        header_len,
        transport_header_len,
        batch,
    )
}

fn split_none(
    input: &[u8],
    header: VirtioHdr,
    cs: usize,
    csum_at: usize,
    batch: &mut TunPacketBatch,
) -> io::Result<()> {
    if usize::from(header.hdr_len) > input.len() || cs > input.len() {
        return invalid("invalid header length");
    }
    copy_single(input, header.flags, cs, csum_at, batch)
}

fn copy_single(
    input: &[u8],
    flags: u8,
    cs: usize,
    csum_at: usize,
    batch: &mut TunPacketBatch,
) -> io::Result<()> {
    let out = batch.packet_mut(0)?;
    out.clear();
    out.extend_from_slice(input);
    if flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
        let initial = be16(out, csum_at)?;
        put16(out, csum_at, 0)?;
        let sum = checksum(range(out, cs, out.len() - cs)?, initial);
        put16(out, csum_at, !sum)?;
    }
    batch.set_len(1);
    Ok(())
}

fn split_gso(
    input: &[u8],
    header: VirtioHdr,
    cs: usize,
    csum_at: usize,
    header_len: usize,
    transport_header_len: usize,
    batch: &mut TunPacketBatch,
) -> io::Result<()> {
    let first = *input
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty packet"))?;
    let version = first >> 4;
    let (ip_header_len, address_offset, address_len) = match version {
        4 => {
            if !matches!(header.gso_type, GSO_TCPV4 | GSO_UDP_L4) {
                return invalid("IP/GSO mismatch");
            }
            let ihl = usize::from(first & 0x0f) * 4;
            if !(20..=60).contains(&ihl) || ihl > input.len() {
                return invalid("invalid IPv4 header length");
            }
            (ihl, 12, 4)
        }
        6 => {
            if !matches!(header.gso_type, GSO_TCPV6 | GSO_UDP_L4) {
                return invalid("IP/GSO mismatch");
            }
            if input.len() < 40 {
                return invalid("short IPv6");
            }
            if cs < 40 {
                return invalid("invalid IPv6 transport offset");
            }
            (40, 8, 16)
        }
        _ => return invalid("IP/GSO mismatch"),
    };
    let expected_checksum = add(
        cs,
        if matches!(header.gso_type, GSO_TCPV4 | GSO_TCPV6) {
            16
        } else {
            6
        },
    )?;
    if (version == 4 && cs != ip_header_len)
        || csum_at != expected_checksum
        || add(csum_at, 2)? > add(cs, transport_header_len)?
    {
        return invalid("invalid transport checksum offset");
    }
    let tcp = matches!(header.gso_type, GSO_TCPV4 | GSO_TCPV6);
    if tcp && transport_header_len < 20 {
        return invalid("short TCP");
    }
    let protocol = if tcp { 6 } else { 17 };
    let payload_len = input.len() - header_len;
    let gso_size = usize::from(header.gso_size);
    if payload_len < gso_size {
        return copy_single(input, header.flags, cs, csum_at, batch);
    }
    let count = payload_len.div_ceil(gso_size);
    if count == 0 {
        return invalid("empty GSO payload");
    }
    if count > TunPacketBatch::MAX_PACKETS {
        return invalid("too many GSO segments");
    }
    let sequence = if tcp { be32(input, add(cs, 4)?)? } else { 0 };
    let base_id = if version == 4 { be16(input, 4)? } else { 0 };

    for index in 0..count {
        let data_start = add(
            header_len,
            index.checked_mul(gso_size).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "segment offset overflow")
            })?,
        )?;
        let data_end = add(data_start, gso_size)?.min(input.len());
        let data = input
            .get(data_start..data_end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "segment bounds"))?;
        let total = add(header_len, data.len())?;
        let transport_len = total
            .checked_sub(cs)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "transport bounds"))?;
        let total_u16 = u16::try_from(total)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "segment too large"))?;
        let transport_u16 = u16::try_from(transport_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "segment too large"))?;
        let out = batch.packet_mut(index)?;
        out.clear();
        out.extend_from_slice(range(input, 0, header_len)?);
        out.extend_from_slice(data);
        if version == 4 {
            put16(out, 2, total_u16)?;
            put16(out, 4, base_id.wrapping_add(index as u16))?;
            put16(out, 10, 0)?;
            let ip_sum = !checksum(range(out, 0, ip_header_len)?, 0);
            put16(out, 10, ip_sum)?;
        } else {
            let ipv6_payload_len = total
                .checked_sub(ip_header_len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "IPv6 bounds"))?;
            let ipv6_payload_u16 = u16::try_from(ipv6_payload_len)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "segment too large"))?;
            put16(out, 4, ipv6_payload_u16)?;
        }
        if tcp {
            put32(
                out,
                add(cs, 4)?,
                sequence.wrapping_add(u32::from(header.gso_size).wrapping_mul(index as u32)),
            )?;
            if index + 1 < count {
                let flags = out.get_mut(add(cs, 13)?).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "short TCP header")
                })?;
                *flags &= !0x09;
            }
        } else {
            put16(out, add(cs, 4)?, transport_u16)?;
        }
        put16(out, csum_at, 0)?;
        let source = range(input, address_offset, address_len)?;
        let destination = range(input, add(address_offset, address_len)?, address_len)?;
        let sum = !checksum(
            range(out, cs, transport_len)?,
            pseudo(protocol, source, destination, transport_u16),
        );
        put16(out, csum_at, sum)?;
    }
    batch.set_len(count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pre-fast-path two-byte implementation. Keep this independent from
    // the native-word path so differential tests protect byte order and carry
    // handling.
    fn scalar_checksum(data: &[u8], initial: u16) -> u16 {
        let mut sum = u32::from(initial);
        for word in data.chunks(2) {
            sum += if let [a, b] = word {
                u32::from(u16::from_be_bytes([*a, *b]))
            } else {
                u32::from(word[0]) << 8
            };
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    #[test]
    fn checksum_matches_scalar_for_lengths_initials_and_alignments() {
        const INITIALS: &[u16] = &[0, 1, 0x1234, 0x7fff, 0xffff];
        const BOUNDARIES: &[usize] = &[
            1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 129, 255, 256, 511,
        ];

        let mut bytes = vec![0; 520];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = match index % 11 {
                0 | 1 => 0xff,
                _ => (index as u8).wrapping_mul(73).wrapping_add(29),
            };
        }

        for offset in 0..8 {
            let aligned = &bytes[offset..];
            for len in 0..=512 {
                let data = &aligned[..len];
                for &initial in INITIALS {
                    assert_eq!(
                        checksum(data, initial),
                        scalar_checksum(data, initial),
                        "offset={offset}, len={len}, initial={initial:#06x}",
                    );
                }
            }
            for &len in BOUNDARIES {
                for &initial in INITIALS {
                    assert_eq!(
                        checksum(&aligned[..len], initial),
                        scalar_checksum(&aligned[..len], initial),
                        "boundary offset={offset}, len={len}, initial={initial:#06x}",
                    );
                }
            }
        }
    }

    fn virtio(
        gso: u8,
        size: u16,
        cs: u16,
        offset: u16,
        hdr_len: u16,
        flags: u8,
        packet: Vec<u8>,
    ) -> Vec<u8> {
        let mut raw = vec![flags, gso];
        raw.extend_from_slice(&hdr_len.to_ne_bytes());
        raw.extend_from_slice(&size.to_ne_bytes());
        raw.extend_from_slice(&cs.to_ne_bytes());
        raw.extend_from_slice(&offset.to_ne_bytes());
        raw.extend_from_slice(&packet);
        raw
    }
    fn packet(v6: bool, tcp: bool, payload: &[u8]) -> (Vec<u8>, usize) {
        let ip = if v6 { 40 } else { 20 };
        let transport = if tcp { 20 } else { 8 };
        let mut p = vec![0; ip + transport];
        if v6 {
            p[0] = 0x60;
            p[6] = if tcp { 6 } else { 17 };
            p[8..24].copy_from_slice(&[1; 16]);
            p[24..40].copy_from_slice(&[2; 16]);
            p[4..6].copy_from_slice(
                &u16::try_from(transport + payload.len())
                    .unwrap()
                    .to_be_bytes(),
            );
        } else {
            p[0] = 0x45;
            p[2..4].copy_from_slice(
                &u16::try_from(ip + transport + payload.len())
                    .unwrap()
                    .to_be_bytes(),
            );
            p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
            p[8] = 64;
            p[9] = if tcp { 6 } else { 17 };
            p[12..16].copy_from_slice(&[10, 0, 0, 1]);
            p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        }
        if tcp {
            p[ip + 4..ip + 8].copy_from_slice(&100u32.to_be_bytes());
            p[ip + 12] = 0x50;
            p[ip + 13] = 0x19; // ACK, PSH, FIN
        } else {
            p[ip + 4..ip + 6]
                .copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        }
        p.extend_from_slice(payload);
        (p, ip)
    }
    // A separate checksum implementation: including a valid checksum produces
    // one's-complement zero after folding.
    fn verify_checksum(packet: &[u8], ip: usize, cs: usize, tcp: bool) {
        let mut sum = 0u32;
        let add = |sum: &mut u32, bytes: &[u8]| {
            for pair in bytes.chunks(2) {
                *sum += if pair.len() == 2 {
                    u32::from(u16::from_be_bytes([pair[0], pair[1]]))
                } else {
                    u32::from(pair[0]) << 8
                };
            }
        };
        if ip == 20 {
            add(&mut sum, &packet[12..20]);
        } else {
            add(&mut sum, &packet[8..40]);
        }
        let len = packet.len() - cs;
        add(&mut sum, &[0, if tcp { 6 } else { 17 }]);
        add(&mut sum, &u16::try_from(len).unwrap().to_be_bytes());
        add(&mut sum, &packet[cs..]);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum, 0xffff, "transport checksum must verify independently");
    }
    fn verify_ip_checksum(packet: &[u8]) {
        let mut sum = 0u32;
        for pair in packet[..20].chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum, 0xffff);
    }
    fn verify_partial_checksum(packet: &[u8], start: usize, initial: u16) {
        let mut sum = u32::from(initial);
        for pair in packet[start..].chunks(2) {
            sum += if pair.len() == 2 {
                u32::from(u16::from_be_bytes([pair[0], pair[1]]))
            } else {
                u32::from(pair[0]) << 8
            };
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum, 0xffff, "partial checksum must verify independently");
    }
    fn split_case(v6: bool, tcp: bool) {
        let payload = b"abcdefghij";
        let (p, ip) = packet(v6, tcp, payload);
        let gso = if tcp {
            if v6 {
                GSO_TCPV6
            } else {
                GSO_TCPV4
            }
        } else {
            GSO_UDP_L4
        };
        let checksum_offset = if tcp { 16 } else { 6 };
        // A malicious or stale kernel header length must not affect GSO
        // parsing; the IP and transport headers determine it instead.
        let raw = virtio(gso, 4, ip as u16, checksum_offset, u16::MAX, 0, p);
        let mut batch = TunPacketBatch::new();
        split_virtio(&raw, &mut batch).unwrap();
        assert_eq!(batch.packets().len(), 3);
        for (i, out) in batch.packets().iter().enumerate() {
            let data = &payload[i * 4..(i * 4 + 4).min(payload.len())];
            assert_eq!(&out[ip + if tcp { 20 } else { 8 }..], data);
            assert_eq!(out.len(), ip + if tcp { 20 } else { 8 } + data.len());
            if v6 {
                assert_eq!(
                    u16::from_be_bytes([out[4], out[5]]) as usize,
                    out.len() - 40
                );
            } else {
                assert_eq!(u16::from_be_bytes([out[2], out[3]]) as usize, out.len());
                assert_eq!(
                    u16::from_be_bytes([out[4], out[5]]),
                    0x1234u16.wrapping_add(i as u16)
                );
                verify_ip_checksum(out);
            }
            if tcp {
                assert_eq!(
                    u32::from_be_bytes(out[ip + 4..ip + 8].try_into().unwrap()),
                    100 + (i * 4) as u32
                );
                assert_eq!(out[ip + 13] & 0x09, if i == 2 { 0x09 } else { 0 });
            } else {
                assert_eq!(
                    u16::from_be_bytes(out[ip + 4..ip + 6].try_into().unwrap()) as usize,
                    out.len() - ip
                );
            }
            verify_checksum(out, ip, ip, tcp);
        }
    }
    #[test]
    fn tcp_v4_segments() {
        split_case(false, true);
    }
    #[test]
    fn tcp_v6_segments() {
        split_case(true, true);
    }
    #[test]
    fn udp_v4_segments() {
        split_case(false, false);
    }
    #[test]
    fn udp_v6_segments() {
        split_case(true, false);
    }

    #[test]
    fn tcp_v6_segments_after_extension_header() {
        let payload = b"abcdefghij";
        let (mut p, _) = packet(true, true, payload);
        // Insert an 8-byte destination-options extension header between IPv6
        // and TCP. The kernel therefore points csum_start at byte 48.
        p[6] = 60;
        p.splice(40..40, [6, 0, 0, 0, 0, 0, 0, 0]);
        p[4..6].copy_from_slice(&(28 + payload.len() as u16).to_be_bytes());
        let raw = virtio(GSO_TCPV6, 4, 48, 16, u16::MAX, 0, p);
        let mut batch = TunPacketBatch::new();
        split_virtio(&raw, &mut batch).unwrap();
        assert_eq!(batch.packets().len(), 3);
        for (i, out) in batch.packets().iter().enumerate() {
            let data = &payload[i * 4..(i * 4 + 4).min(payload.len())];
            assert_eq!(&out[..4], &raw[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + 4]);
            assert_eq!(
                &out[6..48],
                &raw[VIRTIO_NET_HDR_LEN + 6..VIRTIO_NET_HDR_LEN + 48]
            );
            assert_eq!(&out[68..], data);
            assert_eq!(
                u16::from_be_bytes([out[4], out[5]]) as usize,
                out.len() - 40
            );
            assert_eq!(out.len() - 48, 20 + data.len());
            assert_eq!(
                u32::from_be_bytes(out[52..56].try_into().unwrap()),
                100 + (i * 4) as u32
            );
            assert_eq!(out[61] & 0x09, if i == 2 { 0x09 } else { 0 });
            verify_checksum(out, 40, 48, true);
        }
    }

    #[test]
    fn none_checksum_and_native_endian_header() {
        let p = vec![1, 2, 0x12, 0x34, 5, 6];
        let raw = virtio(GSO_NONE, 0, 2, 0, 6, VIRTIO_NET_HDR_F_NEEDS_CSUM, p.clone());
        let h = virtio_header(&raw).unwrap();
        assert_eq!(h.hdr_len, 6);
        let mut batch = TunPacketBatch::new();
        split_virtio(&raw, &mut batch).unwrap();
        assert_eq!(batch.packets()[0], [1, 2, 0xe8, 0xc5, 5, 6]);
        let raw = virtio(GSO_NONE, 0, 2, 0, 6, 0, p.clone());
        split_virtio(&raw, &mut batch).unwrap();
        assert_eq!(batch.packets()[0], p);
    }

    #[test]
    fn short_gso_without_checksum_preserves_packet() {
        let (p, ip) = packet(false, true, b"abc");
        let raw = virtio(GSO_TCPV4, 4, ip as u16, 16, 0, 0, p.clone());
        let mut batch = TunPacketBatch::new();
        split_virtio(&raw, &mut batch).unwrap();
        assert_eq!(batch.packets(), &[p]);
    }

    #[test]
    fn short_gso_with_checksum_only_updates_checksum() {
        let (mut p, ip) = packet(false, true, b"abc");
        p[ip + 16..ip + 18].copy_from_slice(&0x1234u16.to_be_bytes());
        let raw = virtio(
            GSO_TCPV4,
            4,
            ip as u16,
            16,
            0,
            VIRTIO_NET_HDR_F_NEEDS_CSUM,
            p.clone(),
        );
        let mut batch = TunPacketBatch::new();
        split_virtio(&raw, &mut batch).unwrap();
        let out = &batch.packets()[0];
        assert_eq!(&out[..ip + 16], &p[..ip + 16]);
        assert_eq!(&out[ip + 18..], &p[ip + 18..]);
        assert_ne!(&out[ip + 16..ip + 18], &p[ip + 16..ip + 18]);
        verify_partial_checksum(out, ip, 0x1234);
    }

    #[test]
    fn malformed_frames_clear_and_reuse_batch() {
        let (p, ip) = packet(false, true, b"abcdefgh");
        let valid = virtio(GSO_TCPV4, 4, ip as u16, 16, 0, 0, p.clone());
        let mut batch = TunPacketBatch::new();
        split_virtio(&valid, &mut batch).unwrap();
        assert_eq!(batch.packets().len(), 2);
        let cases = [
            vec![0; 9],
            virtio(99, 1, ip as u16, 16, 0, 0, p.clone()),
            virtio(GSO_TCPV4, 0, ip as u16, 16, 0, 0, p.clone()),
            virtio(GSO_TCPV4, 4, ip as u16, 99, 0, 0, p.clone()),
            virtio(GSO_TCPV6, 4, ip as u16, 16, 0, 0, p.clone()),
            virtio(GSO_TCPV4, 4, ip as u16, 16, 0, 0, {
                let mut x = p.clone();
                x[ip + 12] = 0x10;
                x
            }),
            virtio(GSO_TCPV4, 4, ip as u16, 16, 0, 0, {
                let mut x = p.clone();
                x.truncate(ip + 13);
                x
            }),
        ];
        for raw in cases {
            assert!(split_virtio(&raw, &mut batch).is_err());
            assert!(batch.packets().is_empty());
        }
        split_virtio(&valid, &mut batch).unwrap();
        assert_eq!(batch.packets().len(), 2);
    }

    #[test]
    fn rejects_over_segment_limit_and_bad_offsets() {
        let (p, ip) = packet(false, false, &[7; 129]);
        let mut batch = TunPacketBatch::new();
        assert!(split_virtio(&virtio(GSO_UDP_L4, 1, ip as u16, 6, 0, 0, p), &mut batch).is_err());
        let (p, ip) = packet(false, false, b"abcd");
        assert!(split_virtio(&virtio(GSO_UDP_L4, 2, ip as u16, 7, 0, 0, p), &mut batch).is_err());
        assert!(split_virtio(
            &virtio(GSO_NONE, 0, u16::MAX, u16::MAX, 0, 0, vec![0]),
            &mut batch
        )
        .is_err());
    }
}
