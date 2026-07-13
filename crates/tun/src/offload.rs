//! Safe, platform-neutral virtio-net GSO receive splitting.

use std::{collections::HashMap, io};

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

// ---------------------------------------------------------------------------
// Linux write-side TCP GRO
//
// This section intentionally has no Linux types or syscalls.  It is the
// write-side counterpart of the splitter above: it plans scatter/gather
// frames by packet index, then Linux materializes iovecs while holding its
// write-operation lock.  Keeping references out of the plan makes the logic
// testable on every host and avoids self-referential packet storage.

pub(crate) const MAX_GRO_IOVECS: usize = 1024;
const TCP: u8 = 6;
const TCP_ACK: u8 = 0x10;
const TCP_PSH: u8 = 0x08;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PayloadFragment {
    pub packet: usize,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct GroOutput {
    pub header: [u8; VIRTIO_NET_HDR_LEN],
    pub head: usize,
    pub fragments: Vec<PayloadFragment>,
}

impl GroOutput {
    pub(crate) fn iovec_count(&self) -> usize {
        2 + self.fragments.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpFlowKey {
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
    ack: u32,
    v6: bool,
}

#[derive(Clone, Copy, Debug)]
struct TcpMeta {
    key: TcpFlowKey,
    ip_len: usize,
    tcp_len: usize,
    payload: usize,
    seq: u32,
    psh: bool,
}

#[derive(Clone, Copy, Debug)]
struct TcpItem {
    key: TcpFlowKey,
    output: usize,
    sent_seq: u32,
    payload_len: u16,
    gso_size: u16,
    ip_len: u8,
    tcp_len: u8,
    psh: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Coalesce {
    Prepend,
    No,
    Append,
}

/// Reusable TCP-only GRO planning state. `reset` retains all allocations.
#[derive(Default)]
pub(crate) struct TcpGroState {
    flows: HashMap<TcpFlowKey, Vec<TcpItem>>,
    item_pool: Vec<Vec<TcpItem>>,
    outputs: Vec<GroOutput>,
    output_pool: Vec<GroOutput>,
}

impl TcpGroState {
    pub(crate) fn outputs(&self) -> &[GroOutput] {
        &self.outputs
    }

    pub(crate) fn reset(&mut self) {
        for (_, mut items) in self.flows.drain() {
            items.clear();
            self.item_pool.push(items);
        }
        for mut output in self.outputs.drain(..) {
            output.fragments.clear();
            self.output_pool.push(output);
        }
    }

    /// Build an ordered TCP4/TCP6 GRO plan and apply VNET accounting to the
    /// selected head packets. Malformed and non-TCP packets are scalar output.
    pub(crate) fn plan(&mut self, packets: &mut [Vec<u8>]) {
        self.reset();
        for index in 0..packets.len() {
            let Some(meta) = tcp_meta(&packets[index]) else {
                self.push_scalar(index);
                continue;
            };
            self.tcp_gro(index, meta, packets);
        }
        self.apply_accounting(packets);
    }

    fn push_scalar(&mut self, packet: usize) {
        let mut output = self.output_pool.pop().unwrap_or(GroOutput {
            header: [0; VIRTIO_NET_HDR_LEN],
            head: packet,
            fragments: Vec::new(),
        });
        output.header = [0; VIRTIO_NET_HDR_LEN];
        output.head = packet;
        output.fragments.clear();
        self.outputs.push(output);
    }

    fn insert(&mut self, packet: usize, meta: TcpMeta) {
        let output = self.outputs.len();
        self.push_scalar(packet);
        let items = self.flows.entry(meta.key).or_insert_with(|| {
            let mut items = self.item_pool.pop().unwrap_or_default();
            items.clear();
            items
        });
        items.push(TcpItem {
            key: meta.key,
            output,
            sent_seq: meta.seq,
            payload_len: meta.payload as u16,
            gso_size: meta.payload as u16,
            ip_len: meta.ip_len as u8,
            tcp_len: meta.tcp_len as u8,
            psh: meta.psh,
        });
    }

    fn tcp_gro(&mut self, packet: usize, meta: TcpMeta, packets: &mut [Vec<u8>]) {
        let Some(item_len) = self.flows.get(&meta.key).map(Vec::len) else {
            self.insert(packet, meta);
            return;
        };

        for item_index in (0..item_len).rev() {
            // Copy one candidate out of the table, rather than cloning the
            // entire per-flow Vec on every packet.
            let item = self.flows.get(&meta.key).expect("flow exists")[item_index];
            let mode = self.can_coalesce(&packets[packet], meta, item, packets);
            if mode == Coalesce::No {
                continue;
            }
            if self.output_is_single(item.output)
                && !tcp_checksum_valid(
                    &packets[self.outputs[item.output].head],
                    item.ip_len as usize,
                    item.key.v6,
                )
            {
                self.flows
                    .get_mut(&meta.key)
                    .expect("flow exists")
                    .remove(item_index);
                continue;
            }
            if !tcp_checksum_valid(&packets[packet], meta.ip_len, meta.key.v6) {
                self.push_scalar(packet);
                return;
            }

            let item = self.merge(packet, meta, item, mode, packets);
            self.flows.get_mut(&meta.key).expect("flow exists")[item_index] = item;
            return;
        }
        self.insert(packet, meta);
    }

    fn output_is_single(&self, output: usize) -> bool {
        self.outputs[output].fragments.is_empty()
    }

    fn can_coalesce(
        &self,
        packet: &[u8],
        meta: TcpMeta,
        item: TcpItem,
        packets: &[Vec<u8>],
    ) -> Coalesce {
        let output = &self.outputs[item.output];
        if output.iovec_count() >= MAX_GRO_IOVECS {
            return Coalesce::No;
        }
        let head = &packets[output.head];
        if meta.tcp_len != item.tcp_len as usize
            || !ip_headers_match(packet, head, meta.key.v6)
            || meta.ip_len + meta.tcp_len + usize::from(item.payload_len) + meta.payload
                > u16::MAX as usize
        {
            return Coalesce::No;
        }
        if meta.tcp_len > 20
            && packet[meta.ip_len + 20..meta.ip_len + meta.tcp_len]
                != head[item.ip_len as usize + 20..item.ip_len as usize + item.tcp_len as usize]
        {
            return Coalesce::No;
        }
        if meta.seq == item.sent_seq.wrapping_add(u32::from(item.payload_len)) {
            if item.psh
                || !item.payload_len.is_multiple_of(item.gso_size)
                || meta.payload > usize::from(item.gso_size)
            {
                Coalesce::No
            } else {
                Coalesce::Append
            }
        } else if meta.seq.wrapping_add(meta.payload as u32) == item.sent_seq {
            if meta.psh
                || meta.payload < usize::from(item.gso_size)
                || (meta.payload > usize::from(item.gso_size) && output.iovec_count() > 2)
            {
                Coalesce::No
            } else {
                Coalesce::Prepend
            }
        } else {
            Coalesce::No
        }
    }

    fn merge(
        &mut self,
        packet: usize,
        meta: TcpMeta,
        mut item: TcpItem,
        mode: Coalesce,
        packets: &[Vec<u8>],
    ) -> TcpItem {
        let output = &mut self.outputs[item.output];
        if mode == Coalesce::Prepend {
            let old_head = output.head;
            output.head = packet;
            output.fragments.insert(
                0,
                PayloadFragment {
                    packet: old_head,
                    start: usize::from(item.ip_len) + usize::from(item.tcp_len),
                    // `payload_len` is aggregate after prior appends. The
                    // old head itself owns only its original full packet
                    // payload; earlier appended segments are already present
                    // as their own fragments and stay after this insertion.
                    end: packets[old_head].len(),
                },
            );
            item.sent_seq = meta.seq;
        } else {
            output.fragments.push(PayloadFragment {
                packet,
                start: meta.ip_len + meta.tcp_len,
                end: meta.ip_len + meta.tcp_len + meta.payload,
            });
            if meta.psh {
                item.psh = true;
            }
        }
        item.payload_len += meta.payload as u16;
        item.gso_size = item.gso_size.max(meta.payload as u16);
        item
    }

    fn apply_accounting(&mut self, packets: &mut [Vec<u8>]) {
        for items in self.flows.values() {
            for item in items {
                let output = &mut self.outputs[item.output];
                if output.fragments.is_empty() {
                    continue;
                }
                let total = u16::from(item.ip_len) + u16::from(item.tcp_len) + item.payload_len;
                let packet = &mut packets[output.head];
                if item.psh {
                    packet[usize::from(item.ip_len) + 13] |= TCP_PSH;
                }
                output.header = vnet_tcp_header(item);
                if item.key.v6 {
                    packet[4..6].copy_from_slice(&(total - u16::from(item.ip_len)).to_be_bytes());
                } else {
                    packet[2..4].copy_from_slice(&total.to_be_bytes());
                    packet[10..12].fill(0);
                    let sum = !checksum(&packet[..usize::from(item.ip_len)], 0);
                    packet[10..12].copy_from_slice(&sum.to_be_bytes());
                }
                let (address, size) = if item.key.v6 { (8, 16) } else { (12, 4) };
                let seed = checksum(
                    &[],
                    pseudo(
                        TCP,
                        &packet[address..address + size],
                        &packet[address + size..address + 2 * size],
                        total - u16::from(item.ip_len),
                    ),
                );
                let checksum_at = usize::from(item.ip_len) + 16;
                packet[checksum_at..checksum_at + 2].copy_from_slice(&seed.to_be_bytes());
            }
        }
    }
}

fn vnet_tcp_header(item: &TcpItem) -> [u8; VIRTIO_NET_HDR_LEN] {
    let mut header = [0; VIRTIO_NET_HDR_LEN];
    header[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header[1] = if item.key.v6 { GSO_TCPV6 } else { GSO_TCPV4 };
    header[2..4].copy_from_slice(&(u16::from(item.ip_len) + u16::from(item.tcp_len)).to_ne_bytes());
    header[4..6].copy_from_slice(&item.gso_size.to_ne_bytes());
    header[6..8].copy_from_slice(&u16::from(item.ip_len).to_ne_bytes());
    header[8..10].copy_from_slice(&16_u16.to_ne_bytes());
    header
}

fn tcp_meta(packet: &[u8]) -> Option<TcpMeta> {
    if packet.len() > u16::MAX as usize || packet.len() < 40 {
        return None;
    }
    let v6 = match packet[0] >> 4 {
        4 if packet[0] & 0x0f == 5 && packet[9] == TCP => {
            if u16::from_be_bytes(packet[2..4].try_into().ok()?) as usize != packet.len()
                || packet[6] & 0x20 != 0
                || packet[6] << 3 != 0
                || packet[7] != 0
            {
                return None;
            }
            false
        }
        6 if packet.len() >= 60 && packet[6] == TCP => {
            if u16::from_be_bytes(packet[4..6].try_into().ok()?) as usize != packet.len() - 40 {
                return None;
            }
            true
        }
        _ => return None,
    };
    let ip_len = if v6 { 40 } else { 20 };
    let tcp_len = usize::from(packet.get(ip_len + 12)? >> 4) * 4;
    if !(20..=60).contains(&tcp_len) || packet.len() < ip_len + tcp_len {
        return None;
    }
    let flags = *packet.get(ip_len + 13)?;
    if flags != TCP_ACK && flags != TCP_ACK | TCP_PSH {
        return None;
    }
    let payload = packet.len() - ip_len - tcp_len;
    if payload == 0 {
        return None;
    }
    let (address, size) = if v6 { (8, 16) } else { (12, 4) };
    let mut src = [0; 16];
    let mut dst = [0; 16];
    src[..size].copy_from_slice(&packet[address..address + size]);
    dst[..size].copy_from_slice(&packet[address + size..address + 2 * size]);
    Some(TcpMeta {
        key: TcpFlowKey {
            src,
            dst,
            src_port: u16::from_be_bytes(packet[ip_len..ip_len + 2].try_into().ok()?),
            dst_port: u16::from_be_bytes(packet[ip_len + 2..ip_len + 4].try_into().ok()?),
            ack: u32::from_be_bytes(packet[ip_len + 8..ip_len + 12].try_into().ok()?),
            v6,
        },
        ip_len,
        tcp_len,
        payload,
        seq: u32::from_be_bytes(packet[ip_len + 4..ip_len + 8].try_into().ok()?),
        psh: flags & TCP_PSH != 0,
    })
}

fn ip_headers_match(packet: &[u8], head: &[u8], v6: bool) -> bool {
    if v6 {
        packet[0] == head[0] && packet[1] >> 4 == head[1] >> 4 && packet[7] == head[7]
    } else {
        packet[1] == head[1] && packet[6] >> 5 == head[6] >> 5 && packet[8] == head[8]
    }
}

fn tcp_checksum_valid(packet: &[u8], ip_len: usize, v6: bool) -> bool {
    let (address, size) = if v6 { (8, 16) } else { (12, 4) };
    let Ok(length) = u16::try_from(packet.len().saturating_sub(ip_len)) else {
        return false;
    };
    let initial = pseudo(
        TCP,
        &packet[address..address + size],
        &packet[address + size..address + 2 * size],
        length,
    );
    !checksum(&packet[ip_len..], initial) == 0
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

    fn tcp_packet(v6: bool, seq: u32, ack: u32, payload: &[u8], flags: u8) -> Vec<u8> {
        let ip = if v6 { 40 } else { 20 };
        let mut packet = vec![0; ip + 20 + payload.len()];
        if v6 {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
            packet[6] = TCP;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&[1; 16]);
            packet[24..40].copy_from_slice(&[2; 16]);
        } else {
            packet[0] = 0x45;
            let total = packet.len() as u16;
            packet[2..4].copy_from_slice(&total.to_be_bytes());
            packet[8] = 64;
            packet[9] = TCP;
            packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
            packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        }
        packet[ip..ip + 2].copy_from_slice(&1000_u16.to_be_bytes());
        packet[ip + 2..ip + 4].copy_from_slice(&2000_u16.to_be_bytes());
        packet[ip + 4..ip + 8].copy_from_slice(&seq.to_be_bytes());
        packet[ip + 8..ip + 12].copy_from_slice(&ack.to_be_bytes());
        packet[ip + 12] = 0x50;
        packet[ip + 13] = flags;
        packet[ip + 20..].copy_from_slice(payload);
        if !v6 {
            let sum = !checksum(&packet[..ip], 0);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        let (address, size) = if v6 { (8, 16) } else { (12, 4) };
        let sum = !checksum(
            &packet[ip..],
            pseudo(
                TCP,
                &packet[address..address + size],
                &packet[address + size..address + 2 * size],
                (packet.len() - ip) as u16,
            ),
        );
        packet[ip + 16..ip + 18].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    fn refresh_tcp_packet(packet: &mut [u8]) {
        let v6 = packet[0] >> 4 == 6;
        let ip = if v6 { 40 } else { 20 };
        let packet_len = packet.len();
        if v6 {
            packet[4..6].copy_from_slice(&((packet_len - ip) as u16).to_be_bytes());
        } else {
            packet[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
            packet[10..12].fill(0);
            let sum = !checksum(&packet[..ip], 0);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        let (address, size) = if v6 { (8, 16) } else { (12, 4) };
        packet[ip + 16..ip + 18].fill(0);
        let sum = !checksum(
            &packet[ip..],
            pseudo(
                TCP,
                &packet[address..address + size],
                &packet[address + size..address + 2 * size],
                (packet_len - ip) as u16,
            ),
        );
        packet[ip + 16..ip + 18].copy_from_slice(&sum.to_be_bytes());
    }

    fn tcp_packet_with_options(
        v6: bool,
        seq: u32,
        ack: u32,
        payload: &[u8],
        options: &[u8],
    ) -> Vec<u8> {
        assert!(options.len().is_multiple_of(4));
        let ip = if v6 { 40 } else { 20 };
        let mut packet = tcp_packet(v6, seq, ack, payload, TCP_ACK);
        packet.splice(ip + 20..ip + 20, options.iter().copied());
        packet[ip + 12] = ((20 + options.len()) as u8 / 4) << 4;
        refresh_tcp_packet(&mut packet);
        packet
    }

    fn gro_output_count(packets: &mut [Vec<u8>]) -> usize {
        let mut state = TcpGroState::default();
        state.plan(packets);
        state.outputs().len()
    }

    #[test]
    fn tcp_gro_interleaves_flows_and_keeps_udp_scalar() {
        let mut packets = vec![
            tcp_packet(false, 10, 1, b"aaaa", TCP_ACK),
            tcp_packet(true, 20, 1, b"bbbb", TCP_ACK),
            vec![
                0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
            ],
            tcp_packet(false, 14, 1, b"cccc", TCP_ACK | TCP_PSH),
            tcp_packet(true, 24, 1, b"dddd", TCP_ACK),
        ];
        let udp = packets[2].clone();
        let mut state = TcpGroState::default();
        state.plan(&mut packets);
        assert_eq!(state.outputs().len(), 3);
        assert_eq!(state.outputs()[0].fragments.len(), 1);
        assert_eq!(state.outputs()[1].fragments.len(), 1);
        assert_eq!(state.outputs()[2].head, 2);
        assert_eq!(packets[2], udp);
        assert_eq!(state.outputs()[0].header[1], GSO_TCPV4);
        assert_eq!(state.outputs()[1].header[1], GSO_TCPV6);
        assert_eq!(packets[0][33] & TCP_PSH, TCP_PSH);
    }

    #[test]
    fn tcp_gro_ack_prepend_and_checksum_rules() {
        let original = vec![
            tcp_packet(false, 104, 7, b"tail", TCP_ACK),
            tcp_packet(false, 100, 7, b"head", TCP_ACK),
            tcp_packet(false, 108, 7, b"more", TCP_ACK),
            tcp_packet(false, 112, 8, b"ack!", TCP_ACK),
        ];
        let mut packets = original.clone();
        let mut state = TcpGroState::default();
        state.plan(&mut packets);
        assert_eq!(state.outputs().len(), 2);
        let output = &state.outputs()[0];
        assert_eq!(output.head, 1);
        assert_eq!(output.fragments.len(), 2);
        assert_eq!(output.fragments[0].packet, 0);
        assert_eq!(output.fragments[1].packet, 2);
        assert_eq!(output.fragments[0].end, packets[0].len());
        assert_eq!(u16::from_be_bytes(packets[1][2..4].try_into().unwrap()), 52);
        let mut raw = output.header.to_vec();
        raw.extend_from_slice(&packets[output.head]);
        for fragment in &output.fragments {
            raw.extend_from_slice(&packets[fragment.packet][fragment.start..fragment.end]);
        }
        let mut split = TunPacketBatch::new();
        split_virtio(&raw, &mut split).unwrap();
        let mut expected = vec![
            original[1].clone(),
            original[0].clone(),
            original[2].clone(),
        ];
        for (index, packet) in expected.iter_mut().enumerate() {
            packet[4..6].copy_from_slice(&(index as u16).to_be_bytes());
            packet[10..12].fill(0);
            let sum = !checksum(&packet[..20], 0);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        assert_eq!(split.packets(), expected.as_slice());

        // Both a corrupt head and a corrupt incoming packet remain scalar.
        let mut bad = vec![
            tcp_packet(false, 1, 1, b"good", TCP_ACK),
            tcp_packet(false, 5, 1, b"next", TCP_ACK),
        ];
        bad[0][36] ^= 1;
        assert_eq!(gro_output_count(&mut bad), 2);
        let mut bad = vec![
            tcp_packet(false, 1, 1, b"good", TCP_ACK),
            tcp_packet(false, 5, 1, b"next", TCP_ACK),
        ];
        bad[1][36] ^= 1;
        assert_eq!(gro_output_count(&mut bad), 2);
    }

    #[test]
    fn tcp_gro_requires_matching_ip_headers_and_tcp_options() {
        #[derive(Clone, Copy, Debug)]
        enum Change {
            V4Tos,
            V4Ttl,
            V4Df,
            V4Reserved,
            V6TrafficClassHigh,
            V6TrafficClassLow,
            V6HopLimit,
        }
        for change in [
            Change::V4Tos,
            Change::V4Ttl,
            Change::V4Df,
            Change::V4Reserved,
            Change::V6TrafficClassHigh,
            Change::V6TrafficClassLow,
            Change::V6HopLimit,
        ] {
            let v6 = matches!(
                change,
                Change::V6TrafficClassHigh | Change::V6TrafficClassLow | Change::V6HopLimit
            );
            let mut packets = vec![
                tcp_packet(v6, 1, 1, b"same", TCP_ACK),
                tcp_packet(v6, 5, 1, b"next", TCP_ACK),
            ];
            match change {
                Change::V4Tos => packets[1][1] = 1,
                Change::V4Ttl => packets[1][8] = 63,
                Change::V4Df => packets[1][6] = 0x40,
                Change::V4Reserved => packets[1][6] = 0x80,
                Change::V6TrafficClassHigh => packets[1][0] |= 1,
                Change::V6TrafficClassLow => packets[1][1] |= 0x10,
                Change::V6HopLimit => packets[1][7] = 63,
            }
            refresh_tcp_packet(&mut packets[1]);
            assert_eq!(gro_output_count(&mut packets), 2, "{change:?}");
        }

        let mut matching = vec![
            tcp_packet_with_options(false, 1, 1, b"same", &[1, 1, 1, 1]),
            tcp_packet_with_options(false, 5, 1, b"next", &[1, 1, 1, 1]),
        ];
        assert_eq!(gro_output_count(&mut matching), 1);
        let mut different = vec![
            tcp_packet_with_options(false, 1, 1, b"same", &[1, 1, 1, 1]),
            tcp_packet_with_options(false, 5, 1, b"next", &[1, 1, 1, 2]),
        ];
        assert_eq!(gro_output_count(&mut different), 2);
    }

    #[test]
    fn tcp_gro_segment_size_and_aggregate_limits_match_wireguard_go() {
        for (name, first_seq, first_len, second_seq, second_len, outputs) in [
            ("append permits a shorter tail", 1, 4, 5, 3, 1),
            ("append rejects a larger segment", 1, 4, 5, 5, 2),
            ("prepend rejects a shorter segment", 5, 4, 2, 3, 2),
            ("prepend permits a larger first segment", 5, 4, 0, 5, 1),
        ] {
            let first_payload = vec![b'a'; first_len];
            let second_payload = vec![b'b'; second_len];
            let mut packets = vec![
                tcp_packet(false, first_seq, 1, &first_payload, TCP_ACK),
                tcp_packet(false, second_seq, 1, &second_payload, TCP_ACK),
            ];
            assert_eq!(gro_output_count(&mut packets), outputs, "{name}");
        }

        let first_payload = vec![b'a'; 32_748];
        let second_payload = vec![b'b'; 32_748];
        let mut overflow = vec![
            tcp_packet(false, 1, 1, &first_payload, TCP_ACK),
            tcp_packet(false, 32_749, 1, &second_payload, TCP_ACK),
        ];
        assert_eq!(gro_output_count(&mut overflow), 2);
    }

    #[test]
    fn tcp_gro_vnet_accounting_and_reset_reuse() {
        let mut packets = vec![
            tcp_packet(false, 1, 1, b"abcd", TCP_ACK),
            tcp_packet(false, 5, 1, b"efgh", TCP_ACK),
        ];
        let mut state = TcpGroState::default();
        state.plan(&mut packets);
        let output = &state.outputs()[0];
        assert_eq!(output.header[0], VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(output.header[1], GSO_TCPV4);
        assert_eq!(&output.header[2..4], &40_u16.to_ne_bytes());
        assert_eq!(&output.header[4..6], &4_u16.to_ne_bytes());
        assert_eq!(&output.header[6..8], &20_u16.to_ne_bytes());
        assert_eq!(&output.header[8..10], &16_u16.to_ne_bytes());
        assert_eq!(u16::from_be_bytes(packets[0][2..4].try_into().unwrap()), 48);
        assert!(!tcp_checksum_valid(&packets[0], 20, false));
        state.reset();
        assert!(state.outputs().is_empty());
    }

    #[test]
    fn tcp_gro_append_then_prepend_keeps_old_head_bounds() {
        let original = vec![
            tcp_packet(false, 100, 7, b"aaaa", TCP_ACK),
            tcp_packet(false, 104, 7, b"bbbb", TCP_ACK),
            tcp_packet(false, 96, 7, b"cccc", TCP_ACK),
        ];
        let mut packets = original.clone();
        let mut state = TcpGroState::default();
        state.plan(&mut packets);
        assert_eq!(state.outputs().len(), 1);
        let output = &state.outputs()[0];
        assert_eq!(output.head, 2);
        assert_eq!(output.fragments.len(), 2);
        assert_eq!(output.fragments[0].packet, 0);
        assert_eq!(output.fragments[0].end, packets[0].len());
        assert_eq!(output.fragments[1].packet, 1);
        let mut raw = output.header.to_vec();
        raw.extend_from_slice(&packets[output.head]);
        for fragment in &output.fragments {
            raw.extend_from_slice(&packets[fragment.packet][fragment.start..fragment.end]);
        }
        let mut split = TunPacketBatch::new();
        split_virtio(&raw, &mut split).unwrap();
        let mut expected = vec![
            original[2].clone(),
            original[0].clone(),
            original[1].clone(),
        ];
        for (index, packet) in expected.iter_mut().enumerate() {
            packet[4..6].copy_from_slice(&(index as u16).to_be_bytes());
            packet[10..12].fill(0);
            let sum = !checksum(&packet[..20], 0);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        assert_eq!(split.packets(), expected.as_slice());
    }

    #[test]
    fn tcp_gro_materialized_frames_round_trip_through_splitter() {
        for v6 in [false, true] {
            let original = vec![
                tcp_packet(v6, u32::MAX - 2, 9, b"abcd", TCP_ACK),
                tcp_packet(v6, 1, 9, b"efgh", TCP_ACK | TCP_PSH),
            ];
            let mut packets = original.clone();
            let mut state = TcpGroState::default();
            state.plan(&mut packets);
            let output = &state.outputs()[0];
            let mut raw = output.header.to_vec();
            raw.extend_from_slice(&packets[output.head]);
            for fragment in &output.fragments {
                raw.extend_from_slice(&packets[fragment.packet][fragment.start..fragment.end]);
            }
            let mut split = TunPacketBatch::new();
            split_virtio(&raw, &mut split).unwrap();
            let mut expected = original;
            if !v6 {
                // The receive-side splitter follows wireguard-go and assigns
                // a distinct IPv4 ID to later reconstructed segments.
                expected[1][4..6].copy_from_slice(&1_u16.to_be_bytes());
                expected[1][10..12].fill(0);
                let sum = !checksum(&expected[1][..20], 0);
                expected[1][10..12].copy_from_slice(&sum.to_be_bytes());
            }
            assert_eq!(split.packets(), expected.as_slice());
        }
    }

    #[test]
    fn tcp_gro_malformed_and_incompatible_packets_stay_scalar() {
        let base = tcp_packet(false, 1, 1, b"data", TCP_ACK);
        let mut cases = Vec::new();
        let mut options = base.clone();
        options[0] = 0x46;
        cases.push(options);
        let mut fragment = base.clone();
        fragment[6] = 0x20;
        cases.push(fragment);
        let mut no_payload = base.clone();
        no_payload.truncate(40);
        no_payload[2..4].copy_from_slice(&40_u16.to_be_bytes());
        cases.push(no_payload);
        let mut syn = base.clone();
        syn[33] = 0x12;
        cases.push(syn);
        let mut bad_length = base.clone();
        bad_length[2..4].copy_from_slice(&99_u16.to_be_bytes());
        cases.push(bad_length);
        let mut extension = tcp_packet(true, 1, 1, b"data", TCP_ACK);
        extension[6] = 0;
        cases.push(extension);
        for packet in cases {
            let before = packet.clone();
            let mut packets = vec![packet];
            let mut state = TcpGroState::default();
            state.plan(&mut packets);
            assert_eq!(state.outputs().len(), 1);
            assert!(state.outputs()[0].fragments.is_empty());
            assert_eq!(packets[0], before);
        }
    }

    #[test]
    fn tcp_gro_arbitrary_inputs_never_escape_packet_ranges() {
        let mut seed = 0x1234_5678_u32;
        for batch_len in 0..=16 {
            let mut packets = Vec::new();
            for _ in 0..batch_len {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let len = (seed as usize) % 96;
                let mut packet = vec![0; len];
                for byte in &mut packet {
                    seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    *byte = seed as u8;
                }
                packets.push(packet);
            }
            let before = packets.clone();
            let mut state = TcpGroState::default();
            state.plan(&mut packets);
            assert!(state.outputs().len() <= before.len());
            for output in state.outputs() {
                assert!(output.head < packets.len());
                for fragment in &output.fragments {
                    assert!(fragment.packet < packets.len());
                    assert!(fragment.start <= fragment.end);
                    assert!(fragment.end <= packets[fragment.packet].len());
                }
                if output.fragments.is_empty() {
                    assert_eq!(packets[output.head], before[output.head]);
                }
            }
        }
    }
}
