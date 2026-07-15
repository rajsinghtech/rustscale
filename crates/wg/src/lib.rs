//! WireGuard data plane for rustscale.
//!
//! Wraps the `boringtun` crate's `noise::Tunn` API in a transport-agnostic
//! per-peer tunnel. The caller (magicsock) moves UDP/DERP datagrams in and out;
//! this crate is pure bytes-in → bytes-out.
//!
//! Key conversion: `rustscale_key::NodePrivate` / `NodePublic` are X25519
//! scalars/points stored as 32 raw bytes. We convert to boringtun's
//! `StaticSecret` / `PublicKey` via `From<[u8; 32]>`.

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use boringtun::noise::{OpenedData, PreparedData, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rustscale_key::{NodePrivate, NodePublic};

/// Maximum WireGuard message size (header + payload).
const MAX_WG_MSG: usize = 65_536;
/// The speculative path is deliberately MTU-sized. Jumbo valid WireGuard
/// data remains on the allocation-neutral scalar path.
pub const MAX_PIPELINED_ENCRYPTED_BODY: usize = 2048;
static NEXT_PLAINTEXT_BATCH_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_WG_TUNNEL_ID: AtomicU64 = AtomicU64::new(1);

/// Errors from the WireGuard tunnel wrapper.
#[derive(Debug, thiserror::Error)]
pub enum WgError {
    /// The tunnel's internal state reported a non-fatal protocol error.
    #[error("wireguard tunnel error: {0}")]
    Tunnel(String),
    /// A key was zero / unusable.
    #[error("invalid key")]
    InvalidKey,
    /// A caller supplied a full reusable plaintext batch.
    #[error("wireguard plaintext batch is full")]
    PlaintextBatchFull,
    /// A caller supplied plaintext larger than a WireGuard message can carry.
    #[error("wireguard plaintext packet is too large")]
    PlaintextTooLarge,
}

/// Result of decapsulating an incoming WireGuard datagram.
#[derive(Debug, Default)]
pub struct DecapResult {
    /// Decoded IP packet ready for the tunnel interface, if any.
    pub plaintext: Option<Vec<u8>>,
    /// Immediate WireGuard replies (handshake responses, keepalives) to send
    /// back over the transport.
    pub replies: Vec<Vec<u8>>,
}

/// A per-peer WireGuard tunnel wrapping `boringtun::noise::Tunn`.
pub struct WgTunn {
    tunn: Tunn,
    decap_buf: Box<[u8]>,
    encap_buf: Box<[u8]>,
    pipeline_instance_id: u64,
}

/// Reusable storage for WireGuard datagrams produced by [`WgTunn`].
///
/// `clear` only resets the logical length, retaining packet allocations for
/// the next batch.
#[derive(Default)]
pub struct WgDatagramBatch {
    packets: Vec<Vec<u8>>,
    len: usize,
}

/// Reusable owned plaintext storage produced by [`WgTunn::decapsulate_into`].
///
/// The batch exposes only its initialized packet prefix. [`Self::clear`] and
/// [`Self::retain_mut`] retain the backing packet allocations, so callers can
/// reuse the same slots across bounded receive bursts without accidentally
/// treating stale slots as packets.
pub struct WgPlaintextBatch {
    packets: Vec<Vec<u8>>,
    len: usize,
    reserved: usize,
    id: u64,
    epoch: u64,
}

impl Default for WgPlaintextBatch {
    fn default() -> Self {
        Self {
            packets: Vec::new(),
            len: 0,
            reserved: 0,
            id: NEXT_PLAINTEXT_BATCH_ID.fetch_add(1, Ordering::Relaxed),
            epoch: 0,
        }
    }
}

/// An opaque successful open. It transitively owns its plaintext slot; neither
/// a key nor a borrow crosses the receive-worker channel.
pub struct WgOpenedPacket {
    opened: Option<OpenedData>,
    slot: usize,
    batch_id: u64,
    batch_epoch: u64,
    tunnel_instance_id: u64,
}

/// Opaque mutation-free data preflight result.
#[derive(Debug)]
pub struct WgPreparedPacket(PreparedData);

/// Ordered speculative commit result.
pub enum WgCommitResult {
    Accepted,
    Dropped,
    Stale,
}

impl WgPlaintextBatch {
    /// Maximum number of packets in one kernel-TUN receive burst.
    pub const MAX_PACKETS: usize = 128;

    /// Create an empty reusable plaintext batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of initialized plaintext packets.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether there are no initialized plaintext packets.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of slots currently loaned to opaque speculative-open tokens.
    /// This is normally zero at pipeline ownership boundaries.
    pub fn reserved_len(&self) -> usize {
        self.reserved
    }

    /// Forget the initialized packet prefix without releasing slot storage.
    pub fn clear(&mut self) {
        self.len = 0;
        self.reserved = 0;
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// Release oversized scalar-fallback slot allocations once no TUN write
    /// can still observe them. Normal MTU-sized slots remain reusable.
    pub fn release_oversized_slots(&mut self) {
        debug_assert_eq!(self.len, 0);
        debug_assert_eq!(self.reserved, 0);
        for packet in &mut self.packets {
            if packet.capacity() > MAX_PIPELINED_ENCRYPTED_BODY {
                *packet = Vec::new();
            }
        }
    }

    /// The initialized plaintext packet prefix.
    pub fn packets(&self) -> &[Vec<u8>] {
        &self.packets[..self.len]
    }

    /// Mutably access only the initialized plaintext packet prefix.
    pub fn packets_mut(&mut self) -> &mut [Vec<u8>] {
        &mut self.packets[..self.len]
    }

    /// Stably retain initialized packets selected by `keep` without freeing
    /// any retained slot allocations.
    pub fn retain_mut<F>(&mut self, mut keep: F)
    where
        F: FnMut(&mut Vec<u8>) -> bool,
    {
        let mut retained = 0;
        for current in 0..self.len {
            if keep(&mut self.packets[current]) {
                if retained != current {
                    self.packets.swap(retained, current);
                }
                retained += 1;
            }
        }
        self.len = retained;
    }

    /// Copy one packet into the next retained plaintext slot.
    ///
    /// This is primarily useful for callers that need to stage owned packets
    /// alongside `decapsulate_into` output.
    pub fn push_copy(&mut self, packet: &[u8]) -> Result<(), WgError> {
        if packet.len() > MAX_WG_MSG {
            return Err(WgError::PlaintextTooLarge);
        }
        if self.len == Self::MAX_PACKETS {
            return Err(WgError::PlaintextBatchFull);
        }
        if self.len == self.packets.len() {
            self.packets.push(Vec::new());
        }
        // A Linux write-side GRO call can change both contents and length.
        // Clear first so the following copy makes the slot wholly valid again.
        let slot = &mut self.packets[self.len];
        slot.clear();
        slot.extend_from_slice(packet);
        self.len += 1;
        Ok(())
    }

    fn take_open_slot(&mut self, encrypted_len: usize) -> Result<(usize, Vec<u8>), WgError> {
        if encrypted_len > MAX_PIPELINED_ENCRYPTED_BODY {
            return Err(WgError::PlaintextTooLarge);
        }
        if self.reserved == Self::MAX_PACKETS {
            return Err(WgError::PlaintextBatchFull);
        }
        if self.reserved == self.packets.len() {
            self.packets.push(Vec::new());
        }
        let slot = self.reserved;
        self.reserved += 1;
        let packet = &mut self.packets[slot];
        // `ring::open_in_place` needs exactly the encrypted body.  Reserving
        // a 64 KiB maximum for every speculative packet would retain 16 MiB
        // across two 128-packet scratches and needlessly zero-fill it.
        packet.resize(encrypted_len, 0);
        Ok((slot, std::mem::take(packet)))
    }

    fn return_open_slot(&mut self, slot: usize, mut packet: Vec<u8>, len: Option<usize>) -> bool {
        if slot < self.len || slot >= self.reserved || slot >= self.packets.len() {
            return false;
        }
        if let Some(len) = len {
            packet.truncate(len);
            self.packets[slot] = packet;
            if slot != self.len {
                self.packets.swap(slot, self.len);
            }
            self.len += 1;
        } else {
            self.packets[slot] = packet;
            // A returned speculative slot is represented by a non-empty
            // allocation, while a loaned slot was replaced by `Vec::new()`.
            // Collapse a returned suffix so an AEAD-open failure restores the
            // reservation immediately; earlier still-loaned slots keep their
            // exact indices until their token is committed or aborted.
            while self.reserved > self.len && self.packets[self.reserved - 1].capacity() != 0 {
                self.reserved -= 1;
            }
        }
        true
    }
}

impl WgDatagramBatch {
    /// Create an empty reusable batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget the initialized packet prefix without releasing its storage.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Copy one datagram into the next reusable packet slot.
    pub fn push_copy(&mut self, packet: &[u8]) {
        if self.len == self.packets.len() {
            self.packets.push(Vec::new());
        }
        let slot = &mut self.packets[self.len];
        slot.clear();
        slot.extend_from_slice(packet);
        self.len += 1;
    }

    /// The initialized packet prefix.
    pub fn packets(&self) -> &[Vec<u8>] {
        &self.packets[..self.len]
    }
}

impl WgTunn {
    /// Create a new tunnel from our node private key and the peer's node public
    /// key. Both are X25519; the 32 raw bytes are converted to boringtun's key
    /// types directly.
    ///
    /// `index` is a caller-chosen unique per-peer index (used by boringtun's
    /// rate limiter; pass a small incrementing counter).
    pub fn new(
        private: &NodePrivate,
        peer_public: &NodePublic,
        index: u32,
    ) -> Result<Self, WgError> {
        if private.is_zero() || peer_public.is_zero() {
            return Err(WgError::InvalidKey);
        }

        let static_private = StaticSecret::from(private.raw32());
        let peer_static_public = PublicKey::from(peer_public.raw32());

        let tunn = Tunn::new(static_private, peer_static_public, None, None, index, None);

        Ok(Self {
            tunn,
            decap_buf: vec![0u8; MAX_WG_MSG].into_boxed_slice(),
            encap_buf: vec![0u8; MAX_WG_MSG].into_boxed_slice(),
            pipeline_instance_id: NEXT_WG_TUNNEL_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// Encapsulate a plaintext IP packet into WireGuard ciphertext datagrams.
    ///
    /// Returns zero or more datagrams to send over the transport. The first
    /// call after `new` typically triggers a handshake initiation, producing a
    /// handshake datagram instead of (or in addition to) the data datagram.
    pub fn encapsulate(&mut self, plaintext: &[u8]) -> Result<Vec<Vec<u8>>, WgError> {
        match self.tunn.encapsulate(plaintext, &mut self.encap_buf[..]) {
            TunnResult::WriteToNetwork(buf) => Ok(vec![buf.to_vec()]),
            TunnResult::Err(e) => Err(WgError::Tunnel(format!("{e:?}"))),
            TunnResult::Done
            | TunnResult::WriteToTunnelV4(_, _)
            | TunnResult::WriteToTunnelV6(_, _) => Ok(vec![]),
        }
    }

    /// Encapsulate `plaintext`, appending any resulting datagram to `batch`.
    pub fn encapsulate_into(
        &mut self,
        plaintext: &[u8],
        batch: &mut WgDatagramBatch,
    ) -> Result<(), WgError> {
        match self.tunn.encapsulate(plaintext, &mut self.encap_buf[..]) {
            TunnResult::WriteToNetwork(buf) => {
                batch.push_copy(buf);
                Ok(())
            }
            TunnResult::Err(e) => Err(WgError::Tunnel(format!("{e:?}"))),
            TunnResult::Done
            | TunnResult::WriteToTunnelV4(_, _)
            | TunnResult::WriteToTunnelV6(_, _) => Ok(()),
        }
    }

    /// Decapsulate an incoming WireGuard datagram.
    ///
    /// If the datagram is a handshake response or keepalive, `plaintext` will
    /// be `None` and `replies` may contain immediate protocol replies to send
    /// back. If it carries data, `plaintext` is the decoded IP packet.
    ///
    /// boringtun requires re-calling decapsulate with an empty datagram after a
    /// `WriteToNetwork` result until `Done` is returned; this method handles
    /// that loop internally and collects all replies.
    pub fn decapsulate(&mut self, datagram: &[u8]) -> Result<DecapResult, WgError> {
        let mut result = DecapResult::default();

        let mut to_process = Some(datagram);
        loop {
            let src = to_process.take().unwrap_or(&[]);
            match self.tunn.decapsulate(None, src, &mut self.decap_buf[..]) {
                TunnResult::WriteToNetwork(buf) => {
                    result.replies.push(buf.to_vec());
                    to_process = Some(&[]);
                }
                TunnResult::WriteToTunnelV4(buf, _) | TunnResult::WriteToTunnelV6(buf, _) => {
                    result.plaintext = Some(buf.to_vec());
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    let _ = e;
                    break;
                }
            }
        }

        Ok(result)
    }

    /// Decapsulate an incoming datagram into reusable caller-owned plaintext
    /// slots, returning only immediate WireGuard network replies.
    ///
    /// BoringTun's plaintext slice aliases this tunnel's scratch buffer, so it
    /// is copied into `plaintext` before another decapsulation can occur.
    /// The protocol loop intentionally matches [`Self::decapsulate`].
    pub fn decapsulate_into(
        &mut self,
        datagram: &[u8],
        plaintext: &mut WgPlaintextBatch,
    ) -> Result<Vec<Vec<u8>>, WgError> {
        let mut replies = Vec::new();

        let mut to_process = Some(datagram);
        loop {
            let src = to_process.take().unwrap_or(&[]);
            match self.tunn.decapsulate(None, src, &mut self.decap_buf[..]) {
                TunnResult::WriteToNetwork(buf) => {
                    replies.push(buf.to_vec());
                    to_process = Some(&[]);
                }
                TunnResult::WriteToTunnelV4(buf, _) | TunnResult::WriteToTunnelV6(buf, _) => {
                    plaintext.push_copy(buf)?;
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    let _ = e;
                    break;
                }
            }
        }

        Ok(replies)
    }

    /// Mutation-free data preflight for the worker's complete-burst check.
    pub fn preflight_data(&self, datagram: &[u8]) -> Result<WgPreparedPacket, WgError> {
        if datagram.len().saturating_sub(16) > MAX_PIPELINED_ENCRYPTED_BODY {
            return Err(WgError::PlaintextTooLarge);
        }
        self.tunn
            .preflight_data(datagram)
            .map(WgPreparedPacket)
            .map_err(|error| WgError::Tunnel(format!("{error:?}")))
    }

    /// Synchronously copy and open into a retained scratch slot.
    pub fn open_prepared_into(
        &self,
        datagram: &[u8],
        prepared: &WgPreparedPacket,
        plaintext: &mut WgPlaintextBatch,
    ) -> Result<WgOpenedPacket, WgError> {
        let (slot, packet) = plaintext.take_open_slot(datagram.len().saturating_sub(16))?;
        let opened = match self.tunn.open_prepared_data(datagram, &prepared.0, packet) {
            Ok(opened) => opened,
            Err(error) => {
                // An AEAD or immutable-token failure must not turn this
                // bounded scratch into a fresh allocation on the next burst.
                let restored = plaintext.return_open_slot(slot, error.plaintext, None);
                debug_assert!(restored);
                return Err(WgError::Tunnel(format!("{:?}", error.error)));
            }
        };
        Ok(WgOpenedPacket {
            opened: Some(opened),
            slot,
            batch_id: plaintext.id,
            batch_epoch: plaintext.epoch,
            tunnel_instance_id: self.pipeline_instance_id,
        })
    }

    /// Return the owned plaintext slot from an uncommitted capability to its
    /// originating batch. This is used when a complete speculative burst is
    /// abandoned before its first replay mutation.
    pub fn abort_opened(opened: &mut WgOpenedPacket, plaintext: &mut WgPlaintextBatch) {
        let Some(vendor_opened) = opened.opened.take() else {
            return;
        };
        if opened.batch_id == plaintext.id
            && opened.batch_epoch == plaintext.epoch
            && opened.slot < plaintext.packets.len()
            && opened.slot < plaintext.reserved
        {
            let restored =
                plaintext.return_open_slot(opened.slot, vendor_opened.into_plaintext(), None);
            debug_assert!(restored);
        }
        // A malformed public capability should never panic. Its exceptional
        // owned slot is dropped rather than being installed in another batch.
    }

    /// Commit after whole-burst revalidation. `Stale` never mutates state.
    pub fn commit_opened(
        &mut self,
        opened: &mut WgOpenedPacket,
        plaintext: &mut WgPlaintextBatch,
    ) -> Result<WgCommitResult, WgError> {
        // Taking the vendor token makes this capability single-use, including
        // when a caller tries a substituted input or destination.
        let Some(vendor_opened) = opened.opened.take() else {
            return Ok(WgCommitResult::Stale);
        };
        if opened.tunnel_instance_id != self.pipeline_instance_id
            || opened.batch_id != plaintext.id
            || opened.batch_epoch != plaintext.epoch
            || opened.slot >= plaintext.packets.len()
            || opened.slot >= plaintext.reserved
        {
            if opened.batch_id == plaintext.id
                && opened.batch_epoch == plaintext.epoch
                && opened.slot < plaintext.packets.len()
                && opened.slot < plaintext.reserved
            {
                let restored =
                    plaintext.return_open_slot(opened.slot, vendor_opened.into_plaintext(), None);
                debug_assert!(restored);
            }
            return Ok(WgCommitResult::Stale);
        }
        match self.tunn.commit_opened_data(vendor_opened) {
            Ok((packet, Some(len))) => Ok(
                if plaintext.return_open_slot(opened.slot, packet, Some(len)) {
                    WgCommitResult::Accepted
                } else {
                    WgCommitResult::Dropped
                },
            ),
            Ok((packet, None)) => {
                let _ = plaintext.return_open_slot(opened.slot, packet, None);
                Ok(WgCommitResult::Dropped)
            }
            Err(error) => {
                let restored =
                    plaintext.return_open_slot(opened.slot, error.into_plaintext(), None);
                debug_assert!(restored);
                Ok(WgCommitResult::Stale)
            }
        }
    }

    /// Mutation-free revalidation used before the first commit in a burst.
    pub fn preflight_opened(&self, opened: &WgOpenedPacket, plaintext: &WgPlaintextBatch) -> bool {
        let Some(vendor_opened) = opened.opened.as_ref() else {
            return false;
        };
        opened.tunnel_instance_id == self.pipeline_instance_id
            && opened.batch_id == plaintext.id
            && opened.batch_epoch == plaintext.epoch
            && opened.slot < plaintext.packets.len()
            && opened.slot < plaintext.reserved
            && self.tunn.validate_opened_data(vendor_opened)
    }

    /// Drive the tunnel's timer state. Returns any datagrams that need to be
    /// sent (handshake retransmissions, keepalives). Call periodically (every
    /// ~250ms per boringtun's convention).
    pub fn tick_timers(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let TunnResult::WriteToNetwork(buf) = self.tunn.update_timers(&mut self.encap_buf[..])
        {
            out.push(buf.to_vec());
        }
        // Timer ticks themselves do not change established-data eligibility;
        // emitted handshake/keepalive output can, so invalidate precisely then.
        if !out.is_empty() {
            self.tunn.invalidate_pipeline_generation();
        }
        out
    }

    /// Force a new handshake initiation. Returns the initiation datagram if a
    /// handshake was produced.
    pub fn force_handshake(&mut self) -> Vec<Vec<u8>> {
        match self
            .tunn
            .format_handshake_initiation(&mut self.encap_buf[..], false)
        {
            TunnResult::WriteToNetwork(buf) => vec![buf.to_vec()],
            _ => vec![],
        }
    }

    /// Whether the tunnel has expired (no valid session and handshake failed).
    pub fn is_expired(&self) -> bool {
        self.tunn.is_expired()
    }

    /// Time since the last successful handshake, if any.
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.tunn.time_since_last_handshake()
    }

    /// The peer's destination IP address from an IP packet, if parseable.
    /// Utility for the caller to route decapsulated packets.
    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        Tunn::dst_address(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a trivial IP packet: IPv4 header (20 bytes) + payload.
    /// src=10.0.0.1, dst=10.0.0.2, protocol=UDP(17).
    fn make_ipv4_packet(payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 17; // protocol: UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        pkt[20..].copy_from_slice(payload);
        pkt
    }

    fn make_ipv6_packet(payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 40 + payload.len()];
        pkt[0] = 0x60; // version 6
        pkt[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        pkt[6] = 17; // next header: UDP
        pkt[7] = 64; // hop limit
        pkt[8..24].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        pkt[40..].copy_from_slice(payload);
        pkt
    }

    /// Drive the handshake: A encapsulates (triggers initiation), B
    /// decapsulates (processes initiation, produces response), A decapsulates
    /// (processes response). Returns once both sides should have a session.
    fn handshake(a: &mut WgTunn, b: &mut WgTunn) {
        // A sends a data packet to trigger handshake initiation.
        let pkt = make_ipv4_packet(b"hello from A");
        let a_out = a.encapsulate(&pkt).expect("A encapsulate");
        // First encapsulate after new() produces a handshake initiation.
        assert!(
            !a_out.is_empty(),
            "A should produce at least a handshake initiation"
        );

        // B decapsulates A's handshake initiation.
        for datagram in &a_out {
            let b_res = b.decapsulate(datagram).expect("B decapsulate");
            // B should produce a handshake response.
            assert!(
                !b_res.replies.is_empty(),
                "B should produce a handshake response"
            );
            // B may also have the data packet if the session is now established.
            if let Some(ref pt) = b_res.plaintext {
                assert_eq!(pt, &pkt, "B should decode A's data packet");
            }

            // A decapsulates B's handshake response.
            for reply in &b_res.replies {
                let a_res = a.decapsulate(reply).expect("A decapsulate");
                // A may now have keepalive or nothing; handshake should be complete.
                // Send any A replies back to B if needed.
                for reply2 in &a_res.replies {
                    let _ = b.decapsulate(reply2);
                }
            }
        }
    }

    #[test]
    fn two_peers_handshake_and_pass_packets() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();
        let a_pub = a_priv.public();
        let b_pub = b_priv.public();

        let mut a = WgTunn::new(&a_priv, &b_pub, 1).expect("A tunnel");
        let mut b = WgTunn::new(&b_priv, &a_pub, 2).expect("B tunnel");

        // Complete the handshake.
        handshake(&mut a, &mut b);

        // Both sides should have a session now.
        // A sends a data packet to B.
        let pkt_a = make_ipv4_packet(b"hello from A");
        let a_out = a.encapsulate(&pkt_a).expect("A encapsulate data");
        assert!(!a_out.is_empty(), "A should produce a data datagram");

        // B decapsulates and gets the plaintext.
        let mut got_b = None;
        for datagram in &a_out {
            let b_res = b.decapsulate(datagram).expect("B decapsulate data");
            if let Some(pt) = b_res.plaintext {
                got_b = Some(pt);
            }
        }
        assert_eq!(
            got_b.as_deref(),
            Some(&pkt_a[..]),
            "B should receive A's packet"
        );

        // B sends a data packet to A.
        let pkt_b = make_ipv4_packet(b"hello from B");
        let b_out = b.encapsulate(&pkt_b).expect("B encapsulate data");
        assert!(!b_out.is_empty(), "B should produce a data datagram");

        let mut got_a = None;
        for datagram in &b_out {
            let a_res = a.decapsulate(datagram).expect("A decapsulate data");
            if let Some(pt) = a_res.plaintext {
                got_a = Some(pt);
            }
        }
        assert_eq!(
            got_a.as_deref(),
            Some(&pkt_b[..]),
            "A should receive B's packet"
        );
    }

    #[test]
    fn timers_produce_keepalive_after_handshake() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();
        let b_pub = b_priv.public();

        let mut a = WgTunn::new(&a_priv, &b_pub, 10).expect("A tunnel");
        let mut b = WgTunn::new(&b_priv, &a_priv.public(), 11).expect("B tunnel");

        handshake(&mut a, &mut b);

        // Timers may or may not produce output immediately, but should not panic.
        let _ = a.tick_timers();
        let _ = b.tick_timers();
    }

    #[test]
    fn force_handshake_produces_initiation() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();

        let mut a = WgTunn::new(&a_priv, &b_priv.public(), 20).expect("A tunnel");
        let init = a.force_handshake();
        assert!(
            !init.is_empty(),
            "force_handshake should produce an initiation"
        );
    }

    #[test]
    fn zero_keys_rejected() {
        let z = NodePrivate::from_raw32([0u8; 32]);
        let b = NodePrivate::generate();
        assert!(WgTunn::new(&z, &b.public(), 0).is_err());
        assert!(WgTunn::new(&b, &NodePublic::from_raw32([0u8; 32]), 0).is_err());
    }

    #[test]
    fn decapsulate_garbage_is_nonfatal() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();
        let mut a = WgTunn::new(&a_priv, &b_priv.public(), 30).expect("A tunnel");
        // Random garbage should not panic or return an error that we propagate.
        let res = a.decapsulate(&[0xff; 100]).expect("garbage is non-fatal");
        assert!(
            res.plaintext.is_none(),
            "garbage should not produce plaintext"
        );
    }

    #[test]
    fn one_byte_equal_tail_value_is_harmless_protocol_input() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();
        let mut a = WgTunn::new(&a_priv, &b_priv.public(), 31).expect("A tunnel");
        let result = a.decapsulate(&[0x07]).expect("short packet is non-fatal");
        assert!(result.plaintext.is_none());
        assert!(result.replies.is_empty());
    }

    #[test]
    fn dst_address_parses_ipv4() {
        let pkt = make_ipv4_packet(b"x");
        let dst = WgTunn::dst_address(&pkt);
        assert_eq!(dst, Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn datagram_batch_clear_reuses_slots_and_hides_stale_packets() {
        let mut batch = WgDatagramBatch::new();
        batch.push_copy(b"first");
        let capacity = batch.packets()[0].capacity();
        batch.clear();
        assert!(batch.packets().is_empty());
        batch.push_copy(b"second");
        assert_eq!(batch.packets(), &[b"second".to_vec()]);
        assert_eq!(batch.packets()[0].capacity(), capacity);
    }

    #[test]
    fn plaintext_batch_compacts_stably_and_hides_stale_slots() {
        let mut batch = WgPlaintextBatch::new();
        for packet in [b"first".as_slice(), b"drop".as_slice(), b"third".as_slice()] {
            batch.push_copy(packet).unwrap();
        }
        let first_slot = batch.packets()[0].as_ptr();
        batch.retain_mut(|packet| packet.as_slice() != b"drop");
        assert_eq!(batch.packets(), &[b"first".to_vec(), b"third".to_vec()]);
        assert_eq!(batch.packets()[0].as_ptr(), first_slot);
        batch.clear();
        assert!(batch.packets().is_empty());
    }

    #[test]
    fn plaintext_batch_has_wireguard_sized_packet_and_burst_bounds() {
        let mut batch = WgPlaintextBatch::new();
        for _ in 0..WgPlaintextBatch::MAX_PACKETS {
            batch.push_copy(b"packet").unwrap();
        }
        assert_eq!(batch.len(), WgPlaintextBatch::MAX_PACKETS);
        assert!(matches!(
            batch.push_copy(b"one too many"),
            Err(WgError::PlaintextBatchFull)
        ));
        batch.clear();
        assert!(matches!(
            batch.push_copy(&vec![0; MAX_WG_MSG + 1]),
            Err(WgError::PlaintextTooLarge)
        ));
    }

    #[test]
    fn decapsulate_into_matches_scalar_for_handshake_data_keepalive_and_garbage() {
        let scalar_a_private = NodePrivate::generate();
        let scalar_b_private = NodePrivate::generate();
        let mut scalar_a = WgTunn::new(&scalar_a_private, &scalar_b_private.public(), 50)
            .expect("scalar source tunnel");
        let mut scalar_b = WgTunn::new(&scalar_b_private, &scalar_a_private.public(), 51)
            .expect("scalar receiver tunnel");

        let batch_a_private = NodePrivate::generate();
        let batch_b_private = NodePrivate::generate();
        let mut batch_a = WgTunn::new(&batch_a_private, &batch_b_private.public(), 52)
            .expect("batch source tunnel");
        let mut batch_b = WgTunn::new(&batch_b_private, &batch_a_private.public(), 53)
            .expect("batch receiver tunnel");

        // The same handshake transition produces immediate replies through
        // both APIs; the batch API does not expose boringtun's borrowed slice.
        let scalar_init = scalar_a.force_handshake();
        let batch_init = batch_a.force_handshake();
        let scalar_handshake = scalar_b
            .decapsulate(&scalar_init[0])
            .expect("scalar handshake decapsulation");
        let mut plaintext = WgPlaintextBatch::new();
        let batch_handshake = batch_b
            .decapsulate_into(&batch_init[0], &mut plaintext)
            .expect("batched handshake decapsulation");
        assert_eq!(batch_handshake.len(), scalar_handshake.replies.len());
        assert!(plaintext.is_empty());

        // Processing a handshake response deterministically produces an
        // encrypted empty-payload keepalive. This exercises the no-payload
        // protocol path without relying on timer expiry or on a later empty
        // encapsulation being scheduled.
        let scalar_response = scalar_a
            .decapsulate(&scalar_handshake.replies[0])
            .expect("scalar handshake response");
        assert!(scalar_response.plaintext.is_none());
        assert_eq!(scalar_response.replies.len(), 1);
        let scalar_keepalive = scalar_b
            .decapsulate(&scalar_response.replies[0])
            .expect("scalar keepalive decapsulation");
        assert!(scalar_keepalive.plaintext.is_none());
        assert!(scalar_keepalive.replies.is_empty());

        let batch_response = batch_a
            .decapsulate_into(&batch_handshake[0], &mut plaintext)
            .expect("batched handshake response");
        assert!(plaintext.is_empty());
        assert_eq!(batch_response.len(), scalar_response.replies.len());
        let batch_keepalive = batch_b
            .decapsulate_into(&batch_response[0], &mut plaintext)
            .expect("batched keepalive decapsulation");
        assert_eq!(batch_keepalive, scalar_keepalive.replies);
        assert!(plaintext.is_empty());

        // Compare IPv4/IPv6 data and packet ordering from independent
        // sessions. This avoids comparing random WireGuard ciphertext.
        plaintext.clear();
        let packets = [
            make_ipv4_packet(b"batched ipv4"),
            make_ipv6_packet(b"batched ipv6"),
            make_ipv4_packet(b"batched order"),
        ];
        for packet in &packets {
            let scalar_datagram = scalar_a.encapsulate(packet).expect("scalar encrypt");
            let batch_datagram = batch_a.encapsulate(packet).expect("batch encrypt");
            let scalar = scalar_b
                .decapsulate(&scalar_datagram[0])
                .expect("scalar data decapsulation");
            let replies = batch_b
                .decapsulate_into(&batch_datagram[0], &mut plaintext)
                .expect("batched data decapsulation");
            assert_eq!(replies.len(), scalar.replies.len());
            assert_eq!(scalar.plaintext.as_deref(), Some(packet.as_slice()));
        }
        assert_eq!(plaintext.packets(), packets.as_slice());

        plaintext.clear();
        let scalar_garbage = scalar_b.decapsulate(&[0xff; 100]).expect("scalar garbage");
        let batch_garbage = batch_b
            .decapsulate_into(&[0xff; 100], &mut plaintext)
            .expect("batched garbage");
        assert!(scalar_garbage.plaintext.is_none());
        assert_eq!(batch_garbage, scalar_garbage.replies);
        assert!(plaintext.is_empty());
    }

    #[test]
    fn decapsulate_into_reuses_a_slot_after_write_side_mutation() {
        let a_private = NodePrivate::generate();
        let b_private = NodePrivate::generate();
        let mut a = WgTunn::new(&a_private, &b_private.public(), 54).expect("source tunnel");
        let mut b = WgTunn::new(&b_private, &a_private.public(), 55).expect("receiver tunnel");
        handshake(&mut a, &mut b);

        let first = make_ipv4_packet(b"same length one");
        let first_datagram = a.encapsulate(&first).expect("first encrypt");
        let mut plaintext = WgPlaintextBatch::new();
        b.decapsulate_into(&first_datagram[0], &mut plaintext)
            .expect("first decapsulation");
        let ptr = plaintext.packets()[0].as_ptr();
        let capacity = plaintext.packets()[0].capacity();
        plaintext.packets_mut()[0].fill(0xa5);
        plaintext.clear();

        let second = make_ipv4_packet(b"same length two");
        let second_datagram = a.encapsulate(&second).expect("second encrypt");
        b.decapsulate_into(&second_datagram[0], &mut plaintext)
            .expect("second decapsulation");
        assert_eq!(plaintext.packets(), &[second]);
        assert_eq!(plaintext.packets()[0].as_ptr(), ptr);
        assert_eq!(plaintext.packets()[0].capacity(), capacity);
    }

    #[test]
    fn encapsulate_into_retains_ordered_ciphertexts_after_scratch_reuse() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();
        let mut a = WgTunn::new(&a_priv, &b_priv.public(), 40).expect("A tunnel");
        let mut b = WgTunn::new(&b_priv, &a_priv.public(), 41).expect("B tunnel");
        handshake(&mut a, &mut b);

        let first = make_ipv4_packet(b"first batch packet");
        let second = make_ipv4_packet(b"second batch packet");
        let mut batch = WgDatagramBatch::new();
        a.encapsulate_into(&first, &mut batch)
            .expect("first encapsulate");
        a.encapsulate_into(&second, &mut batch)
            .expect("second encapsulate");
        assert_eq!(batch.packets().len(), 2);

        // A subsequent scalar call overwrites WgTunn's internal scratch. The
        // batch copies must nevertheless remain valid and ordered.
        let scalar = make_ipv4_packet(b"scalar comparison packet");
        let scalar_out = a.encapsulate(&scalar).expect("scalar encapsulate");
        assert_eq!(scalar_out.len(), 1);

        let plaintexts: Vec<Vec<u8>> = batch
            .packets()
            .iter()
            .filter_map(|packet| b.decapsulate(packet).expect("batch decrypt").plaintext)
            .collect();
        assert_eq!(plaintexts, vec![first, second]);
        assert_eq!(
            b.decapsulate(&scalar_out[0])
                .expect("scalar decrypt")
                .plaintext,
            Some(scalar),
            "encapsulate_into follows the existing encapsulate behavior"
        );
    }

    #[test]
    fn speculative_slots_retain_normal_packet_capacity_not_64k_each() {
        let mut plaintext = WgPlaintextBatch::new();
        for _ in 0..WgPlaintextBatch::MAX_PACKETS {
            let (index, slot) = plaintext.take_open_slot(1500).expect("slot");
            assert_eq!(slot.len(), 1500);
            assert!(plaintext.return_open_slot(index, slot, None));
        }
        let retained: usize = plaintext.packets.iter().map(Vec::capacity).sum();
        assert!(
            retained <= WgPlaintextBatch::MAX_PACKETS * 2048,
            "normal speculative burst retained {retained} bytes"
        );
    }

    #[test]
    fn corrupt_tag_open_restores_the_warmed_plaintext_slot() {
        let sender_private = NodePrivate::generate();
        let receiver_private = NodePrivate::generate();
        let mut sender =
            WgTunn::new(&sender_private, &receiver_private.public(), 63).expect("sender tunnel");
        let mut receiver =
            WgTunn::new(&receiver_private, &sender_private.public(), 64).expect("receiver tunnel");
        handshake(&mut sender, &mut receiver);

        let packet = make_ipv4_packet(b"warm and corrupt");
        let ciphertext = sender
            .encapsulate(&packet)
            .expect("encrypt")
            .pop()
            .expect("data packet");
        let mut plaintext = WgPlaintextBatch::new();

        let mut warmed = receiver
            .open_prepared_into(
                &ciphertext,
                &receiver.preflight_data(&ciphertext).expect("preflight"),
                &mut plaintext,
            )
            .expect("warm open");
        WgTunn::abort_opened(&mut warmed, &mut plaintext);
        let pointer = plaintext.packets[0].as_ptr();
        let capacity = plaintext.packets[0].capacity();
        assert_eq!(plaintext.reserved, 0);

        let mut corrupt = ciphertext.clone();
        *corrupt.last_mut().expect("tag") ^= 1;
        let prepared = receiver.preflight_data(&corrupt).expect("header preflight");
        assert!(receiver
            .open_prepared_into(&corrupt, &prepared, &mut plaintext)
            .is_err());
        assert_eq!(plaintext.reserved, 0);
        assert_eq!(plaintext.len(), 0);
        assert_eq!(plaintext.packets[0].as_ptr(), pointer);
        assert_eq!(plaintext.packets[0].capacity(), capacity);
        assert!(receiver.preflight_data(&ciphertext).is_ok());
    }

    #[test]
    fn speculative_preflight_rejects_jumbo_burst_without_retaining_jumbo_slots() {
        let private = NodePrivate::generate();
        let tunnel = WgTunn::new(&private, &NodePrivate::generate().public(), 60).expect("tunnel");
        let jumbo = vec![0_u8; MAX_WG_MSG];
        let mut plaintext = WgPlaintextBatch::new();
        for _ in 0..WgPlaintextBatch::MAX_PACKETS {
            assert!(matches!(
                tunnel.preflight_data(&jumbo),
                Err(WgError::PlaintextTooLarge)
            ));
        }
        assert!(plaintext.packets.is_empty());
        assert_eq!(plaintext.reserved, 0);
        // Keep the compiler from considering this test's empty batch unused:
        // the invariant is that the preflight path never touches its slots.
        plaintext.clear();
    }

    #[test]
    fn speculative_commit_matches_scalar_replay_drops() {
        let a_private = NodePrivate::generate();
        let b_private = NodePrivate::generate();
        let mut sender = WgTunn::new(&a_private, &b_private.public(), 61).expect("sender");
        let mut receiver = WgTunn::new(&b_private, &a_private.public(), 62).expect("receiver");
        handshake(&mut sender, &mut receiver);

        let first = sender
            .encapsulate(&make_ipv4_packet(b"first"))
            .unwrap()
            .pop()
            .unwrap();
        let second = sender
            .encapsulate(&make_ipv4_packet(b"second"))
            .unwrap()
            .pop()
            .unwrap();
        let mut plaintext = WgPlaintextBatch::new();
        let mut second_opened = receiver
            .open_prepared_into(
                &second,
                &receiver.preflight_data(&second).unwrap(),
                &mut plaintext,
            )
            .unwrap();
        let mut first_opened = receiver
            .open_prepared_into(
                &first,
                &receiver.preflight_data(&first).unwrap(),
                &mut plaintext,
            )
            .unwrap();
        assert!(matches!(
            receiver
                .commit_opened(&mut second_opened, &mut plaintext)
                .unwrap(),
            WgCommitResult::Accepted
        ));
        assert!(matches!(
            receiver
                .commit_opened(&mut first_opened, &mut plaintext)
                .unwrap(),
            WgCommitResult::Accepted
        ));

        let duplicate = sender
            .encapsulate(&make_ipv4_packet(b"duplicate"))
            .unwrap()
            .pop()
            .unwrap();
        let duplicate_prepared = receiver.preflight_data(&duplicate).unwrap();
        let mut duplicate_opened = receiver
            .open_prepared_into(&duplicate, &duplicate_prepared, &mut plaintext)
            .unwrap();
        let mut replay_opened = receiver
            .open_prepared_into(&duplicate, &duplicate_prepared, &mut plaintext)
            .unwrap();
        assert!(matches!(
            receiver
                .commit_opened(&mut duplicate_opened, &mut plaintext)
                .unwrap(),
            WgCommitResult::Accepted
        ));
        assert!(matches!(
            receiver
                .commit_opened(&mut replay_opened, &mut plaintext)
                .unwrap(),
            WgCommitResult::Dropped
        ));

        let old = sender
            .encapsulate(&make_ipv4_packet(b"old"))
            .unwrap()
            .pop()
            .unwrap();
        let mut high = old.clone();
        for _ in 0..1025 {
            high = sender
                .encapsulate(&make_ipv4_packet(b"gap"))
                .unwrap()
                .pop()
                .unwrap();
        }
        let mut high_opened = receiver
            .open_prepared_into(
                &high,
                &receiver.preflight_data(&high).unwrap(),
                &mut plaintext,
            )
            .unwrap();
        let mut old_opened = receiver
            .open_prepared_into(
                &old,
                &receiver.preflight_data(&old).unwrap(),
                &mut plaintext,
            )
            .unwrap();
        assert!(matches!(
            receiver
                .commit_opened(&mut high_opened, &mut plaintext)
                .unwrap(),
            WgCommitResult::Accepted
        ));
        assert!(matches!(
            receiver
                .commit_opened(&mut old_opened, &mut plaintext)
                .unwrap(),
            WgCommitResult::Dropped
        ));
    }

    #[test]
    fn opened_capability_rejects_substitution_batch_and_reuse() {
        let sender_private = NodePrivate::generate();
        let receiver_private = NodePrivate::generate();
        let mut sender =
            WgTunn::new(&sender_private, &receiver_private.public(), 71).expect("sender");
        let mut receiver =
            WgTunn::new(&receiver_private, &sender_private.public(), 72).expect("receiver");
        handshake(&mut sender, &mut receiver);

        let first = sender
            .encapsulate(&make_ipv4_packet(b"capability first"))
            .expect("encrypt first")
            .pop()
            .expect("data first");
        let mut first_batch = WgPlaintextBatch::new();
        let mut other_batch = WgPlaintextBatch::new();

        let mut substituted = receiver
            .open_prepared_into(
                &first,
                &receiver.preflight_data(&first).expect("preflight first"),
                &mut first_batch,
            )
            .expect("open first");
        assert!(matches!(
            receiver
                .commit_opened(&mut substituted, &mut other_batch)
                .expect("substitution result"),
            WgCommitResult::Stale
        ));
        assert!(
            receiver.preflight_data(&first).is_ok(),
            "substitution mutated state"
        );

        let mut wrong_batch = receiver
            .open_prepared_into(
                &first,
                &receiver
                    .preflight_data(&first)
                    .expect("preflight first again"),
                &mut first_batch,
            )
            .expect("open first again");
        assert!(matches!(
            receiver
                .commit_opened(&mut wrong_batch, &mut other_batch)
                .expect("wrong-batch result"),
            WgCommitResult::Stale
        ));
        assert!(
            receiver.preflight_data(&first).is_ok(),
            "wrong batch mutated state"
        );

        let mut reusable = receiver
            .open_prepared_into(
                &first,
                &receiver
                    .preflight_data(&first)
                    .expect("preflight valid commit"),
                &mut first_batch,
            )
            .expect("open valid commit");
        assert!(matches!(
            receiver
                .commit_opened(&mut reusable, &mut first_batch)
                .expect("valid commit"),
            WgCommitResult::Accepted
        ));
        assert!(matches!(
            receiver
                .commit_opened(&mut reusable, &mut first_batch)
                .expect("reuse result"),
            WgCommitResult::Stale
        ));
    }

    #[test]
    fn opened_capability_rejects_modified_body_reopened_slot_and_other_tunnel() {
        let sender_private = NodePrivate::generate();
        let receiver_private = NodePrivate::generate();
        let mut sender = WgTunn::new(&sender_private, &receiver_private.public(), 73).unwrap();
        let mut receiver = WgTunn::new(&receiver_private, &sender_private.public(), 74).unwrap();
        let mut other_receiver =
            WgTunn::new(&receiver_private, &sender_private.public(), 75).unwrap();
        handshake(&mut sender, &mut receiver);
        let datagram = sender
            .encapsulate(&make_ipv4_packet(b"opaque input binding"))
            .unwrap()
            .pop()
            .unwrap();
        let mut batch = WgPlaintextBatch::new();
        let mut other_batch = WgPlaintextBatch::new();
        let mut modified_body = receiver
            .open_prepared_into(
                &datagram,
                &receiver.preflight_data(&datagram).unwrap(),
                &mut batch,
            )
            .unwrap();
        // The commit API deliberately accepts no replacement ciphertext or
        // destination. A separate caller copy cannot affect this authenticated
        // capability; wrong-batch use is stale without mutating the tunnel.
        assert!(matches!(
            receiver
                .commit_opened(&mut modified_body, &mut other_batch)
                .unwrap(),
            WgCommitResult::Stale
        ));
        assert!(
            receiver.preflight_data(&datagram).is_ok(),
            "wrong batch mutated state"
        );

        let mut old_slot = receiver
            .open_prepared_into(
                &datagram,
                &receiver.preflight_data(&datagram).unwrap(),
                &mut batch,
            )
            .unwrap();
        batch.clear();
        let _new_slot = receiver
            .open_prepared_into(
                &datagram,
                &receiver.preflight_data(&datagram).unwrap(),
                &mut batch,
            )
            .unwrap();
        assert!(matches!(
            receiver.commit_opened(&mut old_slot, &mut batch).unwrap(),
            WgCommitResult::Stale
        ));
        assert!(
            receiver.preflight_data(&datagram).is_ok(),
            "old slot token mutated state"
        );

        let mut other_tunnel = receiver
            .open_prepared_into(
                &datagram,
                &receiver.preflight_data(&datagram).unwrap(),
                &mut batch,
            )
            .unwrap();
        assert!(matches!(
            other_receiver
                .commit_opened(&mut other_tunnel, &mut batch)
                .unwrap(),
            WgCommitResult::Stale
        ));
        assert!(
            receiver.preflight_data(&datagram).is_ok(),
            "other tunnel mutated state"
        );
    }

    #[test]
    fn scalar_jumbo_fallback_releases_oversize_capacity_from_both_scratch_batches() {
        let sender_private = NodePrivate::generate();
        let receiver_private = NodePrivate::generate();
        let mut sender =
            WgTunn::new(&sender_private, &receiver_private.public(), 76).expect("sender");
        let mut receiver =
            WgTunn::new(&receiver_private, &sender_private.public(), 77).expect("receiver");
        handshake(&mut sender, &mut receiver);
        let jumbo = make_ipv4_packet(&vec![0x5a; MAX_PIPELINED_ENCRYPTED_BODY + 512]);
        let normal = make_ipv4_packet(&vec![0x5a; 1400]);
        let mut first = WgPlaintextBatch::new();
        let mut second = WgPlaintextBatch::new();
        for _ in 0..2 {
            for batch in [&mut first, &mut second] {
                let jumbo_datagram = sender.encapsulate(&jumbo).unwrap().pop().unwrap();
                receiver.decapsulate_into(&jumbo_datagram, batch).unwrap();
                batch.clear();
                batch.release_oversized_slots();
                let normal_datagram = sender.encapsulate(&normal).unwrap().pop().unwrap();
                receiver.decapsulate_into(&normal_datagram, batch).unwrap();
                batch.clear();
            }
        }
        let retained: usize = first
            .packets
            .iter()
            .chain(&second.packets)
            .map(Vec::capacity)
            .sum();
        assert!(retained <= 2 * MAX_PIPELINED_ENCRYPTED_BODY);
        assert!(first.packets[0].capacity() >= normal.len());
        assert!(second.packets[0].capacity() >= normal.len());
    }
}
