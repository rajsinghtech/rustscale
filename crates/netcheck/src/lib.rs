//! STUN-based network probing for rustscale, ported from Tailscale's Go
//! `net/netcheck` and `net/stun` packages.
//!
//! - [`stun`] — an RFC 5389 subset: binding request/response codec, XOR-MAPPED-
//!   ADDRESS parsing (v4+v6), fingerprint, `is_stun` quick check.
//! - [`Report`] — the result of a netcheck run, mirroring Go's
//!   `netcheck.Report` (UDP/IPv4/IPv6 flags, per-region latencies, reflexive
//!   endpoints, preferred DERP region).
//! - [`Prober`] — probes each DERP region over UDP STUN, measures latency, and
//!   picks the preferred region.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

mod captivedetection;
pub mod icmp;
mod prober;
mod report;
mod stun;

pub use captivedetection::{
    available_endpoints, builtin_endpoints, DetectResult, Detector, Endpoint, EndpointProvider,
    DETECT_TIMEOUT,
};
pub use prober::{NetcheckError, Prober, ProberOpts, REPORT_TIMEOUT};
pub use report::Report;
pub use stun::{
    is_stun, new_tx_id, parse_binding_request, parse_response, request, response, StunError, TxID,
    HEADER_LEN, MAGIC_COOKIE, TX_ID_LEN,
};
