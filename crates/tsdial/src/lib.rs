//! Outbound dial abstraction — consolidates every ad-hoc
//! `TcpStream::connect` behind a single [`Dialer`] with three dial paths:
//!
//! - **SystemDial** — outbound-to-internet (control plane, DERPs, upstream
//!   DNS). Netns-bound, connection-tracked for link-change teardown.
//! - **UserDial** — user-initiated traffic (SOCKS, tsnet.Dial, DNS
//!   forwarder). Route-aware, happy-eyeballs, not tracked.
//! - **PeerDial** — peer-to-peer. Plain TCP, no netns, no proxy.
//!
//! Mirrors Go's `net/tsdial/` package.

mod dialer;
mod dns_map;
mod peer_dial;
mod system_dial;
mod user_dial;

pub use dialer::{global, set_global, system_dial, user_dial, Dialer, UserDialPlan};
pub use dns_map::{DnsMap, DnsMapError};
