//! UDP port mapping client for rustscale, ported from Tailscale's Go
//! `net/portmapper` package. Supports NAT-PMP (RFC 6886), PCP (RFC 6887),
//! and UPnP IGD (SSDP discovery + SOAP AddPortMapping).
//!
//! # API
//!
//! - [`Client::new`] — construct a port mapping client with default gateway
//!   detection.
//! - [`Client::probe`] — detect which protocols the gateway supports.
//! - [`Client::get_mapping`] — create/renew a mapping, returning the external
//!   `ip:port`. Caches the last working method and renews at half-lifetime.
//! - [`Client::close`] — release any active mapping.
//!
//! Gateway detection is pluggable via [`Client::set_gateway_lookup`] so tests
//! can inject a fake gateway without touching the real LAN.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

mod client;
mod gateway;
mod http;
mod pcp;
mod pmp;
mod upnp;
mod xml;

#[cfg(test)]
mod tests;

pub use client::{Client, ClientConfig, Mapping, MappingKind, ProbeResult};
pub use gateway::{likely_home_router_ip, GatewayInfo};

/// NAT-PMP / PCP port (RFC 6886 §3.1, RFC 6887 §8.1).
pub(crate) const PXP_PORT: u16 = 5351;
/// UPnP SSDP discovery port.
pub(crate) const UPNP_PORT: u16 = 1900;
/// SSDP multicast address.
#[allow(clippy::ip_constant)]
pub(crate) const SSDP_MULTICAST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(239, 255, 255, 250);

/// RFC 6886 recommended 2-hour map lifetime.
pub(crate) const MAP_LIFETIME_SECS: u32 = 7200;

/// How long we wait for port-mapping services to respond. They're one L3 hop
/// away on the LAN, so we don't give them much time (mirrors Go's 250 ms).
pub(crate) const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

/// How long we trust a recently-probed service before re-probing.
pub(crate) const TRUST_DURATION: std::time::Duration = std::time::Duration::from_mins(10);

/// Internal wire-format parse entrypoints exposed for fuzz targets.
/// Not part of the stable public API.
#[doc(hidden)]
pub mod _fuzz {
    pub use crate::pcp::parse_common_header as parse_pcp_header;
    pub use crate::pcp::parse_map_response as parse_pcp_map_response;
    pub use crate::pmp::parse_response as parse_pmp_response;
}

/// A port-mapping error that means no NAT mapping is available (gateway not
/// found, all services disabled, etc.).
#[derive(Debug, thiserror::Error)]
pub enum PortMapError {
    #[error("no port mapping services available")]
    NoServices,
    #[error("gateway not in a usable range")]
    GatewayRange,
    #[error("gateway is IPv6 (unsupported)")]
    GatewayIPv6,
    #[error("port mapping disabled by configuration")]
    Disabled,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl Clone for PortMapError {
    fn clone(&self) -> Self {
        match self {
            Self::NoServices => Self::NoServices,
            Self::GatewayRange => Self::GatewayRange,
            Self::GatewayIPv6 => Self::GatewayIPv6,
            Self::Disabled => Self::Disabled,
            Self::Io(error) => Self::Io(std::io::Error::new(error.kind(), error.to_string())),
            Self::Protocol(error) => Self::Protocol(error.clone()),
        }
    }
}
