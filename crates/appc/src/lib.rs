//! App Connector implementation for rustscale.
//!
//! Ports Go's `tailscale.com/appc` package. An App Connector provides
//! DNS-domain-oriented routing of traffic. It watches DNS responses for
//! configured domains and dynamically publishes routes to ensure traffic
//! to those domains is routed through the connector node.
//!
//! # Modules
//!
//! - [`connector`]: [`AppConnector`] struct, [`RouteAdvertiser`] trait
//! - [`observe`]: DNS response observation and matching
//! - [`conn25`]: Peer connector selection, split-DNS resolver map
//! - [`routes`]: Prefix type, address comparison, set difference helpers
//! - [`ratelog`]: Rate-limited logging for route writes

#![forbid(unsafe_code)]

pub mod conn25;
pub mod connector;
pub mod observe;
pub mod ratelog;
pub mod routes;

pub use conn25::{app_dns_routes, is_peer_eligible_connector, pick_connector, Conn25AttrInput};
pub use connector::{AppConnector, AppConnectorConfig, AppcError, RouteAdvertiser};
pub use ratelog::RateLogger;
pub use routes::{compare_addr, has_suffix, routes_without, Prefix};
