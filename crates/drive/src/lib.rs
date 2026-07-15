//! A bounded, capability-confined Taildrive core.
//!
//! This crate contains the share/configuration model, Taildrive capability
//! grant parsing, and the WebDAV level-1 operations needed to browse and use
//! remote shares. It deliberately does not mount a filesystem, expose a
//! LocalAPI endpoint, or register a PeerAPI route. An integrator must obtain
//! capability grants from an authenticated netmap peer; request headers are
//! never an authority source.
//!
//! Sharing is fail-closed: a new [`ConfigStore`] is disabled and contains no
//! roots. Each enabled share is held through a `cap_std` directory capability,
//! and symbolic links are rejected rather than followed.

#![forbid(unsafe_code)]

mod auth;
mod config;
mod http;
mod path;

pub use auth::{AuthError, AuthenticatedPeer, Permission, Permissions};
pub use config::{ConfigError, ConfigStore, Limits, Share, Snapshot};
pub use http::{HeaderMap, Request, RequestControl, Response, Server};
pub use path::{encode_path_component, PathError};

/// Peer capability carrying Taildrive share grants.
pub const CAPABILITY_TAILDRIVE: &str = "tailscale.com/cap/drive";

/// Peer capability advertising that a peer can share folders with us.
pub const CAPABILITY_TAILDRIVE_SHARER: &str = "tailscale.com/cap/drive-sharer";
