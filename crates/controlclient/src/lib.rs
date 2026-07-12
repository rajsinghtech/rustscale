//! ts2021 Noise-based control plane client for rustscale.
//!
//! Ports the Tailscale control protocol stack:
//! - [`controlbase`] — Noise IK handshake and length-framed encrypted records
//!   (Go: `control/controlbase`).
//! - [`controlhttp`] — HTTP `/ts2021` upgrade dance
//!   (Go: `control/controlhttp`).
//! - [`client`] — `RegisterRequest` and `MapRequest` long-poll flows
//!   (Go: `control/controlclient`, `control/ts2021`).

#![forbid(unsafe_code)]

pub mod c2n;
pub mod client;
pub mod controlbase;
pub mod controlhttp;
pub mod login_flags;

pub use c2n::{C2nHandler, C2nRequest, C2nResponse, C2nRouter};
pub use client::{ControlClient, RegisterError, StreamMapError};
pub use controlbase::{NoiseConn, NoiseError, NoiseIo, ProtocolVersion};
pub use controlhttp::{dial_control, fetch_server_pub_key, DialError, NoiseStream};
pub use login_flags::{LoginFlags, LOGIN_DEFAULT, LOGIN_EPHEMERAL, LOGIN_INTERACTIVE};

use std::collections::HashMap;

use rustscale_tailcfg::MapResponse;

/// Extract control knobs from a [`MapResponse`]'s self-node `CapMap`.
///
/// Mirrors Go's `mapSession.send(...)` → `controlKnobs.UpdateFromNodeAttributes(
/// resp.Node.CapMap)` (controlclient/map.go:302). Each capability present in
/// the CapMap becomes a knob entry:
/// - Capabilities with no argument values → `"true"` (matches Go's
///   `capMap.Contains(...)` semantics).
/// - Capabilities with argument values (e.g. `"one-cgnat?v=true"`) → the
///   first argument's raw JSON string, or `"true"` if the arg list is empty.
///
/// Returns an empty map when `MapResponse.Node` is absent.
pub fn extract_knobs_from_map_response(resp: &MapResponse) -> HashMap<String, String> {
    let mut knobs = HashMap::new();
    if let Some(ref node) = resp.Node {
        for (cap, args) in &node.CapMap {
            let value = if args.is_empty() {
                "true".to_string()
            } else {
                // Use the first argument's raw JSON, stripping surrounding
                // quotes from string values for ergonomic typed accessors.
                let raw = &args[0].0;
                if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
                    raw[1..raw.len() - 1].to_string()
                } else {
                    raw.clone()
                }
            };
            knobs.insert(cap.clone(), value);
        }
    }
    knobs
}

#[cfg(test)]
mod knob_tests {
    use super::*;
    use rustscale_controlknobs::ControlKnobs;
    use rustscale_tailcfg::{MapResponse, Node, RawMessage};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn extract_from_empty_response() {
        let resp = MapResponse::default();
        let knobs = extract_knobs_from_map_response(&resp);
        assert!(knobs.is_empty());
    }

    #[test]
    fn extract_from_node_capmap() {
        let mut cap_map = rustscale_tailcfg::NodeCapMap::new();
        cap_map.insert("debug-always-stun".into(), vec![]);
        cap_map.insert("debug-disable-upnp".into(), vec![]);
        cap_map.insert("silent-disco".into(), vec![]);
        let resp = MapResponse {
            Node: Some(Node {
                CapMap: cap_map,
                ..Default::default()
            }),
            ..Default::default()
        };
        let knobs = extract_knobs_from_map_response(&resp);
        assert_eq!(knobs.get("debug-always-stun"), Some(&"true".to_string()));
        assert_eq!(knobs.get("debug-disable-upnp"), Some(&"true".to_string()));
        assert_eq!(knobs.get("silent-disco"), Some(&"true".to_string()));
    }

    #[test]
    fn extract_with_arg_values() {
        let mut cap_map = rustscale_tailcfg::NodeCapMap::new();
        cap_map.insert("custom-knob".into(), vec![RawMessage("\"hello\"".into())]);
        cap_map.insert("numeric-knob".into(), vec![RawMessage("42".into())]);
        let resp = MapResponse {
            Node: Some(Node {
                CapMap: cap_map,
                ..Default::default()
            }),
            ..Default::default()
        };
        let knobs = extract_knobs_from_map_response(&resp);
        assert_eq!(knobs.get("custom-knob"), Some(&"hello".to_string()));
        assert_eq!(knobs.get("numeric-knob"), Some(&"42".to_string()));
    }

    #[test]
    fn apply_to_control_knobs() {
        let ck = Arc::new(ControlKnobs::new());
        let mut cap_map = rustscale_tailcfg::NodeCapMap::new();
        cap_map.insert("debug-always-stun".into(), vec![]);
        let resp = MapResponse {
            Node: Some(Node {
                CapMap: cap_map,
                ..Default::default()
            }),
            ..Default::default()
        };
        let extracted = extract_knobs_from_map_response(&resp);
        ck.apply(extracted);
        assert!(ck.get_bool("debug-always-stun", false));
        assert!(ck.has("debug-always-stun"));
    }

    #[test]
    fn apply_fires_on_change() {
        let ck = Arc::new(ControlKnobs::new());
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        ck.on_change(
            "debug-always-stun",
            Box::new(move |_| {
                c.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let mut cap_map = rustscale_tailcfg::NodeCapMap::new();
        cap_map.insert("debug-always-stun".into(), vec![]);
        let resp = MapResponse {
            Node: Some(Node {
                CapMap: cap_map,
                ..Default::default()
            }),
            ..Default::default()
        };
        ck.apply(extract_knobs_from_map_response(&resp));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
