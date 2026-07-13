//! Peer path MTU discovery (PMTUD) — Don't Fragment socket option management.
//!
//! Port of Go's `wgengine/magicsock/peermtu*.go` (130 lines + 3 platform files).
//!
//! The PMTUD probe logic (multi-size ping bursts, probe-size tracking per
//! endpoint, `WIRE_MTUS_TO_PROBE`) lives in the main magicsock module. This
//! module handles the platform-specific socket option plumbing that sets/clears
//! the Don't Fragment (DF) bit on the magicsock UDP sockets, plus the
//! `update_pmtud` orchestration function that integrates with control knobs
//! and endpoint state resets.

mod platform;

#[cfg(all(target_os = "linux", not(target_os = "android")))]
mod linux;
#[cfg(all(target_os = "linux", not(target_os = "android")))]
use linux as sys;

#[cfg(all(target_os = "macos", not(target_os = "ios")))]
mod darwin;
#[cfg(all(target_os = "macos", not(target_os = "ios")))]
use darwin as sys;

#[cfg(not(any(
    all(target_os = "linux", not(target_os = "android")),
    all(target_os = "macos", not(target_os = "ios")),
)))]
mod stubs;
#[cfg(not(any(
    all(target_os = "linux", not(target_os = "android")),
    all(target_os = "macos", not(target_os = "ios")),
)))]
use stubs as sys;

use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

use rustscale_controlknobs::ControlKnobs;
use rustscale_disco::Message as DiscoMessage;

pub use sys::SetDfError;

/// Enable/disable DF on a tokio UDP socket for the appropriate network type
/// based on the socket's local address. Returns the network string used.
fn set_df_on_socket(
    socket: &tokio::net::UdpSocket,
    enable: bool,
) -> (String, Result<(), SetDfError>) {
    let local = socket.local_addr();
    let network = match &local {
        Ok(SocketAddr::V4(_)) => "udp4",
        Ok(SocketAddr::V6(_)) => "udp6",
        Err(_) => "udp4",
    };
    let fd = socket.as_raw_fd();
    let result = sys::set_dont_fragment(fd, network, enable);
    (network.to_string(), result)
}

/// Query the DF bit state on a tokio UDP socket.
fn get_df_on_socket(socket: &tokio::net::UdpSocket) -> Result<bool, SetDfError> {
    let local = socket.local_addr();
    let network = match &local {
        Ok(SocketAddr::V4(_)) => "udp4",
        Ok(SocketAddr::V6(_)) => "udp6",
        Err(_) => "udp4",
    };
    let fd = socket.as_raw_fd();
    sys::get_dont_fragment(fd, network)
}

/// Update the PMTUD configuration for the magicsock UDP socket.
/// Mirrors Go's `Conn.UpdatePMTUD()`.
///
/// Returns `(new_enabled, changed)` — `changed` is true if the effective PMTUD
/// status changed (caller should reset endpoint states).
pub fn update_pmtud(
    socket: Option<&tokio::net::UdpSocket>,
    control_knobs: Option<&ControlKnobs>,
    current_enabled: bool,
) -> (bool, bool) {
    let enable = should_pmtud(control_knobs);
    if enable == current_enabled {
        return (current_enabled, false);
    }

    let Some(sock) = socket else {
        return (current_enabled, false);
    };

    let (_network, result) = set_df_on_socket(sock, enable);

    let new_status = match result {
        Ok(()) => {
            log::info!("magicsock: peermtu: peer MTU status updated to {enable}");
            enable
        }
        Err(e) => {
            log::warn!(
                "magicsock: peermtu: updating peer MTU status to {enable} failed ({e}), disabling"
            );
            let _ = set_df_on_socket(sock, false);
            false
        }
    };

    (new_status, new_status != current_enabled)
}

/// Whether PMTUD should be enabled, based on control knobs and defaults.
/// Mirrors Go's `ShouldPMTUD()` (peermtu.go:38-57).
///
/// Priority: env override → control knob → default false
pub fn should_pmtud(control_knobs: Option<&ControlKnobs>) -> bool {
    if let Ok(v) = std::env::var("TS_DEBUG_ENABLE_PMTUD") {
        match v.as_str() {
            "1" | "true" | "TRUE" | "True" => return true,
            "0" | "false" | "FALSE" | "False" => return false,
            _ => {}
        }
    }
    if let Some(knobs) = control_knobs {
        if knobs.get_bool("peer-mtu-enable", false) {
            return true;
        }
    }
    false
}

/// Query the DF bit state on the magicsock socket.
/// Mirrors Go's `DontFragSetting()`. Returns (df_set, error).
/// Since our code has a single UDP socket, we check just that one.
pub fn dont_frag_setting(socket: Option<&tokio::net::UdpSocket>) -> Result<bool, SetDfError> {
    match socket {
        Some(sock) => get_df_on_socket(sock),
        None => Ok(false),
    }
}

/// Whether a disco TX error should be logged (suppress EMSGSIZE for
/// padded disco pings used in PMTUD probing).
/// Mirrors Go's `pmtuShouldLogDiscoTxErr` (peermtu.go:122-130).
pub fn should_log_disco_tx_err(msg: &DiscoMessage, err: &std::io::Error) -> bool {
    if let DiscoMessage::Ping(ping) = msg {
        if ping.padding > 0 {
            if let Some(raw) = err.raw_os_error() {
                if raw == libc::EMSGSIZE {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_should_pmtud_default_false() {
        let _env_lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::remove_var("TS_DEBUG_ENABLE_PMTUD");
        assert!(!should_pmtud(None));
    }

    #[test]
    fn test_should_pmtud_env_override() {
        let _env_lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::set_var("TS_DEBUG_ENABLE_PMTUD", "1");
        assert!(should_pmtud(None));
        std::env::set_var("TS_DEBUG_ENABLE_PMTUD", "0");
        assert!(!should_pmtud(None));
        std::env::remove_var("TS_DEBUG_ENABLE_PMTUD");
    }

    #[test]
    fn test_should_pmtud_control_knob() {
        let _env_lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::remove_var("TS_DEBUG_ENABLE_PMTUD");
        let knobs = ControlKnobs::new();
        // Default: false
        assert!(!should_pmtud(Some(&knobs)));

        // Enable via control knob
        let mut vals = std::collections::HashMap::new();
        vals.insert("peer-mtu-enable".to_string(), "true".to_string());
        knobs.apply(vals);
        assert!(should_pmtud(Some(&knobs)));
    }

    #[test]
    fn test_should_log_disco_tx_err_emsgsize_with_padding() {
        let ping = DiscoMessage::Ping(rustscale_disco::Ping {
            tx_id: [0u8; 12],
            node_key: rustscale_key::NodePublic::from_raw32([0u8; 32]),
            padding: 100,
        });
        let err = std::io::Error::from_raw_os_error(libc::EMSGSIZE);
        assert!(!should_log_disco_tx_err(&ping, &err));
    }

    #[test]
    fn test_should_log_disco_tx_err_emsgsize_no_padding() {
        let ping = DiscoMessage::Ping(rustscale_disco::Ping {
            tx_id: [0u8; 12],
            node_key: rustscale_key::NodePublic::from_raw32([0u8; 32]),
            padding: 0,
        });
        let err = std::io::Error::from_raw_os_error(libc::EMSGSIZE);
        assert!(should_log_disco_tx_err(&ping, &err));
    }

    #[test]
    fn test_should_log_disco_tx_err_other_error() {
        let ping = DiscoMessage::Ping(rustscale_disco::Ping {
            tx_id: [0u8; 12],
            node_key: rustscale_key::NodePublic::from_raw32([0u8; 32]),
            padding: 100,
        });
        let err = std::io::Error::from_raw_os_error(libc::EPERM);
        assert!(should_log_disco_tx_err(&ping, &err));
    }

    #[test]
    fn test_dont_fragment_set_get_roundtrip() {
        let sock = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&sock);

        // Enable DF
        let result = sys::set_dont_fragment(fd, "udp4", true);
        assert!(result.is_ok(), "set_dont_fragment(true) failed: {result:?}");

        // Verify it's set
        let df = sys::get_dont_fragment(fd, "udp4").unwrap();
        assert!(df, "DF should be set after enabling");

        // Disable DF
        sys::set_dont_fragment(fd, "udp4", false).unwrap();
        let df = sys::get_dont_fragment(fd, "udp4").unwrap();
        assert!(!df, "DF should be cleared after disabling");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_update_pmtud_toggle() {
        let _env_lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::remove_var("TS_DEBUG_ENABLE_PMTUD");
        let tokio_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // With no control knobs and no env, should_pmtud returns false.
        // If current is true, update should toggle to false.
        let (new_enabled, changed) = update_pmtud(Some(&tokio_sock), None, true);
        assert!(!new_enabled);
        assert!(changed);

        // Enable via env, current is false → should toggle to true
        std::env::set_var("TS_DEBUG_ENABLE_PMTUD", "1");
        let (new_enabled, changed) = update_pmtud(Some(&tokio_sock), None, false);
        assert!(new_enabled);
        assert!(changed);

        // Already enabled → no change
        let (new_enabled, changed) = update_pmtud(Some(&tokio_sock), None, true);
        assert!(new_enabled);
        assert!(!changed);

        // Cleanup
        std::env::remove_var("TS_DEBUG_ENABLE_PMTUD");
    }
}
