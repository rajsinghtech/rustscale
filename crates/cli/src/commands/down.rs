//! `rustscale down` — disconnect from Tailscale.
//!
//! Ports Go's `cmd/tailscale/cli/down.go`. The daemon's prefs-write path
//! is not yet available, so this surfaces a clear "not yet supported" message
//! and exits. The full MaskedPrefs machinery will land in the IPN phase.

use std::path::Path;

use crate::CliError;

/// `rustscale down` — disconnect from Tailscale.
///
/// Ports Go's `cmd/tailscale/cli/down.go`. The daemon's prefs-write path
/// is not yet available, so this surfaces a clear "not yet supported" message
/// and exits. The full MaskedPrefs machinery will land in the IPN phase.
#[allow(clippy::unused_async)]
pub async fn run(_args: Vec<String>, _socket: &Path) -> Result<(), CliError> {
    Err(CliError(
        "down: not yet supported by rustscaled (prefs write path pending IPN phase)".into(),
    ))
}
