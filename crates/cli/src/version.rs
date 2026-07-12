//! Version stamping for the `rustscale` CLI. The git rev is stamped at build
//! time via `build.rs` (RUSTSCALE_VERSION_LONG), falling back to
//! `CARGO_PKG_VERSION` when git is unavailable (e.g. crates.io tarball).

/// The short version string (package version).
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The long version string (git describe), or the package version if git
/// was not available at build time.
pub const CLIENT_VERSION_LONG: &str = match option_env!("RUSTSCALE_VERSION_LONG") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Return the human-readable client version string.
pub fn client_version_string() -> String {
    CLIENT_VERSION_LONG.to_string()
}
