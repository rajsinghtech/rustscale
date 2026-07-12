// build.rs - regenerate include/rustscale.h via cbindgen and stamp git version.
// The committed header is the source of truth; build.rs keeps it fresh.
use std::path::PathBuf;
use std::process::Command;

/// Run `git describe --tags --long --always --dirty` from the workspace root
/// and expose the result as `RUSTSCALE_VERSION_LONG` to the crate via
/// `option_env!`. Falls back silently to `CARGO_PKG_VERSION` when git is
/// unavailable (e.g. crates.io tarball builds with no `.git` directory).
fn stamp_version() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crate must be in workspace/crates/ffi");

    let out = Command::new("git")
        .arg("describe")
        .arg("--tags")
        .arg("--long")
        .arg("--always")
        .arg("--dirty")
        .current_dir(workspace_dir)
        .output();

    if let Ok(o) = out {
        if o.status.success() {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_owned();
            if !v.is_empty() {
                println!("cargo:rustc-env=RUSTSCALE_VERSION_LONG={v}");
            }
        }
    }
    // Re-stamp when the git HEAD changes (live development). Harmless when
    // there is no .git directory — cargo just ignores the directive.
    println!("cargo:rerun-if-changed=.git/HEAD");
}

fn main() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crate must be in workspace/crates/ffi");
    let out = workspace_dir.join("include").join("rustscale.h");

    stamp_version();

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    let cfg = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml"))
        .expect("failed to read cbindgen.toml");

    match cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(cfg)
        .generate()
    {
        Ok(bindings) => {
            let _ = bindings.write_to_file(out);
        }
        Err(e) => {
            // Don't fail the build; the committed header may already exist.
            println!("cargo:warning=cbindgen failed: {e}");
        }
    }
}
