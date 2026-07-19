// build.rs — stamp git version for the CLI's `version` subcommand.
// Exposes RUSTSCALE_VERSION_LONG via option_env! (git describe), falling back
// to CARGO_PKG_VERSION when git is unavailable.
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTSCALE_VERSION_LONG");
    if let Ok(explicit) = std::env::var("RUSTSCALE_VERSION_LONG") {
        let explicit = explicit.trim();
        if !explicit.is_empty() {
            println!("cargo:rustc-env=RUSTSCALE_VERSION_LONG={explicit}");
            return;
        }
    }

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crate must be in workspace/crates/cli");

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
    println!("cargo:rerun-if-changed=.git/HEAD");
}
