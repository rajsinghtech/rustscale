// build.rs - regenerate include/rustscale.h via cbindgen on every build.
// The committed header is the source of truth; build.rs keeps it fresh.
use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crate must be in workspace/crates/ffi");
    let out = workspace_dir.join("include").join("rustscale.h");

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
