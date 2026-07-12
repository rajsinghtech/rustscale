//! Connect to a running rustscale node's LocalAPI socket and print /status.
//!
//! Usage:
//!   cargo run --example localapi-status -- /path/to/rustscale.sock
//!
//! If no path is given, defaults to `<state_dir>/rustscale.sock` where
//! state_dir is the RUSTSCALE_STATE_DIR env var or /tmp/rustscale.
//!
//! This demonstrates the LocalAPI client side: a simple Unix-socket HTTP/1.1
//! client that sends a GET request and prints the JSON response.

use std::env;
use std::io::{Read, Write};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(unix)]
fn main() {
    let socket_path: PathBuf = env::args().nth(1).map_or_else(
        || {
            let state_dir =
                env::var("RUSTSCALE_STATE_DIR").unwrap_or_else(|_| "/tmp/rustscale".into());
            PathBuf::from(state_dir).join("rustscale.sock")
        },
        PathBuf::from,
    );

    if !socket_path.exists() {
        eprintln!("error: socket not found at {}", socket_path.display());
        eprintln!("hint: start a rustscale node with .localapi(true) or .localapi_path(path)");
        std::process::exit(1);
    }

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot connect to {}: {e}", socket_path.display());
            std::process::exit(1);
        }
    };

    let request =
        "GET /localapi/v0/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if let Err(e) = stream.write_all(request.as_bytes()) {
        eprintln!("error: write failed: {e}");
        std::process::exit(1);
    }

    let mut response = String::new();
    if let Err(e) = stream.read_to_string(&mut response) {
        eprintln!("error: read failed: {e}");
        std::process::exit(1);
    }

    // Split headers and body.
    let body = match response.split_once("\r\n\r\n") {
        Some((_headers, body)) => body,
        None => &response,
    };

    // Pretty-print the JSON if possible, otherwise print raw.
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        let pretty = serde_json::to_string_pretty(&json).unwrap_or_else(|_| body.to_string());
        println!("{pretty}");
    } else {
        println!("{body}");
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("localapi-status: this example requires a Unix platform");
}
