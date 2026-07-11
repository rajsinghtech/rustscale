//! rustscale-serve — minimal HTTP serving over tsnet (plain TCP + optional TLS).
//!
//! Serves a fixed index page and a `/bench` endpoint that streams N megabytes
//! for benchmarking. This is the serve-side prerequisite for the phase-10a
//! performance benchmarking (iperf3/HTTP throughput comparisons).
//!
//! # Usage
//!
//! ```sh
//! cargo run --example rustscale-serve -- \
//!   --authkey tskey-... \
//!   --hostname my-serve \
//!   --port 8080 \
//!   --bytes 4
//! ```
//!
//! Add `--tls` to serve over TLS (self-signed-per-node cert at this stage).
//! `--authkey` can be omitted if `TS_AUTHKEY` is set in the environment.

use rustscale_tsnet::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut authkey = std::env::var("TS_AUTHKEY").unwrap_or_default();
    let mut hostname = "rustscale-serve".to_string();
    let mut port: u16 = 8080;
    let mut bytes_mb: usize = 4;
    let mut tls = false;
    let mut control_url = rustscale_tsnet::DEFAULT_CONTROL_URL.to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--authkey" => {
                i += 1;
                if i < args.len() {
                    authkey = args[i].clone();
                }
            }
            "--hostname" => {
                i += 1;
                if i < args.len() {
                    hostname = args[i].clone();
                }
            }
            "--port" => {
                i += 1;
                if i < args.len() {
                    port = args[i].parse().unwrap_or(8080);
                }
            }
            "--bytes" => {
                i += 1;
                if i < args.len() {
                    bytes_mb = args[i].parse().unwrap_or(4);
                }
            }
            "--tls" => {
                tls = true;
            }
            "--control-url" => {
                i += 1;
                if i < args.len() {
                    control_url = args[i].clone();
                }
            }
            "--help" | "-h" => {
                eprintln!("rustscale-serve — HTTP serving over tsnet\n");
                eprintln!("Usage: rustscale-serve [OPTIONS]\n");
                eprintln!("Options:");
                eprintln!("  --authkey <key>     Tailscale auth key (or TS_AUTHKEY env)");
                eprintln!("  --hostname <name>   Node hostname (default: rustscale-serve)");
                eprintln!("  --port <port>       Listen port (default: 8080)");
                eprintln!("  --bytes <MB>        Megabytes to stream from /bench (default: 4)");
                eprintln!("  --tls               Serve over TLS (self-signed per-node cert)");
                eprintln!("  --control-url <url> Control plane URL");
                eprintln!("  --help              Show this help");
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if authkey.is_empty() {
        eprintln!("error: --authkey or TS_AUTHKEY env var is required");
        std::process::exit(2);
    }

    let mut server = Server::builder()
        .hostname(hostname.as_str())
        .auth_key(authkey.as_str())
        .control_url(control_url.as_str())
        .ephemeral(true)
        .build()?;

    eprintln!("bringing up tsnet server (hostname={hostname})...");
    Box::pin(server.up()).await?;

    let status = server.status();
    eprintln!("online: {}", status.up);
    eprintln!("tailscale IPs: {:?}", status.tailscale_ips);
    eprintln!("peers: {}", status.peer_count);
    eprintln!(
        "serving on port {port} ({})",
        if tls { "TLS" } else { "plain TCP" }
    );

    // Start the listener.
    if tls {
        let mut listener = server.listen_tls(port).await?;
        loop {
            match listener.accept().await {
                Ok(mut stream) => {
                    let mb = bytes_mb;
                    tokio::spawn(async move {
                        let _ = serve_http(&mut stream, mb).await;
                    });
                }
                Err(e) => eprintln!("tls accept error: {e}"),
            }
        }
    } else {
        let mut listener = server.listen(port).await?;
        loop {
            match listener.accept().await {
                Ok(mut stream) => {
                    let mb = bytes_mb;
                    tokio::spawn(async move {
                        let _ = serve_http(&mut stream, mb).await;
                    });
                }
                Err(e) => eprintln!("accept error: {e}"),
            }
        }
    }
}

/// Minimal HTTP/1.1 handler: parse the request path, respond with a fixed
/// page or stream N MB from `/bench`.
async fn serve_http<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    bytes_mb: usize,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split(' ').nth(1).unwrap_or("/");

    if path == "/bench" {
        // Stream N MB of zeroes in 64KB chunks. Content-Length is set so
        // clients can measure raw throughput without chunked encoding.
        let total = bytes_mb * 1024 * 1024;
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(header.as_bytes()).await?;
        let chunk = vec![0xAAu8; 65_536];
        let mut sent = 0usize;
        while sent < total {
            let end = (sent + chunk.len()).min(total);
            stream.write_all(&chunk[..end - sent]).await?;
            sent = end;
        }
    } else {
        let body = format!(
            "<html><body><h1>rustscale-serve</h1>\
             <p>Serving on tsnet. IPs: use /bench?bytes={bytes_mb}MB</p>\
             <p>Endpoints: <a href=\"/bench\">/bench</a> (streams {bytes_mb} MB)</p>\
             </body></html>"
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await?;
    }
    stream.shutdown().await.ok();
    Ok(())
}
