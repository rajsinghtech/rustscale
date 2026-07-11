//! Minimal "hello from rustscale" webserver.
//!
//! Joins a tailnet and serves HTTP on port 8080 over the tailnet.
//! Any tailnet peer can curl `http://<hostname>:8080/` to see the greeting.
//!
//! Usage:
//!   cargo run --example hello --release
//!
//! Environment:
///    RUSTSCALE_AUTH_KEY — tailscale auth key (tskey-...)
///    RUSTSCALE_HOSTNAME — node hostname (default: "hello")
use std::env;

use rustscale_tsnet::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_key = env::var("RUSTSCALE_AUTH_KEY")
        .or_else(|_| {
            env::args()
                .nth(1)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no key"))
        })
        .map_err(|_| "pass auth key via RUSTSCALE_AUTH_KEY or argv[1]")?;

    let hostname = env::var("RUSTSCALE_HOSTNAME").unwrap_or_else(|_| "hello".into());

    let mut server = Server::builder()
        .hostname(hostname.clone())
        .auth_key(&auth_key)
        .ephemeral(true)
        .build()?;

    println!("Bringing up rustscale node '{hostname}'...");
    Box::pin(server.up()).await?;

    let status = server.status();
    println!("Node is up!");
    println!("  Hostname:   {}", status.hostname);
    println!("  IPs:        {:?}", status.tailscale_ips);
    println!("  Peers:      {}", status.peer_count);
    for ip in &status.tailscale_ips {
        println!("Listening on http://{ip}:8080/");
    }

    let mut listener = server.listen(8080).await?;
    println!("Serving HTTP on tailnet port 8080");

    let body = b"hello from rustscale\n";

    loop {
        let mut stream = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };

        let mut buf = vec![0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.shutdown().await;
    }
}
