//! Unit + integration tests for the SOCKS5 proxy (RFC 1928).
//!
//! Wire-protocol tests use `tokio::io::Cursor`/raw bytes (no live tailnet);
//! the integration test starts a real OS listener with a mock dialer backed
//! by a local echo server and drives a hand-rolled SOCKS5 client through it.

use std::io;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

#[tokio::test]
async fn cancel_token_wakes_all_registered_waiters_and_late_waiters() {
    let cancel = Arc::new(CancelToken::new());
    let first = {
        let cancel = Arc::clone(&cancel);
        tokio::spawn(async move { cancel.cancelled().await })
    };
    let second = {
        let cancel = Arc::clone(&cancel);
        tokio::spawn(async move { cancel.cancelled().await })
    };
    tokio::task::yield_now().await;
    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(1), first)
        .await
        .expect("first cancellation waiter did not wake")
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), second)
        .await
        .expect("second cancellation waiter did not wake")
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), cancel.cancelled())
        .await
        .expect("late cancellation waiter did not wake");
}

// ---------------------------------------------------------------------------
// Mock dialer
// ---------------------------------------------------------------------------

/// A dialer that always connects to a fixed local backend address, returning
/// the real OS stream + its local address. Used by the integration test.
struct MockDialer {
    backend: SocketAddr,
}

#[async_trait]
impl SocksDialer for MockDialer {
    async fn dial(&self, _addr: &str) -> io::Result<(BoxedStream, SocketAddr)> {
        let s = TcpStream::connect(self.backend).await?;
        let local = s.local_addr()?;
        Ok((Box::new(s), local))
    }
}

/// A dialer that always fails with a chosen io kind — for reply-code mapping.
struct FailingDialer {
    kind: io::ErrorKind,
}

#[async_trait]
impl SocksDialer for FailingDialer {
    async fn dial(&self, _addr: &str) -> io::Result<(BoxedStream, SocketAddr)> {
        Err(io::Error::new(self.kind, "failing dialer (test)"))
    }
}

// ---------------------------------------------------------------------------
// SocksAddr marshal / parse round-trips
// ---------------------------------------------------------------------------

#[tokio::test]
async fn socksaddr_ipv4_round_trip() {
    let a = SocksAddr::Ipv4 {
        addr: Ipv4Addr::new(100, 64, 0, 2),
        port: 443,
    };
    let bytes = a.marshal().unwrap();
    assert_eq!(bytes, vec![0x01, 100, 64, 0, 2, 0x01, 0xBB]);
    let mut cur = Cursor::new(bytes);
    let parsed = SocksAddr::parse(&mut cur).await.unwrap();
    assert_eq!(parsed, a);
}

#[tokio::test]
async fn socksaddr_ipv6_round_trip() {
    let a = SocksAddr::Ipv6 {
        addr: Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1),
        port: 80,
    };
    let bytes = a.marshal().unwrap();
    assert_eq!(bytes[0], 0x04);
    assert_eq!(bytes.len(), 1 + 16 + 2);
    let mut cur = Cursor::new(bytes);
    let parsed = SocksAddr::parse(&mut cur).await.unwrap();
    assert_eq!(parsed, a);
}

#[tokio::test]
async fn socksaddr_domain_round_trip() {
    let a = SocksAddr::Domain {
        name: "peer.tailnet.ts.net".into(),
        port: 22,
    };
    let bytes = a.marshal().unwrap();
    let mut cur = Cursor::new(bytes);
    let parsed = SocksAddr::parse(&mut cur).await.unwrap();
    assert_eq!(parsed, a);
}

#[tokio::test]
async fn socksaddr_domain_too_long_returns_none() {
    let a = SocksAddr::Domain {
        name: "x".repeat(256),
        port: 1,
    };
    assert!(a.marshal().is_none());
}

#[tokio::test]
async fn socksaddr_parse_unsupported_atyp() {
    let bytes = vec![0x09, 0, 0];
    let mut cur = Cursor::new(bytes);
    let err = SocksAddr::parse(&mut cur).await.unwrap_err();
    assert!(err.contains("unsupported address type"));
}

#[tokio::test]
async fn socksaddr_host_port_formats() {
    let v4 = SocksAddr::Ipv4 {
        addr: Ipv4Addr::new(1, 2, 3, 4),
        port: 5,
    };
    assert_eq!(v4.host_port(), "1.2.3.4:5");
    let v6 = SocksAddr::Ipv6 {
        addr: Ipv6Addr::LOCALHOST,
        port: 9,
    };
    assert_eq!(v6.host_port(), "[::1]:9");
    let d = SocksAddr::Domain {
        name: "host".into(),
        port: 7,
    };
    assert_eq!(d.host_port(), "host:7");
}

// ---------------------------------------------------------------------------
// Reply encoding
// ---------------------------------------------------------------------------

#[test]
fn marshal_reply_success_ipv4() {
    let bind = SocksAddr::Ipv4 {
        addr: Ipv4Addr::new(100, 64, 0, 1),
        port: 1080,
    };
    let out = marshal_reply(0x00, &bind);
    // VER REPLY RSV ATYP ADDR... PORT...
    assert_eq!(out[0], 0x05);
    assert_eq!(out[1], 0x00);
    assert_eq!(out[2], 0x00);
    assert_eq!(out[3], 0x01);
    assert_eq!(&out[4..8], &[100, 64, 0, 1]);
    assert_eq!(&out[8..10], &1080u16.to_be_bytes());
}

#[test]
fn marshal_reply_failure_uses_zero_bind() {
    let out = marshal_reply(0x05, &ZERO_BIND);
    assert_eq!(out[0], 0x05);
    assert_eq!(out[1], 0x05);
    assert_eq!(out[2], 0x00);
    assert_eq!(out[3], 0x01);
    assert_eq!(&out[4..8], &[0, 0, 0, 0]);
    assert_eq!(&out[8..10], &0u16.to_be_bytes());
}

#[test]
fn marshal_reply_command_not_supported_code() {
    let out = marshal_reply(reply::COMMAND_NOT_SUPPORTED, &ZERO_BIND);
    assert_eq!(out[1], 0x07);
}

// ---------------------------------------------------------------------------
// Request parsing (all three address types)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_request_connect_ipv4() {
    // VER=5 CMD=1 RSV=0 ATYP=1 100.64.0.2 port=443
    let bytes = vec![0x05, 0x01, 0x00, 0x01, 100, 64, 0, 2, 0x01, 0xBB];
    let mut cur = Cursor::new(bytes);
    let req = parse_request(&mut cur).await.unwrap();
    assert_eq!(req.command, 0x01);
    assert_eq!(
        req.destination,
        SocksAddr::Ipv4 {
            addr: Ipv4Addr::new(100, 64, 0, 2),
            port: 443,
        }
    );
}

#[tokio::test]
async fn parse_request_connect_domain() {
    let name = b"example.com";
    let mut bytes = vec![0x05, 0x01, 0x00, 0x03, name.len() as u8];
    bytes.extend_from_slice(name);
    bytes.extend_from_slice(&80u16.to_be_bytes());
    let mut cur = Cursor::new(bytes);
    let req = parse_request(&mut cur).await.unwrap();
    assert_eq!(req.command, 0x01);
    assert_eq!(
        req.destination,
        SocksAddr::Domain {
            name: "example.com".into(),
            port: 80,
        }
    );
}

#[tokio::test]
async fn parse_request_connect_ipv6() {
    let mut bytes = vec![0x05, 0x01, 0x00, 0x04];
    bytes.extend_from_slice(&[0u8; 16]);
    bytes.extend_from_slice(&443u16.to_be_bytes());
    let mut cur = Cursor::new(bytes);
    let req = parse_request(&mut cur).await.unwrap();
    assert_eq!(req.command, 0x01);
    assert_eq!(
        req.destination,
        SocksAddr::Ipv6 {
            addr: Ipv6Addr::UNSPECIFIED,
            port: 443,
        }
    );
}

#[tokio::test]
async fn parse_request_wrong_version_errors() {
    let bytes = vec![0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80];
    let mut cur = Cursor::new(bytes);
    let err = parse_request(&mut cur).await.unwrap_err();
    assert!(err.contains("incompatible SOCKS version"));
}

#[tokio::test]
async fn parse_request_truncated_errors() {
    let bytes = vec![0x05, 0x01]; // missing RSV + addr
    let mut cur = Cursor::new(bytes);
    assert!(parse_request(&mut cur).await.is_err());
}

// ---------------------------------------------------------------------------
// Greeting negotiation (via real loopback — exercises negotiate_greeting)
// ---------------------------------------------------------------------------

async fn greet_round_trip(client_methods: &[u8], expect_accept: bool) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let res = negotiate_greeting(&mut s, false).await;
        if res.is_ok() {
            s.write_all(&[0x05, 0x00]).await.unwrap();
        } else {
            s.write_all(&[0x05, 0xFF]).await.unwrap();
        }
        s
    });
    let mut c = TcpStream::connect(addr).await.unwrap();
    let mut req = vec![0x05, client_methods.len() as u8];
    req.extend_from_slice(client_methods);
    c.write_all(&req).await.unwrap();
    let mut resp = [0u8; 2];
    c.read_exact(&mut resp).await.unwrap();
    let _s = server.await.unwrap();
    // expected: accept -> 05 00 ; reject -> 05 FF
    assert_eq!(resp[0], 0x05);
    if expect_accept {
        assert_eq!(resp[1], 0x00);
    } else {
        assert_eq!(resp[1], 0xFF);
    }
    resp.to_vec()
}

#[tokio::test]
async fn greeting_accepts_no_auth() {
    greet_round_trip(&[0x00], true).await;
}

#[tokio::test]
async fn greeting_accepts_no_auth_among_others() {
    greet_round_trip(&[0x02, 0x00, 0x01], true).await;
}

#[tokio::test]
async fn greeting_rejects_without_no_auth() {
    greet_round_trip(&[0x02], false).await;
}

#[tokio::test]
async fn greeting_rejects_bad_version() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ = negotiate_greeting(&mut s, false).await;
        // negotiate_greeting errors before writing; the reply is written by
        // handle_conn. Here we just close.
    });
    let mut c = TcpStream::connect(addr).await.unwrap();
    // VER=4 (bad), NMETHODS=1, METHOD=0
    c.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
    // Server closes without a valid reply; expect EOF or a short read.
    let mut buf = [0u8; 2];
    let _ = c.read(&mut buf).await;
    server.await.unwrap();
}

// ---------------------------------------------------------------------------
// bind-addr parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_bind_addr_forms() {
    let full = parse_bind_addr("127.0.0.1:1080").unwrap();
    assert_eq!(full, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080));

    let colon = parse_bind_addr(":1080").unwrap();
    assert_eq!(
        colon,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080)
    );

    let bare = parse_bind_addr("1080").unwrap();
    assert_eq!(bare, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080));

    assert!(parse_bind_addr("").is_err());
    assert!(parse_bind_addr("garbage").is_err());
}

// ---------------------------------------------------------------------------
// Integration: full CONNECT through the proxy to a local echo server
// ---------------------------------------------------------------------------

/// A tiny echo server: accepts one connection and echoes back bytes until EOF.
async fn echo_server(listener: TcpListener) {
    let (mut s, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 256];
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if s.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Hand-rolled SOCKS5 client CONNECT. Returns the established stream.
async fn socks5_connect(proxy: SocketAddr, dest: SocksAddr) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    // greeting: VER=5 NMETHODS=1 METHODS=[no-auth]
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greply = [0u8; 2];
    s.read_exact(&mut greply).await?;
    if greply[0] != 0x05 || greply[1] != 0x00 {
        return Err(io::Error::other(format!("greeting rejected: {greply:?}")));
    }
    // request: VER=5 CMD=1 RSV=0 <addr>
    let mut req = vec![0x05, 0x01, 0x00];
    req.extend_from_slice(&dest.marshal().unwrap());
    s.write_all(&req).await?;
    // reply: VER REPLY RSV <bind-addr>
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(io::Error::other(format!("bad reply ver {hdr:?}")));
    }
    if hdr[1] != 0x00 {
        return Err(io::Error::other(format!(
            "connect failed reply={:#x}",
            hdr[1]
        )));
    }
    // consume the bound address (length depends on ATYP).
    let atyp = hdr[3];
    let addr_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            len[0] as usize
        }
        _ => return Err(io::Error::other(format!("bad bind atyp {atyp:#x}"))),
    };
    let mut rest = vec![0u8; addr_len + 2];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

#[tokio::test]
async fn socks5_connect_echo_roundtrip() {
    // Echo backend on an ephemeral port.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(echo_server(echo));

    // Proxy with a mock dialer that always connects to the echo backend.
    let handle = spawn_socks5("127.0.0.1:0", MockDialer { backend: echo_addr }, None)
        .await
        .unwrap();
    let proxy = handle.local_addr();

    // Client CONNECT to an arbitrary IPv4 target (the dialer ignores it).
    let mut s = socks5_connect(
        proxy,
        SocksAddr::Ipv4 {
            addr: Ipv4Addr::new(100, 64, 0, 9),
            port: 4242,
        },
    )
    .await
    .expect("socks5 connect");

    // Echo roundtrip.
    let payload = b"hello-through-socks5";
    s.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    // A second exchange to be sure the copy is bidirectional.
    s.write_all(b"again").await.unwrap();
    let mut g2 = vec![0u8; 5];
    s.read_exact(&mut g2).await.unwrap();
    assert_eq!(&g2, b"again");

    // Close the client first so the echo server sees EOF and exits;
    // otherwise echo_task.await hangs.
    drop(s);
    let mut h = handle;
    h.stop().await;
    let _ = echo_task.await;
}

#[tokio::test]
async fn socks5_connect_domain_addr_type() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(echo_server(echo));
    let handle = spawn_socks5("127.0.0.1:0", MockDialer { backend: echo_addr }, None)
        .await
        .unwrap();
    let proxy = handle.local_addr();

    let mut s = socks5_connect(
        proxy,
        SocksAddr::Domain {
            name: "peer.tailnet.ts.net".into(),
            port: 80,
        },
    )
    .await
    .expect("socks5 connect (domain)");

    s.write_all(b"dom").await.unwrap();
    let mut got = vec![0u8; 3];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"dom");

    drop(s);
    let mut h = handle;
    h.stop().await;
    let _ = echo_task.await;
}

#[tokio::test]
async fn socks5_connect_ipv6_addr_type() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(echo_server(echo));
    let handle = spawn_socks5("127.0.0.1:0", MockDialer { backend: echo_addr }, None)
        .await
        .unwrap();
    let proxy = handle.local_addr();

    let mut s = socks5_connect(
        proxy,
        SocksAddr::Ipv6 {
            addr: Ipv6Addr::LOCALHOST,
            port: 9999,
        },
    )
    .await
    .expect("socks5 connect (ipv6)");

    s.write_all(b"v6").await.unwrap();
    let mut got = vec![0u8; 2];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"v6");

    drop(s);
    let mut h = handle;
    h.stop().await;
    let _ = echo_task.await;
}

// ---------------------------------------------------------------------------
// Reply-code mapping for dial failures
// ---------------------------------------------------------------------------

async fn connect_and_read_reply(proxy: SocketAddr, dest: SocksAddr) -> u8 {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greply = [0u8; 2];
    s.read_exact(&mut greply).await.unwrap();
    let mut req = vec![0x05, 0x01, 0x00];
    req.extend_from_slice(&dest.marshal().unwrap());
    s.write_all(&req).await.unwrap();
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    // drain bind addr
    let atyp = hdr[3];
    let addr_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.unwrap();
            len[0] as usize
        }
        _ => 0,
    };
    let mut rest = vec![0u8; addr_len + 2];
    let _ = s.read_exact(&mut rest).await;
    hdr[1]
}

#[tokio::test]
async fn socks5_dial_refused_maps_to_05() {
    let handle = spawn_socks5(
        "127.0.0.1:0",
        FailingDialer {
            kind: io::ErrorKind::ConnectionRefused,
        },
        None,
    )
    .await
    .unwrap();
    let code = connect_and_read_reply(
        handle.local_addr(),
        SocksAddr::Ipv4 {
            addr: Ipv4Addr::new(1, 2, 3, 4),
            port: 80,
        },
    )
    .await;
    assert_eq!(code, 0x05);
    let mut h = handle;
    h.stop().await;
}

#[tokio::test]
async fn socks5_dial_host_unreachable_maps_to_04() {
    let handle = spawn_socks5(
        "127.0.0.1:0",
        FailingDialer {
            kind: io::ErrorKind::HostUnreachable,
        },
        None,
    )
    .await
    .unwrap();
    let code = connect_and_read_reply(
        handle.local_addr(),
        SocksAddr::Ipv4 {
            addr: Ipv4Addr::new(1, 2, 3, 4),
            port: 80,
        },
    )
    .await;
    assert_eq!(code, 0x04);
    let mut h = handle;
    h.stop().await;
}

#[tokio::test]
async fn socks5_dial_general_failure_maps_to_01() {
    let handle = spawn_socks5(
        "127.0.0.1:0",
        FailingDialer {
            kind: io::ErrorKind::Other,
        },
        None,
    )
    .await
    .unwrap();
    let code = connect_and_read_reply(
        handle.local_addr(),
        SocksAddr::Ipv4 {
            addr: Ipv4Addr::new(1, 2, 3, 4),
            port: 80,
        },
    )
    .await;
    assert_eq!(code, 0x01);
    let mut h = handle;
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Unsupported commands
// ---------------------------------------------------------------------------

#[tokio::test]
async fn socks5_bind_command_rejected_07() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    // No echo task: the command is rejected before any dial, so no backend
    // connection is ever made. Drop the listener to free the port.
    drop(echo);
    let handle = spawn_socks5("127.0.0.1:0", MockDialer { backend: echo_addr }, None)
        .await
        .unwrap();
    let proxy = handle.local_addr();

    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greply = [0u8; 2];
    s.read_exact(&mut greply).await.unwrap();
    // BIND command (0x02)
    let mut req = vec![0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4];
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 0x05);
    assert_eq!(hdr[1], 0x07); // command not supported
                              // drain bind addr (ipv4)
    let mut rest = vec![0u8; 6];
    let _ = s.read_exact(&mut rest).await;

    drop(s);
    let mut h = handle;
    h.stop().await;
}

#[tokio::test]
async fn socks5_udp_associate_rejected_07() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    drop(echo);
    let handle = spawn_socks5("127.0.0.1:0", MockDialer { backend: echo_addr }, None)
        .await
        .unwrap();
    let proxy = handle.local_addr();

    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greply = [0u8; 2];
    s.read_exact(&mut greply).await.unwrap();
    // UDP ASSOCIATE (0x03)
    let mut req = vec![0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4];
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[1], 0x07);

    drop(s);
    let mut h = handle;
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Username/password authentication (RFC 1929)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_client_auth_round_trip() {
    // VER=1 ULEN=4 "user" PLEN=4 "pass"
    let mut bytes = vec![
        0x01, 0x04, b'u', b's', b'e', b'r', 0x04, b'p', b'a', b's', b's',
    ];
    let mut cur = std::io::Cursor::new(&mut bytes[..]);
    let (user, pass) = parse_client_auth(&mut cur).await.unwrap();
    assert_eq!(user, "user");
    assert_eq!(pass, "pass");
}

#[tokio::test]
async fn parse_client_auth_bad_version() {
    let bytes = [0x02, 0x01, b'x', 0x01, b'y'];
    let mut cur = std::io::Cursor::new(&bytes[..]);
    let err = parse_client_auth(&mut cur).await.unwrap_err();
    assert!(err.to_string().contains("bad SOCKS auth version"));
}

#[tokio::test]
async fn greeting_rejects_when_password_required_but_not_offered() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let res = negotiate_greeting(&mut s, true).await;
        if res.is_err() {
            s.write_all(&[0x05, 0xFF]).await.unwrap();
        }
    });
    let mut c = TcpStream::connect(addr).await.unwrap();
    // Offer only no-auth (0x00), not password (0x02)
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    c.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0xFF); // no acceptable methods
    server.await.unwrap();
}

#[tokio::test]
async fn greeting_accepts_password_method_when_required() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let method = negotiate_greeting(&mut s, true).await.unwrap();
        s.write_all(&[0x05, method]).await.unwrap();
    });
    let mut c = TcpStream::connect(addr).await.unwrap();
    // Offer password (0x02)
    c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut resp = [0u8; 2];
    c.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0x02); // password method selected
    server.await.unwrap();
}

/// Hand-rolled SOCKS5 client CONNECT with username/password auth.
async fn socks5_connect_with_auth(
    proxy: SocketAddr,
    dest: SocksAddr,
    username: &str,
    password: &str,
) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    // greeting: offer both no-auth and password
    s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    let mut greply = [0u8; 2];
    s.read_exact(&mut greply).await?;
    if greply[0] != 0x05 {
        return Err(io::Error::other("bad version"));
    }
    if greply[1] == 0x00 {
        // no-auth selected, proceed to request
    } else if greply[1] == 0x02 {
        // password auth sub-negotiation (RFC 1929)
        let mut auth = vec![0x01, username.len() as u8];
        auth.extend_from_slice(username.as_bytes());
        auth.push(password.len() as u8);
        auth.extend_from_slice(password.as_bytes());
        s.write_all(&auth).await?;
        let mut auth_resp = [0u8; 2];
        s.read_exact(&mut auth_resp).await?;
        if auth_resp[1] != 0x00 {
            return Err(io::Error::other("auth failed"));
        }
    } else {
        return Err(io::Error::other(format!("method rejected: {greply:?}")));
    }
    // request
    let mut req = vec![0x05, 0x01, 0x00];
    req.extend_from_slice(&dest.marshal().unwrap());
    s.write_all(&req).await?;
    // reply
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(io::Error::other(format!("connect failed: {:#x}", hdr[1])));
    }
    let atyp = hdr[3];
    let addr_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            len[0] as usize
        }
        _ => return Err(io::Error::other("bad atyp")),
    };
    let mut rest = vec![0u8; addr_len + 2];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

#[tokio::test]
async fn socks5_auth_success_roundtrip() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(echo_server(echo));

    let handle = spawn_socks5(
        "127.0.0.1:0",
        MockDialer { backend: echo_addr },
        Some(("admin".into(), "secret".into())),
    )
    .await
    .unwrap();
    let proxy = handle.local_addr();

    let mut s = socks5_connect_with_auth(
        proxy,
        SocksAddr::Ipv4 {
            addr: Ipv4Addr::new(100, 64, 0, 9),
            port: 4242,
        },
        "admin",
        "secret",
    )
    .await
    .expect("socks5 connect with auth");

    let payload = b"authed-socks5";
    s.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    drop(s);
    let mut h = handle;
    h.stop().await;
    let _ = echo_task.await;
}

#[tokio::test]
async fn socks5_auth_wrong_password_rejected() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    drop(echo);

    let handle = spawn_socks5(
        "127.0.0.1:0",
        MockDialer { backend: echo_addr },
        Some(("admin".into(), "secret".into())),
    )
    .await
    .unwrap();
    let proxy = handle.local_addr();

    let result = socks5_connect_with_auth(
        proxy,
        SocksAddr::Ipv4 {
            addr: Ipv4Addr::new(1, 2, 3, 4),
            port: 80,
        },
        "admin",
        "wrong",
    )
    .await;

    assert!(result.is_err(), "auth with wrong password should fail");
    let mut h = handle;
    h.stop().await;
}
