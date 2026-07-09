//! Unit tests for the FFI handle table lifecycle and error paths,
//! plus an #[ignore] e2e loopback echo test over the FFI layer.
//
// c"" literals require Rust 2024 edition; we're on 2021.
#![allow(clippy::manual_c_str_literals)]

use std::ffi::CString;
use std::os::raw::c_char;

use super::*;

// ---------------------------------------------------------------------------
// ts_new / ts_close lifecycle
// ---------------------------------------------------------------------------

#[test]
fn ts_new_returns_valid_handle() {
    let h = ts_new();
    assert!(h >= 0, "ts_new should return non-negative handle, got {h}");
    // Clean up.
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_close_is_idempotent() {
    let h = ts_new();
    assert_eq!(ts_close(h), RS_OK);
    // Second close is a no-op (handle gone, no server to shut down).
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn multiple_servers_coexist() {
    let a = ts_new();
    let b = ts_new();
    let c = ts_new();
    assert!(a != b && b != c && a != c, "handles must be unique");
    assert_eq!(ts_close(a), RS_OK);
    assert_eq!(ts_close(b), RS_OK);
    assert_eq!(ts_close(c), RS_OK);
}

// ---------------------------------------------------------------------------
// ts_set_* error paths
// ---------------------------------------------------------------------------

#[test]
fn ts_set_hostname_bad_handle() {
    assert_eq!(
        ts_set_hostname(99999, b"foo\0".as_ptr().cast::<c_char>()),
        RS_ERR_NOENT
    );
}

#[test]
fn ts_set_hostname_null() {
    let h = ts_new();
    assert_eq!(ts_set_hostname(h, std::ptr::null()), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_set_authkey_bad_handle() {
    assert_eq!(
        ts_set_authkey(99999, b"k\0".as_ptr().cast::<c_char>()),
        RS_ERR_NOENT
    );
}

#[test]
fn ts_set_authkey_null() {
    let h = ts_new();
    assert_eq!(ts_set_authkey(h, std::ptr::null()), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_set_control_url_null() {
    let h = ts_new();
    assert_eq!(ts_set_control_url(h, std::ptr::null()), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_set_state_dir_null() {
    let h = ts_new();
    assert_eq!(ts_set_state_dir(h, std::ptr::null()), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_set_ephemeral_bad_handle() {
    assert_eq!(ts_set_ephemeral(99999, 1), RS_ERR_NOENT);
}

#[test]
fn ts_set_ephemeral_works() {
    let h = ts_new();
    assert_eq!(ts_set_ephemeral(h, 1), RS_OK);
    assert_eq!(ts_set_ephemeral(h, 0), RS_OK);
    assert_eq!(ts_close(h), RS_OK);
}

// ---------------------------------------------------------------------------
// ts_up error paths
// ---------------------------------------------------------------------------

#[test]
fn ts_up_bad_handle() {
    assert_eq!(ts_up(99999), RS_ERR_NOENT);
}

// ---------------------------------------------------------------------------
// ts_listen / ts_dial error paths
// ---------------------------------------------------------------------------

#[test]
fn ts_listen_bad_handle() {
    let proto = b"tcp\0".as_ptr().cast::<c_char>();
    let addr = b":8080\0".as_ptr().cast::<c_char>();
    assert_eq!(ts_listen(99999, proto, addr), RS_ERR_NOENT);
}

#[test]
fn ts_listen_null_addr() {
    let h = ts_new();
    let proto = b"tcp\0".as_ptr().cast::<c_char>();
    assert_eq!(ts_listen(h, proto, std::ptr::null()), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_listen_bad_proto() {
    let h = ts_new();
    let proto = b"udp\0".as_ptr().cast::<c_char>();
    let addr = b":8080\0".as_ptr().cast::<c_char>();
    assert_eq!(ts_listen(h, proto, addr), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_dial_bad_handle() {
    let proto = b"tcp\0".as_ptr().cast::<c_char>();
    let addr = b"100.64.0.2:443\0".as_ptr().cast::<c_char>();
    assert_eq!(ts_dial(99999, proto, addr), RS_ERR_NOENT);
}

#[test]
fn ts_dial_null_addr() {
    let h = ts_new();
    let proto = b"tcp\0".as_ptr().cast::<c_char>();
    assert_eq!(ts_dial(h, proto, std::ptr::null()), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

// ---------------------------------------------------------------------------
// ts_accept / ts_listener_close error paths
// ---------------------------------------------------------------------------

#[test]
fn ts_accept_bad_listener() {
    assert_eq!(ts_accept(99999), RS_ERR_NOENT);
}

#[test]
fn ts_listener_close_bad_handle() {
    assert_eq!(ts_listener_close(99999), RS_ERR_NOENT);
}

// ---------------------------------------------------------------------------
// ts_conn_* error paths
// ---------------------------------------------------------------------------

#[test]
fn ts_conn_read_bad_conn() {
    let mut buf = [0u8; 64];
    assert_eq!(
        ts_conn_read(99999, buf.as_mut_ptr().cast::<c_char>(), 64),
        RS_ERR_NOENT
    );
}

#[test]
fn ts_conn_read_null_buf() {
    let h = ts_new();
    assert_eq!(ts_conn_read(h, std::ptr::null_mut(), 64), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_conn_write_bad_conn() {
    let buf = b"hello\0";
    assert_eq!(
        ts_conn_write(99999, buf.as_ptr().cast::<c_char>(), 5),
        RS_ERR_NOENT
    );
}

#[test]
fn ts_conn_write_null_buf() {
    let h = ts_new();
    assert_eq!(ts_conn_write(h, std::ptr::null(), 5), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_conn_close_bad_conn() {
    assert_eq!(ts_conn_close(99999), RS_ERR_NOENT);
}

// ---------------------------------------------------------------------------
// ts_errmsg / ts_status_json error paths
// ---------------------------------------------------------------------------

#[test]
fn ts_errmsg_bad_handle() {
    let mut buf = [0u8; 256];
    assert_eq!(
        ts_errmsg(99999, buf.as_mut_ptr().cast::<c_char>(), 256),
        RS_ERR_NOENT
    );
}

#[test]
fn ts_errmsg_null_buf() {
    let h = ts_new();
    assert_eq!(ts_errmsg(h, std::ptr::null_mut(), 256), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_status_json_bad_handle() {
    let mut buf = [0u8; 1024];
    assert_eq!(
        ts_status_json(99999, buf.as_mut_ptr().cast::<c_char>(), 1024),
        RS_ERR_NOENT
    );
}

#[test]
fn ts_status_json_down_server() {
    let h = ts_new();
    let mut buf = [0u8; 1024];
    let n = ts_status_json(h, buf.as_mut_ptr().cast::<c_char>(), 1024);
    assert!(n >= 0, "status_json should succeed on non-up server");
    let json = std::str::from_utf8(&buf[..n as usize]).unwrap();
    assert!(
        json.contains("\"up\":false"),
        "json should have up:false: {json}"
    );
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_errmsg_captures_error() {
    let h = ts_new();
    // Trigger an error by calling ts_up without an auth key.
    let _ = ts_up(h);
    let mut buf = [0u8; 512];
    let n = ts_errmsg(h, buf.as_mut_ptr().cast::<c_char>(), 512);
    assert!(n > 0, "errmsg should have content after error");
    let msg = std::str::from_utf8(&buf[..n as usize]).unwrap();
    assert!(!msg.is_empty(), "error message should not be empty");
    assert_eq!(ts_close(h), RS_OK);
}

// ---------------------------------------------------------------------------
// ts_set_exit_node / ts_clear_exit_node error paths
// ---------------------------------------------------------------------------

#[test]
fn ts_set_exit_node_bad_handle() {
    let addr = b"100.64.0.5\0".as_ptr().cast::<c_char>();
    assert_eq!(ts_set_exit_node(99999, addr), RS_ERR_NOENT);
}

#[test]
fn ts_set_exit_node_null_addr() {
    let h = ts_new();
    assert_eq!(ts_set_exit_node(h, std::ptr::null()), RS_ERR_INVAL);
    assert_eq!(ts_close(h), RS_OK);
}

#[test]
fn ts_clear_exit_node_bad_handle() {
    assert_eq!(ts_clear_exit_node(99999), RS_ERR_NOENT);
}

// ---------------------------------------------------------------------------
// parse_port unit tests
// ---------------------------------------------------------------------------

#[test]
fn parse_port_variants() {
    assert_eq!(parse_port(":8080"), Some(8080));
    assert_eq!(parse_port("0.0.0.0:8080"), Some(8080));
    assert_eq!(parse_port("100.64.0.1:443"), Some(443));
    assert_eq!(parse_port("8080"), Some(8080));
    assert_eq!(parse_port(""), None);
    assert_eq!(parse_port("notaport"), None);
    assert_eq!(parse_port("invalid:port:here"), None);
}

// ---------------------------------------------------------------------------
// write_to_buf unit tests
// ---------------------------------------------------------------------------

#[test]
fn write_to_buf_truncates() {
    let mut buf = [0u8; 8];
    let n = write_to_buf(
        buf.as_mut_ptr().cast::<c_char>(),
        8,
        "hello world this is too long",
    );
    assert_eq!(n, 7); // 8 - 1 for NUL
    assert_eq!(&buf[..7], b"hello w");
    assert_eq!(buf[7], 0); // NUL terminated
}

#[test]
fn write_to_buf_fits() {
    let mut buf = [0u8; 32];
    let n = write_to_buf(buf.as_mut_ptr().cast::<c_char>(), 32, "hello");
    assert_eq!(n, 5);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(buf[5], 0);
}

#[test]
fn write_to_buf_null_buf() {
    assert_eq!(
        write_to_buf(std::ptr::null_mut(), 32, "hello"),
        RS_ERR_INVAL
    );
}

// ---------------------------------------------------------------------------
// Use-after-close returns error
// ---------------------------------------------------------------------------

#[test]
fn use_after_close_returns_noent() {
    let h = ts_new();
    let proto = b"tcp\0".as_ptr().cast::<c_char>();
    let addr = b":8080\0".as_ptr().cast::<c_char>();

    // Close the server.
    assert_eq!(ts_close(h), RS_OK);

    // Operations on the closed handle should fail.
    assert_eq!(ts_up(h), RS_ERR_NOENT);
    assert_eq!(ts_listen(h, proto, addr), RS_ERR_NOENT);
    assert_eq!(
        ts_set_hostname(h, b"x\0".as_ptr().cast::<c_char>()),
        RS_ERR_NOENT
    );
}

// ---------------------------------------------------------------------------
// E2E: two-server loopback echo over the FFI layer (#[ignore])
// ---------------------------------------------------------------------------

/// Two tsnet servers joined to the same ephemeral tailnet, exercising the
/// full FFI lifecycle: ts_new → ts_set_* → ts_up → ts_listen → ts_dial →
/// ts_conn_write → ts_conn_read → ts_conn_close → ts_close.
///
/// The test body runs in a spawned thread with a hard 120s deadline. If any
/// FFI call hangs (despite internal 90s timeouts), the deadline fires and
/// the test fails with diagnostics instead of hanging forever.
#[test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET env"]
fn ffi_e2e_two_nodes_echo() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");

    // Run the test body in a thread with a hard 120s deadline.
    let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<String, String>>();

    std::thread::spawn(move || {
        let result = ffi_e2e_two_nodes_echo_body(&authkey);
        let _ = done_tx.send(result);
    });

    match done_rx.recv_timeout(std::time::Duration::from_secs(180)) {
        Ok(Ok(msg)) => eprintln!("{msg}"),
        Ok(Err(e)) => panic!("{e}"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
            "ffi_e2e_two_nodes_echo: HARD DEADLINE exceeded (180s) — \
             an FFI blocking call hung. Internal timeouts (90s) should have \
             prevented this; investigate which call blocked."
        ),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("ffi_e2e_two_nodes_echo: worker thread panicked")
        }
    }
}

fn ffi_e2e_two_nodes_echo_body(authkey: &str) -> Result<String, String> {
    /// Helper: call ts_errmsg for a handle and return the string.
    fn errmsg(handle: i32) -> String {
        let mut buf = [0u8; 512];
        let n = ts_errmsg(handle, buf.as_mut_ptr().cast::<c_char>(), 512);
        if n > 0 {
            String::from_utf8_lossy(&buf[..n as usize]).into_owned()
        } else {
            "(no error message)".into()
        }
    }

    // Unique hostname suffix to avoid collisions with stale nodes.
    let uid = std::process::id();
    let host_b = CString::new(format!("rustscale-ffi-b-{uid}")).unwrap();
    let host_a = CString::new(format!("rustscale-ffi-a-{uid}")).unwrap();

    // --- Server B (listener) ---
    let b = ts_new();
    if b < 0 {
        return Err(format!("ts_new B failed: {b}"));
    }

    let rc = ts_set_hostname(b, host_b.as_ptr());
    if rc != RS_OK {
        return Err(format!("ts_set_hostname B: {rc}: {}", errmsg(b)));
    }

    let rc = ts_set_authkey(b, CString::new(authkey).unwrap().as_ptr());
    if rc != RS_OK {
        return Err(format!("ts_set_authkey B: {rc}: {}", errmsg(b)));
    }

    let rc = ts_set_ephemeral(b, 1);
    if rc != RS_OK {
        return Err(format!("ts_set_ephemeral B: {rc}"));
    }

    let up_b = ts_up(b);
    if up_b != RS_OK {
        return Err(format!("ts_up B failed: {up_b}: {}", errmsg(b)));
    }

    // Get B's IP from status JSON.
    let mut status_buf = [0u8; 4096];
    let n = ts_status_json(b, status_buf.as_mut_ptr().cast::<c_char>(), 4096);
    if n <= 0 {
        return Err(format!("status_json B failed: {n}"));
    }
    let status_str = std::str::from_utf8(&status_buf[..n as usize]).unwrap();
    let status: serde_json::Value =
        serde_json::from_str(status_str).map_err(|e| format!("parse status B: {e}"))?;
    let ip_b = status["tailscale_ips"][0]
        .as_str()
        .ok_or("missing tailscale_ips[0]")?;
    eprintln!("Server B IP: {ip_b}");

    // B listens.
    let proto = b"tcp\0".as_ptr().cast::<c_char>();
    let listen_addr = b":4242\0".as_ptr().cast::<c_char>();
    let listener = ts_listen(b, proto, listen_addr);
    if listener < 0 {
        return Err(format!("ts_listen failed: {listener}: {}", errmsg(b)));
    }

    // --- Server A (dialer) ---
    let a = ts_new();
    if a < 0 {
        return Err(format!("ts_new A failed: {a}"));
    }
    let rc = ts_set_hostname(a, host_a.as_ptr());
    if rc != RS_OK {
        return Err(format!("ts_set_hostname A: {rc}: {}", errmsg(a)));
    }
    let rc = ts_set_authkey(a, CString::new(authkey).unwrap().as_ptr());
    if rc != RS_OK {
        return Err(format!("ts_set_authkey A: {rc}: {}", errmsg(a)));
    }
    let rc = ts_set_ephemeral(a, 1);
    if rc != RS_OK {
        return Err(format!("ts_set_ephemeral A: {rc}"));
    }

    let up_a = ts_up(a);
    if up_a != RS_OK {
        return Err(format!("ts_up A failed: {up_a}: {}", errmsg(a)));
    }

    // Wait for A to see B's *specific* IP in its netmap (hard 90s deadline).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let mut sbuf = [0u8; 4096];
        let sn = ts_status_json(a, sbuf.as_mut_ptr().cast::<c_char>(), 4096);
        if sn > 0 {
            let sstr = std::str::from_utf8(&sbuf[..sn as usize]).unwrap();
            if let Ok(sv) = serde_json::from_str::<serde_json::Value>(sstr) {
                let found = sv["peers"].as_array().is_some_and(|peers| {
                    peers.iter().any(|p| {
                        p["ips"]
                            .as_array()
                            .is_some_and(|ips| ips.iter().any(|i| i.as_str() == Some(ip_b)))
                    })
                });
                if found {
                    break;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            // Rich diagnostics: dump current peer list.
            let mut sbuf2 = [0u8; 4096];
            let sn2 = ts_status_json(a, sbuf2.as_mut_ptr().cast::<c_char>(), 4096);
            let peers_dump = if sn2 > 0 {
                std::str::from_utf8(&sbuf2[..sn2 as usize]).unwrap_or("(utf8 error)")
            } else {
                "(status_json failed)"
            };
            return Err(format!(
                "A never saw B ({ip_b}) in its netmap after 90s\n\
                 A status: {peers_dump}"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Give the WG handshake a moment to complete after the peer appeared.
    std::thread::sleep(std::time::Duration::from_secs(3));

    // A dials B. Retry up to 2 times — the WG handshake may not have
    // completed when the peer first appears in the netmap, causing the
    // first dial to time out.
    let dial_addr = CString::new(format!("{ip_b}:4242")).unwrap();
    let mut conn_a: i32 = -1;
    for attempt in 1..=2 {
        eprintln!("FFI dial attempt {attempt}");
        let rc = ts_dial(a, proto, dial_addr.as_ptr());
        if rc >= 0 {
            conn_a = rc;
            break;
        }
        eprintln!("FFI dial attempt {attempt} failed: {rc}: {}", errmsg(a));
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }
    if conn_a < 0 {
        return Err(format!("all ts_dial attempts failed: {}", errmsg(a)));
    }

    // B accepts (FFI has internal 90s timeout).
    let conn_b = ts_accept(listener);
    if conn_b < 0 {
        return Err(format!("ts_accept failed: {conn_b}"));
    }

    // A writes, B reads and echoes.
    let msg = b"hello ffi e2e";
    let written = ts_conn_write(conn_a, msg.as_ptr().cast::<c_char>(), msg.len() as i32);
    if written < 0 {
        return Err(format!("A write failed: {written}"));
    }
    if written != msg.len() as i32 {
        return Err(format!("A write short: {written} != {}", msg.len()));
    }

    let mut rbuf = [0u8; 64];
    let nread = ts_conn_read(conn_b, rbuf.as_mut_ptr().cast::<c_char>(), 64);
    if nread <= 0 {
        return Err(format!("B read failed: {nread}"));
    }
    if &rbuf[..nread as usize] != msg {
        return Err(format!(
            "B read mismatch: {:?} != {msg:?}",
            &rbuf[..nread as usize]
        ));
    }

    // B echoes back.
    let written = ts_conn_write(conn_b, rbuf.as_ptr().cast::<c_char>(), nread);
    if written < 0 {
        return Err(format!("B write failed: {written}"));
    }

    let nread2 = ts_conn_read(conn_a, rbuf.as_mut_ptr().cast::<c_char>(), 64);
    if nread2 <= 0 {
        return Err(format!("A read failed: {nread2}"));
    }
    if &rbuf[..nread2 as usize] != msg {
        return Err(format!(
            "A read mismatch: {:?} != {msg:?}",
            &rbuf[..nread2 as usize]
        ));
    }

    // Clean up.
    let _ = ts_conn_close(conn_a);
    let _ = ts_conn_close(conn_b);
    let _ = ts_listener_close(listener);
    let _ = ts_close(a);
    let _ = ts_close(b);

    Ok("ffi_e2e_two_nodes_echo: OK".into())
}
