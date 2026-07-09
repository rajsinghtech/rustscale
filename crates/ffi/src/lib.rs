//! C ABI over rustscale tsnet — a `libtailscale` equivalent.
//!
//! Exports a C-callable API with opaque integer handles (not raw pointers)
//! mirroring the Go libtailscale style. All `extern "C"` functions catch
//! panics so unwinding never crosses the FFI boundary.
//!
//! # Handle model
//!
//! - Server handle (`int`) — [`ts_new`] → `ts_set_*` → [`ts_up`] → [`ts_close`].
//! - Listener handle (`int`) — [`ts_listen`] → [`ts_accept`] → [`ts_listener_close`].
//! - Connection handle (`int`) — [`ts_accept`]/[`ts_dial`] → `ts_conn_*` →
//!   [`ts_conn_close`].
//!
//! Handles are non-negative; a negative return is an errno-style error code.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::CStr;
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use rustscale_netstack::NetstackStream;
use rustscale_tsnet::{Server, ServerBuilder}; // ---------------------------------------------------------------------------
                                              // Error codes (errno-style, negative)
                                              // ---------------------------------------------------------------------------

/// Success.
pub const RS_OK: c_int = 0;
/// Invalid argument (EINVAL).
pub const RS_ERR_INVAL: c_int = -22;
/// No such handle (ENOENT).
pub const RS_ERR_NOENT: c_int = -2;
/// Server already up / resource busy (EBUSY).
pub const RS_ERR_BUSY: c_int = -16;
/// Operation timed out (ETIMEDOUT).
pub const RS_ERR_TIMEOUT: c_int = -110;
/// Generic failure.
pub const RS_ERR_UNKNOWN: c_int = -1;

/// Default timeout for blocking FFI operations (dial, accept, read).
/// Prevents unbounded hangs in C callers that can't handle async cancellation.
/// 60s is generous enough for a WG handshake + DERP relay round trip.
const FFI_BLOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Global tokio runtime (lazy)
// ---------------------------------------------------------------------------

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
    })
}

// ---------------------------------------------------------------------------
// Handle allocation
// ---------------------------------------------------------------------------

static NEXT_HANDLE: AtomicI32 = AtomicI32::new(1);

fn alloc_handle() -> i32 {
    NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Per-resource entries
// ---------------------------------------------------------------------------

struct ServerEntry {
    builder: ServerBuilder,
    hostname: String,
    server: Option<Arc<Mutex<Server>>>,
    starting: bool,
    last_error: String,
}

struct ListenerEntry {
    accept_rx: tokio::sync::mpsc::Receiver<Result<NetstackStream, String>>,
}

struct ConnEntry {
    stream: Arc<Mutex<NetstackStream>>,
}

// ---------------------------------------------------------------------------
// Global handle table
// ---------------------------------------------------------------------------

struct HandleTable {
    servers: HashMap<i32, ServerEntry>,
    listeners: HashMap<i32, ListenerEntry>,
    connections: HashMap<i32, ConnEntry>,
}

static HANDLE_TABLE: OnceLock<Mutex<HandleTable>> = OnceLock::new();

fn table() -> &'static Mutex<HandleTable> {
    HANDLE_TABLE.get_or_init(|| {
        Mutex::new(HandleTable {
            servers: HashMap::new(),
            listeners: HashMap::new(),
            connections: HashMap::new(),
        })
    })
}

// ---------------------------------------------------------------------------
// Panic boundary + helpers
// ---------------------------------------------------------------------------

fn catch<F>(label: &str, f: F) -> c_int
where
    F: FnOnce() -> c_int + std::panic::UnwindSafe,
{
    if let Ok(code) = std::panic::catch_unwind(f) {
        code
    } else {
        eprintln!("rustscale FFI: panic in {label}");
        RS_ERR_UNKNOWN
    }
}

fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees a valid NUL-terminated string.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().ok().map(String::from)
}

/// Write `src` into the caller's buffer (NUL-terminated).
/// Returns bytes written excluding NUL, or a negative error.
fn write_to_buf(buf: *mut c_char, buflen: c_int, src: &str) -> c_int {
    if buf.is_null() || buflen <= 0 {
        return RS_ERR_INVAL;
    }
    let src_bytes = src.as_bytes();
    let cap = buflen as usize;
    let n = src_bytes.len().min(cap.saturating_sub(1));
    // SAFETY: caller guarantees buf is valid for buflen bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(src_bytes.as_ptr(), buf.cast::<u8>(), n);
        *buf.add(n) = 0;
    }
    n as c_int
}

/// Parse a port from ":8080", "0.0.0.0:8080", "100.64.0.1:8080", or "8080".
fn parse_port(addr: &str) -> Option<u16> {
    let t = addr.trim();
    if t.is_empty() {
        return None;
    }
    t.parse::<u16>()
        .ok()
        .or_else(|| t.parse::<SocketAddr>().ok().map(|s| s.port()))
        .or_else(|| t.rsplit(':').next().and_then(|s| s.parse().ok()))
}

/// Set last_error on a server handle (call with table locked).
fn set_server_error(t: &mut HandleTable, handle: i32, msg: impl Into<String>) {
    if let Some(e) = t.servers.get_mut(&handle) {
        e.last_error = msg.into();
    }
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

/// Create a new tsnet server handle.
#[no_mangle]
pub extern "C" fn ts_new() -> c_int {
    catch("ts_new", || {
        let h = alloc_handle();
        let mut t = table().lock().expect("table poisoned");
        t.servers.insert(
            h,
            ServerEntry {
                builder: Server::builder(),
                hostname: "rustscale".into(),
                server: None,
                starting: false,
                last_error: String::new(),
            },
        );
        h
    })
}

/// Set the auth key.
#[no_mangle]
pub extern "C" fn ts_set_authkey(handle: c_int, authkey: *const c_char) -> c_int {
    catch("ts_set_authkey", || {
        let Some(key) = cstr_to_string(authkey) else {
            return RS_ERR_INVAL;
        };
        let mut t = table().lock().expect("table poisoned");
        let Some(e) = t.servers.get_mut(&handle) else {
            return RS_ERR_NOENT;
        };
        if e.server.is_some() || e.starting {
            return RS_ERR_BUSY;
        }
        e.builder = e.builder.clone().auth_key(key);
        RS_OK
    })
}

/// Set the hostname.
#[no_mangle]
pub extern "C" fn ts_set_hostname(handle: c_int, hostname: *const c_char) -> c_int {
    catch("ts_set_hostname", || {
        let Some(name) = cstr_to_string(hostname) else {
            return RS_ERR_INVAL;
        };
        let mut t = table().lock().expect("table poisoned");
        let Some(e) = t.servers.get_mut(&handle) else {
            return RS_ERR_NOENT;
        };
        if e.server.is_some() || e.starting {
            return RS_ERR_BUSY;
        }
        e.builder = e.builder.clone().hostname(&name);
        e.hostname = name;
        RS_OK
    })
}

/// Set the control-plane URL.
#[no_mangle]
pub extern "C" fn ts_set_control_url(handle: c_int, url: *const c_char) -> c_int {
    catch("ts_set_control_url", || {
        let Some(s) = cstr_to_string(url) else {
            return RS_ERR_INVAL;
        };
        let mut t = table().lock().expect("table poisoned");
        let Some(e) = t.servers.get_mut(&handle) else {
            return RS_ERR_NOENT;
        };
        if e.server.is_some() || e.starting {
            return RS_ERR_BUSY;
        }
        e.builder = e.builder.clone().control_url(s);
        RS_OK
    })
}

/// Set the state directory.
#[no_mangle]
pub extern "C" fn ts_set_state_dir(handle: c_int, dir: *const c_char) -> c_int {
    catch("ts_set_state_dir", || {
        let Some(s) = cstr_to_string(dir) else {
            return RS_ERR_INVAL;
        };
        let mut t = table().lock().expect("table poisoned");
        let Some(e) = t.servers.get_mut(&handle) else {
            return RS_ERR_NOENT;
        };
        if e.server.is_some() || e.starting {
            return RS_ERR_BUSY;
        }
        e.builder = e.builder.clone().state_dir(PathBuf::from(s));
        RS_OK
    })
}

/// Set the ephemeral flag (0 = false, non-zero = true).
#[no_mangle]
pub extern "C" fn ts_set_ephemeral(handle: c_int, ephemeral: c_int) -> c_int {
    catch("ts_set_ephemeral", || {
        let mut t = table().lock().expect("table poisoned");
        let Some(e) = t.servers.get_mut(&handle) else {
            return RS_ERR_NOENT;
        };
        if e.server.is_some() || e.starting {
            return RS_ERR_BUSY;
        }
        e.builder = e.builder.clone().ephemeral(ephemeral != 0);
        RS_OK
    })
}

/// Bring the server online (blocking). Returns 0 on success.
#[no_mangle]
pub extern "C" fn ts_up(handle: c_int) -> c_int {
    catch("ts_up", || {
        // Phase 1: claim the builder (set starting=true), release the lock.
        let builder = {
            let mut t = table().lock().expect("table poisoned");
            let Some(e) = t.servers.get_mut(&handle) else {
                return RS_ERR_NOENT;
            };
            if e.server.is_some() {
                e.last_error = "server already up".into();
                return RS_ERR_BUSY;
            }
            if e.starting {
                e.last_error = "up() already in progress".into();
                return RS_ERR_BUSY;
            }
            e.starting = true;
            e.builder.clone()
        };

        // Phase 2: build + up() outside the lock (may take 30s+).
        let mut server = match builder.build() {
            Ok(s) => s,
            Err(e) => {
                let msg = e.to_string();
                let mut t = table().lock().expect("table poisoned");
                if let Some(e) = t.servers.get_mut(&handle) {
                    e.starting = false;
                    e.last_error = msg;
                }
                return RS_ERR_INVAL;
            }
        };

        let result = runtime().block_on(server.up());

        // Phase 3: store the result.
        let mut t = table().lock().expect("table poisoned");
        let Some(e) = t.servers.get_mut(&handle) else {
            return RS_ERR_NOENT;
        };
        e.starting = false;
        match result {
            Ok(()) => {
                e.server = Some(Arc::new(Mutex::new(server)));
                e.last_error.clear();
                RS_OK
            }
            Err(err) => {
                e.last_error = err.to_string();
                RS_ERR_UNKNOWN
            }
        }
    })
}

/// Shut down and destroy a server handle. Returns 0 on success.
#[no_mangle]
pub extern "C" fn ts_close(handle: c_int) -> c_int {
    catch("ts_close", || {
        // Remove from the table, close outside the lock.
        let server_arc = {
            let mut t = table().lock().expect("table poisoned");
            t.servers.remove(&handle).and_then(|e| e.server)
        };

        if let Some(arc) = server_arc {
            let mut server = arc.lock().expect("server mutex poisoned");
            runtime().block_on(server.close());
        }
        RS_OK
    })
}

// ---------------------------------------------------------------------------
// Error + status retrieval
// ---------------------------------------------------------------------------

/// Retrieve the last error message for a server handle into `buf`.
/// Returns bytes written (excluding NUL), or a negative code.
#[no_mangle]
pub extern "C" fn ts_errmsg(handle: c_int, buf: *mut c_char, buflen: c_int) -> c_int {
    catch("ts_errmsg", || {
        let t = table().lock().expect("table poisoned");
        let Some(e) = t.servers.get(&handle) else {
            return RS_ERR_NOENT;
        };
        write_to_buf(buf, buflen, &e.last_error)
    })
}

/// Retrieve server status as JSON into `buf`.
/// Returns bytes written (excluding NUL), or a negative code.
#[no_mangle]
pub extern "C" fn ts_status_json(handle: c_int, buf: *mut c_char, buflen: c_int) -> c_int {
    catch("ts_status_json", || {
        // Clone Arc under the global lock, then lock the server separately.
        let (server_arc, hostname) = {
            let t = table().lock().expect("table poisoned");
            let Some(e) = t.servers.get(&handle) else {
                return RS_ERR_NOENT;
            };
            (e.server.clone(), e.hostname.clone())
        };

        let json = match server_arc {
            Some(arc) => {
                let server = arc.lock().expect("server mutex poisoned");
                let st = server.status();
                status_to_json(&st)
            }
            None => serde_json::json!({ "up": false, "hostname": hostname }),
        };
        let s = serde_json::to_string(&json).unwrap_or_else(|_| "{}".into());
        write_to_buf(buf, buflen, &s)
    })
}

fn status_to_json(st: &rustscale_tsnet::ServerStatus) -> serde_json::Value {
    let peers: Vec<serde_json::Value> = st
        .peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "ips": p.ips.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
                "path_class": format!("{:?}", p.path_class),
            })
        })
        .collect();
    serde_json::json!({
        "up": st.up,
        "hostname": st.hostname,
        "tailscale_ips": st.tailscale_ips.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
        "peer_count": st.peer_count,
        "peers": peers,
        "packet_drops": st.packet_drops,
    })
}

// ---------------------------------------------------------------------------
// Listen + Accept
// ---------------------------------------------------------------------------

/// Start listening. `addr` may be ":PORT", "0.0.0.0:PORT", or just "PORT".
/// `proto` is reserved (only "tcp" supported). Returns a listener handle.
#[no_mangle]
pub extern "C" fn ts_listen(handle: c_int, proto: *const c_char, addr: *const c_char) -> c_int {
    catch("ts_listen", || {
        let proto_s = cstr_to_string(proto).unwrap_or_default();
        if !proto_s.is_empty() && proto_s != "tcp" {
            let mut t = table().lock().expect("table poisoned");
            set_server_error(&mut t, handle, format!("unsupported proto: {proto_s}"));
            return RS_ERR_INVAL;
        }

        let Some(addr_s) = cstr_to_string(addr) else {
            let mut t = table().lock().expect("table poisoned");
            set_server_error(&mut t, handle, "null addr");
            return RS_ERR_INVAL;
        };
        let Some(port) = parse_port(&addr_s) else {
            let mut t = table().lock().expect("table poisoned");
            set_server_error(&mut t, handle, format!("invalid addr: {addr_s}"));
            return RS_ERR_INVAL;
        };

        // Clone the Arc, release the global lock.
        let server_arc = {
            let mut t = table().lock().expect("table poisoned");
            let Some(e) = t.servers.get_mut(&handle) else {
                return RS_ERR_NOENT;
            };
            if let Some(arc) = &e.server {
                arc.clone()
            } else {
                e.last_error = "server not up".into();
                return RS_ERR_BUSY;
            }
        };

        let listener = {
            let server = server_arc.lock().expect("server mutex poisoned");
            runtime().block_on(server.listen(port))
        };

        match listener {
            Ok(mut listener) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<Result<NetstackStream, String>>(64);
                runtime().spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok(stream) => {
                                if tx.send(Ok(stream)).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(e.to_string())).await;
                                break;
                            }
                        }
                    }
                });

                let lh = alloc_handle();
                let mut t = table().lock().expect("table poisoned");
                t.listeners.insert(lh, ListenerEntry { accept_rx: rx });
                lh
            }
            Err(e) => {
                let mut t = table().lock().expect("table poisoned");
                set_server_error(&mut t, handle, e.to_string());
                RS_ERR_UNKNOWN
            }
        }
    })
}

/// Close a listener handle. Returns 0 on success.
#[no_mangle]
pub extern "C" fn ts_listener_close(listener: c_int) -> c_int {
    catch("ts_listener_close", || {
        let mut t = table().lock().expect("table poisoned");
        if t.listeners.remove(&listener).is_some() {
            RS_OK
        } else {
            RS_ERR_NOENT
        }
    })
}

/// Accept the next incoming connection (blocking).
/// Returns a non-negative connection handle or a negative error code.
#[no_mangle]
pub extern "C" fn ts_accept(listener: c_int) -> c_int {
    catch("ts_accept", || {
        // Take the receiver out of the table, recv, put it back.
        let mut rx = {
            let mut t = table().lock().expect("table poisoned");
            let Some(entry) = t.listeners.get_mut(&listener) else {
                return RS_ERR_NOENT;
            };
            let (_, dead) = tokio::sync::mpsc::channel::<Result<NetstackStream, String>>(1);
            std::mem::replace(&mut entry.accept_rx, dead)
        };

        let result =
            runtime().block_on(async { tokio::time::timeout(FFI_BLOCK_TIMEOUT, rx.recv()).await });

        // Put the receiver back regardless.
        {
            let mut t = table().lock().expect("table poisoned");
            if let Some(entry) = t.listeners.get_mut(&listener) {
                entry.accept_rx = rx;
            }
        }

        match result {
            Ok(Some(Ok(stream))) => {
                let ch = alloc_handle();
                let arc = Arc::new(Mutex::new(stream));
                let mut t = table().lock().expect("table poisoned");
                t.connections.insert(ch, ConnEntry { stream: arc });
                ch
            }
            Ok(Some(Err(_msg))) => RS_ERR_UNKNOWN,
            Ok(None) => RS_ERR_NOENT,
            Err(_) => RS_ERR_TIMEOUT,
        }
    })
}

// ---------------------------------------------------------------------------
// Dial
// ---------------------------------------------------------------------------

/// Dial a remote `addr` (e.g. "100.64.0.2:443" or "peer:80").
/// Returns a non-negative connection handle or a negative error code.
#[no_mangle]
pub extern "C" fn ts_dial(handle: c_int, proto: *const c_char, addr: *const c_char) -> c_int {
    catch("ts_dial", || {
        let proto_s = cstr_to_string(proto).unwrap_or_default();
        if !proto_s.is_empty() && proto_s != "tcp" {
            let mut t = table().lock().expect("table poisoned");
            set_server_error(&mut t, handle, format!("unsupported proto: {proto_s}"));
            return RS_ERR_INVAL;
        }

        let Some(addr_s) = cstr_to_string(addr) else {
            let mut t = table().lock().expect("table poisoned");
            set_server_error(&mut t, handle, "null addr");
            return RS_ERR_INVAL;
        };

        let server_arc = {
            let t = table().lock().expect("table poisoned");
            let Some(e) = t.servers.get(&handle) else {
                return RS_ERR_NOENT;
            };
            let Some(ref arc) = e.server else {
                return RS_ERR_BUSY;
            };
            arc.clone()
        };

        let stream = {
            let server = server_arc.lock().expect("server mutex poisoned");
            runtime().block_on(async {
                tokio::time::timeout(FFI_BLOCK_TIMEOUT, server.dial(&addr_s)).await
            })
        };

        match stream {
            Ok(Ok(s)) => {
                let ch = alloc_handle();
                let arc = Arc::new(Mutex::new(s));
                let mut t = table().lock().expect("table poisoned");
                t.connections.insert(ch, ConnEntry { stream: arc });
                ch
            }
            Ok(Err(e)) => {
                let mut t = table().lock().expect("table poisoned");
                set_server_error(&mut t, handle, e.to_string());
                RS_ERR_UNKNOWN
            }
            Err(_) => {
                let mut t = table().lock().expect("table poisoned");
                set_server_error(&mut t, handle, "dial timed out");
                RS_ERR_TIMEOUT
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Connection read/write/close
// ---------------------------------------------------------------------------

/// Read up to `len` bytes into `buf` (blocking).
/// Returns bytes read (0 = EOF), or a negative error code.
#[no_mangle]
pub extern "C" fn ts_conn_read(conn: c_int, buf: *mut c_char, len: c_int) -> c_int {
    catch("ts_conn_read", || {
        if buf.is_null() || len < 0 {
            return RS_ERR_INVAL;
        }
        if len == 0 {
            return 0;
        }

        let stream_arc = {
            let t = table().lock().expect("table poisoned");
            let Some(e) = t.connections.get(&conn) else {
                return RS_ERR_NOENT;
            };
            e.stream.clone()
        };

        let mut read_buf = vec![0u8; len as usize];
        let result = {
            let mut stream = stream_arc.lock().expect("conn mutex poisoned");
            runtime().block_on(async {
                tokio::time::timeout(FFI_BLOCK_TIMEOUT, stream.read(&mut read_buf)).await
            })
        };

        match result {
            Ok(Ok(n)) => {
                if n > 0 {
                    // SAFETY: caller guarantees buf is valid for len bytes.
                    unsafe {
                        std::ptr::copy_nonoverlapping(read_buf.as_ptr(), buf.cast::<u8>(), n);
                    }
                }
                n as c_int
            }
            Ok(Err(_)) => RS_ERR_UNKNOWN,
            Err(_) => RS_ERR_TIMEOUT,
        }
    })
}

/// Write `len` bytes from `buf` (blocking).
/// Returns bytes written, or a negative error code.
#[no_mangle]
pub extern "C" fn ts_conn_write(conn: c_int, buf: *const c_char, len: c_int) -> c_int {
    catch("ts_conn_write", || {
        if buf.is_null() || len < 0 {
            return RS_ERR_INVAL;
        }
        if len == 0 {
            return 0;
        }

        let stream_arc = {
            let t = table().lock().expect("table poisoned");
            let Some(e) = t.connections.get(&conn) else {
                return RS_ERR_NOENT;
            };
            e.stream.clone()
        };

        // SAFETY: caller guarantees buf is valid for len bytes.
        let data: Vec<u8> =
            unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len as usize).to_vec() };

        let result = {
            let mut stream = stream_arc.lock().expect("conn mutex poisoned");
            runtime().block_on(stream.write_all(&data))
        };

        match result {
            Ok(()) => len,
            Err(_) => RS_ERR_UNKNOWN,
        }
    })
}

/// Close a connection handle. Returns 0 on success.
#[no_mangle]
pub extern "C" fn ts_conn_close(conn: c_int) -> c_int {
    catch("ts_conn_close", || {
        let mut t = table().lock().expect("table poisoned");
        if t.connections.remove(&conn).is_some() {
            RS_OK
        } else {
            RS_ERR_NOENT
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
