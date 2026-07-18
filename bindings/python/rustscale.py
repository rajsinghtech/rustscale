#!/usr/bin/env python3
"""
rustscale — Python binding for librustscale via ctypes.

A pythonic wrapper over the C ABI.  No build system, no Rust toolchain needed
at runtime — just the shared library (librustscale.dylib / .so).

Quick start:
    from rustscale import Server

    srv = Server(hostname="my-app", auth_key="tskey-...", ephemeral=True)
    srv.up()

    listener = srv.listen("tcp", ":8080")
    conn = listener.accept()

    data = conn.read(1024)
    conn.write(b"echo: " + data)
    conn.close()
    listener.close()
    srv.close()

When TS_E2E_AUTHKEY and TS_E2E_TAILNET are set, `python3 rustscale.py` runs a
two-node echo smoke test.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
import time
from ctypes import (
    POINTER,
    c_char,
    c_char_p,
    c_int,
    create_string_buffer,
)
from pathlib import Path

__all__ = [
    "Connection",
    "Listener",
    "RS_ERR_BUSY",
    "RS_ERR_INVAL",
    "RS_ERR_NOENT",
    "RS_ERR_TIMEOUT",
    "RS_ERR_UNKNOWN",
    "RS_OK",
    "RustscaleError",
    "Server",
]

# ---------------------------------------------------------------------------
# Load the shared library
# ---------------------------------------------------------------------------

def _find_lib() -> ctypes.CDLL:
    """Locate librustscale in common locations."""
    candidates = []

    # 1. RUSTSCALE_LIB env var (explicit override).
    if env := os.environ.get("RUSTSCALE_LIB"):
        candidates.append(Path(env))

    # 2. Relative to this file (repo layout).
    here = Path(__file__).resolve().parent
    repo_root = here.parent.parent
    ext = ".dylib" if platform.system() == "Darwin" else ".so"
    candidates.append(repo_root / "target" / "debug" / f"librustscale{ext}")
    candidates.append(repo_root / "target" / "release" / f"librustscale{ext}")

    for p in candidates:
        if p.exists():
            return ctypes.CDLL(str(p))

    raise FileNotFoundError(
        f"librustscale not found. Set RUSTSCALE_LIB or build with "
        f"`cargo build -p rustscale-ffi`. Searched: {candidates}"
    )


_lib = _find_lib()

# ---------------------------------------------------------------------------
# Function signatures
# ---------------------------------------------------------------------------

_lib.ts_new.restype = c_int
_lib.ts_new.argtypes = []

_lib.ts_set_authkey.restype = c_int
_lib.ts_set_authkey.argtypes = [c_int, c_char_p]

_lib.ts_set_hostname.restype = c_int
_lib.ts_set_hostname.argtypes = [c_int, c_char_p]

_lib.ts_set_control_url.restype = c_int
_lib.ts_set_control_url.argtypes = [c_int, c_char_p]

_lib.ts_set_state_dir.restype = c_int
_lib.ts_set_state_dir.argtypes = [c_int, c_char_p]

_lib.ts_set_ephemeral.restype = c_int
_lib.ts_set_ephemeral.argtypes = [c_int, c_int]

_lib.ts_up.restype = c_int
_lib.ts_up.argtypes = [c_int]

_lib.ts_close.restype = c_int
_lib.ts_close.argtypes = [c_int]

_lib.ts_errmsg.restype = c_int
_lib.ts_errmsg.argtypes = [c_int, POINTER(c_char), c_int]

_lib.ts_status_json.restype = c_int
_lib.ts_status_json.argtypes = [c_int, POINTER(c_char), c_int]

_lib.ts_listen.restype = c_int
_lib.ts_listen.argtypes = [c_int, c_char_p, c_char_p]

_lib.ts_listener_close.restype = c_int
_lib.ts_listener_close.argtypes = [c_int]

_lib.ts_accept.restype = c_int
_lib.ts_accept.argtypes = [c_int]

_lib.ts_dial.restype = c_int
_lib.ts_dial.argtypes = [c_int, c_char_p, c_char_p]

_lib.ts_conn_read.restype = c_int
_lib.ts_conn_read.argtypes = [c_int, POINTER(c_char), c_int]

_lib.ts_conn_write.restype = c_int
_lib.ts_conn_write.argtypes = [c_int, c_char_p, c_int]

_lib.ts_conn_close.restype = c_int
_lib.ts_conn_close.argtypes = [c_int]


# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

RS_OK = 0
RS_ERR_INVAL = -22
RS_ERR_NOENT = -2
RS_ERR_BUSY = -16
RS_ERR_TIMEOUT = -110
RS_ERR_UNKNOWN = -1


class RustscaleError(Exception):
    """Error from a librustscale operation."""

    def __init__(self, code: int, message: str = ""):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}" if message else f"[{code}]")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check(code: int, server_handle: int | None = None) -> None:
    """Raise RustscaleError if code is negative."""
    if code >= 0:
        return
    msg = ""
    if server_handle is not None:
        buf = create_string_buffer(512)
        n = _lib.ts_errmsg(server_handle, buf, 512)
        if n > 0:
            msg = buf.value.decode()
    raise RustscaleError(code, msg)


def _to_cstr(s: str | bytes) -> bytes:
    if isinstance(s, str):
        return s.encode("utf-8")
    return s


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class Server:
    """An embedded Tailscale server."""

    def __init__(
        self,
        hostname: str = "rustscale",
        auth_key: str | None = None,
        control_url: str | None = None,
        state_dir: str | None = None,
        ephemeral: bool = False,
    ):
        self._handle = _lib.ts_new()
        if self._handle < 0:
            raise RustscaleError(self._handle, "ts_new failed")

        if hostname:
            _check(_lib.ts_set_hostname(self._handle, _to_cstr(hostname)), self._handle)
        if auth_key:
            _check(_lib.ts_set_authkey(self._handle, _to_cstr(auth_key)), self._handle)
        if control_url:
            _check(_lib.ts_set_control_url(self._handle, _to_cstr(control_url)), self._handle)
        if state_dir:
            _check(_lib.ts_set_state_dir(self._handle, _to_cstr(state_dir)), self._handle)
        if ephemeral:
            _check(_lib.ts_set_ephemeral(self._handle, 1), self._handle)

    def up(self) -> None:
        """Bring the server online (blocking)."""
        _check(_lib.ts_up(self._handle), self._handle)

    def close(self) -> None:
        """Shut down the server."""
        if self._handle >= 0:
            _lib.ts_close(self._handle)
            self._handle = -1

    def listen(self, proto: str = "tcp", addr: str = ":0") -> "Listener":
        """Start listening for incoming connections."""
        lh = _lib.ts_listen(self._handle, _to_cstr(proto), _to_cstr(addr))
        _check(lh, self._handle)
        return Listener(lh, self._handle)

    def dial(self, addr: str, proto: str = "tcp") -> "Connection":
        """Dial a remote address."""
        ch = _lib.ts_dial(self._handle, _to_cstr(proto), _to_cstr(addr))
        _check(ch, self._handle)
        return Connection(ch)

    def status(self) -> dict:
        """Return server status as a dict."""
        buf = create_string_buffer(8192)
        n = _lib.ts_status_json(self._handle, buf, 8192)
        _check(n, self._handle)
        return json.loads(buf.value.decode())

    @property
    def handle(self) -> int:
        return self._handle

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Listener:
    """A TCP listener on the tailnet."""

    def __init__(self, handle: int, server_handle: int):
        self._handle = handle
        self._server_handle = server_handle

    def accept(self, timeout: float | None = None) -> "Connection":
        """Accept the next incoming connection (blocking)."""
        ch = _lib.ts_accept(self._handle)
        _check(ch, self._server_handle)
        return Connection(ch)

    def close(self) -> None:
        if self._handle >= 0:
            _lib.ts_listener_close(self._handle)
            self._handle = -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Connection:
    """A TCP connection over the tailnet."""

    def __init__(self, handle: int):
        self._handle = handle

    def read(self, n: int = 4096) -> bytes:
        """Read up to n bytes."""
        buf = (c_char * n)()
        r = _lib.ts_conn_read(self._handle, buf, n)
        _check(r)
        return bytes(buf[:r])

    def write(self, data: bytes) -> int:
        """Write data. Returns number of bytes written."""
        w = _lib.ts_conn_write(self._handle, data, len(data))
        _check(w)
        return w

    def close(self) -> None:
        if self._handle >= 0:
            _lib.ts_conn_close(self._handle)
            self._handle = -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # File-like interface.
    def recv(self, n=4096):
        return self.read(n)

    def send(self, data):
        return self.write(data)


# ---------------------------------------------------------------------------
# __main__ smoke test
# ---------------------------------------------------------------------------

def _smoke():
    authkey = os.environ.get("TS_E2E_AUTHKEY")
    if not authkey:
        print("rustscale.py: TS_E2E_AUTHKEY not set; load-only smoke OK")
        return

    print("starting two-node echo test...")

    srv_b = Server(
        hostname="rustscale-py-b",
        auth_key=authkey,
        ephemeral=True,
    )
    srv_b.up()
    st = srv_b.status()
    ip_b = st["tailscale_ips"][0]
    print(f"B up: {ip_b}")

    listener = srv_b.listen("tcp", ":4242")

    srv_a = Server(
        hostname="rustscale-py-a",
        auth_key=authkey,
        ephemeral=True,
    )
    srv_a.up()

    # Wait for A to see B.
    for _ in range(120):
        st = srv_a.status()
        if st.get("peer_count", 0) > 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("A never saw B")

    # A dials B.
    conn_a = srv_a.dial(f"{ip_b}:4242")
    conn_b = listener.accept()

    msg = b"hello python ffi"
    conn_a.write(msg)
    data = conn_b.read()
    assert data == msg, f"expected {msg!r}, got {data!r}"
    print(f"B recv: {data}")

    conn_b.write(data)
    echo = conn_a.read()
    assert echo == msg, f"expected {msg!r}, got {echo!r}"
    print(f"A recv: {echo}")

    conn_a.close()
    conn_b.close()
    listener.close()
    srv_a.close()
    srv_b.close()
    print("OK")


if __name__ == "__main__":
    _smoke()
