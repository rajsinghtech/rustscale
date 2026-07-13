# CapturePcap Implementation Spec

Pre-digested for a Codex coding agent. Do **not** re-read Go sources broadly — everything below is byte-exact.

---

## 1. Pcap wire format (byte-exact, little-endian)

### Global header (24 bytes)

Go code (`feature/capture/capture.go:63-71`):
```go
binary.Write(w, binary.LittleEndian, uint32(0xA1B2C3D4)) // magic
binary.Write(w, binary.LittleEndian, uint16(2))          // version major
binary.Write(w, binary.LittleEndian, uint16(4))          // version minor
binary.Write(w, binary.LittleEndian, uint32(0))          // this zone
binary.Write(w, binary.LittleEndian, uint32(0))          // sigfigs
binary.Write(w, binary.LittleEndian, uint32(65535))      // snaplen
binary.Write(w, binary.LittleEndian, uint32(147))        // linktype = USER0
```

Layout:
```
Offset  Size  Field
0       4     0xA1B2C3D4  (magic, LE = d4 c3 b2 a1 on wire)
4       2     2           (version major)
6       2     4           (version minor)
8       4     0           (timezone)
12      4     0           (sigfigs)
16      4     65535       (snaplen)
20      4     147         (linktype = LINKTYPE_USER0 = 147)
```

### Per-packet record (16 bytes + custom metadata + raw packet)

Go code (`capture.go:73-81`):
```go
func writePktHeader(w *bytes.Buffer, when time.Time, length int) {
    s := when.Unix()
    us := when.UnixMicro() - (s * 1000000)
    binary.Write(w, binary.LittleEndian, uint32(s))      // ts seconds
    binary.Write(w, binary.LittleEndian, uint32(us))     // ts microseconds
    binary.Write(w, binary.LittleEndian, uint32(length)) // incl_len
    binary.Write(w, binary.LittleEndian, uint32(length)) // orig_len
}
```

### Custom metadata (after 16-byte pcap header, before raw packet bytes)

Go code (`capture.go:180-213`) — the `LogPacket` function writes:

```go
// 1. path (u16 LE) — one of the CapturePath enum values
binary.Write(b, binary.LittleEndian, uint16(path))

// 2. SNAT metadata
if meta.DidSNAT {
    binary.Write(b, binary.LittleEndian, uint8(meta.OriginalSrc.Addr().BitLen()/8)) // 4 or 16
    b.Write(meta.OriginalSrc.Addr().AsSlice())
} else {
    binary.Write(b, binary.LittleEndian, uint8(0)) // addr len == 0
}

// 3. DNAT metadata
if meta.DidDNAT {
    binary.Write(b, binary.LittleEndian, uint8(meta.OriginalDst.Addr().BitLen()/8)) // 4 or 16
    b.Write(meta.OriginalDst.Addr().AsSlice())
} else {
    binary.Write(b, binary.LittleEndian, uint8(0)) // addr len == 0
}

// 4. raw packet bytes
b.Write(data)
```

For the common case (no SNAT/DNAT), the metadata is exactly **4 bytes**:
```
Offset  Size  Field
0       2     path (u16 LE)
2       1     0   (SNAT addr len = 0)
3       1     0   (DNAT addr len = 0)
```

Full per-packet record on wire: `[16-byte pcap header][N-byte metadata][raw packet]` where `N = 4 + (SNAT addr len if DidSNAT else 0) + (DNAT addr len if DidDNAT else 0)`.

The `length` field in the pkt header equals `len(data) + extraLen` where `extraLen = 4 + SNAT_bytes + DNAT_bytes`. Go computes this via `customDataLen(meta)` at `capture.go:169-178`.

### CapturePath enum values

From `net/packet/capture.go:56-74`:
```go
FromLocal          CapturePath = 0    // local system → TUN → WG → peer
FromPeer           CapturePath = 1    // peer → WG → decap → TUN → local
SynthesizedToLocal CapturePath = 2    // tailscaled-generated → local netstack
SynthesizedToPeer  CapturePath = 3    // tailscaled-generated → WG → peer
PathDisco          CapturePath = 254  // disco frame info
```

### CaptureMeta struct

From `net/packet/capture.go:48-54`:
```go
type CaptureMeta struct {
    DidSNAT     bool           // SNAT performed, address changed
    OriginalSrc netip.AddrPort // pre-SNAT source
    DidDNAT     bool           // DNAT performed
    OriginalDst netip.AddrPort // pre-DNAT destination
}
```

Populated by the checksum module (`net/packet/checksum/checksum.go:25-54`) when rewriting SNAT/DNAT addresses. For a first implementation, all four fields can be zero/false (the coding agent should still carry the fields in the Rust struct for completeness).

### CaptureCallback / CaptureSink interfaces

From `net/packet/capture.go:12-46`:
```go
type CaptureCallback func(CapturePath, time.Time, []byte, CaptureMeta)

type CaptureSink interface {
    Close() error
    NumOutputs() int
    CaptureCallback() CaptureCallback
    WaitCh() <-chan struct{}
    RegisterOutput(w io.Writer) (unregister func())
}
```

---

## 2. Capture points in the Go data path (tstun/wrap.go)

| Point | File:Line | CapturePath | Description |
|-------|-----------|-------------|-------------|
| Outbound to WG | `wrap.go:1003-1004` | `FromLocal` (0) | TUN read → packet decoded, immediately before filter + DNAT. `captHook(packet.FromLocal, t.now(), p.Buffer(), p.CaptureMeta)` |
| Inbound from WG | `wrap.go:1157-1159` | `FromPeer` (1) | WG decapsulated → inside `filterPacketInboundFromWireGuard`, immediately before filter check. `captHook(packet.FromPeer, t.now(), p.Buffer(), p.CaptureMeta)` |
| Netstack→Local | `wrap.go:1397-1399` | `SynthesizedToLocal` (2) | Netstack `WriteInject` path: synthesized packet targeting local stack. `captHook(packet.SynthesizedToLocal, t.now(), p.Buffer(), p.CaptureMeta)` |
| Netstack→Peer | `wrap.go:1532-1535` | `SynthesizedToPeer` (3) | Netstack `WriteInject` path: synthesized packet targeting remote peer. `captHook(packet.SynthesizedToPeer, t.now(), b.Flatten(), packet.CaptureMeta{})` |

**Key detail for FromLocal** (`wrap.go:1001-1004`):
```go
p.Decode(data[res.dataOffset:])
if buildfeatures.HasCapture && captHook != nil {
    captHook(packet.FromLocal, t.now(), p.Buffer(), p.CaptureMeta)
}
```

**Key detail for FromPeer** (`wrap.go:1157-1160`):
```go
func (t *Wrapper) filterPacketInboundFromWireGuard(p *packet.Parsed, captHook packet.CaptureCallback, ...) {
    if captHook != nil {
        captHook(packet.FromPeer, t.now(), p.Buffer(), p.CaptureMeta)
    }
    // ... filter logic follows
```

**Key detail for SynthesizedToLocal** (`wrap.go:1394-1400`):
```go
p.Decode(buf)
captHook := t.captureHook.Load()
if captHook != nil {
    captHook(packet.SynthesizedToLocal, t.now(), p.Buffer(), p.CaptureMeta)
}
```

**Key detail for SynthesizedToPeer** (`wrap.go:1532-1535`):
```go
if capt := t.captureHook.Load(); capt != nil {
    b := pkt.ToBuffer()
    capt(packet.SynthesizedToPeer, t.now(), b.Flatten(), packet.CaptureMeta{})
}
```

---

## 3. Sink design: multiplex fanout (feature/capture/capture.go)

### Structure (`capture.go:95-102`)
```go
type Sink struct {
    ctx       context.Context
    ctxCancel context.CancelFunc
    mu        sync.Mutex
    outputs   set.HandleSet[io.Writer]   // map[set.Handle]io.Writer
    flushTimer *time.Timer               // or nil if not running
}
```

### RegisterOutput (`capture.go:112-129`)
1. Checks `s.ctx.Done()` — if already closed, returns noop.
2. Writes pcap global header to the writer.
3. Adds writer to `s.outputs` under a `set.Handle` (opaque uint64 key from Go's `set.HandleSet`).
4. Returns an `unregister` closure: locks mu, deletes from outputs map.

### LogPacket (`capture.go:183-243`)
1. Check `s.ctx.Done()` — if closed, return.
2. Compute `extraLen` from `customDataLen(meta)`.
3. Get a pooled buffer, write 16-byte pcap header + custom metadata + raw data.
4. Lock mu; iterate outputs, call `Write()` on each.
5. On error: close output if `io.Closer`, remove from outputs set.
6. If no flush timer running, start one (100ms `time.AfterFunc`) that iterates outputs and calls `Flush()` on any that implement `http.Flusher`.

### Close (`capture.go:145-161`)
1. Cancel context (signals WaitCh).
2. Stop flush timer.
3. Close any output implementing `io.Closer`.
4. Nil the outputs map.

### WaitCh (`capture.go:163-167`)
Returns `s.ctx.Done()` — blocking until sink is closed.

### newSink factory (`capture.go:84-90`)
```go
func newSink() packet.CaptureSink {
    ctx, c := context.WithCancel(context.Background())
    return &Sink{ctx: ctx, ctxCancel: c}
}
```

---

## 4. LocalAPI handler (feature/capture/capture.go and localapi Registration)

### Registration (`capture.go:22-25`, called in init())
```go
func init() {
    feature.Register("capture")
    localapi.Register("debug-capture", serveLocalAPIDebugCapture)
}
```

### Handler (`capture.go:27-52`)
```go
func serveLocalAPIDebugCapture(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    if !h.PermitWrite {
        http.Error(w, "debug access denied", http.StatusForbidden)
        return
    }
    if r.Method != "POST" {
        http.Error(w, "POST required", http.StatusMethodNotAllowed)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.(http.Flusher).Flush()

    b := h.LocalBackend()
    s := b.GetOrSetCaptureSink(newSink)
    unregister := s.RegisterOutput(w)

    select {
    case <-ctx.Done():
    case <-s.WaitCh():
    }
    unregister()
    b.ClearCaptureSink()
}
```

Flow:
1. Require `PermitWrite` (e.g. same-uid or root).
2. Require POST method.
3. Write 200 OK + flush (no body yet — pcap data follows as the HTTP body).
4. Get-or-create the capture sink via `LocalBackend.GetOrSetCaptureSink(newSink)`.
5. Register the `http.ResponseWriter` as an output (writes pcap global header + streams packets).
6. Block until client disconnects (`ctx.Done()`) or sink closes itself.
7. Unregister this output.
8. Call `ClearCaptureSink()` — if no more outputs, tears down the sink and unhooks it from the TUN wrapper.

### GetOrSetCaptureSink (ipnlocal/local.go:1278-1293)
```go
func (b *LocalBackend) GetOrSetCaptureSink(newSink func() packet.CaptureSink) packet.CaptureSink {
    if !buildfeatures.HasCapture { return nil }
    b.mu.Lock()
    defer b.mu.Unlock()
    if b.debugSink != nil { return b.debugSink }
    s := newSink()
    b.debugSink = s
    b.e.InstallCaptureHook(s.CaptureCallback())  // <-- wires into tstun.Wrapper
    return s
}
```

### ClearCaptureSink (ipnlocal/local.go:1296-1315)
```go
func (b *LocalBackend) ClearCaptureSink() {
    // ...lock, check ctx...
    if b.debugSink != nil && b.debugSink.NumOutputs() == 0 {
        b.debugSink.Close()
        b.debugSink = nil
        b.e.InstallCaptureHook(nil)  // <-- unhooks from tstun.Wrapper
    }
}
```

### InstallCaptureHook (tstun/wrap.go:1578-1583)
```go
func (t *Wrapper) InstallCaptureHook(cb packet.CaptureCallback) {
    if !buildfeatures.HasCapture { return }
    t.captureHook.Store(cb)
}
```

`captureHook` is a `syncs.AtomicValue[packet.CaptureCallback]` declared at `wrap.go:224`.

---

## 5. CLI subcommand (cmd/tailscale/cli/debug-capture.go)

Build-tag gated: `//go:build !ios && !ts_omit_capture`.

```go
func runCapture(ctx context.Context, args []string) error {
    stream, err := localClient.StreamDebugCapture(ctx)
    if err != nil { return err }
    defer stream.Close()

    switch captureArgs.outFile {
    case "-":                          // stdout
        _, err = io.Copy(os.Stdout, stream)
    case "":                           // launch wireshark
        // write Lua dissector to temp file, exec wireshark -X lua_script:... -k -i -
    default:                           // write to file
        f, _ := os.OpenFile(captureArgs.outFile, O_WRONLY|O_CREATE|O_TRUNC, 0644)
        _, err = io.Copy(f, stream)
    }
}
```

The Lua dissector is at `feature/capture/dissector/ts-dissector.lua` — worth including as a resource in the Rust crate.

### Go client side (client/local/local.go:1337-1355)
```go
func (lc *Client) StreamDebugCapture(ctx context.Context) (io.ReadCloser, error) {
    req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+apitype.LocalAPIHost+"/localapi/v0/debug-capture", nil)
    res, err := lc.doLocalRequestNiceError(req)
    if err != nil { return nil, err }
    if res.StatusCode != 200 { res.Body.Close(); return nil, errors.New(res.Status) }
    return res.Body, nil
}
```

### tsnet Server.CapturePcap (tsnet/tsnet.go:2205-2231)
```go
func (s *Server) CapturePcap(ctx context.Context, pcapFile string) error {
    stream, err := s.localClient.StreamDebugCapture(ctx)
    // ...open file, spawn io.Copy goroutine...
    go func() { defer stream.Close(); defer f.Close(); _, _ = io.Copy(f, stream) }()
    return nil
}
```

---

## 6. Rust code locations and proposed insertion points

### 6.1 Capture module location: `crates/capture/`

**New crate**: `crates/capture/` with crate name `rustscale-capture`.

Files:
- `crates/capture/src/lib.rs` — `CapturePath` enum, `CaptureMeta` struct, `CaptureCallback` type alias, `CaptureSink` trait.
- `crates/capture/src/sink.rs` — `Sink` struct (mpsc-based fanout, pcap encoder, flush timer).
- `crates/capture/src/encoder.rs` — pcap header + per-packet + custom metadata binary encoding.

**Alternative** (simpler, since the crate is tightly coupled): embed as `crates/tsnet/src/capture/` module. Choose based on whether feature-gating is needed.

### 6.2 `CapturePath` enum and `CaptureMeta` struct

Proposed Rust (in new `crates/capture/src/lib.rs`):
```rust
/// Where in the data path the packet was captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CapturePath {
    FromLocal          = 0,
    FromPeer           = 1,
    SynthesizedToLocal = 2,
    SynthesizedToPeer  = 3,
    PathDisco          = 254,
}

/// Metadata about SNAT/DNAT rewrites for the captured packet.
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureMeta {
    pub did_snat: bool,
    pub original_src: Option<IpAddr>,
    pub did_dnat: bool,
    pub original_dst: Option<IpAddr>,
}

pub type CaptureCallback = Arc<dyn Fn(CapturePath, Instant, &[u8], &CaptureMeta) + Send + Sync>;

pub trait CaptureSink: Send + Sync {
    fn close(&self);
    fn num_outputs(&self) -> usize;
    fn capture_callback(&self) -> CaptureCallback;
    fn wait_ch(&self) -> oneshot::Receiver<()>;
    fn register_output(&self, w: Box<dyn Write + Send + 'static>) -> Box<dyn FnOnce() + Send>;
}
```

### 6.3 Sink implementation (mpsc-based fanout)

Proposed structure matches Go's pattern but uses `tokio::sync::Notify` + `Mutex<HashMap<u64, Box<dyn Write + Send>>>`:

```rust
pub struct Sink {
    inner: Arc<Mutex<SinkInner>>,
    cb: CaptureCallback,
    close_tx: tokio::sync::oneshot::Sender<()>,
    close_rx: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

struct SinkInner {
    next_id: u64,
    outputs: HashMap<u64, Box<dyn Write + Send>>,
    flush_armed: bool,
}
```

- `RegisterOutput`: lock, write 24-byte pcap global header, insert, return unregister closure.
- `LogPacket` (the `CaptureCallback`): lock, write encoded packet to all outputs, arm 100ms flush timer (via spawned tokio task). On write error, close+remove.
- `Close`: send on close_tx, close all outputs.

### 6.4 LocalApiState additions

File: `crates/tsnet/src/localapi.rs:93-159`. Add:

```rust
pub(crate) struct LocalApiState {
    // ...existing fields...
    pub capture_sink: Arc<std::sync::Mutex<Option<rustscale_capture::Sink>>>,
}
```

### 6.5 LocalAPI dispatch — new endpoint

File: `crates/tsnet/src/localapi.rs`, in the `match endpoint` dispatch at `~line 765`.

Add handler route:
```rust
"debug-capture" if method == "POST" => {
    handle_debug_capture(conn, state).await?;
}
```

Handler function (new, near `handle_watch_ipn_bus` at `~line 1531`):
```rust
async fn handle_debug_capture<W: AsyncWrite + Unpin>(
    conn: &mut W,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    // 1. Require read-write access (same as Go's PermitWrite).
    // 2. Write HTTP 200 + "Content-Type: application/octet-stream" + flush.
    // 3. Get-or-create capture sink.
    // 4. Wrap conn as a writer, register as output.
    // 5. Wait for client disconnect (conn read returning EOF) or sink closed.
    // 6. Unregister, clear sink if no more outputs.
}
```

The writer wrapper needs to be a `struct CaptureConnWriter<W>(Arc<Mutex<W>>)` implementing `Write + Send` so the sink can write to it from the capture callback. Calls the underlying `AsyncWrite` via `block_in_place` or sends through a channel.

**Simpler approach**: spawn a task that receives encoded pcap data over an `mpsc::Receiver<Bytes>` and writes it to `conn`. The sink's output writes into the `mpsc::Sender`. This avoids the `AsyncWrite` in sync `Write` problem.

Architecture:
```
LogPacket (sync callback) → writes to all registered mpsc::Sender<Bytes>
                            ↓
spawned task for each HTTP client: reads from mpsc::Receiver, writes to AsyncWrite, flushes every 100ms
```

### 6.6 TUN pump capture points

File: `crates/tsnet/src/tun_pump.rs`.

**FromLocal** (outbound TUN→WG): in `send_tun_batch()` at `~line 138`:
```rust
filt.update_outbound(packet);
// INSERT: capture_callback(CapturePath::FromLocal, Instant::now(), packet, &CaptureMeta::default())
```

**FromPeer** (inbound WG→TUN): in `process_tun_inbound()` at `~line 151`:
```rust
let dropped = {
    let mut filt = filter.lock().unwrap();
    filt.check_in(&pt).is_drop()
};
// INSERT: capture_callback(CapturePath::FromPeer, Instant::now(), &pt, &CaptureMeta::default())
// (before the filter drop check to match Go ordering, or after since capture in Go is before filter)
```

Go captures at `FromPeer` **before** the filter check (`wrap.go:1158-1159` is inside `filterPacketInboundFromWireGuard` called before the actual filter response check at `wrap.go:1304`). So Rust should also capture before filtering.

Similarly, `FromLocal` in Go is captured **before** the filter at `wrap.go:1003-1004`.

### 6.7 Netstack pump capture points

File: `crates/tsnet/src/netstack_pump.rs`.

**FromPeer** (inbound WG→Netstack): in `handle_inbound_wg()` delivery callback at `~line 40+`:
```rust
ns.push_rx(pt);
// INSERT: capture_callback(CapturePath::FromPeer, ...) before push_rx
```

**FromLocal** (outbound Netstack→WG): in the drain loop at `~line 85+`:
```rust
let Some(pkt) = netstack.pop_tx() else { break };
{
    let mut filt = filter.lock().unwrap();
    filt.update_outbound(&pkt);
}
// INSERT: capture_callback(CapturePath::FromLocal, ...) before encapsulate_and_send
encapsulate_and_send(&magicsock, &wg_tunnels, &route_table, &pkt).await;
```

**SynthesizedToLocal** and **SynthesizedToPeer**: harder to wire because the netstack's internal poll loop generates these. Defer to a follow-up phase, or skip initially (the four main capture points already give full visibility).

### 6.8 LocalClient — new method

File: `crates/localclient/src/lib.rs`, add after `watch_ipn_bus()` at `~line 149`:

```rust
/// POST /localapi/v0/debug-capture — streams a pcap-formatted packet capture.
///
/// Returns a raw safesocket Connection. The caller reads raw pcap bytes until
/// EOF (daemon closes the connection). The pcap global header is the first
/// thing returned.
pub async fn stream_debug_capture(&self) -> Result<Connection, LocalClientError> {
    let stream = self.connect_and_send("POST", "/localapi/v0/debug-capture").await?;
    Ok(stream)
    // Note: connect_and_send sends "Content-Length: 0\r\nConnection: close\r\n\r\n"
    // which is correct — the daemon writes 200 OK then pcap data until disconnect.
}
```

Also add a higher-level `CaptureStream` wrapper (like `WatchIpnBus` at `crates/localclient/src/stream.rs`) that strips the HTTP response header and yields raw bytes.

### 6.9 CLI debug subcommand

File: `crates/cli/src/commands/debug.rs`.

The current dispatcher at `debug.rs:13-31` works by `action` string → `client.debug(action)` → JSON. For the streaming capture endpoint, it needs special handling.

Add a `capture` action:
```rust
pub async fn run(args: Vec<String>, socket: &Path, json: bool) -> Result<(), CliError> {
    let action = args.iter().find(|a| !a.starts_with("--")).map_or("status", String::as_str);
    if action == "capture" {
        return run_capture(args, socket).await;
    }
    // ...existing debug logic...
}

async fn run_capture(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let out_file = /* parse -o flag */;
    let client = LocalClient::new(socket);
    let mut stream = client.stream_debug_capture().await?;
    // Strip HTTP response header, then copy pcap data to out_file/stdout/wireshark
}
```

**Wireshark launch**: the Lua dissector lives at `feature/capture/dissector/ts-dissector.lua` in the Go repo. For Rust, either embed the Lua string as a `const` in the binary or ship it alongside. The CLI writes it to a temp file, then runs:
```bash
wireshark -X lua_script:/tmp/ts-dissector.lua -k -i -
```

### 6.10 tsnet Server::capture_pcap replacement

File: `crates/tsnet/src/api.rs:808`.

Replace the stub:
```rust
pub async fn capture_pcap(&self, pcap_file: &str) -> Result<(), TsnetError> {
    let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
    let stream = inner.local_client.stream_debug_capture().await
        .map_err(|e| TsnetError::Other(e.to_string()))?;

    let file = tokio::fs::File::create(pcap_file).await
        .map_err(|e| TsnetError::Other(e.to_string()))?;

    tokio::spawn(async move {
        // Copy from stream to file, stripping HTTP header
        // ...until EOF (server shutdown closes the stream)
    });

    Ok(())
}
```

---

## 7. Implementation order (recommended)

1. **New crate `crates/capture/`**: types (`CapturePath`, `CaptureMeta`, `CaptureCallback`, `CaptureSink` trait) and `Sink` with mpsc fanout + pcap encoder.
2. **Add `capture_sink` field** to `LocalApiState` in `crates/tsnet/src/localapi.rs`.
3. **Wire capture callback** at `FromLocal` and `FromPeer` points in `tun_pump.rs`.
4. **Wire capture callback** at `FromLocal` and `FromPeer` points in `netstack_pump.rs`.
5. **Add `POST /localapi/v0/debug-capture` handler** in `localapi.rs`.
6. **Add `stream_debug_capture()`** to `LocalClient` in `crates/localclient/src/lib.rs`.
7. **Add CLI `debug capture` subcommand** in `crates/cli/src/commands/debug.rs`.
8. **Replace `capture_pcap()` stub** in `crates/tsnet/src/api.rs`.
9. **Acceptance**: `tools/check.sh capture && tools/check.sh tsnet && tools/check.sh localclient && tools/check.sh cli`.

---

## 8. Acceptance criteria

1. `cargo build` workspace compiles.
2. `cargo test -p rustscale-capture` passes (unit tests for pcap encoder + sink fanout).
3. Integration: `cargo test -p rustscale-tsnet -- localapi::tests::test_debug_capture` passes (exercises the LocalAPI endpoint via the in-memory loopback client, verifies pcap magic bytes in response).
4. The pcap output is valid: first 4 bytes = `d4 c3 b2 a1`, byte 20 = 147 (USER0 linktype).
5. `tools/check.sh` (workspace) passes.
6. Manual: `rustscale debug capture -o /tmp/test.pcap` produces a readable pcap (verified with `file /tmp/test.pcap` = "tcpdump capture file...").
7. Lua dissector at `feature/capture/dissector/ts-dissector.lua` is embedded/included so `rustscale debug capture` (no args) launches Wireshark with it.
