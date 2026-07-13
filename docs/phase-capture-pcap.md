# Phase: CapturePcap (packet capture debug stream)

Port Tailscale's `feature/capture` packet capture to rustscale: a pcap stream of
plaintext packets crossing the data path, exposed via `Server::capture_pcap`,
LocalAPI, and the CLI.

Go references (read-only, quote-verified 2026-07-13):
- `/Users/rajsingh/Documents/GitHub/tailscale/feature/capture/capture.go` (244 loc — the whole sink)
- `/Users/rajsingh/Documents/GitHub/tailscale/net/packet/capture.go` (CapturePath/CaptureMeta)
- `/Users/rajsingh/Documents/GitHub/tailscale/net/tstun/wrap.go` (hook callpoints)
- `/Users/rajsingh/Documents/GitHub/tailscale/cmd/tailscale/cli/debug.go` (`debug capture` subcommand)

## Wire format (byte-exact, all little-endian)

Pcap global header, written once per registered output:

| bytes | value |
| --- | --- |
| u32 | 0xA1B2C3D4 (magic) |
| u16 | 2 (version major) |
| u16 | 4 (version minor) |
| u32 | 0 (thiszone) |
| u32 | 0 (sigfigs) |
| u32 | 65535 (snaplen) |
| u32 | 147 (linktype LINKTYPE_USER0) |

Per-packet record (`writePktHeader` + custom tailscale metadata + payload):

| bytes | value |
| --- | --- |
| u32 | unix seconds |
| u32 | microseconds remainder (`when.unix_micro() - s*1_000_000`) |
| u32 | caplen = len(payload) + extra |
| u32 | len   = same |
| u16 | CapturePath |
| u8  | SNAT addr len (0 if no SNAT), then that many raw addr bytes |
| u8  | DNAT addr len (0 if no DNAT), then that many raw addr bytes |
| ... | raw IP packet payload |

`extra` = 4 + snat_addr_len + dnat_addr_len (the two u8 length prefixes + u16
path + addr bytes). Rustscale has no NAT rewriting in the capture path today, so
`CaptureMeta` is a struct with `original_src: Option<IpAddr>` /
`original_dst: Option<IpAddr>` that callers currently pass as `None` — encoder
must still emit the two zero length bytes.

CapturePath values (u8 in Go, written as u16 LE in the record):
- 0 FromLocal (local system → TUN outbound)
- 1 FromPeer (received from a remote peer, post-decapsulate)
- 2 SynthesizedToLocal (generated in-process, delivered to local netstack)
- 3 SynthesizedToPeer (generated in-process, sent to a peer)
- 254 PathDisco (not wired in this phase)

## Sink semantics (mirror Go `Sink`)

- `Sink::register_output(w) -> unregister-handle`: writes the pcap global
  header immediately, then receives every subsequent record. Multiple outputs
  supported (HandleSet in Go → `HashMap<u64, Output>` + counter).
- A failing write drops (and closes) that output only.
- Flush coalescing: after writing a record, if no flush timer is pending, start
  a 100ms timer that flushes all outputs (matters for the streaming HTTP path).
- `close()` cancels the sink: future `log_packet` calls are no-ops, outputs are
  closed, `wait()` (a `Notify`/`CancellationToken`) fires.
- Capture is **off** unless a sink is installed; the hot path must pay only an
  atomic-load / `Option<Arc<Sink>>` check when disabled. Use
  `arc_swap`-style `RwLock<Option<Arc<Sink>>>` or `ArcSwapOption` (prefer a
  plain `parking_lot`-free `std::sync::RwLock` — match existing crate style).

Implementation shape in Rust: `crates/tsnet/src/capture.rs` (module, not a new
crate). Outputs are `mpsc::Sender<Vec<u8>>`-backed or a small trait
`CaptureOutput: Send { fn write(&mut self, buf: &[u8]) -> io::Result<()>; fn flush(&mut self); }`
— implementor's choice, but the fanout must not block the packet path on a slow
HTTP client (bounded channel + drop-output-on-full is acceptable and should be
documented in a comment).

## Hook points (keep insertions minimal and additive — a perf agent is
concurrently touching magicsock; do NOT modify crates/magicsock)

- TUN mode, `crates/tsnet/src/tun_pump.rs`:
  - outbound: after TUN read / before WG encapsulate → `FromLocal` (0)
  - inbound: after WG decapsulate / before TUN write → `FromPeer` (1)
- Netstack mode, `crates/tsnet/src/netstack_pump.rs`:
  - outbound (`encapsulate_and_send`, plaintext pkt argument) → `SynthesizedToPeer` (3)
  - inbound (post-decapsulate, before `netstack.push_rx`) → `SynthesizedToLocal` (2)

The sink lives on the tsnet running state (alongside proxy_mapper etc.); pumps
grab a clone of the `Arc` slot at spawn time and check per-packet.

## API surface

1. `Server::capture_pcap(&self, pcap_file: &str)` (existing stub at
   `crates/tsnet/src/api.rs:808`): install-or-get the sink, open the file,
   write header, register it. Capture runs until `Server::close` (document
   this). Calling twice with different paths registers a second output.
2. LocalAPI `POST /localapi/v0/debug-capture` in `crates/tsnet/src/localapi.rs`:
   requires read-write peer identity (see existing 403 checks); responds `200`
   then streams raw pcap bytes until the client disconnects (follow the
   `watch-ipn-bus` streaming pattern). On disconnect, unregister the output;
   when the last output unregisters via this path, clear the sink (Go clears
   unconditionally — match Go: clear on handler exit).
3. `crates/localclient`: `debug_capture()` returning a streaming reader,
   modeled on `watch_ipn_bus()` but raw bytes, not line-delimited JSON.
4. CLI `rustscale debug capture [-o <file>]` in `crates/cli`
   (`debug` subcommand already exists): `-o -` or default writes to stdout,
   `-o file.pcap` writes to a file; run until ctrl-c/EOF.

## Acceptance criteria (run these yourself)

- `cargo build --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all`.
- Unit tests in `capture.rs`: byte-exact golden test of global header
  (26 bytes: `d4 c3 b2 a1 02 00 04 00 ...` ending `93 00 00 00`), record
  encoding with no-NAT meta (u16 path + two zero bytes), multi-output fanout,
  erroring-output removal, close semantics.
- An integration-style test in tsnet that runs a netstack-mode packet through
  and asserts the sink observed ≥1 record with a parseable pcap stream.
- Do not commit; do not spawn other agents.
