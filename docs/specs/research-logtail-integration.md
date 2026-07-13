# Logtail Integration into rustscale Daemon

**Goal**: Port Go's `logpolicy` + `logtail` startup wiring so `rustscaled` uploads
logs to `log.tailscale.com` (or `TS_LOG_TARGET`) under collection
`tailnode.log.tailscale.io`, with a config file persisted alongside state,
and the `POST /logtail/flush` C2N handler wired for live flush.

---

## 1. Go Startup Order (tailscaled)

### Sequence in `cmd/tailscaled/tailscaled.go:411` (`run()`)

1. Parse CLI flags, load config file (`conffile.Load(args.confFile)`)
2. Create `netmon.Monitor` (if not Windows service)
3. **Create `logpolicy.Policy`** — lines 446–454:
   ```go
   pol := logpolicy.Options{
       Collection: logtail.CollectionNode,   // "tailnode.log.tailscale.io"
       NetMon:     netMon,
       Health:     sys.HealthTracker.Get(),
       Bus:        sys.Bus.Get(),
   }.New()
   pol.SetVerbosityLevel(args.verbose)
   publicLogID = pol.PublicID   // <-- this is the PublicID
   logPol = pol
   defer func() {
       ctx, cancel := context.WithTimeout(context.Background(), time.Second)
       defer cancel()
       pol.Shutdown(ctx)
   }()
   ```
4. Deferred shutdown flushes logs **after** everything else closes
5. `publicLogID` is passed to `startIPNServer()` → `getLocalBackend()`
6. In `getLocalBackend()` at line 631:
   ```go
   backendLogID: logID,    // stored as b.backendLogID (logid.PublicID)
   ```
7. **SetLogFlusher** later in `startIPNServer()` at line 687:
   ```go
   lb.SetLogFlusher(logPol.Logtail.StartFlush)
   ```
8. When `Hostinfo` is built (line 3054):
   ```go
   hostinfo.BackendLogID = b.backendLogID.String()
   hostinfo.FrontendLogID = opts.FrontendLogID  // empty for daemon (set by GUI)
   ```

### Key observation

The **logtail PrivateID** and the **Hostinfo BackendLogID** derive from the **same**
persisted `PrivateID` — they are one and the same. In Go:
- `logpolicy.NewConfig()` generates (or loads) a `logid.PrivateID` → derives `PublicID`
- `logtail.Config.PrivateID = newc.PrivateID`  ← the private key for log upload auth
- `publicLogID = newc.PublicID` ← the public ID sent to control as `BackendLogID`
- The PublicID string **is** the SHA-256 hex of PrivateID (see `logid` package)

### Go config file format

File: `{LogsDir}/{cmdname}.log.conf` — JSON with fields `Collection`, `PrivateID`, `PublicID`:

```json
{
    "Collection": "tailnode.log.tailscale.io",
    "PrivateID": "0123456789abcdef...",
    "PublicID":  "fedcba9876543210..."
}
```

`PublicID` is derived from `PrivateID.Public()` before save. `Validate()` checks:
`c.Collection == collection && !c.PrivateID.IsZero() && c.PrivateID.Public() == c.PublicID`.

### `NoLogsNoSupport` / logging disabled

Go checks `envknob.NoLogsNoSupport()` and `testenv.InTest()` — if true, uses
a no-op HTTP transport (`noopPretendSuccessTransport`) and does **not** attach
an on-disk filch buffer. The logger still writes to stderr but uploads disappear.

### `TS_LOGS_DIR`

Overrides `LogsDir()` return value. Otherwise platform-specific default
(e.g. `/var/lib/tailscale` on Linux, `%ProgramData%\Tailscale` on Windows).

---

## 2. ID Unification Requirement

**Current rustscale state** (confirmed in `crates/tsnet/src/lifecycle.rs:1244–1250`):
```rust
let backend_log_id = if let Some(dir) = self.config.state_dir.as_ref() {
    rustscale_logid::PrivateID::load_or_create(&dir.join("logid-private"))?
} else {
    rustscale_logid::PrivateID::new()
}
.public()
.to_string();
```

This already persists a `PrivateID` at `{state_dir}/logid-private` and exposes
its `PublicID` hex string as `backend_log_id`. The `apply_runtime_fields`
function in `hostinfo.rs:298–299` copies this into `Hostinfo.BackendLogID`.

**The fix**: This **same** PrivateID must be used as `logtail.Config.private_id`.
The logtail client's upload URL is `{base_url}/c/{collection}/{private_id}` —
the private_id is the hex of the PrivateID bytes.

**Recommendation**: Share the `PrivateID` directly as the logtail `private_id`.
Since `logtail.Config` currently takes `private_id: String`, just pass
`backend_log_id` through? **No** — `backend_log_id` is the **PublicID** hex,
but logtail needs the **PrivateID** hex. The existing code already has the
`PrivateID` object on line 1245 — it calls `.public().to_string()` and discards
the private half. We need to keep both.

**Design**: `RunningState` should store the `PrivateID` alongside `backend_log_id`.
When constructing the `LogTail`, pass `private_id = persisted_private.to_string()`.

### FrontendLogID

In Go, `FrontendLogID` is set only by GUI frontends (Tailscale macOS/iOS app,
Android app, Windows GUI) — their own log instance's `PublicID`. The daemon
leaves it empty. rustscale should mirror this: set `FrontendLogID` only when
a frontend connect to the LocalAPI sets it via `SetFrontendLogID`.

---

## 3. Rust Design: LogPolicy Module

### Where to put it

Create a new module `crates/logpolicy` (new crate `rustscale-logpolicy`) that:

1. **Determines the log directory** (port of `logpolicy.LogsDir`)
2. **Loads or creates the `logpolicy.Config`** JSON file (`{logdir}/rustscaled.log.conf`)
3. **Constructs a `logtail::Config`** and creates `LogTail`
4. **Provides a `StartFlush` closure** for the C2N handler
5. **Handles `TS_NO_LOGS_NO_SUPPORT`** env var (opt out)

### Collection constant

```rust
pub const DEFAULT_COLLECTION: &str = "tailnode.log.tailscale.io";
```

### Opt-in via config/env

Respect:
- `TS_NO_LOGS_NO_SUPPORT` env var → disable log upload
- `TS_LOG_TARGET` env var → override BaseURL
- `TS_LOGS_DIR` env var → override log directory

### Routing daemon log lines into logtail

**Current rustscale logging**: ~100% `eprintln!()` across `crates/tsnet/src/`
and `crates/rustscaled/src/`. No `log::` crate usage in either. No structured
logging framework.

**Plan**: Install a global `log::Log` implementation that:
- Writes to stderr (preserving current behavior)
- Also forwards to the `LogTail` buffer

In the daemon, before `server.up()`:
```rust
use log::LevelFilter;
let logger: Box<dyn log::Log> = LogtailLogger::new(logtail_handle);
log::set_boxed_logger(logger).unwrap();
log::set_max_level(LevelFilter::Info);
```

The `LogtailLogger` implements `log::Log`, converts `Record` → `LogEntry`,
calls `logtail.write_entry()`. All existing `eprintln!()` call sites would need
to migrate to `log::info!()` / `log::warn!()`. This is a separate (large) effort.

**Short-term alternative**: Provide a `logtail::log::LogtailWriter` that
implements `std::io::Write` and install it as a replacement for `eprintln`.
No — Rust `eprintln!` does not go through a replaceable `io::Write` like Go's
`log.SetOutput()`. Each `eprintln!()` calls `stderr().write_all()` directly.

**Recommended approach**: The daemon should install a `log` crate logger that
also writes to stderr (for backwards compat). The background task in the end
could update all `eprintln!` call sites to `log::info!`/`log::warn!`/`log::error!`.
The `LogTail` `Write` method would accept these.

### `LogTail` gap analysis

Missing from `crates/logtail/src/lib.rs`:
- **No `io::Write` impl** on `LogTail` — Go's `*Logger` implements `io.Writer`
  so it can be used as `log.SetOutput(lw)`. Add `impl io::Write for LogTail`.
- **No `log::Log` adapter** — would be nice to bridge `log` crate → `LogTail`
- **Config should accept a `logid::PrivateID`** directly, not a `String`.
- **No `FlushDelayFn`** (Go default 2s) — currently flushes immediately on each write.
  Should batch ~2s of logs before upload.
- **No `Disabled` kill switch** — process-wide `Disable()` similar to
  `logtailDisabled` in Go.
- **No `SetEnabled`** — per-logger enable/disable without destroying it.
- **No `Stderr` echo level gating** — Go's `Logger.Write` conditionally echoes
  to stderr based on `stderrLevel`. Our `LogTail::write` always writes to the
  buffer; there's no stderr mirror.

---

## 4. Concrete Files to Modify

### New file: `crates/logpolicy/Cargo.toml`

New crate `rustscale-logpolicy` with deps: `rustscale-logid`, `rustscale-logtail`,
`serde`, `serde_json`, `thiserror`, `log`.

### New file: `crates/logpolicy/src/lib.rs`

```rust
pub struct Config {
    pub collection: String,
    pub private_id: PrivateID,
    pub public_id: PublicID,
}
pub struct Policy {
    pub logtail: LogTail,
    pub public_id: PublicID,
}
pub fn logs_dir() -> PathBuf { /* port LogsDir */ }
pub fn new(collection: &str, dir: Option<PathBuf>) -> Result<Policy>;
pub fn start_flush(policy: &Policy);
```

### Modify: `crates/logtail/src/lib.rs`

- `struct Config`: change `private_id: String` → `private_id: logid::PrivateID`
- Add `impl io::Write for LogTail` that calls `write_entry`
- Add `pub fn upload_url(&self) -> String` using `private_id.0` hex
- Add `pub fn disabled() -> bool` / `pub fn set_enabled(&self, enabled: bool)`
- Add `flush_delay` field to `Config` (default 2s)
- Add `stderr` field to `Config` (default `io::stderr()`), with level gating

### Modify: `crates/tsnet/src/lifecycle.rs`

- In `up_inner()` around line 1244, keep the `PrivateID` object instead of
  discarding to `.public().to_string()`
- Store `private_id: PrivateID` on `RunningState` alongside `backend_log_id: String`
- After building the server, create a `LogPolicy` using `private_id`
- Call `log::set_boxed_logger()` with a log-to-logtail adapter
- Pass `policy.logtail` to C2N backend for flush

### Modify: `crates/tsnet/src/c2n.rs`

- `LogtailFlushHandler` (line 301–307): currently returns 204 no-op.
  Change to hold an `Arc<dyn Fn() + Send + Sync>` that calls `logtail.flush()`
- Storage: add a `logtail_flush: Option<Arc<dyn Fn() + Send + Sync>>` to
  `TsnetC2nBackend` and `C2nBackendData`
- `try_flush_logs(&self): bool` → calls the flush closure if present

### Modify: `crates/rustscaled/src/daemon.rs`

- In `run()` / `run_with_auth_key()` / `run_interactive()`:
  - Before `server.up()`, create `LogPolicy` with the state directory
  - Install `logtail` logger as global `log` handler
  - Register the flush function with the C2N backend
  - Shutdown the policy in deferred cleanup (after `server.close()`)

### Modify: `crates/rustscaled/src/main.rs`

- Accept `--no-logs` flag (or `TS_NO_LOGS_NO_SUPPORT` env) to disable logtail
- Accept `TS_LOG_TARGET` env for custom log server URL

### Add: `crates/logtail/src/log.rs` (optional)

```rust
pub struct LogtailLogger {
    lt: Arc<LogTail>,
    // stderr fallback
}

impl log::Log for LogtailLogger {
    fn enabled(&self, _: &log::Metadata) -> bool { true }
    fn log(&self, record: &log::Record) {
        // write to stderr AND lt.write_entry()
    }
    fn flush(&self) { self.lt.flush(); }
}
```

---

## 5. C2N `POST /logtail/flush` in Go

Go handler at `ipn/ipnlocal/c2n.go:140`:
```go
func handleC2NLogtailFlush(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
    if b.TryFlushLogs() {
        w.WriteHeader(http.StatusNoContent)
    } else {
        http.Error(w, "no log flusher wired up", http.StatusInternalServerError)
    }
}
```

`TryFlushLogs` (line 6199):
```go
func (b *LocalBackend) TryFlushLogs() bool {
    if !buildfeatures.HasLogTail || b.logFlushFunc == nil {
        return false
    }
    b.logFlushFunc()
    return true
}
```

The `SetLogFlusher` is called at tailscaled startup:
```go
lb.SetLogFlusher(logPol.Logtail.StartFlush)
```

Where `logPol.Logtail` is a `*logtail.Logger`, and `StartFlush()` calls
`tryDrainWake()` to unblock the background upload goroutine.

**Rust implementation**: `logtail::LogTail::flush()` sets `flush_notify.notify_waiters()`
— already does this. The C2N handler just needs a reference to the `LogTail`.
The current stub `try_flush_logs` returns `true` without doing anything;
we need to actually call `self.logtail.flush()`.

---

## 6. Acceptance Criteria

- `cargo build --workspace` succeeds
- `cargo test` passes all existing tests
- `cargo clippy` passes
- A `LogTail` is created at daemon startup with the same PrivateID as Hostinfo.BackendLogID
- `POST /logtail/flush` via c2n calls `LogTail::flush()` and returns 204
- `TS_NO_LOGS_NO_SUPPORT=1` disables uploads (no-op transport)
- `TS_LOG_TARGET` overrides the upload URL
- `TS_LOGS_DIR` overrides the log config directory
- Config persists at `{logdir}/rustscaled.log.conf` as JSON
- `log::info!` / `log::warn!` calls in the daemon route into the logtail buffer
