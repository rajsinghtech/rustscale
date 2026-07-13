# Audit Logging — Pre-digest for Porting

## 1. Wire Type: `tailcfg.AuditLogRequest`

**Go source:** `tailcfg/tailcfg.go:3593–3621`

```go
type ClientAuditAction string

const (
    AuditNodeDisconnect = ClientAuditAction("DISCONNECT_NODE")
)

type AuditLogRequest struct {
    Version   CapabilityVersion `json:",omitzero"`    // i32
    NodeKey   key.NodePublic    `json:",omitzero"`    // [32]byte
    Action    ClientAuditAction `json:",omitzero"`    // string
    Details   string            `json:",omitzero"`
    Timestamp time.Time         `json:",omitzero"`    // RFC3339
}
```

Wire endpoint: `POST /machine/audit-log`.

**Rust target:** Add to `crates/tailcfg/src/` (new file `audit.rs` or inline `lib.rs`):

```rust
pub type ClientAuditAction = String;

pub const AUDIT_NODE_DISCONNECT: &str = "DISCONNECT_NODE";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditLogRequest {
    pub Version: CapabilityVersion,
    pub NodeKey: NodeKey,
    pub Action: ClientAuditAction,
    pub Details: String,
    pub Timestamp: chrono::DateTime<chrono::Utc>,
}
```

Note: Go's `time.Time` serializes to RFC3339. The rustscale `tailcfg` crate doesn't depend on chrono today; either add `chrono` or use a manual `String` + serde helper for RFC3339.

## 2. Logger Lifecycle

**Go source:** `ipn/auditlog/auditlog.go:91–471`

### Internal transaction type (client-side only, not sent to control)

```go
type transaction struct {
    EventID   string                  `json:",omitempty"`  // unique dedup key
    Retries   int                     `json:",omitempty"`  // send attempt counter
    Action    tailcfg.ClientAuditAction `json:",omitempty"`
    Details   string                  `json:",omitempty"`
    TimeStamp time.Time               `json:",omitzero"`
}
```

### Logger struct

```go
type Logger struct {
    logf        logger.Logf
    retryLimit  int                // max attempts per txn
    flusher     chan struct{}      // async flush signal (buffered 1)
    done        chan struct{}      // closed when flushWorker exits
    ctx         context.Context
    ctxCancel   context.CancelFunc
    backoffOpts                    // min, max, multiplier

    mu        sync.Mutex
    store     LogStore             // persistent storage
    profileID ipn.ProfileID        // key for store
    transport Transport            // nil before Start
}
```

### Constructor

```go
func NewLogger(opts Opts) *Logger {
    // opts: RetryLimit, Store (LogStore), Logf
    // creates context, buffered flusher chan (1), done chan
    // sets defaultBackoffOpts
}
```

### `Start(Transport)`

1. Sets `al.transport = t`
2. Reads persisted count via `al.storedCountLocked()`
3. Spawns `go al.flushWorker()`
4. If there are pending logs, triggers `al.flushAsync()`

### `Enqueue(action, details string)`

1. Creates `transaction{Action, Details, TimeStamp: now()}` with random `EventID` (`fmt.Sprint(timeStamp, rands.HexString(16))`)
2. Calls `al.enqueue(txn)` which:
   - Locks `al.mu`
   - Calls `al.appendToStoreLocked([txn])` (persists immediately)
   - If `al.transport != nil`, calls `al.flushAsync()`
3. Returns `ErrAuditLogStorageFailure` if store save fails

### `FlushAndStop(ctx)`

1. `al.stop()` — cancels context, waits for `al.done` close
2. `al.flush(ctx)` — sends all pending synchronously

### flushWorker goroutine

```
loop:
  select {
  case <-ctx.Done(): return
  case <-flusher:
    err := flush(ctx)
    if err == context.Canceled: return
    if err != nil:
      retryDelay = max(min, min(retryDelay*multiplier, max))
      retry.Reset(retryDelay)
    else:
      retryDelay = 0; retry.Stop()
  case <-retry.C:
    flushAsync()  // re-trigger
  }
```

### Retry/backoff constants

From `auditlog.go:79–89`:
```go
var defaultBackoffOpts = backoffOpts{
    min:        time.Millisecond * 500,   // 500ms
    max:        10 * time.Second,          // 10s
    multiplier: 2,
}
```

Retry limit configured in `extension.go:95`:
```go
RetryLimit: 32,
```

### Dedup by EventID

From `auditlog.go:383–400`:
```go
func deduplicateAndSort(txns []*transaction) []*transaction {
    // First occurrence wins; sorts by timestamp oldest-first
}
```

Used in `appendToStoreLocked`: new txns are prepended, then deduped (first wins ≡ newest retained), then oldest-first sorted.

### Persistence via LogStore

**Go source:** `ipn/auditlog/store.go:44–61`

```go
type LogStore interface {
    save(key ipn.ProfileID, txns []*transaction) error
    load(key ipn.ProfileID) ([]*transaction, error)
}
```

Concrete implementation `logStateStore` wrapping `ipn.StateStore`:

```go
func (s *logStateStore) generateKey(key ipn.ProfileID) string {
    return "auditlog-" + string(key)
}
// save → json.Marshal(txns) → store.WriteState(StateKey("auditlog-"+key), data)
// load → store.ReadState(StateKey("auditlog-"+key)) → json.Unmarshal
```

On platforms without a default store path (macOS), `SetStoreFilePath(path)` must be called before first use. Fallback is `mem:auditlog`.

## 3. Every Go Call Site Emitting an Audit Entry

**Only one action is currently defined and one call site exists.**

### Action type

```go
// tailcfg/tailcfg.go:3593-3602
type ClientAuditAction string
const AuditNodeDisconnect = ClientAuditAction("DISCONNECT_NODE")
```

### Call site: Disconnect check

**Go source:** `ipn/ipnlocal/local.go:5161–5165`

```go
if mp.WantRunningSet && !mp.WantRunning && b.pm.CurrentPrefs().WantRunning() {
    if err := actor.CheckProfileAccess(b.pm.CurrentProfile(), ipnauth.Disconnect, b.extHost.AuditLogger()); err != nil {
        errs = append(errs, err)
    }
}
```

**Dispatched through** `ipn/ipnauth/access.go:16`:
```go
Disconnect = ProfileAccess(1 << iota)
```

**Policy check with audit** (`ipn/ipnauth/policy.go:54–79`):

```go
func CheckDisconnectPolicy(actor Actor, profile ipn.LoginProfileView, reason string, auditFn AuditLogFunc) error {
    if !buildfeatures.HasSystemPolicy { return nil }
    if alwaysOn, _ := policyclient.Get().GetBoolean(pkey.AlwaysOn, false); !alwaysOn { return nil }
    if allowWithReason, _ := policyclient.Get().GetBoolean(pkey.AlwaysOnOverrideWithReason, false); !allowWithReason {
        return errors.New("disconnect not allowed: always-on mode is enabled")
    }
    if reason == "" { return errors.New("disconnect not allowed: reason required") }
    if auditFn != nil {
        var details string
        if username, _ := actor.Username(); username != "" {
            details = fmt.Sprintf("%q is being disconnected by %q: %v", profile.Name(), username, reason)
        } else {
            details = fmt.Sprintf("%q is being disconnected: %v", profile.Name(), reason)
        }
        if err := auditFn(tailcfg.AuditNodeDisconnect, details); err != nil { return err }
    }
    return nil
}
```

**ExtensionHost aggregation** (`ipn/ipnlocal/extension_host.go:515–538`):

```go
func (h *ExtensionHost) AuditLogger() ipnauth.AuditLogFunc {
    if !h.active() { return noop }
    loggers := make([]ipnauth.AuditLogFunc, 0, len(h.hooks.AuditLoggers))
    for _, provider := range h.hooks.AuditLoggers {
        loggers = append(loggers, provider())
    }
    return func(action tailcfg.ClientAuditAction, details string) error {
        h.logf("auditlog: %v: %v", action, details)
        for _, logger := range loggers {
            if err := logger(action, details); err != nil { errs = append(errs, err) }
        }
        return errors.Join(errs...)
    }
}
```

**AuditLogFunc type** (`ipn/ipnauth/actor.go:17`):
```go
type AuditLogFunc func(action tailcfg.ClientAuditAction, details string) error
```

**Extension wiring** (`ipn/auditlog/extension.go:65–184`):
- Registers `controlClientChanged` hook → creates `Logger` per profile
- Registers `AuditLoggers` hook → `getCurrentLogger()` returns `logger.Enqueue` or `noCurrentLogger` (which returns `errNoLogger`)

Summary: as of this writing, the ONLY auditable action is `DISCONNECT_NODE`. Future actions would add more `ClientAuditAction` consts and call `AuditLogger()(action, details)` from other prefs-change paths.

## 4. Transport: Control Client Delivery

### Go implementation

**Go source:** `control/controlclient/direct.go:1912–1951`

```go
func (c *Auto) SendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) error {
    return c.direct.sendAuditLog(ctx, auditLog)
}

func (c *Direct) sendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) (err error) {
    nc, err := c.getNoiseClient()         // get or create Noise HTTP/2 client
    if err != nil { return fmt.Errorf("%w: %w", errNoNoiseClient, err) }

    nodeKey, ok := c.GetPersist().PublicNodeKeyOK()
    if !ok { return errNoNodeKey }

    req := &tailcfg.AuditLogRequest{
        Version: tailcfg.CurrentCapabilityVersion,
        NodeKey: nodeKey,
        Action:  auditLog.Action,
        Details: auditLog.Details,
    }

    res, err := nc.Post(ctx, "/machine/audit-log", nodeKey, req)
    if err != nil { return fmt.Errorf("%w: %w", errHTTPPostFailure, err) }
    defer res.Body.Close()
    if res.StatusCode != 200 {
        all, _ := io.ReadAll(res.Body)
        return errBadHTTPResponse(res.StatusCode, string(all))
    }
    return nil
}
```

**Key observation:** The Go impl reuses an existing Noise HTTP/2 client (from `c.getNoiseClient()`). Unlike the standalone Rust `ControlClient::set_dns` which dials fresh each time, this uses the long-lived control connection. For rustscale, the auditlog `Transport` impl should hold a reference to the `ControlClient` or a way to dial + post.

### Retriable error classification

**Go source:** `control/controlclient/errors.go:34–51`

```go
var (
    errNoNodeKey       = &apiResponseError{errors.New("no node key"), true}
    errNoNoiseClient   = &apiResponseError{errors.New("no noise client"), true}
    errHTTPPostFailure = &apiResponseError{errors.New("http failure"), true}
)

func errBadHTTPResponse(code int, msg string) error {
    retryable := false
    switch code {
    case 429, 500, 502, 503, 504: retryable = true
    }
    return &apiResponseError{fmt.Errorf("http error %d: %s", code, msg), retryable}
}
```

The Go auditlog checks retryability via `IsRetryableError(err)`:
```go
func IsRetryableError(err error) bool {
    retryable, ok := errors.AsType[interface{ error; Retryable() bool }](err)
    return ok && retryable.Retryable()
}
```

### Transport interface (Go)

```go
type Transport interface {
    SendAuditLog(context.Context, tailcfg.AuditLogRequest) error
}
```

`controlclient.Auto` implements this:
```go
var _ auditlog.Transport = (*controlclient.Auto)(nil)
```

### Response shape

`/machine/audit-log` returns HTTP 200 on success. Non-200 is an error. No response body is expected on success.

## 5. Rustscale Existing Wiring Points

### Store trait — persistence layer

**File:** `crates/ipn/src/store.rs:25–32`

```rust
pub trait Store: Send + Sync {
    fn read_state(&self, key: &str) -> io::Result<Option<Vec<u8>>>;
    fn write_state(&self, key: &str, data: &[u8]) -> io::Result<()>;
}
```

Implementations: `MemStore` (HashMap), `FileStore` (file per key). The auditlog `LogStore` impl should wrap this, using key `"auditlog-" + profileID`.

### ProfileID type

**File:** `crates/ipn/src/profiles.rs:16`
```rust
pub type ProfileID = String;
```

Already the same as Go's `ipn.ProfileID`.

### ControlClient ad-hoc POST pattern (set_dns)

**File:** `crates/controlclient/src/client.rs:445–492`

```rust
pub async fn set_dns(&self, req: &SetDNSRequest) -> Result<SetDNSResponse, RegisterError> {
    let noise_stream = dial_control(
        &self.host, &self.machine_key, &self.control_key,
        self.version, self.extra_root_certs.as_deref(),
    ).await?;

    let (conn, stream) = noise_stream.into_parts();
    let noise_io = NoiseIo::new(conn, stream);
    let (mut h2_send, h2_conn) = establish_h2(noise_io).await?;
    tokio::spawn(async move { let _ = h2_conn.await; });

    let body = serde_json::to_vec(req)?;
    let request = http::Request::builder()
        .method("POST").uri("/machine/set-dns")
        .header("content-type", "application/json").body(()).unwrap();

    let (resp_future, mut send_stream) = h2_send.send_request(request, false)?;
    send_stream.send_data(bytes::Bytes::from(body), true)?;

    let resp = resp_future.await?;
    // check status, read body
}
```

The auditlog Transport will follow this exact pattern, with URI `/machine/audit-log`.

### tsnet lifecycle — where audit logging wires in

**File:** `crates/tsnet/src/lifecycle.rs` (Server::up method)

The `Server::up()` method:
- Calls `self.bootstrap().await` → returns `BootstrapOutput`
- Spawns tasks: link_monitor, netstack, periodic_endpoint_updates, map-stream update

The auditlogger hook should be created in `Server::up()` after the controlclient is established, similar to how the map-stream update task is spawned.

The `api.rs` / `lifecycle.rs` files are where:
- Prefs changes happen (exit node, want_running toggle)
- Profile switches happen
- These are the natural Rust equivalents of Go's `ipn/ipnlocal/local.go` prefs-change paths

## 6. Concrete Rust Design: `crates/auditlog`

### New crate structure

```
crates/auditlog/
  Cargo.toml
  src/
    lib.rs          — re-exports
    logger.rs       — Logger (tokio task, backoff, enqueue)
    store.rs        — LogStore trait + StateLogStore impl over ipn::store::Store
    transport.rs    — Transport trait + ControlClientTransport impl
    transaction.rs  — Transaction (EventID, Retries, Action, Details, Timestamp)
```

### Dependencies

```toml
[dependencies]
rustscale-tailcfg = { path = "../tailcfg" }
rustscale-key = { path = "../key" }
rustscale-ipn = { path = "../ipn" }
rustscale-controlclient = { path = "../controlclient" }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
tokio = { workspace = true, features = ["time", "sync"] }
rand = { workspace = true }
chrono = { workspace = true }  # or home-grown RFC3339 serde
thiserror = { workspace = true }
tracing = { workspace = true }
```

### Transaction

```rust
//! Client-side only, never sent to control. Used for dedup + retry tracking.

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Transaction {
    EventID: String,
    Retries: i32,
    Action: String,
    Details: String,
    TimeStamp: DateTime<Utc>,
}
```

### LogStore trait + StateLogStore impl

```rust
pub trait LogStore: Send + Sync {
    fn save(&self, profile_id: &str, txns: &[Transaction]) -> io::Result<()>;
    fn load(&self, profile_id: &str) -> io::Result<Vec<Transaction>>;
}

pub struct StateLogStore {
    store: Arc<dyn Store>,
}

impl StateLogStore {
    fn key(profile_id: &str) -> String {
        format!("auditlog-{profile_id}")
    }
}

impl LogStore for StateLogStore {
    fn save(&self, profile_id: &str, txns: &[Transaction]) -> io::Result<()> {
        let data = serde_json::to_vec(txns).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.store.write_state(&Self::key(profile_id), &data)
    }

    fn load(&self, profile_id: &str) -> io::Result<Vec<Transaction>> {
        // Returns Ok(vec![]) for missing key (not an error)
        match self.store.read_state(&Self::key(profile_id))? {
            None => Ok(vec![]),
            Some(data) if data.is_empty() => Ok(vec![]),
            Some(data) => serde_json::from_slice(&data)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}
```

### Transport trait

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send_audit_log(&self, req: AuditLogRequest) -> Result<(), TransportError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transient: {0}")]
    Retryable(String),
    #[error("permanent: {0}")]
    Permanent(String),
}
```

### ControlClient transport implementation

Follows the exact pattern from `ControlClient::set_dns` (crates/controlclient/src/client.rs:445–492).

```rust
pub struct ClientTransport {
    host: String,
    machine_key: MachinePrivate,
    control_key: MachinePublic,
    version: i32,
    extra_root_certs: Option<Vec<u8>>,
}

#[async_trait]
impl Transport for ClientTransport {
    async fn send_audit_log(&self, req: AuditLogRequest) -> Result<(), TransportError> {
        // 1. dial_control → noise stream
        // 2. establish_h2
        // 3. POST /machine/audit-log with JSON body
        // 4. Check status: 200 = ok
        //    429/5xx → TransportError::Retryable
        //    Other → TransportError::Permanent
        // 5. Dial/noise/h2 errors → TransportError::Retryable
    }
}
```

### Logger

```rust
pub struct Logger {
    logf: Box<dyn Fn(&str) + Send + Sync>,
    retry_limit: u32,
    flush_tx: mpsc::Sender<()>,         // unbounded channel for async flush signals
    cancel: tokio::sync::watch::Sender<bool>,  // stop signal
    join: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,

    // Shared state behind Arc<Mutex<>>
    inner: Arc<Mutex<LoggerInner>>,
}

struct LoggerInner {
    store: Box<dyn LogStore>,
    profile_id: Option<String>,
    transport: Option<Box<dyn Transport>>,
    unsent: Vec<Transaction>,     // in-memory cache of persisted
}
```

Key methods:
- `Logger::new(store, logf) -> Self` (retry_limit default 32)
- `Logger::start(&self, transport)` — spawns background task
- `Logger::set_profile_id(&self, id: &str)`
- `Logger::enqueue(&self, action: &str, details: &str) -> Result<()>` — persists, signals flush
- `Logger::flush_and_stop(&self) -> Result<()>` — stops, drains
- `Logger::flush(&self) -> Result<()>` — send loop, retry/permanent logic

Background task:
```
loop {
    select {
    case <-cancel: break
    case <-flush_rx:
        flush()
        if err:
            retry_delay = backoff(retry_delay)
            tokio::time::sleep(retry_delay)
            self.flush_async()  // re-trigger
        else:
            retry_delay = 0
    }
}
```

Backoff: 500ms → 1s → 2s → 4s → 8s → 10s (capped).

Per-txn retry in `send_to_transport`:
- Sends each txn individually
- If permanent error or retry_limit exceeded → mark complete (drop)
- If retryable + under limit → increment Retries, keep in unsent
- If context cancelled → batch-return remaining as unsent

### Wiring in tsnet

In `crates/tsnet/src/lifecycle.rs` (`Server::up()`):

```rust
// After bootstrap, after controlclient is available:
if cfg!(feature = "auditlog") {
    let store = Arc::new(StateLogStore::new(state_store.clone()));
    let logger = Logger::new(store, ...);
    let transport = ClientTransport {
        host: control_url.clone(),
        machine_key: machine_key.clone(),
        control_key: server_pub_key,
        version: CURRENT_CAP_VERSION,
        extra_root_certs: extra_root_certs.clone(),
    };
    logger.set_profile_id(&profile_id);
    logger.start(Box::new(transport));
    // Store Arc<Logger> on ServerInner so prefs-change paths can call enqueue
    // Before disconnect: logger.enqueue(AUDIT_NODE_DISCONNECT, details)
}
```

### `tailcfg` additions

See §1 above. New file `crates/tailcfg/src/audit.rs`:

```rust
pub type ClientAuditAction = String;
pub const AUDIT_NODE_DISCONNECT: &str = "DISCONNECT_NODE";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditLogRequest {
    #[serde(default, skip_serializing_if = "is_zero_version")]
    pub Version: CapabilityVersion,
    #[serde(default, skip_serializing_if = "rustscale_key::is_zero_node_key")]
    pub NodeKey: NodeKey,
    pub Action: ClientAuditAction,
    pub Details: String,
    pub Timestamp: String,  // RFC3339 — or use chrono
}
```

Add to `lib.rs`:
```rust
mod audit;
pub use audit::{AuditLogRequest, ClientAuditAction, AUDIT_NODE_DISCONNECT};
```

### Key differences from Go

| Aspect | Go | Rust |
|--------|----|------|
| Transport reuse | Reuses existing Noise HTTP/2 client (`c.getNoiseClient()`) | Dials fresh per call (like `set_dns`) |
| Goroutine | `go flushWorker()` | `tokio::spawn` |
| Error classification | `apiResponseError{retryable bool}` with `errors.AsType` | `TransportError::Retryable` / `Permanent` enum |
| ProfileID type | `ipn.ProfileID` (string alias) | `ProfileID = String` |
| StateStore | `ipn.StateStore` interface (`ReadState`/`WriteState`) | `ipn::store::Store` trait |
| Extension framework | `ipnext.RegisterExtension` + hooks | Direct wiring in tsnet lifecycle (no extension framework yet) |
| Feature detection | `buildfeatures.HasSystemPolicy` | Cargo feature flag `auditlog` |
| Backoff | `time.NewTimer` + `retry.Reset` | `tokio::time::sleep` in loop |
| Dedup | `set.Set[string]` on EventID | `std::collections::HashSet<String>` |
