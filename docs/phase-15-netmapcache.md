# Phase 15: Netmap Disk Cache

Port Go `ipn/ipnlocal/netmapcache.go` — persist the most recent netmap to disk so the node can rejoin the tailnet without a full re-authentication on restart.

## Goal

When a node restarts, the control client currently performs a full registration flow (including auth key or interactive login). By writing the last good netmap to a file before shutdown, on restart the node can present the cached netmap to skip the initial register-and-wait-for-map cycle. The control plane will still send an updated netmap if one exists; the cache just eliminates the cold-start delay.

## CRITICAL: Stay strictly within scope

ONLY create the netmap cache logic and wire it into `controlclient` and `tsnet`. Do NOT modify: magicsock, netstack, portmapper, derp, netmon, tun, filter, dns. The cache file format and read/write logic is owned by controlclient; tsnet provides the StateStore integration.

## What to build

### 1. `crates/controlclient/src/netmapcache.rs` — new module

```rust
pub struct NetmapCache {
    store: Box<dyn StateStore>,
    key: String,
}

impl NetmapCache {
    pub fn new(store: Box<dyn StateStore>) -> Self;
    pub fn read(&self) -> Result<Option<NetworkMap>>;
    pub fn write(&self, nm: &NetworkMap) -> Result<()>;
    pub fn clear(&self) -> Result<()>;
}
```

- Serialize/deserialize `NetworkMap` via JSON (matching `tailcfg.NetworkMap`)  
- Key: `"netmap-cache"` in the StateStore
- On write: only persist if the netmap has a node with valid NodeKey (avoid caching partial/error maps)
- On read: validate the NodeKey is non-zero and the map is structurally sound

### 2. `crates/tsnet/src/state.rs` — StateStore trait + file-backed implementation

```rust
pub trait StateStore: Send + Sync {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn write(&self, key: &str, value: &[u8]) -> Result<()>;
}

pub struct FileStateStore {
    dir: PathBuf,
}

impl FileStateStore {
    pub fn new(dir: PathBuf) -> Self;
}
```

- Files named by hex-encoded key in a flat directory  
- Atomic write via tempfile + rename  
- Default dir: `$TSNET_STATE_DIR` or `$HOME/.rustscale/state/`

### 3. Wire into control client

- On successful netmap update from the control plane: call `NetmapCache::write(nm)`
- On control client initialization: call `NetmapCache::read()` and if a valid cached netmap exists, pass it as the initial netmap to skip the register → wait-for-map dance
- On auth failure or explicit logout: call `NetmapCache::clear()`

### 4. Wire into tsnet

- `tsnet::Server` initializes `FileStateStore` from the configured state directory  
- Creates a `NetmapCache` and passes it to `controlclient::Client` during construction  

## Go references

- `/Users/rajsingh/Documents/GitHub/tailscale/ipn/ipnlocal/netmapcache.go` — Go implementation  
- `/Users/rajsingh/Documents/GitHub/tailscale/ipn/store.go` — StateStore interface  
- `/Users/rajsingh/Documents/GitHub/tailscale/ipn/store/storage.go` — file-backed store  
- `/Users/rajsingh/Documents/GitHub/tailscale/control/controlclient/direct.go` lines ~200-260 — where Go reads cached netmap  

## Acceptance criteria

- `cargo build --workspace` passes
- `cargo test --workspace` passes
- `cargo clippy` passes
- Cached netmap is written on each successful netmap update
- On restart with a valid cached netmap, registration is skipped
- On auth failure, cache is cleared
- FileStateStore writes atomically (no partial files on crash)
- Run build/test/clippy at the end and fix all errors

## Implementation order

1. Read Go netmapcache.go and store.go
2. Create `crates/tsnet/src/state.rs` with StateStore trait + FileStateStore
3. Create `crates/controlclient/src/netmapcache.rs`
4. Wire write into netmap update path
5. Wire read into control client init path
6. Wire clear into auth failure path
7. Integrate into tsnet::Server startup
8. Run cargo build && cargo test && cargo clippy
