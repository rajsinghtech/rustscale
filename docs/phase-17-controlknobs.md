# Phase 17: Control Knobs (Feature Flags)

Port Go `control/controlknobs/controlknobs.go` — dynamic feature flags from the control plane.

## Goal

The control plane can send feature flags (called "control knobs") in the netmap response to enable/disable experimental or configurable client-side behavior without a client update. Examples: new protocol versions, debug logging, alternative path selection algorithms, DERP rollout gates. The Rust client must parse and apply these knobs from the netmap.

## CRITICAL: Stay strictly within scope

ONLY create `crates/controlknobs/` or a module in `crates/controlclient/` to ingest and expose control knobs. Add a `knobs: HashMap<String, String>` field to the `NetmapUpdate` if it does not already exist. Do NOT modify: magicsock, netstack, portmapper, derp, netmon, tun, filter, dns, wg, tsnet (except wiring a reference to the knobs down to controlclnt consumers).

## What to build

### 1. `crates/controlknobs/` — new crate (or module in controlclient)

```rust
pub struct ControlKnobs {
    knobs: Arc<RwLock<HashMap<String, String>>>,
}

impl ControlKnobs {
    pub fn new() -> Self;
    
    /// Apply a batch of knob values from the netmap.
    pub fn apply(&self, knobs: HashMap<String, String>);
    
    /// Get a boolean knob by name.
    pub fn get_bool(&self, name: &str, default: bool) -> bool;
    
    /// Get a float64 knob by name.
    pub fn get_float(&self, name: &str, default: f64) -> f64;
    
    /// Get a string knob by name.
    pub fn get_string(&self, name: &str, default: &str) -> String;
    
    /// Check if a knob with this name is present.
    pub fn has(&self, name: &str) -> bool;
    
    /// Register a callback for when a specific knob changes.
    pub fn on_change(&self, name: &str, callback: Box<dyn Fn(Option<&str>) + Send>);
    
    /// Get all current knobs (for testing/inspection).
    pub fn all(&self) -> HashMap<String, String>;
}
```

### 2. Wire into control client

- During `Client::poll_netmap()`, after parsing the netmap response, extract the `ControlKnobs` field (if present) and call `ControlKnobs::apply()`
- The `ControlKnobs` instance is shared via `Arc<RwLock<...>>` so consumers (magicsock, derp, etc.) can query knobs without coupling to controlclient

### 3. Key knobs the Go client supports (implement as no-ops for now — just parse and store)

Most knobs are for future use. The architecture should support them being read by downstream crates, but actually acting on them is out of scope for this phase. Known knob names from Go:

- `debug.magicsock` — enable magicsock debug logging
- `debug.derp` — enable DERP debug logging
- `debug.disco` — enable disco debug logging
- `debug.netmap` — log full netmap on each update
- `debug.watchdog` — enable watchdog logging
- `debug.metrics` — enable periodic metrics logging
- `routeselection.disable_relay` — force-disable relay paths
- `routeselection.disable_direct` — force-disable direct paths
- `routeselection.relay_only` — force all traffic through DERP
- `bbr.enabled` — enable BBR congestion control
- `bbr.bw` — BBR bandwidth estimate
- `derp.max_hops` — maximum DERP relay hops
- `disco.max_peers_per_call` — limit peers per disco call
- `netcheck.freq` — netcheck frequency override
- `shutdown.tailscale.com` — remote shutdown URL

### 4. Wire into tsnet

- `tsnet::Server` holds an `Arc<ControlKnobs>` 
- Passes it to `controlclient::Client` during construction
- Other crates can acquire a reference via `Server.control_knobs()` (behind an `Arc`)

## Go references

- `/Users/rajsingh/Documents/GitHub/tailscale/control/controlknobs/controlknobs.go` — full implementation
- `/Users/rajsingh/Documents/GitHub/tailscale/tailcfg/tailcfg.go` — look for the knobs field in Netmap (search for `ControlKnobs` or `Debug`)
- `/Users/rajsingh/Documents/GitHub/tailscale/control/controlclient/direct.go` — where knobs are extracted from netmap

## Acceptance criteria

- `cargo build --workspace` passes
- `cargo test --workspace` passes
- `cargo clippy` passes
- Control knobs are parsed from netmap updates
- Knobs are queryable by name with typed accessors (bool, float, string)
- On-change callbacks fire when a knob value changes
- All Go knob names are accepted and stored (even if not acted upon)
- Thread-safe: multiple concurrent readers
- Run build/test/clippy at the end and fix all errors

## Implementation order

1. Read Go controlknobs.go
2. Create crates/controlknobs/Cargo.toml
3. Create crates/controlknobs/src/lib.rs
4. Wire into controlclient's netmap update path
5. Wire Arc<ControlKnobs> through tsnet::Server
6. Run cargo build && cargo test && cargo clippy
