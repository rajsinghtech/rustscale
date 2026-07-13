# Phase: IPN audit logging (`ipn/auditlog` port)

Port Tailscale's client-side audit logger: a persistent, retried queue of
auditable client actions delivered to control over the Noise channel.

Go references (read-only, verified 2026-07-13):
- `/Users/rajsingh/Documents/GitHub/tailscale/ipn/auditlog/auditlog.go` (471 loc — Logger, LogStore, backoff)
- `/Users/rajsingh/Documents/GitHub/tailscale/ipn/auditlog/store.go` (platform store path — we skip this; we use the ipn Store trait)
- `/Users/rajsingh/Documents/GitHub/tailscale/control/controlclient/direct.go:1912-1952` (transport)
- `/Users/rajsingh/Documents/GitHub/tailscale/tailcfg/tailcfg.go:3593-3630` (wire types)
- `/Users/rajsingh/Documents/GitHub/tailscale/ipn/auditlog/auditlog_test.go` (behavioral tests worth mirroring)

## Wire types (add to `crates/tailcfg`)

```go
type ClientAuditAction string          // e.g. "DISCONNECT_NODE" (AuditNodeDisconnect)
// POST https://<control>/machine/audit-log  (over Noise, like set-dns)
type AuditLogRequest struct {
    Version   CapabilityVersion `json:",omitzero"`  // client's CurrentCapabilityVersion
    NodeKey   key.NodePublic    `json:",omitzero"`
    Action    ClientAuditAction `json:",omitzero"`
    Details   string            `json:",omitzero"`
    Timestamp time.Time         `json:",omitzero"`
}
```

Response: 200 = success (body ignored); non-200 = error with body text.
Follow the existing tailcfg serde conventions (Go field names, omit-empty
behavior matching `omitzero`, null tolerance like the rest of `crates/tailcfg`).

## New crate: `crates/auditlog`

Mirror the Go package semantics exactly:

- `Transaction` (stored JSON, field names as Go): `EventID` (client-only),
  `Retries` (client-only), `Action`, `Details`, `TimeStamp` — all
  `omitempty`/`omitzero` equivalents.
- `LogStore`: persist `Vec<Transaction>` as JSON under key
  `"auditlog-" + profile_id`, backed by the existing
  `rustscale_ipn::store::Store` trait (`crates/ipn/src/store.rs`:
  `read_state`/`write_state`). Missing key → empty vec.
- `Transport` trait: `async fn send_audit_log(&self, req: &AuditLogRequest) -> Result<(), TransportError>`
  where `TransportError` carries a `retryable: bool` classification
  (Go: `IsRetryableError`; connection/5xx-ish failures retryable, permanent
  rejections not — mirror how controlclient classifies errors elsewhere; when
  in doubt, network errors retryable, HTTP non-200 permanent except 5xx/429).
- `Logger` semantics (port precisely from auditlog.go):
  - `new(opts)` with `retry_limit`, store, then `set_profile_id` (settable once;
    same value twice is OK), `start(transport)` (error if already started;
    restores persisted queue and triggers an async flush if non-empty).
  - `enqueue(action, details)`: EventID = timestamp string + 16 hex random
    chars; append-to-store with dedup-by-EventID (newest first before dedup,
    then sort oldest→newest by timestamp); signal the flush worker
    (non-blocking, coalesced — bounded channel of 1).
  - Flush worker (tokio task): on signal, load pending → send each in order via
    transport. Per txn: ctx-cancelled → stop, keep rest unsent; retryable error
    and `retries+1 < retry_limit` → increment retries, keep unsent; other
    errors → treat as complete (log "failed permanently"). Remove completed
    txns from store; re-persist unsent. On flush error, retry with backoff
    min 500ms, ×2, max 10s (reset on success).
  - `flush_and_stop()`: cancel worker, then one final synchronous flush attempt
    (with a caller-supplied timeout); unsent logs stay persisted.
- Unit tests mirroring auditlog_test.go: enqueue-persists, dedup, retry-limit
  exhaustion completes, restore-on-start flushes, profile-id-change rejected,
  stop persists unsent. Use a mock transport with scriptable failures.

## Transport implementation (`crates/controlclient`)

Add `send_audit_log(&self, req: &AuditLogRequest)` to the control client,
modeled directly on `set_dns` (`crates/controlclient/src/client.rs:438-466`):
Noise POST to `/machine/audit-log`, fill `Version` (current capability
version constant already in the crate), `NodeKey` from persisted node key,
200 = OK. Classify errors retryable/permanent as described above.

## Wiring (`crates/tsnet`)

- `Server` running state owns an `Arc<auditlog::Logger>` created at startup
  with the profile's Store and profile ID (see how ProfileManager and the
  netmap cache get the store in lifecycle.rs), started once the control
  client is up; `flush_and_stop` (short timeout, ~5s) during `close()`.
- Emit the one action Go currently defines: `DISCONNECT_NODE`
  (`AuditNodeDisconnect`) with a `Details` reason string, when the node is
  intentionally disconnected: LocalAPI prefs PATCH setting `WantRunning=false`
  (`crates/tsnet/src/localapi.rs:443` area) and logout. Details: use
  `"cli"`/the provided reason; Go sends a user-entered or generated reason —
  a generated `"disconnect requested via LocalAPI"` is fine.
- Keep the enqueue call sites fail-open: an enqueue error must not block the
  disconnect; log and continue.

## Acceptance criteria (run yourself)

- `cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all`
- New crate registered in workspace `Cargo.toml`; JSON snapshot test asserting
  `AuditLogRequest` serializes with exact Go field names; store roundtrip test
  with the `auditlog-<profile>` key.
- Do NOT modify `crates/magicsock` (another agent owns it). Do not commit; do
  not spawn other agents.
- Update the `IPN audit logging` row in `docs/parity.md` to ✅ with a summary.
