# Taildrive status and security boundary

RustScale has a bounded Taildrive server layer in `crates/drive`, wired to the
live control/netmap, PeerAPI, and a deliberately small LocalAPI configuration
surface. It was compared with Tailscale's `drive/`, `feature/drive`,
`ipn/ipnlocal/peerapi_drive.go`, `ipn/ipnlocal/drive.go`, and
`ipn/localapi/localapi_drive.go`.

## Implemented

### Configuration and platform boundary

- Upstream-compatible share-name normalization and serde share model.
- Validated, all-or-nothing runtime configuration replacement. New runtimes
  start disabled with no shares. A failed replacement retains the complete old
  snapshot, and each request retains one immutable snapshot.
- Sharing can only be enabled while the signed self-node netmap contains the
  `drive:share` attribute. Revoking that attribute immediately disables the
  runtime, drops every pinned share root, and cancels active requests.
- No shares are inferred from a state directory or host environment, and share
  configuration is not persisted. Shutdown, logout, and profile changes clear
  it. Host files are therefore never exposed by default or carried silently to
  another profile/tailnet.
- Share roots must be canonical absolute directories and cannot name a
  filesystem/volume root. They are opened component-by-component without
  following links; the validated capability handle is stored so later path
  replacement cannot retarget an active snapshot.
- Non-empty `who` and `bookmarkData` fields fail closed because user switching
  and macOS security-scoped bookmark support are not implemented.

### Authorization and revocation

- `/v0/drive` is dispatched by both netstack and TUN PeerAPI servers only after
  connection WhoIs resolves a non-zero node key from the live peer map.
- Access grants come exclusively from the signed packet filter's
  `CapGrant.CapMap["tailscale.com/cap/drive"]` values for the authenticated
  source IP and a same-family local node IP, matching upstream `PeerCaps` flow.
  A peer's `Node.CapMap`, HTTP headers, query parameters, and request paths are
  never treated as Taildrive grants.
- Explicit grant parsing supports `ro`, `rw`, wildcard, and per-share
  precedence with grant count/size limits and fail-closed errors.
  Non-wildcard selectors must already be canonical; authority selectors are
  never lowercased or trimmed into a broader grant.
- Identity, peer state, packet-filter grants, and the request cancellation
  token are derived under one authorization epoch. Every non-keepalive map
  update installs peer/filter changes atomically for Taildrive, cancels all
  requests authorized under the prior map, and starts a fresh epoch. Invalid
  filter updates fail closed rather than retaining stale grants.
- Ungranted shares return 404 inside WebDAV, read-only writes return 403, and a
  peer with no Taildrive capability is rejected before WebDAV dispatch.

### Protocol and resource bounds

- WebDAV level 1 supports `OPTIONS`, `PROPFIND` depth 0/1, `GET`, `HEAD`, atomic
  `PUT`, `MKCOL`, non-recursive `DELETE`, same-share `MOVE`, and same-share file
  `COPY`.
- Strict origin-form, UTF-8, and percent-decoded path handling rejects
  traversal, encoded separators, ambiguous share aliases, non-portable device
  names, symbolic links, and absolute/cross-share destinations.
- PeerAPI enforces strict Content-Length framing, rejects transfer encoding,
  duplicate or malformed lengths, incomplete bodies, and oversized Taildrive
  bodies before allocation. Connection reads/writes and filesystem operations
  have deadlines; map change, task cancellation, and connection-task teardown
  cancel request-scoped work.
- Configurable request/grant/path/body/response/directory limits are enforced.
  Blocking filesystem work uses a fixed worker count and bounded queue.
  FIFOs, devices, sockets, reparse points, and symlink sources are rejected.
- Uploads use same-directory temporary files, `sync_all`, a final cancellation
  check, and rename. Cancellation after sync cannot publish the destination,
  and failed uploads remove their temporary file.

### LocalAPI

The local, peer-credential-authorized API exposes:

- `GET /localapi/v0/drive/status` — enabled state, signed `sharingAllowed`
  state, generation, and configured shares.
- `GET /localapi/v0/drive/config` — current `{ "enabled", "shares" }` runtime
  configuration.
- `PUT /localapi/v0/drive/config` — bounded, all-or-nothing replacement using
  the same object shape. This mutation requires LocalAPI read-write identity
  (root or the daemon UID on Unix); read-only local identities receive 403.

These endpoints intentionally provide no platform mount, remote composition,
or automatic persistence behavior.

## Tested

Hermetic core and wiring tests cover browse/read/write/move/delete,
unauthorized peers, signed grant narrowing from read-write to read-only,
complete capability revocation, forged grant headers, disabled startup,
read-only LocalAPI mutation denial, failed-config atomicity, bounded parsing,
request cancellation, deterministic root replacement, FIFO/socket rejection,
worker saturation, post-sync cancellation, traversal, symlink escape,
oversized requests, and malicious `Destination` values.

## Deferred

Platform filesystem mounts, local composition of remote nodes, Finder/Explorer
integration, GUI/CLI share management, persistent profile-scoped share
configuration, subprocess user switching, macOS bookmarks, WebDAV locking,
recursive collection copy/delete, range responses, metadata caching, and
availability probing remain deferred. The current work is a secure server and
configuration parity layer, not complete Taildrive product parity.
