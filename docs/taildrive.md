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
  the WireGuard key that decrypted the TCP SYN is preserved through the
  userspace stack/TUN flow table and exactly matches the live owner of the
  source address. Source IP, WhoIs output, and client headers alone cannot
  establish peer identity.
- Peer updates reconcile by stable `Node.ID`. Key/address rotation atomically
  replaces address ownership, WireGuard tunnels, magicsock direct/DERP/relay
  state, routes, filter grants, and Taildrive authorization. Duplicate IDs,
  keys, invalid addresses, and duplicate address ownership fail closed. Old
  keys lose their tunnel and send paths and cannot authorize after rotation.
- Access grants come exclusively from the signed packet filter's
  `CapGrant.CapMap["tailscale.com/cap/drive"]` values for the authenticated
  source IP and a same-family local node IP, matching upstream `PeerCaps` flow.
  A peer's `Node.CapMap`, HTTP headers, query parameters, and request paths are
  never treated as Taildrive grants.
- Explicit grant parsing supports `ro`, `rw`, wildcard, and per-share
  precedence with grant count/size limits and fail-closed errors.
  Non-wildcard selectors must already be canonical; authority selectors are
  never lowercased or trimmed into a broader grant.
- Identity, peer state, packet-filter grants, and a request commit permit are
  derived under one authorization epoch. Every non-keepalive map or runtime
  config update exclusively revokes the old epoch, cancels staging work, and
  drains any already-linearized publication before installing/releasing the
  new epoch. PUT, streaming PUT, MKCOL, DELETE, MOVE, and COPY compare the
  epoch while holding the same short commit barrier across their irreversible
  mkdir/remove/rename publication. After revocation returns, old authority
  cannot commit a filesystem change. Invalid filter updates fail closed rather
  than retaining stale grants.
- Ungranted shares return 404 inside WebDAV, read-only writes return 403, and a
  peer with no Taildrive capability is rejected before WebDAV dispatch.

### Protocol and resource bounds

- WebDAV level 1 supports `OPTIONS`, `PROPFIND` depth 0/1, `GET`, `HEAD`, atomic
  `PUT`, `MKCOL`, non-recursive `DELETE`, same-share `MOVE`, and same-share file
  `COPY`.
- Strict origin-form, UTF-8, and percent-decoded path handling rejects
  traversal, encoded separators, ambiguous share aliases, non-portable device
  names, symbolic links, and absolute/cross-share destinations.
- PeerAPI reads only the HTTP head until Taildrive method, path, destination,
  live key/address ownership, and signed grant checks pass. It enforces strict
  Content-Length framing, rejects transfer encoding, duplicate or malformed
  lengths, incomplete bodies, and oversized Taildrive bodies before upload.
  Global connection and declared-body semaphores bound aggregate PeerAPI work.
  Connection reads/writes and filesystem operations have deadlines; map
  change, task cancellation, and connection-task teardown cancel
  request-scoped work.
- Configurable request/grant/path/body/response/directory limits are enforced.
  Blocking filesystem work uses a fixed worker count and bounded queue.
  FIFOs, devices, sockets, reparse points, and symlink sources are rejected.
- PUT bodies stream in 64 KiB chunks through a two-slot channel to the bounded
  filesystem pool; a full-body clone is never made. Uploads use same-directory
  temporary files, `sync_all`, a final cancellation check, and rename. PUT,
  DELETE, MOVE, and COPY accept only regular files/directories as each method
  permits. They re-stat no-follow under the publication barrier immediately
  before replace, unlink, or rename, so a raced-in FIFO, socket, device, or
  symlink remains untouched.
  Configuration root opening, upload/copy I/O, and sync happen outside the
  commit barrier; only the final publication is guarded. Cancellation after
  sync cannot publish the destination, and failed or truncated uploads remove
  their temporary file.

### LocalAPI

The local, peer-credential-authorized API exposes:

- `GET /localapi/v0/drive/status` — enabled state, signed `sharingAllowed`
  state, generation, and configured shares.
- `GET /localapi/v0/drive/config` — current `{ "enabled", "shares" }` runtime
  configuration and a strong opaque `ETag`. It hashes the generation and exact
  config with a fresh cryptographic per-runtime nonce, preventing restart ABA
  without including persisted secrets or key material.
- `PUT /localapi/v0/drive/config` — bounded, all-or-nothing replacement using
  the same object shape and a mandatory `If-Match` from the preceding GET.
  A concurrent mutation returns 412 without changing the newer snapshot.

The status/config reads require ordinary LocalAPI read-write identity. Config
mutation is stricter: only root or the daemon UID may change roots on Unix;
`OperatorUser` is denied until user switching or per-caller filesystem
capabilities exist. Bodies and responses are limited to 1 MiB. These endpoints
intentionally provide no platform mount, remote composition, security-scoped
bookmark, or automatic persistence behavior.

All socket and authenticated loopback LocalAPI routes now use the same phased
reader: a 64 KiB/deadline-bounded header is read without consuming body bytes;
peer identity, route permission, stale-listener checks, and global/per-identity
request admission happen before body reads. Content-Length is unique and
strict, transfer encoding is rejected, route-specific/global/identity byte
limits apply, and body reads have an overall minimum-rate deadline. Early EOF
or disconnect cancels the request before dispatch. This protects zero-body and
non-Drive endpoints as well as Drive configuration.

### CLI

The first production CLI slice intentionally follows the upstream local-share
names where they apply:

- `rustscale drive status [--json]` reports runtime/capability state,
  generation, and configured shares.
- `rustscale drive list [--json]` prints upstream-style `name`, `path`, and
  `as` columns, or the share array as JSON.
- `rustscale drive share <name> <path>` adds a share or replaces the path for
  an existing normalized name through one ETag-guarded complete replacement.
- `rustscale drive unshare <name>` removes one share through the same CAS. The
  last removal returns the runtime to disabled.

CLI and LocalAPI operations have bounded response sizes and a ten-second
request deadline; Ctrl-C drops the in-flight request. Cancellation or a
transport/response failure during mutation reports that commit may be
ambiguous and directs the operator to re-read the list. Share names use
upstream lowercasing/character rules. Paths are made absolute and then opened
component-by-component without following links before LocalAPI is contacted;
the daemon repeats the authoritative capability open before publication.
Remote mounts/composition, rename, share-as, and macOS bookmark commands fail
explicitly rather than claiming support.

## Tested

Hermetic core, LocalAPI, localclient, and CLI tests cover
compare-and-swap concurrent mutations, restart-unique ETags, daemon/root versus
operator authorization (including raw pre-body denial), phased LocalAPI body
admission, cancellation/deadlines, bounded JSON responses, CLI completion and text/JSON
shapes, malicious names, traversal, symlink and special-file roots, explicit
remote/bookmark rejection, browse/read/write/move/delete, unauthorized peers,
signed grant narrowing from read-write to read-only,
complete capability revocation, forged grant headers, disabled startup,
read-only LocalAPI mutation denial, failed-config atomicity, bounded parsing,
request cancellation, deterministic root replacement, FIFO/socket rejection,
worker saturation, post-sync cancellation, publication-time special-object
swaps that remain untouched, traversal, symlink escape,
oversized requests, malicious `Destination` values, body-before-authorization
framing, aggregate byte admission, old-key denial/new-key success, tunnel/send
path removal on rotation, duplicate address ownership, eight concurrent 16 MiB
streaming uploads, and revocation injected immediately before every mutating
WebDAV publication followed by successful new-epoch retries.

## Deferred

Platform filesystem mounts, local composition of remote nodes, Finder/Explorer
integration, GUI share management, CLI rename/share-as, persistent
profile-scoped share configuration, subprocess user switching, macOS
bookmarks, WebDAV locking,
recursive collection copy/delete, range responses, metadata caching, and
availability probing remain deferred. The current work is a secure server and
configuration parity layer, not complete Taildrive product parity.
