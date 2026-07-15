# Taildrive status and security boundary

RustScale now has a bounded Taildrive core in `crates/drive`. It was compared
with Tailscale's `drive/`, `feature/drive`, PeerAPI and LocalAPI integration,
and the relevant `tsnet` callers and tests.

## Implemented

- Upstream-compatible share-name normalization and serde share model.
- Validated, all-or-nothing configuration replacement. New stores are disabled
  with no shares, and requests retain one immutable snapshot.
- Explicit Taildrive capability-grant parsing (`ro`, `rw`, wildcard and
  per-share precedence), with grant count/size limits and fail-closed errors.
- A WebDAV level-1 endpoint for `OPTIONS`, `PROPFIND` depth 0/1, `GET`, `HEAD`,
  atomic `PUT`, `MKCOL`, non-recursive `DELETE`, same-share `MOVE`, and
  same-share file `COPY`.
- Strict origin-form, UTF-8 and percent-decoded path handling. Traversal,
  encoded separators, ambiguous share aliases, non-portable device names and
  symbolic links are rejected. Share roots use `cap_std` directory handles so
  filesystem operations remain capability-confined during concurrent renames.
- Permissions come only from an authenticated peer object built from netmap
  capability values; HTTP headers cannot select identity or grants. Ungranted
  shares return 404, read-only writes return 403, and absolute/cross-share
  destinations cannot turn the daemon into a deputy.
- Configurable request/grant/path/body/response/directory limits plus request
  cancellation and deadlines. Uploads use same-directory temporary files,
  `sync_all`, and rename; failed uploads remove their temporary file.
- Hermetic protocol tests for browse/read/write/move/delete, authorization,
  oversized/cancelled requests, traversal, symlink escape and malicious
  `Destination` values.

## Deliberately not wired yet

The core is **not** registered at PeerAPI `/v0/drive`, exposed through LocalAPI,
or enabled by `tsnet`. The current RustScale PeerAPI identity passed to handlers
does not include the authenticated peer's Taildrive `CapMap` values, so wiring
now would require trusting incomplete authorization. Consequently this change
cannot expose host files, even when a state directory exists.

Before wiring, PeerAPI must pass a request-scoped authenticated node identity
and the exact `tailscale.com/cap/drive` values, enforce bounded HTTP parsing
before constructing `drive::Request`, and propagate connection cancellation and
deadlines. LocalAPI share mutation must retain existing read/write peer-credential
checks and persist only configurations accepted by `ConfigStore`.

Platform filesystem mounts, Finder/Explorer integration, macOS bookmark access,
GUI/CLI share management, subprocess user switching, WebDAV locking,
recursive collection copy/delete, range responses, metadata caching, and local
composition of multiple remote nodes are deferred. Non-empty `who` and
`bookmarkData` fields therefore fail closed rather than silently running with
the daemon's authority.
