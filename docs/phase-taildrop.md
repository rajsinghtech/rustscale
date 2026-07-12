# Phase: Taildrop (`rustscale file cp|get`) 

Go refs (read all):
- `cmd/tailscale/cli/file.go` — CLI surface: `file cp <files...> <target>:`,
  `file get [--wait] [--verbose] [--conflict=skip|overwrite|rename] <dir>`.
- `feature/taildrop/localapi.go` — LocalAPI handlers: `PUT /localapi/v0/file-put/<stableID>/<filename>`,
  `GET /localapi/v0/files/`, `GET /localapi/v0/files/<name>`, `DELETE /localapi/v0/files/<name>`,
  `GET /localapi/v0/file-targets`, `GET /localapi/v0/await-waiting-files`.
- `feature/taildrop/` — daemon-side receive/send over PeerAPI: peers send files via
  `PUT /v0/put/<filename>` on the *PeerAPI* (rustscale already has a PeerAPI:
  crates/tsnet/src/peerapi.rs — phase-18, has /v0/* endpoint routing + WhoIs auth).
- `tailcfg` capabilities: peers advertise taildrop via `CapabilityFileSharing`
  (check Go's `tailcfg` for the exact cap name); file targets = peers with the cap
  that are online + same user (or tagged rules) — mirror Go's `FileTargets()` logic
  in `ipn/ipnlocal/` (search FileTargets).

## Work items

1. **PeerAPI receive**: `PUT /v0/put/<filename>` handler in peerapi.rs — auth via
   WhoIs (same-user or per Go's rules), stream body to a spool dir
   `<state_dir>/files/` with partial-file naming, enforce a max size knob.
   Emit `Notify{FilesWaiting}` on completion.
2. **LocalAPI endpoints** (localapi.rs): files list/get/delete, file-targets
   (from netmap peers with the sharing cap + online), file-put (daemon dials the
   target's PeerAPI over the tailnet via the existing netstack dial path and
   streams the upload), await-waiting-files (long-poll on the notify bus).
3. **localclient + CLI**: `rustscale file cp <path...> <host-or-ip>:` (resolve
   target via file-targets; `-` stdin with `--name`), `rustscale file get
   [--wait] [--conflict=...] <dest-dir>` (download all waiting files then delete
   from spool). Progress output kept simple (bytes, no fancy bars).
4. Tests: two-node in-process test (the interop/testcontrol harness already boots
   multi-node setups — see crates/tsnet tests) sending a file A→B: file-targets
   shows B from A, cp succeeds, B's files list shows it, get retrieves with
   matching bytes, conflict modes behave.

## Non-goals

Resume/partial-transfer recovery, inbox GUI semantics, Windows paths, sendfile
optimizations, `file get --loop` daemon mode beyond --wait single-shot.

## Acceptance criteria

- Standard four checks + musl-target clippy, all clean.
- Two-node integration test green.
- docs/parity.md Taildrop row updated.
