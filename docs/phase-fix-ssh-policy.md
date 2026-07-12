# Fix phase: wire the Tailscale SSH server policy callback

Verified gap #3 (docs/audit/verified.md): the SSH server (`crates/ssh`) exists
(~1200 LOC, merged phase-10) but its policy feed is hardcoded to reject
everything — `Arc::new(|| None)` at `crates/ssh/src/*` / the tsnet wiring. So
`listen_ssh` accepts TCP then denies every session. This makes the whole server
dead code.

## Go references
- `ssh/tailssh/tailssh.go` — `evalSSHPolicy` / how the server obtains the
  `*tailcfg.SSHPolicy` from the netmap (`SSHPolicy` field) and evaluates
  `SSHRule`s (principals, action, sessionAction, accept/reject, check-period).
- `tailcfg` SSHPolicy/SSHRule/SSHPrincipal/SSHAction types.
- `ipn/ipnlocal/local.go` — where LocalBackend feeds the current SSH policy +
  WhoIs identity into the ssh server.

## Work items
1. Find the hardcoded `|| None` policy callback in crates/ssh (grep for the
   closure returning None / the SSHPolicy feed) and the tsnet `listen_ssh`
   wiring that installs it.
2. Feed the real policy: source `tailcfg.SSHPolicy` from the current netmap
   (rustscale tailcfg + tsnet netmap accessor — check crates/tailcfg has the
   SSHPolicy/SSHRule types; if fields are missing, add them serde-compatibly).
3. Evaluate rules on connection: match the connecting peer (WhoIs identity —
   crates/tsnet already has WhoIs) against rule principals; return the matching
   SSHAction (accept/reject, allowLocalPortForwarding, etc.). Reject cleanly
   when no rule matches.
4. Keep it behind the existing `ssh` feature flag; don't change the feature
   gating.

## Tests
- Policy-eval unit tests: rule matching by principal (user/group/tag/anyone),
  accept vs reject, no-match → reject.
- If an in-process SSH handshake test is feasible with the existing test
  harness, add one asserting an allowed peer gets a session and a disallowed
  peer is rejected. If a full handshake is too heavy, cover the policy decision
  path directly and document that.

## Acceptance
- Standard four checks + `cargo clippy --workspace --all-targets --target
  x86_64-unknown-linux-musl -- -D warnings`, all clean.
- docs/parity.md Tailscale SSH row → ✅ (or 🔶 with remaining gaps named).
- Update docs/audit/verified.md finding #3 status if you touch it (optional).
