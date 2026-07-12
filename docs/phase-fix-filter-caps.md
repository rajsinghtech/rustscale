# Fix phase: filter capability ACLs + shields-up

Two verified security gaps in `crates/filter` (docs/audit/verified.md #2, #13).

## Gap 1: capability ACLs not evaluated (#2)
`crates/filter/src/lib.rs` (~line 306) `no_cap()` / the capability-match path
always returns false, so capability-grant-based ACL rules (`tailcfg.FilterRule`
with `CapGrant`/`SrcCaps`/`Caps`) are silently ignored. Go evaluates these in
`wgengine/filter/filter.go` (`runIn`/`CheckCaps`, `matchesCap`).

Go refs: `wgengine/filter/filter.go`, `tailcfg` FilterRule/CapGrant/CapMatch,
`wgengine/filter/match.go`.

Work:
1. Port the capability-match logic: a packet/peer with the right caps satisfies
   a rule's cap requirement. Match Go's semantics for src caps and dst cap
   grants.
2. Ensure the netmap → filter compile path (where rustscale builds Matches from
   the netmap FilterRules) actually carries cap info through; today it likely
   drops it — trace crates/tsnet where the filter is built from the netmap.

## Gap 2: shields-up mode (#13)
`filter/src/lib.rs` (~line 49) has no shields_up field. Go's ShieldsUp pref
drops all inbound traffic that isn't part of an existing/established flow.
The pref exists in crates/ipn Prefs but is never wired to the filter.

Work:
3. Add a shields_up flag to the filter; when set, deny new inbound flows per
   Go's behavior (`filter.go` shields handling — inbound-only, established
   allowed).
4. Wire the ShieldsUp pref through: PATCH /prefs → rebuild/reconfigure filter.

## Tests
- Capability rule: peer with cap X allowed to a cap-gated dst, peer without cap
  denied (table-driven, mirror Go filter tests).
- Shields-up: inbound new flow denied when shields up, allowed when down;
  outbound unaffected.

## Acceptance
- Standard four checks + musl-target clippy, clean.
- Existing filter tests still green.
- docs/parity.md Packet filter row → ✅/🔶.
