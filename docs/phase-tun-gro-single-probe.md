# TUN TCP GRO Single-Probe Flow Lookup

## Evidence

The `gcp-20260713-183843` client profile attributes 2.33% exclusive CPU to
`DefaultHasher::write` and another 1.19% to hashing `TcpFlowKey`. The TCP GRO
happy path currently probes `TcpGroState::flows` three times for one packet:
candidate lookup, candidate reload, and merged-item update.

## Required change

- Preserve `HashMap<TcpFlowKey, Vec<TcpItem>>` and its randomized default
  hasher.
- Perform one flow-table lookup on the established-flow happy path and retain
  that mutable entry through candidate selection, validation, and update.
- Refactor helpers only as needed to borrow disjoint GRO state. Do not clone
  flow items or packet buffers and do not introduce unsafe code.
- Preserve reverse candidate order, invalid-checksum eviction, scalar fallback,
  prepend/append accounting, PSH behavior, IPv4/IPv6 behavior, and output order.
- A missing flow may use the normal entry insertion path; optimize the repeated
  established-flow probes measured in the profile.

## Verification

- Existing TUN unit and integration tests must pass unchanged.
- Add focused tests proving that multiple candidates in one flow still select
  the newest compatible candidate, remove an invalid head, and retain older
  candidates for a later match.
- Add a test-only counting `BuildHasher` or equivalent instrumentation proving
  an established-flow append performs one table hash, without weakening the
  production hasher.
- Run `cargo test -p rustscale-tun`, clippy for the crate, `tools/check.sh`, and
  the native Linux TUN test gate.
- Re-run the same-zone direct GCP benchmark with profiling. Accept the phase
  only if `DefaultHasher::write` plus `hash_one<TcpFlowKey>` materially falls
  from the 3.52% baseline without throughput, latency, RSS, GRO, or correctness
  regression.
