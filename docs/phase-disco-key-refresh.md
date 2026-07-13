# Phase: Refresh peer disco keys from netmap updates

## Problem

`Magicsock::set_netmap` updates candidates and HomeDERP for an existing peer,
but `Endpoint::peer_disco_key` is fixed at construction. A fresh peer can first
arrive from registration data with a zero disco key and later receive its real
key through a control update. The reverse `disco_to_peer` map then contains the
new key while CLI ping still reads the zero key from `Endpoint`, sends nothing,
and times out. Key rotation has the same stale-state failure.

This was observed in a fresh two-node GCP TUN run: both nodes connected to DERP
and published local plus STUN endpoints, while every production
`ping --until-direct --c=120` request timed out and no throughput measurement
started.

## Required behavior

1. Add an endpoint operation that refreshes the peer disco key and reports the
   previous key when it changes.
2. In `Magicsock::set_netmap`, update an existing endpoint's disco key before
   creating the probe list.
3. Keep `disco_to_peer` consistent: remove the previous non-zero mapping only
   when it still points at this peer, and insert the new non-zero mapping.
   Handle zero to non-zero, non-zero to a different non-zero key, unchanged
   keys, and non-zero to zero without deleting another peer's mapping.
4. Preserve candidates, confirmed path state, pending pings, HomeDERP, and all
   unrelated endpoint state when only the disco key changes.
5. Do not weaken the production CLI path gate or add a benchmark fallback.

## Tests

- A focused endpoint test covers unchanged and changed disco keys.
- A magicsock netmap regression test creates a peer with a zero disco key,
  applies a second netmap with the real key, and proves the endpoint and reverse
  lookup use the new key.
- Cover rotation and stale reverse-map removal, including the guard that avoids
  removing a mapping now owned by a different peer.

## Validation

- `tools/check.sh rustscale-magicsock`
- `cargo test -p rustscale-magicsock`
- `cargo clippy -p rustscale-magicsock --all-targets -- -D warnings`
- `bash -n tools/bench/gcp/run-config.sh`

After merge, repeat the retained direct GCP run with `RUSTSCALE_DEBUG=1` on the
Rust daemons, capture the product CLI path transcript, and attach `perf` only
after the CLI reports a direct path.
