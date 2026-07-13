# Phase: CLI ping forces direct discovery

## Evidence

The focused GCP run `bench-results/gcp-20260713-100005` reached both Rustscale
nodes through DERP, but `rustscale ping --until-direct --c=30` returned 30 DERP
pongs and never established a direct path. The retained 22-31 ms DERP replies
prove that node lookup, disco encryption, DERP bootstrap fanout, and CLI pong
callbacks were healthy.

The missing operation is a fresh CallMeMaybe exchange. `set_netmap` sends one,
but that one-shot send can race initial DERP readiness. `cli_ping` currently
pings only the UDP candidates already stored on the endpoint plus DERP. Unlike
Tailscale's user-initiated disco ping behavior, it cannot repair an empty or
stale direct-discovery state by telling the peer to probe our current UDP
addresses.

## Goal

Make `rustscale ping --until-direct` an unthrottled, do-it-now direct discovery
operation while preserving its existing first-pong result contract.

## Scope

### CLI ping

In `crates/magicsock/src/lib.rs`, keep the existing callback registration,
candidate CLI pings, and DERP CLI ping. For every `cli_ping` attempt with a
nonzero peer disco key and direct paths enabled:

1. Build a `Message::CallMeMaybe` from the current `local_udp_addrs`.
2. Seal it for the peer.
3. Send it through `Magicsock::send_via_derp` using the endpoint's current
   `derp_send_region`.
4. Therefore preserve targeted sending for a known region and use the existing
   all-region bootstrap fanout when HomeDERP and the learned route are zero.

Do not gate this send on `Endpoint::should_send_call_me_maybe` or
`should_start_discovery`: a CLI ping is explicitly user initiated and must not
inherit the background discovery rate limit. `--until-direct` is already
bounded by the CLI count and interval.

The CallMeMaybe send must not replace, delay, or suppress the DERP CLI ping.
The first pong still completes the current attempt, so an initial attempt may
legitimately print DERP while its CallMeMaybe causes the peer to probe us. An
authenticated incoming UDP ping records the peer's observed source through the
existing `learn_candidate` path; the next CLI attempt can then return direct.

Do not add sleeps, retry tasks, heartbeat activity, callback replacement, or a
second callback. Repeated CLI invocations supply the retry cadence.

### CallMeMaybe receive

In `Inner::handle_disco_derp`, retain every authenticated address from
`Message::CallMeMaybe` with `Endpoint::learn_candidate` before sending the
existing discovery ping to it. This mirrors the durable candidate behavior
already used for authenticated UDP ping sources and lets later CLI/background
rounds reuse peer-advertised endpoints.

Keep existing candidate deduplication and bounds. Ignore no entire message
because one address is already known. Do not send a reciprocal CallMeMaybe
from the receive handler; the initiating CLI attempt already advertises its
side and the UDP ping source teaches the other side.

### Linux warning cleanup

In `crates/magicsock/src/udp_batch.rs`, mark `Control::as_ptr` as test-only (or
inline it into its test). It is used only by the Linux cmsg layout test and
currently produces a Linux release `dead_code` warning that macOS validation
cannot see. No GSO behavior changes belong in this phase.

## Tests

Add a fake-DERP integration test that deterministically models the live race:

1. Create two Magicsock peers with UDP sockets and an instrumented fake DERP.
2. Deliberately drop or suppress the initial set-netmap CallMeMaybe exchange so
   neither endpoint starts with a usable UDP candidate.
3. Allow DERP traffic, then invoke CLI ping from A.
4. The first completed result may be DERP, but the CLI-triggered CallMeMaybe
   must cause B to UDP-probe A and teach A B's observed source.
5. Repeated CLI ping attempts must produce a direct result within a bounded
   timeout, and A's `peer_path_class` must be `Direct`.

Also assert that the unknown-HomeDERP CLI path still fans out rather than
silently dropping CallMeMaybe. Preserve the existing tests that CLI ping sends
both candidate and DERP pings and completes through unknown-region fanout.

Prefer extending the fake relay with a small deterministic drop/count hook
over production-only observability or sleeps. Keep the hook test-only.

## Acceptance

- `cargo fmt --all --check`
- `RUST_TEST_THREADS=1 cargo test -p rustscale-magicsock`
- `cargo clippy -p rustscale-magicsock --all-targets -- -D warnings`
- Linux release/check has no new `udp_batch` dead-code warning.
- `RUST_TEST_THREADS=1 tools/check.sh`
- No change to CLI flags, output format, ping count, normal data sending, or
  non-CLI discovery cadence.

After merge, rerun the focused same-zone/direct `rs-tun --profile` cell. The
path gate must reach direct before interpreting any UDP GSO throughput result.
