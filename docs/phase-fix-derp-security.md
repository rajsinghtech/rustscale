# Fix phase: DERP client pinned-key verify + send rate limiting

Two verified P0s in `crates/derp/src/client.rs` (docs/audit/verified.md #1, #14).

## Gap 1: pinned server-key verification (SECURITY, #1)
Today the client accepts whatever server key it receives in the
ServerKey/ServerInfo handshake (`client.rs` ~line 147; `server_key` starts
zeroed and is filled from `recv_server_key()` with no check). Go verifies the
received DERP server public key against the key pinned in the DERPMap for that
region/node, so a MITM on the relay connection is detectable.

Go refs: `derp/derphttp/derphttp_client.go` (server key handling),
`derp/derp_client.go` `ServerPublicKey`, and how magicsock passes the expected
key from `DERPMap` region nodes into the derp client.

Work:
1. Thread the expected server public key (from the DERPMap node entry, field
   is typically the region node's key) into the derp client
   connect/handshake path.
2. After `recv_server_key`, compare against the expected key; on mismatch,
   fail the connection with a typed error (do NOT proceed). When no expected
   key is configured (e.g. bootstrap before DERPMap), preserve current behavior
   but log — match Go's posture.
3. Wire magicsock's DERP dial to pass the pinned key.

## Gap 2: send rate limiting (CORRECTNESS, #14)
`send_packet` (`client.rs` ~line 396) writes unconditionally; Go rate-limits
client→server frames (token bucket) to avoid overrunning the server queue and
causing head-of-line blocking. Go ref: `derp/derp_client.go` send path /
`rate.Limiter` usage.

Work:
4. Add a token-bucket limiter on the send path with Go-comparable defaults
   (check the Go constants). Drop or briefly block per Go's behavior.

## Tests
- Handshake with matching key succeeds; mismatched key rejected (unit test with
  a fake server key).
- Rate limiter: burst then sustained rate behaves as configured (unit test on
  the limiter, not requiring a live server).

## Acceptance
- Standard four checks + musl-target clippy, all clean.
- Interop tests (crates/interop-testcontrol, derp server tests) still green —
  the pinned key must be correctly plumbed so the in-process DERP tests pass.
- docs/parity.md DERP client row → ✅/🔶 as appropriate.
