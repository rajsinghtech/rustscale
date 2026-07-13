# Phase: Linux recvmmsg remediation

## Context

The first live same-zone direct benchmark after enabling Linux UDP GRO reached a
direct path but collapsed from hundreds of Mbps to about 0.05 Mbps with low CPU.
That is a receive-drop regression. GRO must not remain enabled without a Linux
end-to-end test that proves the kernel ancillary-data and split behavior used by
the production socket.

## Scope

- Keep Linux `recvmmsg` receive batching with a maximum logical batch of 128.
- Disable and remove UDP GRO from the production receive path.
- Remove GRO-only tail buffers, control parsing, socket-option toggling, and
  scalar fallback state that exists only for unsupported `recvmmsg`.
- If `recvmmsg` returns `ENOSYS`, fall back to the established scalar Tokio
  receive/drain loop.
- Keep malformed or oversized consumed batches atomic and recoverable.
- Keep the non-Linux path unchanged.
- Preserve zero-length datagrams, source addresses, order, and task-owned
  reusable storage without per-datagram allocation.

## Acceptance

- Linux GNU and musl compile checks pass.
- Focused `recvmmsg` loopback tests cover ordering, sources, zero-length packets,
  reuse, truncation rejection, and atomic failure.
- `RUST_TEST_THREADS=1 tools/check.sh` passes.
- A live same-zone direct rs-tun benchmark restores throughput above the failed
  0.05 Mbps run before the remediation is considered complete.
