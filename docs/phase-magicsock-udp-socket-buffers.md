# Phase: Magicsock UDP Socket Buffer Parity

## Goal

Match Tailscale's direct-UDP socket buffer policy so Linux GRO bursts are not
dropped by the kernel before Rustscale can batch and decrypt them. Preserve
cross-platform behavior, pre-bound socket support, startup availability, and
the current process RSS advantage.

## Evidence

- The repeat-median direct benchmark at
  `bench-results/gcp-20260713-173223` reached 997.8 Mbps P1, but the receiving
  client reported `rxq_overflow_delta=10369`.
- The same run reported successful UDP GRO and RXQ instrumentation, 484,640
  coalesced kernel messages, zero GRO parse failures, and zero permanent
  fallbacks. The queue overflow is therefore the next observed receive-side
  loss point; it is not evidence of a GRO parser failure.
- Tailscale defines `socketBufferSize = 7 << 20` in
  `../tailscale/wgengine/magicsock/magicsock.go` and applies it to both read and
  write directions for every magicsock UDP connection.
- On Linux, Tailscale first attempts `SO_RCVBUFFORCE` or `SO_SNDBUFFORCE`, then
  falls back to the portable setter if the force option fails. Force failures
  affect throughput only and do not prevent startup.
- Rustscale currently binds or accepts a Tokio `UdpSocket` without changing
  either socket buffer.

## Required Behavior

1. Define the requested magicsock UDP socket buffer size as exactly 7 MiB,
   matching Tailscale.
2. Apply the policy once to both sockets created from `udp_bind` and sockets
   supplied through `MagicsockConfig::udp_socket`, before receive/send tasks
   start.
3. Apply the policy to both receive and send directions.
4. On Linux, try `SO_RCVBUFFORCE` and `SO_SNDBUFFORCE` first. If either force
   call fails, attempt the corresponding portable `SO_RCVBUF` or `SO_SNDBUF`
   setter. Do not run the portable setter after a successful force call.
5. On non-Linux platforms, use the portable setters directly. Platform
   clamping is acceptable and must not be treated as startup failure.
6. Socket option failures must be best-effort and observable, never fatal.
   Emit one bounded structured diagnostic containing requested size, actual
   receive/send sizes when readable, and force/portable outcome classes. Do
   not log raw descriptors or credentials.
7. Extend the rs-tun benchmark's bounded runtime-stat capture to retain the
   socket-buffer diagnostic so the effective GCP configuration is part of the
   result evidence.
8. Do not alter UDP GRO/GSO enablement, packet ordering, channel capacity,
   scalar fallbacks, DERP behavior, or non-magicsock UDP sockets.

## Tests And Gates

- Unit-test the force/portable decision policy, including successful force,
  force failure followed by portable success, and dual failure reporting.
- On Unix, bind a real UDP socket, apply the helper, and assert neither
  `SO_RCVBUF` nor `SO_SNDBUF` decreases. Log actual values because an
  unprivileged kernel may clamp them.
- Verify both pre-bound and newly-bound construction paths call the common
  policy through a focused seam or construction test.
- Extend `tools/bench/gcp/run-config.sh --self-test` for the new bounded
  diagnostic match.
- Run formatting, focused magicsock tests, clippy, `tools/check.sh`, and native
  Linux focused tests.
- Re-run the same-zone direct rs-tun benchmark with `--repeat 3 --profile`.
  Compare throughput, latency, RSS, binary size, and final RXQ overflow delta
  against `gcp-20260713-173223`. Keep the change only if configuration is
  verified and results do not show a repeatable material regression.

