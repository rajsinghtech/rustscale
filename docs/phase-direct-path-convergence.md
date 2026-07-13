# Phase: Direct path convergence

## Problem

The production same-zone GCP TUN run proved that WireGuard data works over
DERP (kernel ICMP measured 23-48 ms), but `rustscale ping --until-direct`
never reports a usable path. The benchmark correctly rejects the run.

## Required behavior

1. A CLI disco ping sends to every current UDP candidate and through the
   peer's DERP region. A working relay must produce a DERP pong even when
   direct candidates exist.
2. WireGuard traffic using DERP continues probing current direct candidates
   and retriggers CallMeMaybe until a direct path is confirmed.
3. An incoming UDP disco ping teaches the endpoint the sender's observed
   source address so subsequent probes use the path that actually reached us.
4. Direct pongs continue to set the selected endpoint and CLI result exactly
   once; DERP pongs report DERP without being misclassified as direct.

## Verification

- Focused magicsock tests cover UDP plus DERP CLI fanout, repeated discovery
  while the best path is absent, and candidate learning from an incoming ping.
- Existing magicsock, tsnet, CLI, daemon, formatting, and clippy checks pass.
- The production GCP matrix slice
  `--topology same-zone --path direct --config rs-tun,ts-tun` reports
  `path_class_reported: direct` before recording throughput.

## Benchmark follow-up

The TUN cleanup must wait until `rustscaled` has exited and `tailscale0` is
gone before starting `tailscaled`, preventing a false `device or resource
busy` failure in the comparison configuration.
