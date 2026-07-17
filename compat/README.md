# Versioned compatibility contracts

These files make RustScale's compatibility denominator reviewable and
reproducible. They are inventories and mappings, not blanket compatibility or
performance claims.

## Pinned provenance

`upstream/provenance.json` pins the canonical `tailscale.com` module, Go module
checksums, repository revision, and source areas. The normalized upstream
snapshots under `upstream/` were extracted from that pin. The CLI snapshot also
records the host platform used for Go's platform-conditioned command tree.
Routine generation never downloads Go modules and does not need network access.

The checked manifests under `manifests/` all use schema version 1 and repeat the
upstream version and checksums. They cover:

- CLI commands, nested commands, flags, aliases, and daemon-free help/exit probes;
- the all-features `rustscale-tsnet` rustdoc public API;
- the C header checked against Rust `no_mangle` exports;
- explicit Python `__all__` exports and their C backing symbols;
- LocalAPI paths, methods, and stable request/response schema identifiers; and
- a complete conceptual mapping of the pinned Go `tsnet` exported denominator.

`tsnet.md` is generated from the JSON mapping for human review.

## Classification vocabulary

- **exact** — the normalized item being compared has the same structural or
  observed contract used by that manifest.
- **semantic** — the same concept is present with an intentional language,
  type, method, output, or schema adaptation.
- **shimmed** — the surface is supplied through a RustScale-specific wrapper,
  alias, or extension.
- **unsupported** — no compatible item or representative behavior was found.

The classification is scoped to the individual manifest item. For example, an
exact CLI command-name match does not claim full runtime behavior parity.

## Offline drift check

```sh
tools/compat/check.sh
```

The gate builds only local artifacts with Cargo offline, runs focused generator
tests, and then regenerates every local manifest in memory. Any byte difference
fails. It does not refresh upstream data; provision the locked Cargo dependency
cache first when starting from an empty machine.

For a deliberate local update after review:

```sh
cargo build -p rustscale-cli -p rustscale-ffi --locked --offline
cargo doc -p rustscale-tsnet --no-deps --all-features --locked --offline
python3 tools/compat/generate.py generate
```

Every manifest carries sorted identifier guards plus shape fingerprints for
signatures, aliases, observed behavior, and schema IDs. Generation refuses to
remove any prior denominator, guarded local API identifier, or prior item shape.
A reviewed removal/change requires the explicit `--allow-removals` flag, so
denominator shrinkage cannot be accepted accidentally.

## Refreshing the upstream pin

Use `tools/go-find.sh` while reviewing the pinned source. Refreshing snapshots
is intentionally separate and may download/build Go dependencies:

```sh
tools/compat/update-upstream.sh
```

The refresh verifies module path, version, module checksums, and VCS revision
before extraction. It also refuses upstream denominator removals unless the
reviewer explicitly passes `--allow-removals`. After a refresh, regenerate the
local manifests and review every changed `unsupported`, `semantic`, `shimmed`,
or `exact` entry.
