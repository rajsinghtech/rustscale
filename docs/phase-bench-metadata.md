# Phase: Immutable benchmark provenance

## Goal

Make every current GCP benchmark cell prove which committed source, binaries,
toolchains, cloud image, and endpoint runtime produced it. Strict aggregation
must reject missing or mixed provenance. This phase changes measurement
identity only; it must not change the workload, dataplane, or paid-cloud
execution.

The source delivery contract is already `git archive HEAD`. A dirty launch
worktree therefore does not mean dirty files were benchmarked. Record both
facts explicitly:

- `source.commit` is the full 40-character `git rev-parse HEAD`.
- `source.delivery` is `git-archive-head`.
- `source.includes_uncommitted_changes` is always `false`.
- `source.launch_worktree_dirty` reports whether tracked, staged, or untracked
  files existed when the matrix command started.
- Print a warning when the launch worktree is dirty that committed `HEAD`, not
  those changes, will be benchmarked.

Pinned starting commit: `81bd40170dbd46b12f547fdaa30e7c402439fe91`.

## Schema contract

Current strict output uses matrix schema 2 and result schema 3. Do not silently
extend the old schema numbers.

`matrix.json` schema 2 must retain all schema-1 selection and workload fields
and add a required `run` object:

```json
{
  "schema_version": 2,
  "run": {
    "id": "gcp-20260714-013438-<stable suffix>",
    "started_at_utc": "2026-07-14T06:34:38Z",
    "source": {
      "commit": "<40 lowercase hex>",
      "delivery": "git-archive-head",
      "includes_uncommitted_changes": false,
      "launch_worktree_dirty": true
    },
    "cloud": {
      "provider": "gcp",
      "project": "<project id or dry-run>",
      "requested_image_project": "ubuntu-os-cloud",
      "requested_image_family": "ubuntu-2204-lts",
      "requested_machine_type": "n1-standard-4",
      "network": "default",
      "disk_type": "pd-standard",
      "disk_gb": 20
    },
    "build": {
      "command": "<exact RUST_BUILD_COMMAND or empty string>",
      "rustflags": "<exact RUSTFLAGS or empty string>",
      "cargo_profile_release_lto": "<exact value or empty string>",
      "cargo_profile_release_codegen_units": "<exact value or empty string>"
    }
  }
}
```

The run ID must be unique enough that two runs started in one second do not
collide, must be filesystem-safe, and must equal the result directory basename.
UTC timestamps must use `YYYY-MM-DDTHH:MM:SSZ`.

Every schema-3 result, including a failed cell and dry-run stub, must contain an
exact copy of the manifest `run` object plus a required `observed` object:

```json
{
  "schema_version": 3,
  "run": { "...": "byte-for-value equal to matrix.run" },
  "observed": {
    "resolved_image": "<full immutable source image URL/name>",
    "server": {
      "zone": "us-central1-a",
      "machine_type": "<observed machine type>",
      "cpu_platform": "<GCE cpuPlatform>",
      "cpu_model": "<lscpu model name>",
      "logical_cpus": 4,
      "kernel_release": "<uname -r>",
      "os_pretty_name": "<PRETTY_NAME>"
    },
    "client": { "...": "same required fields" },
    "toolchain": {
      "server_cargo": "<cargo --version>",
      "server_rustc_verbose": "<rustc -Vv>",
      "client_cargo": "<cargo --version>",
      "client_rustc_verbose": "<rustc -Vv>"
    },
    "product": {
      "server": [{"path":"<absolute>","version":"<output>","sha256":"<64 lowercase hex>"}],
      "client": [{"path":"<absolute>","version":"<output>","sha256":"<64 lowercase hex>"}]
    }
  }
}
```

The actual representation may use named product entries instead of arrays if
that makes validation clearer. It must identify every executable that affects
the selected config, not only the footprint target:

- `rs-tun`: `rustscaled` on both endpoints and the `rustscale` CLI used for
  path gating on both endpoints.
- `ts-tun`: `tailscaled` and `tailscale` on both endpoints.
- `rs-userspace`: the RustScale benchmark executable(s) used by that config.
- `ts-userspace`: the Tailscale executable(s) used by that config.

Versions are trimmed, nonempty command output. SHA-256 values are lowercase
64-character hex. Resolve executable paths first (`command -v` or the explicit
path used by the runner), then version and hash that same file. Never hash a
different PATH candidate. Multiline version output may be stored as a string.

The resolved image must come from the created boot disk/instance, not a second
`describe-from-family` lookup that could race an image-family update. Observed
machine type and CPU platform must come from the created instance. Kernel, OS,
CPU model/count, Rust toolchain, versions, and hashes must be collected from
each actual endpoint after startup and Rust build, before the first measured
cell for that topology.

## Propagation

Add a small structured Python helper under `tools/bench/gcp/` for constructing,
validating, and attaching metadata. Do not add more ad hoc JSON string assembly
or duplicate large Python heredocs in each config path.

`run-matrix.sh` creates the run object once, atomically writes matrix schema 2,
and passes the manifest path plus topology-specific observed metadata to
`run-config.sh` through explicit non-secret arguments or file paths. Metadata
files must live under the result directory, contain no auth keys/tokens, and be
written atomically. `run-config.sh` must fail closed before measurement if
current-run metadata is missing or malformed.

Normal and profile-only invocations must preserve the accepted result JSON.
Profile metadata should reference the same run ID and source commit, but this
phase must not turn profiling into a selected result cell.

Dry-run uses explicit, validator-recognized placeholders for fields that
require a VM. Placeholders must say `dry-run`; do not use plausible fake hashes,
versions, images, kernels, or CPU models. Real host-derived fields such as the
commit and dirty-launch disclosure remain real. A production strict aggregate
must reject dry-run observed metadata.

## Strict validation

`aggregate.py` strict mode requires matrix schema 2 and result schema 3. It
must reject:

- a missing, malformed, or unsupported manifest/result schema;
- a result `run` object not deeply equal to `matrix.run`;
- malformed source commit, timestamp, run ID, cloud/build fields, endpoint
  fields, toolchain strings, product versions, or hashes;
- a result whose endpoint zones do not match the selected topology's actual
  invocation metadata;
- dry-run placeholders in a non-dry-run manifest;
- current cells mixed from different runs, commits, images, machines, or
  binaries.

Apply provenance validation to failed cells as well as successful cells.
Measurement validation remains unchanged.

`--allow-partial` must continue to collect historical schema-1 matrices and
pre-schema-3 cells as visibly legacy/partial data. It must never upgrade them
to current provenance or make them eligible for strict success. The HTML header
for schema-2 matrices must show run ID, UTC start, short commit plus dirty-launch
disclosure, requested/resolved image, machine type, RustScale version(s), and
Tailscale version(s). Existing detail output already exposes raw JSON.

## Deterministic tests

Extend the existing self-tests and `tools/bench/check.sh` so one quiet command
covers all of the following without credentials or GCP:

1. Focused and full dry-runs emit matrix schema 2 and result schema 3.
2. The result directory basename equals `run.id`; every selected result has a
   deeply equal `run` object.
3. Dry-run observed metadata is explicit and deterministic enough to assert.
4. Strict aggregation accepts a complete valid production-shaped fixture.
5. Strict aggregation rejects missing provenance and mutations of commit, run
   ID, timestamp, cloud image/machine, endpoint environment, toolchain, product
   version, and product hash, for both successful and failed cells.
6. Partial collection still normalizes historical positive results and keeps
   historical failures numeric-null and visibly legacy.
7. Source dirty detection covers tracked, staged, and untracked files while
   preserving `includes_uncommitted_changes: false`.
8. Remote metadata parsing handles spaces, quotes, and multiline version or
   `rustc -Vv` output through JSON/files rather than shell interpolation.
9. Profile-only mode does not overwrite a normal result and references the same
   run identity.
10. `bash -n`, manifest tests, representative dry-runs, renderer tests, and
    `git diff --check` pass through `tools/bench/check.sh`.

Do not run a paid GCP benchmark in this phase. Do not change Rust dataplane code.
