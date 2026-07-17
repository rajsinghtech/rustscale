#!/usr/bin/env bash
# Explicitly refresh normalized snapshots from the pinned tailscale.com module.
# Normal compatibility checks never call this script and remain offline.
set -euo pipefail

cd "$(dirname "$0")/../.."

provenance="compat/upstream/provenance.json"
module="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["module"])' "$provenance")"
version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$provenance")"

metadata="$(go mod download -json "${module}@${version}")"
module_dir="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])' <<<"$metadata")"

# Verify all immutable provenance before compiling anything from the module.
METADATA="$metadata" python3 - "$provenance" <<'PY'
import json, os, sys
expected = json.load(open(sys.argv[1], encoding="utf-8"))
actual = json.loads(os.environ["METADATA"])
checks = {
    "Path": expected["module"],
    "Version": expected["version"],
    "Sum": expected["sum"],
    "GoModSum": expected["go_mod_sum"],
}
for key, want in checks.items():
    got = actual.get(key)
    if got != want:
        raise SystemExit(f"upstream provenance mismatch for {key}: {got!r} != {want!r}")
revision = actual.get("Origin", {}).get("Hash")
if revision != expected["revision"]:
    raise SystemExit(f"upstream revision mismatch: {revision!r} != {expected['revision']!r}")
PY

tmp="$(mktemp -d "${TMPDIR:-/tmp}/rustscale-compat.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

(
  cd "$module_dir"
  go build -o "$tmp/tailscale" ./cmd/tailscale
)
"$tmp/tailscale" --json-docs >"$tmp/cli.json"

python3 tools/compat/generate.py refresh-upstream \
  --module-dir "$module_dir" \
  --cli-json "$tmp/cli.json" \
  --cli-bin "$tmp/tailscale" \
  "$@"
