#!/usr/bin/env bash
# Runs a Go command with the pinned testcontrol inner-mux audit patch applied.
# The dependency cache is never modified: a temporary local module fork is
# patched and removed on exit.
set -euo pipefail

cd "$(dirname "$0")"

if [[ $# -eq 0 ]]; then
  echo "usage: with-audit-patch.sh <go command and arguments>" >&2
  exit 2
fi

version=$(go list -m -f '{{.Version}}' tailscale.com)
[[ "$version" == v1.100.0 ]] || {
  echo "with-audit-patch.sh: unexpected tailscale.com version: $version" >&2
  exit 1
}
module_dir=$(go list -m -f '{{.Dir}}' tailscale.com)
patch_file="$PWD/patches/audit-log-inner-mux.patch"
[[ -d "$module_dir/tstest/integration/testcontrol" && -f "$patch_file" ]] || {
  echo "with-audit-patch.sh: pinned source or audit patch is unavailable" >&2
  exit 1
}

tmp_root=${TMPDIR:-/tmp}
tmp_root=${tmp_root%/}
tmp=$(mktemp -d "$tmp_root/rustscale-testcontrol.XXXXXX")
cleanup() { chmod -R u+w "$tmp" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT HUP INT TERM
cp -R "$module_dir" "$tmp/tailscale"
chmod -R u+w "$tmp/tailscale"
chmod u+w "$tmp/tailscale/tstest/integration/testcontrol/testcontrol.go" \
  "$tmp/tailscale/tstest/integration/testcontrol/testcontrol_test.go"
(
  cd "$tmp/tailscale/tstest/integration/testcontrol"
  patch --batch --forward -p0 <"$patch_file"
)

# Use a temporary modfile to point only tailscale.com at the local patched
# module; all other pinned dependencies retain their checked-in checksums.
cp go.mod "$tmp/go.mod"
cp go.sum "$tmp/go.sum"
printf '\nreplace tailscale.com => %s\n' "$tmp/tailscale" >>"$tmp/go.mod"
go "$1" -modfile="$tmp/go.mod" "${@:2}"
