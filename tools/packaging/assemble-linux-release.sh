#!/usr/bin/env bash
# Assemble one Linux release archive from already-built production binaries.
# This is deliberately build-free so consumers can prove the exact archive.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <target> <binary-directory> <output-directory>" >&2
  exit 2
fi

target=$1
binary_dir=$2
output_dir=$3
case "$target" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-unknown-linux-musl) ;;
  *) echo "unsupported Linux release target: $target" >&2; exit 2 ;;
esac
[[ -d "$binary_dir" ]] || { echo "missing binary directory: $binary_dir" >&2; exit 1; }

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
archive="rustscale-${target}.tar.gz"
stage=$(mktemp -d "${TMPDIR:-/tmp}/rustscale-linux-release.XXXXXX")
trap 'rm -rf "$stage"' EXIT
mkdir -p "$output_dir"

for file in rustscale rustscaled librustscale.a; do
  [[ -f "$binary_dir/$file" ]] || { echo "missing production artifact: $binary_dir/$file" >&2; exit 1; }
done
[[ -f "$binary_dir/librustscale.so" ]] || { echo "missing production artifact: $binary_dir/librustscale.so" >&2; exit 1; }
[[ -f "$root/include/rustscale.h" ]] || { echo "missing generated header" >&2; exit 1; }

install -m 755 "$binary_dir/rustscale" "$stage/rustscale"
install -m 755 "$binary_dir/rustscaled" "$stage/rustscaled"
install -m 755 "$binary_dir/librustscale.so" "$stage/librustscale.so"
install -m 644 "$binary_dir/librustscale.a" "$stage/librustscale.a"
install -m 644 "$root/include/rustscale.h" "$stage/rustscale.h"
install -m 644 "$root/LICENSE" "$stage/LICENSE"
install -m 644 "$root/packaging/systemd/rustscaled.service" "$stage/rustscaled.service"
install -m 644 "$root/packaging/systemd/rustscaled.default" "$stage/rustscaled.default"
tar --format=ustar -czf "$output_dir/$archive" -C "$stage" .
sha256sum "$output_dir/$archive" | sed 's|  .*/|  |' > "$output_dir/SHA256SUMS"
