#!/usr/bin/env bash
# tools/where.sh — find line numbers of a pattern in a file without re-reading
# the whole file into an agent's context. Prints "file:line: matched-text" for
# each hit (like grep -n) so the agent can then read a narrow offset/limit
# window around the exact line it wants to edit.
#
# This is the #1 token-sink fix from phases 5-7: agents re-read their own
# large files (tsnet/src/lib.rs was re-read 53x in phase 7, 124K chars) just
# to locate one function. Use this instead.
#
# Usage:
#   tools/where.sh <pattern> <file>            # case-insensitive grep -n
#   tools/where.sh <pattern> <file> [extra rg/grep flags]
# Example:
#   tools/where.sh 'fn up' crates/tsnet/src/lib.rs
#   tools/where.sh 'auth_key' crates/tsnet/src/lib.rs -n -i
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <pattern> <file> [grep flags...]" >&2
  exit 2
fi
PATTERN="$1"; FILE="$2"; shift 2

if [ ! -f "$FILE" ]; then
  echo "$0: not a file: $FILE" >&2
  exit 1
fi

# Prefer ripgrep (faster, ignores nothing by default here), fall back to grep.
if command -v rg >/dev/null 2>&1; then
  rg -n --no-heading --color never "$@" "$PATTERN" "$FILE" || true
else
  grep -n --color=never "$@" "$PATTERN" "$FILE" || true
fi
