#!/usr/bin/env bash
# tools/go-find.sh — search the Go reference tree for types, functions, or any
# pattern. Prevents agents from reading full Go files just to locate a struct
# definition or function signature.
#
# The Go reference tree is read-only at /Users/rajsingh/Documents/GitHub/tailscale.
# This script searches it with ripgrep (or grep) and prints file:line:matched
# lines with the function/type context header.
#
# Usage:
#   tools/go-find.sh <pattern>        # search full Go tree (case-insensitive)
#   tools/go-find.sh <pattern> <path> # restrict to a subdir, e.g. "tsnet/" "magicsock/"
#   tools/go-find.sh -x <pattern>     # exact word match (type-def, fn-name)
#   tools/go-find.sh -t "struct"      # find Go struct definitions
#   tools/go-find.sh -f "func "       # find Go function declarations
#
# Examples:
#   tools/go-find.sh -x Listen         # find all uses of "Listen" in Go tree
#   tools/go-find.sh -t "WhoIs"        # find type "WhoIs" struct definition
#   tools/go-find.sh "func.*Listen" tsnet/  # function decls in tsnet/
#   tools/go-find.sh -f magicsock      # find all top-level funcs in magicsock
set -euo pipefail

GO_TREE="/Users/rajsingh/Documents/GitHub/tailscale"
PATTERN=""
SUBDIR=""
MODE="grep"

while [[ "${1:-}" == -* ]]; do
  case "$1" in
    -t) MODE="type"; shift ;;
    -f) MODE="func"; shift ;;
    -x) MODE="exact"; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

if [ $# -lt 1 ]; then
  echo "usage: $0 [-t|-f|-x] <pattern> [go-subdir]" >&2
  echo "  -t  find type/struct definitions: 'type <pattern>'" >&2
  echo "  -f  find function declarations: 'func <pattern>'" >&2
  echo "  -x  exact word match (boundary-aware)" >&2
  exit 2
fi

PATTERN="$1"
SUBDIR="${2:-}"
SEARCH_DIR="$GO_TREE"
[ -n "$SUBDIR" ] && SEARCH_DIR="$GO_TREE/$SUBDIR"

if [ ! -d "$SEARCH_DIR" ]; then
  echo "$0: not found: $SEARCH_DIR" >&2
  exit 1
fi

RG_OPTS=(-n --no-heading --color never)

case "$MODE" in
  type)
    RG_OPTS+=(-g '*.go')
    PATTERN="type\\s+${PATTERN}"
    ;;
  func)
    RG_OPTS+=(-g '*.go')
    PATTERN="func\\s+${PATTERN}"
    ;;
  exact)
    RG_OPTS+=(-w)
    ;;
  grep)
    RG_OPTS+=(-g '*.go')
    ;;
esac

if command -v rg >/dev/null 2>&1; then
  rg "${RG_OPTS[@]}" -i "$PATTERN" "$SEARCH_DIR" 2>/dev/null || true
else
  find "$SEARCH_DIR" -name '*.go' -exec grep -n -i "$PATTERN" {} + 2>/dev/null || true
fi
