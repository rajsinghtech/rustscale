#!/usr/bin/env bash
# tools/go-find.sh — search the Go reference tree for types, functions, or any
# pattern. Prevents agents from reading full Go files just to locate a struct
# definition or function signature.
#
# The Go reference tree is read-only. By default this uses the pinned canonical
# Go module; set TAILSCALE_GO_REPO to search a full clone instead.
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

if [[ -n "${TAILSCALE_GO_REPO:-}" ]]; then
  GO_TREE="$TAILSCALE_GO_REPO"
else
  command -v go >/dev/null 2>&1 || {
    echo "$0: go is required unless TAILSCALE_GO_REPO is set" >&2
    exit 1
  }
  GO_TREE="$(go mod download -json tailscale.com@v1.100.0 |
    sed -n 's/^[[:space:]]*"Dir": "\([^"]*\)",/\1/p')"
fi
[[ -n "$GO_TREE" ]] || {
  echo "$0: could not locate tailscale.com@v1.100.0" >&2
  exit 1
}
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
SEARCH_DIR="${SUBDIR:-.}"

if [ ! -d "$GO_TREE/$SEARCH_DIR" ]; then
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
  (cd "$GO_TREE" && rg "${RG_OPTS[@]}" -i "$PATTERN" "$SEARCH_DIR" 2>/dev/null) || true
else
  (cd "$GO_TREE" && find "$SEARCH_DIR" -name '*.go' -exec grep -n -i "$PATTERN" {} + 2>/dev/null) || true
fi
