#!/usr/bin/env bash
# tools/commit.sh — commit rustscale work as the local user (no AI branding).
# Runs the CI gate (tools/check.sh), stages, and commits. Silent on success
# except for the final commit hash. Matches the orchestrator's repeated
# `cargo fmt && tools/check.sh && git add -A && git -c user.name=...` ritual
# but as a single reusable command.
#
# Usage:
#   tools/commit.sh "message"          # check + stage all + commit
#   tools/commit.sh "message" --no-check  # skip the verify gate
#   tools/commit.sh "message" -- files..  # stage only listed paths
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: tools/commit.sh \"<message>\" [--no-check] [-- <paths>...]" >&2
  exit 2
fi

MSG="$1"; shift
RUN_CHECK=1
PATHS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --no-check) RUN_CHECK=0; shift ;;
    --) shift; PATHS=("$@"); break ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ "$RUN_CHECK" = 1 ]; then
  tools/check.sh >/dev/null
fi

cargo fmt --all >/dev/null 2>&1 || true

if [ ${#PATHS[@]} -gt 0 ]; then
  git add -- "${PATHS[@]}"
else
  git add -A
fi

git -c user.name=rajsinghtech -c user.email=rajsinghcpre@gmail.com \
  commit -q -m "$MSG"

git log -1 --format='%h %s'
