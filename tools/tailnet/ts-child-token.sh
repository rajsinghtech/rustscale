#!/usr/bin/env bash
# ts-child-token.sh — exchange a child tailnet's own OAuth client secret for an
# access token. Fallback for when the cross-tailnet flow (ts-cross-tailnet-token.sh)
# is not available.
#
# Usage: ts-child-token.sh <child-oauth-id> <child-oauth-secret>
#
# Env:
#   TS_API_BASE_URL  (default https://api.tailscale.com)
#
# Output: the child-scoped access token on stdout.
# Exit:   0 success, 1 runtime error, 2 usage error.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
. "$DIR/_lib.sh"

CID="${1:-}"
CSEC="${2:-}"
[[ -n "$CID" && -n "$CSEC" ]] || die "usage: $0 <child-oauth-id> <child-oauth-secret>" 2

mint_child_token "$CID" "$CSEC"
