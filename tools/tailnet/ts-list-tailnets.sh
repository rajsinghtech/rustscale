#!/usr/bin/env bash
# ts-list-tailnets.sh — list all tailnets in your org (primary + API-only).
#
# Usage: ts-list-tailnets.sh <org_access_token>
#
# Env:
#   TS_API_BASE_URL  (default https://api.tailscale.com)
#
# Output: the list JSON on stdout ({ "tailnets": [ {id, displayName, orgId, createdAt}, … ] }).
# Exit:   0 success, 1 runtime error, 2 usage error.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
. "$DIR/_lib.sh"

TOKEN="${1:-}"
[[ -n "$TOKEN" ]] || die "usage: $0 <org_access_token>" 2

curl -fsS "$TS_API_BASE_URL/api/v2/organizations/-/tailnets" \
  -H "Authorization: Bearer $TOKEN"
