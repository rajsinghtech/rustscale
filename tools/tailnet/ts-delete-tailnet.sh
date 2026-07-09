#!/usr/bin/env bash
# ts-delete-tailnet.sh — delete a tailnet. Idempotent: HTTP 404 is treated as success.
#
# Usage: ts-delete-tailnet.sh <child_access_token> <dnsName>
#
# ⚠️ The token MUST be scoped to the child tailnet (use ts-cross-tailnet-token.sh
#    or ts-child-token.sh). The org token CANNOT delete a child tailnet and will
#    get a 403/404.
#
# Env:
#   TS_API_BASE_URL  (default https://api.tailscale.com)
#
# Output: none on success; diagnostic messages on stderr.
# Exit:   0 success (or already gone), 1 runtime error, 2 usage error.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
. "$DIR/_lib.sh"

TOKEN="${1:-}"
DNS="${2:-}"
[[ -n "$TOKEN" && -n "$DNS" ]] || die "usage: $0 <child_access_token> <dnsName>" 2

ENC_DNS="$(jq -nr --arg v "$DNS" '$v|@uri')"

echo "deleting tailnet: $DNS" >&2
code="$(curl -s -o /tmp/ts-delete-body.$$ -w '%{http_code}' -X DELETE \
  "$TS_API_BASE_URL/api/v2/tailnet/$ENC_DNS" \
  -H "Authorization: Bearer $TOKEN")"
body="$(cat /tmp/ts-delete-body.$$ 2>/dev/null || true)"; rm -f /tmp/ts-delete-body.$$

case "$code" in
  200) echo "deleted" >&2; exit 0 ;;
  404) echo "already gone (404)" >&2; exit 0 ;;
  *)   die "delete $DNS failed: HTTP $code: $body" 1 ;;
esac
