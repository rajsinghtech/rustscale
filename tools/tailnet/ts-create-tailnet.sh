#!/usr/bin/env bash
# ts-create-tailnet.sh — create an API-only tailnet in your org.
#
# Usage: ts-create-tailnet.sh <org_access_token> <displayName>
#
# Env:
#   TS_API_BASE_URL  (default https://api.tailscale.com)
#
# Output: the full create JSON on stdout (id, dnsName, oauthClient.{id,secret}, …).
#         ⚠️ Capture oauthClient.secret now — it is shown ONCE and cannot be retrieved.
# Exit:   0 success, 1 runtime error, 2 usage error.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
. "$DIR/_lib.sh"

TOKEN="${1:-}"
NAME="${2:-}"
[[ -n "$TOKEN" ]] || die "usage: $0 <org_access_token> <displayName>" 2
[[ -n "$NAME" ]]  || die "usage: $0 <org_access_token> <displayName>" 2

# displayName rules: ^[A-Za-z0-9' -]{1,50}$
if ! [[ "$NAME" =~ ^[A-Za-z0-9\ \'\-]{1,50}$ ]]; then
  die "displayName must match ^[A-Za-z0-9' -]{1,50}\$: got: $NAME" 2
fi

echo "creating tailnet: $NAME" >&2
curl -fsS -X POST "$TS_API_BASE_URL/api/v2/organizations/-/tailnets" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data "$(jq -nc --arg n "$NAME" '{displayName:$n}')"
