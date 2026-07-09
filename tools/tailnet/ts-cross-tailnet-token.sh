#!/usr/bin/env bash
# ts-cross-tailnet-token.sh — mint a stateless access token scoped to a child tailnet
# using your org OAuth client (cross-tailnet flow).
#
# Usage: ts-cross-tailnet-token.sh <child-stable-id>
#   <child-stable-id> is the `id` field from the create response (e.g. T123456CNTRL),
#   NOT the dnsName.
#
# Env:
#   TS_ORG_CLIENT_ID        required
#   TS_ORG_CLIENT_SECRET    required (client_credentials mode)
#     — OR —
#   TS_OIDC_JWT             required (WIF mode; will mint an org token first)
#   TS_API_BASE_URL         (default https://api.tailscale.com)
#
# Requirements (enforced server-side):
#   - Org OAuth client has the `all` scope.
#   - Org OAuth client lives on a tailnet with the `tailnet-creation-api` flag.
#   - The child tailnet is API-only (created by this API).
#
# Output: the child-scoped access token on stdout.
# Exit:   0 success, 1 runtime error, 2 usage error.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
. "$DIR/_lib.sh"

CHILD_ID="${1:-}"
[[ -n "$CHILD_ID" ]] || die "usage: $0 <child-stable-id>" 2

mint_cross_tailnet_token "$CHILD_ID"
