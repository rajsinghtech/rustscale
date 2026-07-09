#!/usr/bin/env bash
# ts-oidc-token.sh — exchange a Workload Identity Federation OIDC JWT for an API access token.
#
# Usage: ts-oidc-token.sh <client_id> <jwt>
#   (or set TS_ORG_CLIENT_ID and TS_OIDC_JWT env vars and call with no args)
#
# Env:
#   TS_API_BASE_URL  (default https://api.tailscale.com)
#
# Output: the access token on stdout (everything else on stderr).
# Exit:   0 success, 1 runtime error, 2 usage error.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
. "$DIR/_lib.sh"

if [[ $# -ge 2 ]]; then
  TS_ORG_CLIENT_ID="$1"
  TS_OIDC_JWT="$2"
fi
require_env TS_ORG_CLIENT_ID TS_OIDC_JWT

mint_org_token
