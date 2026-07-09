#!/usr/bin/env bash
# ts-org-token.sh — exchange an org OAuth client secret for an API access token.
#
# Auth modes (pick one via env):
#   TS_ORG_CLIENT_ID + TS_ORG_CLIENT_SECRET  → client_credentials grant
#   TS_ORG_CLIENT_ID + TS_OIDC_JWT           → WIF / GitHub OIDC token-exchange
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

mint_org_token
