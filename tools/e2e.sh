#!/usr/bin/env bash
# e2e.sh — provision an ephemeral tailnet, run `cargo test -- --ignored` e2e tests
# against it, and always delete it afterwards.
#
# Auth (either):
#   TS_ORG_TOKEN                            — pre-minted org token (CI/WIF path)
#   TS_ORG_CLIENT_ID + TS_ORG_CLIENT_SECRET — OAuth client creds (local path;
#                                             `source .secrets/tailscale.env`)
#
# The org client is tailnets-scope only, so the child oauthClient creds from the
# create response are the ONLY way to operate on/delete the tailnet. Capture them
# before anything else and trap cleanup.
set -euo pipefail
cd "$(dirname "$0")/.."

API="${TS_API_BASE_URL:-https://api.tailscale.com}"

if [[ -z "${TS_ORG_TOKEN:-}" ]]; then
  [[ -n "${TS_ORG_CLIENT_ID:-}" && -n "${TS_ORG_CLIENT_SECRET:-}" ]] || {
    echo "need TS_ORG_TOKEN or TS_ORG_CLIENT_ID/SECRET (source .secrets/tailscale.env)" >&2; exit 2; }
  TS_ORG_TOKEN=$(curl -fsS -X POST "$API/api/v2/oauth/token" \
    -d client_id="$TS_ORG_CLIENT_ID" -d client_secret="$TS_ORG_CLIENT_SECRET" | jq -r .access_token)
fi

NAME="rustscale-e2e-$(date +%s)"
echo "creating ephemeral tailnet: $NAME" >&2
CREATED=$(curl -fsS -X POST "$API/api/v2/organizations/-/tailnets" \
  -H "Authorization: Bearer $TS_ORG_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"displayName\":\"$NAME\"}")

DNS=$(echo "$CREATED" | jq -r .dnsName)
CHILD_CID=$(echo "$CREATED" | jq -r .oauthClient.id)
CHILD_CSEC=$(echo "$CREATED" | jq -r .oauthClient.secret)
[[ -n "$DNS" && "$DNS" != null && -n "$CHILD_CSEC" && "$CHILD_CSEC" != null ]] || {
  echo "create failed: $CREATED" >&2; exit 1; }
echo "created: $DNS" >&2

child_token() {
  curl -fsS -X POST "$API/api/v2/oauth/token" \
    -d client_id="$CHILD_CID" -d client_secret="$CHILD_CSEC" | jq -r .access_token
}

cleanup() {
  echo "deleting tailnet: $DNS" >&2
  T=$(child_token) || { echo "WARN: could not mint child token for cleanup" >&2; return 0; }
  curl -sS -o /dev/null -w 'delete HTTP %{http_code}\n' -X DELETE \
    "$API/api/v2/tailnet/$DNS" -H "Authorization: Bearer $T" >&2 || true
}
trap cleanup EXIT

CHILD_TOKEN=$(child_token)

# API-only tailnets require tagged auth keys ("tailnet-owned auth key must have
# tags set"), and the tag must exist in the policy file first.
curl -fsS -X POST "$API/api/v2/tailnet/$DNS/acl" \
  -H "Authorization: Bearer $CHILD_TOKEN" -H 'Content-Type: application/json' \
  -d '{"tagOwners":{"tag:e2e":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}' >/dev/null

# Reusable ephemeral preauthorized key for nodes under test.
AUTHKEY=$(curl -fsS -X POST "$API/api/v2/tailnet/$DNS/keys" \
  -H "Authorization: Bearer $CHILD_TOKEN" -H 'Content-Type: application/json' \
  -d '{"capabilities":{"devices":{"create":{"reusable":true,"ephemeral":true,"preauthorized":true,"tags":["tag:e2e"]}}},"expirySeconds":3600}' \
  | jq -r .key)
[[ -n "$AUTHKEY" && "$AUTHKEY" != null ]] || { echo "authkey mint failed" >&2; exit 1; }

export TS_E2E_TAILNET="$DNS"
export TS_E2E_AUTHKEY="$AUTHKEY"
export TS_E2E_API_TOKEN="$CHILD_TOKEN"

# E2E tests are #[ignore]d unit-style tests gated on TS_E2E_* env vars.
cargo test --workspace -- --ignored
