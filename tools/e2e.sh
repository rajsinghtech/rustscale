#!/usr/bin/env bash
# e2e.sh — provision an ephemeral tailnet, run `cargo test -- --ignored` e2e tests
# against it, and always delete it afterwards.
#
# Auth (either):
#   TS_ORG_TOKEN                            — pre-minted org token (CI/WID path)
#   TS_ORG_CLIENT_ID + TS_ORG_CLIENT_SECRET — OAuth client creds (local path;
#                                             `source .secrets/tailscale.env`)
#
# The org client is tailnets-scope only, so the child oauthClient creds from the
# create response are the ONLY way to operate on/delete the tailnet. We persist
# them to .secrets/last-e2e-tailnet.json immediately after create so a killed
# run can clean up its orphaned tailnet on the next invocation.
set -euo pipefail
cd "$(dirname "$0")/.."

API="${TS_API_BASE_URL:-https://api.tailscale.com}"
LAST_TAILNET_FILE=".secrets/last-e2e-tailnet.json"

if [[ -z "${TS_ORG_TOKEN:-}" ]]; then
  [[ -n "${TS_ORG_CLIENT_ID:-}" && -n "${TS_ORG_CLIENT_SECRET:-}" ]] || {
    echo "need TS_ORG_TOKEN or TS_ORG_CLIENT_ID/SECRET (source .secrets/tailscale.env)" >&2; exit 2; }
  TS_ORG_TOKEN=$(curl -fsS -X POST "$API/api/v2/oauth/token" \
    -d client_id="$TS_ORG_CLIENT_ID" -d client_secret="$TS_ORG_CLIENT_SECRET" | jq -r .access_token)
fi

# ---------------------------------------------------------------------------
# Cleanup leftover tailnet from a previous killed run (best-effort).
# ---------------------------------------------------------------------------
cleanup_leftover() {
  if [[ -f "$LAST_TAILNET_FILE" ]]; then
    local leftover
    leftover=$(cat "$LAST_TAILNET_FILE" 2>/dev/null || echo "")
    if [[ -n "$leftover" && "$leftover" != "null" ]]; then
      local l_dns l_cid l_csec
      l_dns=$(echo "$leftover" | jq -r .dnsName // empty)
      l_cid=$(echo "$leftover" | jq -r .clientId // empty)
      l_csec=$(echo "$leftover" | jq -r .clientSecret // empty)
      if [[ -n "$l_dns" && -n "$l_cid" && -n "$l_csec" ]]; then
        echo "cleaning up leftover tailnet: $l_dns" >&2
        local lt
        lt=$(curl -fsS -X POST "$API/api/v2/oauth/token" \
          -d client_id="$l_cid" -d client_secret="$l_csec" 2>/dev/null | jq -r .access_token 2>/dev/null || echo "")
        if [[ -n "$lt" && "$lt" != "null" ]]; then
          curl -sS -o /dev/null -X DELETE \
            "$API/api/v2/tailnet/$l_dns" -H "Authorization: Bearer $lt" >&2 2>/dev/null || true
          echo "leftover cleanup done" >&2
        fi
      fi
    fi
    rm -f "$LAST_TAILNET_FILE"
  fi
}
cleanup_leftover

# ---------------------------------------------------------------------------
# Create a fresh ephemeral tailnet.
# ---------------------------------------------------------------------------
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

# Immediately persist child creds so a killed run can clean up.
mkdir -p .secrets
jq -n --arg dns "$DNS" --arg cid "$CHILD_CID" --arg csec "$CHILD_CSEC" \
  '{dnsName: $dns, clientId: $cid, clientSecret: $csec}' > "$LAST_TAILNET_FILE"
chmod 600 "$LAST_TAILNET_FILE"

child_token() {
  curl -fsS -X POST "$API/api/v2/oauth/token" \
    -d client_id="$CHILD_CID" -d client_secret="$CHILD_CSEC" | jq -r .access_token
}

# ---------------------------------------------------------------------------
# Cleanup: delete the tailnet and remove the persisted creds file.
# Trap INT, TERM, and EXIT so SIGTERM (e.g. kill from CI) still runs cleanup.
# ---------------------------------------------------------------------------
DNS_VAR="$DNS"
CHILD_CID_VAR="$CHILD_CID"
CHILD_CSEC_VAR="$CHILD_CSEC"

cleanup() {
  echo "deleting tailnet: $DNS_VAR" >&2
  T=$(curl -fsS -X POST "$API/api/v2/oauth/token" \
    -d client_id="$CHILD_CID_VAR" -d client_secret="$CHILD_CSEC_VAR" 2>/dev/null \
    | jq -r .access_token 2>/dev/null || echo "")
  if [[ -n "$T" && "$T" != "null" ]]; then
    curl -sS -o /dev/null -w 'delete HTTP %{http_code}\n' -X DELETE \
      "$API/api/v2/tailnet/$DNS_VAR" -H "Authorization: Bearer $T" >&2 || true
  else
    echo "WARN: could not mint child token for cleanup" >&2
  fi
  rm -f "$LAST_TAILNET_FILE"
}
trap cleanup INT TERM EXIT

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

# Enable HTTPS cert provisioning so the ACME e2e can run (best-effort; the
# test skips itself if CertDomains stays empty). LE staging avoids prod
# rate limits.
if curl -sS -o /dev/null -w '%{http_code}' -X PATCH \
     "$API/api/v2/tailnet/$DNS/settings" \
     -H "Authorization: Bearer $CHILD_TOKEN" -H 'Content-Type: application/json' \
     --data '{"httpsEnabled": true}' | grep -q 200; then
  export TS_E2E_HTTPS=1
  export RUSTSCALE_ACME_URL="${RUSTSCALE_ACME_URL:-https://acme-staging-v02.api.letsencrypt.org/directory}"
else
  echo "WARN: could not enable httpsEnabled; ACME e2e will skip" >&2
fi

# E2E tests are #[ignore]d unit-style tests gated on TS_E2E_* env vars.
cargo test --workspace -- --ignored
