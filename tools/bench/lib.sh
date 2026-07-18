#!/usr/bin/env bash
# tools/bench/lib.sh — shared ephemeral-tailnet provisioning for bench harnesses.
#
# Sourced by run-local.sh and run-tailscaled.sh. NOT meant to be run directly.
# Factored from tools/e2e.sh — does NOT modify tools/e2e.sh.
#
# Auth (either):
#   TS_ORG_TOKEN                            — pre-minted org token (CI/WID path)
#   TS_ORG_CLIENT_ID + TS_ORG_CLIENT_SECRET — OAuth client creds (local path;
#                                             `source .secrets/tailscale.env`)
#
# After sourcing, call:
#   bench_provision_tailnet   — creates tailnet, sets globals, traps cleanup
#   bench_mint_authkey [BOOL] — mints a reusable authkey (ephemeral by default)
#   bench_cleanup_tailnet     — explicit cleanup (also called via EXIT trap)
#
# Globals set by bench_provision_tailnet:
#   BENCH_DNS         — tailnet DNS name
#   BENCH_CHILD_CID   — child oauth client id
#   BENCH_CHILD_CSEC  — child oauth client secret
#   BENCH_CHILD_TOKEN — child-scoped access token
#   BENCH_API         — API base URL

# shellcheck shell=bash
: "${TS_API_BASE_URL:=https://api.tailscale.com}"
BENCH_API="${TS_API_BASE_URL}"
BENCH_LAST_FILE=".secrets/last-bench-tailnet.json"

# ---------------------------------------------------------------------------
# Internal: cleanup leftover tailnet from a previous killed run (best-effort).
# ---------------------------------------------------------------------------
_bench_cleanup_leftover() {
  if [[ -f "$BENCH_LAST_FILE" ]]; then
    local leftover
    leftover=$(cat "$BENCH_LAST_FILE" 2>/dev/null || echo "")
    if [[ -n "$leftover" && "$leftover" != "null" ]]; then
      local l_dns l_cid l_csec
      l_dns=$(echo "$leftover" | jq -r '.dnsName // empty')
      l_cid=$(echo "$leftover" | jq -r '.clientId // empty')
      l_csec=$(echo "$leftover" | jq -r '.clientSecret // empty')
      if [[ -n "$l_dns" && -n "$l_cid" && -n "$l_csec" ]]; then
        echo "[bench] cleaning up leftover tailnet: $l_dns" >&2
        local lt
        lt=$(curl -fsS -X POST "$BENCH_API/api/v2/oauth/token" \
          -d client_id="$l_cid" -d client_secret="$l_csec" 2>/dev/null \
          | jq -r .access_token 2>/dev/null || echo "")
        if [[ -n "$lt" && "$lt" != "null" ]] &&
          curl -fsS --retry 3 --retry-delay 3 --retry-all-errors \
            -o /dev/null -X DELETE \
            "$BENCH_API/api/v2/tailnet/$l_dns" -H "Authorization: Bearer $lt" \
            >&2 2>/dev/null; then
          rm -f "$BENCH_LAST_FILE"
          return 0
        fi
      fi
    fi
    echo "[bench] leftover tailnet cleanup failed; preserving $BENCH_LAST_FILE" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Provision a fresh ephemeral tailnet. Sets globals and traps cleanup.
# ---------------------------------------------------------------------------
bench_provision_tailnet() {
  # Resolve org token.
  if [[ -z "${TS_ORG_TOKEN:-}" ]]; then
    [[ -n "${TS_ORG_CLIENT_ID:-}" && -n "${TS_ORG_CLIENT_SECRET:-}" ]] || {
      echo "[bench] need TS_ORG_TOKEN or TS_ORG_CLIENT_ID/SECRET" >&2; return 2; }
    TS_ORG_TOKEN=$(curl -fsS -X POST "$BENCH_API/api/v2/oauth/token" \
      -d client_id="$TS_ORG_CLIENT_ID" -d client_secret="$TS_ORG_CLIENT_SECRET" \
      | jq -r .access_token)
  fi

  _bench_cleanup_leftover

  local name created=""
  for attempt in 1 2 3 4 5; do
    name="rustscale-bench-$(date +%s)-$attempt"
    echo "[bench] creating ephemeral tailnet: $name (attempt $attempt)" >&2
    created=$(curl -fsS --retry 3 --retry-delay 3 --retry-all-errors \
      -X POST "$BENCH_API/api/v2/organizations/-/tailnets" \
      -H "Authorization: Bearer $TS_ORG_TOKEN" -H 'Content-Type: application/json' \
      -d "{\"displayName\":\"$name\"}" 2>/dev/null) && break
    echo "[bench] attempt $attempt failed, retrying..." >&2
    sleep $((attempt * 3))
  done

  BENCH_DNS=$(echo "$created" | jq -r .dnsName)
  BENCH_CHILD_CID=$(echo "$created" | jq -r .oauthClient.id)
  BENCH_CHILD_CSEC=$(echo "$created" | jq -r .oauthClient.secret)
  [[ -n "$BENCH_DNS" && "$BENCH_DNS" != null && -n "$BENCH_CHILD_CSEC" && "$BENCH_CHILD_CSEC" != null ]] || {
    echo "[bench] create failed: $created" >&2; return 1; }
  echo "[bench] created: $BENCH_DNS" >&2

  # Persist child creds immediately for leak protection.
  mkdir -p .secrets
  jq -n --arg dns "$BENCH_DNS" --arg cid "$BENCH_CHILD_CID" --arg csec "$BENCH_CHILD_CSEC" \
    '{dnsName: $dns, clientId: $cid, clientSecret: $csec}' > "$BENCH_LAST_FILE"
  chmod 600 "$BENCH_LAST_FILE"

  # Mint child-scoped token.
  BENCH_CHILD_TOKEN=$(curl -fsS -X POST "$BENCH_API/api/v2/oauth/token" \
    -d client_id="$BENCH_CHILD_CID" -d client_secret="$BENCH_CHILD_CSEC" \
    | jq -r .access_token)

  # Set all-to-all grants; API-owned tailnets use autogroup:admin to own tag:e2e.
  curl -fsS --retry 3 --retry-delay 3 --retry-all-errors \
    -X POST "$BENCH_API/api/v2/tailnet/$BENCH_DNS/acl" \
    -H "Authorization: Bearer $BENCH_CHILD_TOKEN" -H 'Content-Type: application/json' \
    -d '{"tagOwners":{"tag:e2e":["autogroup:admin"]},"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}' >/dev/null

  trap bench_cleanup_tailnet INT TERM EXIT
}

# ---------------------------------------------------------------------------
# Mint a reusable preauthorized authkey. The optional argument is the JSON
# boolean controlling ephemeral device enrollment (default: true). Prints the
# key to stdout.
# ---------------------------------------------------------------------------
bench_mint_authkey() {
  local ephemeral="${1:-true}"
  (( $# <= 1 )) && [[ "$ephemeral" == true || "$ephemeral" == false ]] || {
    echo "[bench] authkey ephemerality must be true or false" >&2
    return 2
  }
  # Refresh a child-scoped token from the child OAuth client creds on every
  # call. The access token minted at provision time expires (~1h), so over a
  # ~40-min matrix the later per-config mints 401 with a stale token. The
  # client creds themselves don't expire, so re-derive the token each time.
  if [[ -n "${BENCH_CHILD_CID:-}" && -n "${BENCH_CHILD_CSEC:-}" ]]; then
    BENCH_CHILD_TOKEN=$(curl -fsS -X POST "$BENCH_API/api/v2/oauth/token" \
      -d client_id="$BENCH_CHILD_CID" -d client_secret="$BENCH_CHILD_CSEC" \
      | jq -r .access_token)
  fi
  local key
  # A full 5-point, 3-repeat userspace cell can exceed 15 minutes. Keep the
  # key valid for the bounded matrix; the caller chooses whether control may
  # reap disconnected devices before the disposable tailnet is deleted.
  key=$(curl -fsS --retry 3 --retry-delay 3 --retry-all-errors \
    -X POST "$BENCH_API/api/v2/tailnet/$BENCH_DNS/keys" \
    -H "Authorization: Bearer $BENCH_CHILD_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"capabilities\":{\"devices\":{\"create\":{\"reusable\":true,\"ephemeral\":$ephemeral,\"preauthorized\":true,\"tags\":[\"tag:e2e\"]}}},\"expirySeconds\":7200}" \
    | jq -r .key)
  [[ -n "$key" && "$key" != null ]] || { echo "[bench] authkey mint failed" >&2; return 1; }
  echo "$key"
}

# ---------------------------------------------------------------------------
# Cleanup: delete the tailnet and remove the persisted creds file.
# ---------------------------------------------------------------------------
bench_cleanup_tailnet() {
  if [[ -n "${BENCH_DNS:-}" ]]; then
    echo "[bench] deleting tailnet: $BENCH_DNS" >&2
    local t
    t=$(curl -fsS -X POST "$BENCH_API/api/v2/oauth/token" \
      -d client_id="$BENCH_CHILD_CID" -d client_secret="$BENCH_CHILD_CSEC" 2>/dev/null \
      | jq -r .access_token 2>/dev/null || echo "")
    if [[ -n "$t" && "$t" != "null" ]] &&
      curl -fsS --retry 3 --retry-delay 3 --retry-all-errors \
        -o /dev/null -X DELETE \
        "$BENCH_API/api/v2/tailnet/$BENCH_DNS" -H "Authorization: Bearer $t" >&2; then
      rm -f "$BENCH_LAST_FILE"
      BENCH_DNS=""
      return 0
    fi
    echo "[bench] tailnet cleanup failed; preserving $BENCH_LAST_FILE" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Wait for a line matching a pattern in a file. Used to sync server/client.
#   _bench_wait_for_pattern <file> <pattern> [timeout_secs]
# ---------------------------------------------------------------------------
_bench_wait_for_pattern() {
  local file="$1" pattern="$2" timeout="${3:-120}"
  local elapsed=0
  while (( elapsed < timeout )); do
    if grep -q "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    sleep 1
    (( elapsed++ ))
  done
  echo "[bench] timed out waiting for '$pattern' in $file (${timeout}s)" >&2
  return 1
}
