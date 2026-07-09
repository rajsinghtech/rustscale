#!/usr/bin/env bash
# Shared helpers for the tailnet-creation scripts.
# Sourced by the other scripts in this directory — not meant to be run directly.
# shellcheck shell=bash

: "${TS_API_BASE_URL:=https://api.tailscale.com}"

# die <msg> [exit-code]
die() {
  echo "error: $1" >&2
  exit "${2:-1}"
}

# require_env VAR [VAR...]
require_env() {
  local v
  for v in "$@"; do
    [[ -n "${!v:-}" ]] || die "environment variable $v is required" 2
  done
}

# url_encode_form KEY=VAL KEY=VAL ...  →  application/x-www-form-urlencoded body
# Uses jq's @uri filter (RFC 3986 percent-encoding) on each key and value.
url_encode_form() {
  local pair k v enc_k enc_v out=""
  for pair in "$@"; do
    k="${pair%%=*}"
    v="${pair#*=}"
    enc_k="$(jq -nr --arg s "$k" '($s|@uri)')"
    enc_v="$(jq -nr --arg s "$v" '($s|@uri)')"
    out+="${enc_k}=${enc_v}&"
  done
  printf '%s' "${out%&}"
}

# post_form <url> <KEY=VAL> ...  →  stdout: response body
post_form() {
  local url="$1"; shift
  local body
  body="$(url_encode_form "$@")"
  curl -fsS -X POST "$url" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "$body"
}

# extract_access_token <json-body>  →  stdout: access_token (or empty on error)
extract_access_token() {
  jq -r '.access_token // empty' <<<"$1"
}

# mint_org_token  →  stdout: org access token
# Uses TS_ORG_CLIENT_ID with EITHER TS_ORG_CLIENT_SECRET (client_credentials)
# OR TS_OIDC_JWT (WIF token-exchange).
mint_org_token() {
  require_env TS_ORG_CLIENT_ID
  local body token
  if [[ -n "${TS_OIDC_JWT:-}" ]]; then
    body="$(post_form "$TS_API_BASE_URL/api/v2/oauth/token-exchange" \
      "client_id=$TS_ORG_CLIENT_ID" "jwt=$TS_OIDC_JWT")"
  elif [[ -n "${TS_ORG_CLIENT_SECRET:-}" ]]; then
    body="$(post_form "$TS_API_BASE_URL/api/v2/oauth/token" \
      "client_id=$TS_ORG_CLIENT_ID" "client_secret=$TS_ORG_CLIENT_SECRET")"
  else
    die "need either TS_ORG_CLIENT_SECRET or TS_OIDC_JWT" 2
  fi
  token="$(extract_access_token "$body")"
  [[ -n "$token" ]] || die "no access_token in response: $body"
  printf '%s' "$token"
}

# mint_cross_tailnet_token <child-stable-id>  →  stdout: child-scoped access token
# Requires TS_ORG_CLIENT_SECRET (cross-tailnet flow uses client_credentials + tailnet=).
# For WIF, mint an org token first then call /oauth/token with Authorization header.
mint_cross_tailnet_token() {
  local child_id="$1"
  [[ -n "$child_id" ]] || die "child stable id required" 2
  require_env TS_ORG_CLIENT_ID
  local body token
  if [[ -n "${TS_ORG_CLIENT_SECRET:-}" ]]; then
    body="$(post_form "$TS_API_BASE_URL/api/v2/oauth/token" \
      "client_id=$TS_ORG_CLIENT_ID" \
      "client_secret=$TS_ORG_CLIENT_SECRET" \
      "tailnet=$child_id")"
  else
    # WIF path: exchange JWT for org token, then re-mint with tailnet= using Bearer.
    local org_token
    org_token="$(mint_org_token)"
    body="$(curl -fsS -X POST "$TS_API_BASE_URL/api/v2/oauth/token" \
      -H "Authorization: Bearer $org_token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      --data "$(url_encode_form "tailnet=$child_id")")"
  fi
  token="$(extract_access_token "$body")"
  [[ -n "$token" ]] || die "no access_token in cross-tailnet response: $body"
  printf '%s' "$token"
}

# mint_child_token <child-oauth-id> <child-oauth-secret>  →  stdout: child access token
mint_child_token() {
  local cid="$1" csec="$2"
  [[ -n "$cid" && -n "$csec" ]] || die "child oauth id and secret required" 2
  local body token
  body="$(post_form "$TS_API_BASE_URL/api/v2/oauth/token" \
    "client_id=$cid" "client_secret=$csec")"
  token="$(extract_access_token "$body")"
  [[ -n "$token" ]] || die "no access_token in child token response: $body"
  printf '%s' "$token"
}
