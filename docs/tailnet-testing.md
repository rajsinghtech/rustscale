# Ephemeral tailnets for e2e testing

Verified live on 2026-07-08. Two auth paths: local uses OAuth client creds from
`.secrets/tailscale.env` (gitignored); CI uses GitHub OIDC / Workload Identity
Federation with the same WIF client tailgate uses (no secret in CI).

## Critical constraint (learned the hard way)

The local org client (`ktAr67Hi6611CNTRL`) has **only the `tailnets` scope**, so:
- ✅ it can create/list tailnets (`POST/GET /api/v2/organizations/-/tailnets`)
- ❌ the cross-tailnet token flow (`-d tailnet=<id>`) returns
  `403 client does not have the all scope`
- ➜ **You MUST capture `oauthClient.id` + `oauthClient.secret` from the create
  response** — that child client is the ONLY way to operate on/delete the tailnet.
  Lose it and the tailnet is stuck forever (we already leaked
  `tail9af23c.ts.net` / `TL8qKinDFt11CNTRL` this way — do not repeat).

## Local flow (verified working)

```bash
source .secrets/tailscale.env   # TS_ORG_CLIENT_ID / TS_ORG_CLIENT_SECRET / TS_API_BASE_URL

ORG_TOKEN=$(tools/tailnet/ts-org-token.sh)
CREATED=$(tools/tailnet/ts-create-tailnet.sh "$ORG_TOKEN" "rustscale-e2e-$(date +%s)")
DNS=$(echo "$CREATED" | jq -r .dnsName)
CHILD_CID=$(echo "$CREATED" | jq -r .oauthClient.id)
CHILD_CSEC=$(echo "$CREATED" | jq -r .oauthClient.secret)

# Child-scoped token (all scope on the child) — works for every
# /api/v2/tailnet/$DNS/* call: ACL, auth keys, devices, DELETE.
CHILD_TOKEN=$(curl -fsS -X POST "$TS_API_BASE_URL/api/v2/oauth/token" \
  -d client_id="$CHILD_CID" -d client_secret="$CHILD_CSEC" | jq -r .access_token)

# e.g. mint a device auth key for the rust client under test.
# API-only tailnets have no human owner, so keys MUST be tagged; make
# autogroup:admin own tag:e2e and allow all-to-all grants:
curl -fsS -X POST "$TS_API_BASE_URL/api/v2/tailnet/$DNS/acl" \
  -H "Authorization: Bearer $CHILD_TOKEN" -H 'Content-Type: application/json' \
  -d '{"tagOwners":{"tag:e2e":["autogroup:admin"]},"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}'
AUTHKEY=$(curl -fsS -X POST "$TS_API_BASE_URL/api/v2/tailnet/$DNS/keys" \
  -H "Authorization: Bearer $CHILD_TOKEN" -H 'Content-Type: application/json' \
  -d '{"capabilities":{"devices":{"create":{"reusable":true,"ephemeral":true,"preauthorized":true,"tags":["tag:e2e"]}}},"expirySeconds":3600}' \
  | jq -r .key)

# ALWAYS clean up (trap this in test scripts):
tools/tailnet/ts-delete-tailnet.sh "$CHILD_TOKEN" "$DNS"
```

Tokens expire in 1h; re-mint per test run, never cache.

## CI flow (GitHub Actions, WIF — same client tailgate uses)

No secret in CI. Requires `permissions: id-token: write` and works only on
`rajsinghtech/*` repos (the WIF subject binding is `repo:rajsinghtech*`) — skip
the job on forks. Pattern (from tailgate `.github/workflows/test-e2e.yml`):

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - name: Mint Tailscale org token via GitHub OIDC (WIF)
    id: tsauth
    run: |
      AUD="api.tailscale.com/TbqNGJkY5611CNTRL-kz4CwX2LK721CNTRL"
      JWT=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$AUD" | jq -r '.value')
      echo "::add-mask::$JWT"
      TOKEN=$(curl -sS -X POST https://api.tailscale.com/api/v2/oauth/token-exchange \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d 'client_id=TbqNGJkY5611CNTRL-kz4CwX2LK721CNTRL' -d "jwt=$JWT" | jq -r '.access_token')
      if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then echo "OIDC token-exchange failed" >&2; exit 1; fi
      echo "::add-mask::$TOKEN"
      echo "token=$TOKEN" >> "$GITHUB_OUTPUT"
```

Then use `${{ steps.tsauth.outputs.token }}` as the ORG token to create a tailnet,
and the child `oauthClient` creds from the create response for everything else
(same constraint as local unless the WIF client has `all` scope — if a
cross-tailnet mint 403s in CI, fall back to child creds).

Guard the job with `if: github.repository == 'rajsinghtech/rustscale'`.

## Scripts

`tools/tailnet/*.sh` are vendored from the tailnet-creation skill:
`ts-org-token.sh`, `ts-create-tailnet.sh`, `ts-child-token.sh`,
`ts-delete-tailnet.sh` (idempotent, 404 = already gone), `ts-list-tailnets.sh`,
`ts-oidc-token.sh`. `ts-cross-tailnet-token.sh` is unusable with the current
`tailnets`-scope client (see constraint above).

## Rules for test code / agents

1. Every test that creates a tailnet must delete it in cleanup (trap EXIT).
2. Persist the child oauthClient creds for the tailnet's whole lifetime.
3. Name tailnets `rustscale-<purpose>-<unix ts>` so leaks are identifiable.
4. Never commit `.secrets/`.

## Tailnet settings API (verified live 2026-07-09)

The child oauthClient CAN update its own tailnet's settings via
`PATCH /api/v2/tailnet/<id>/settings` (200, takes effect immediately):

```bash
CHILD_TOKEN=$(tools/tailnet/ts-child-token.sh "$CID" "$CSEC")
curl -X PATCH "$TS_API_BASE_URL/api/v2/tailnet/$TID/settings" \
  -H "Authorization: Bearer $CHILD_TOKEN" -H 'Content-Type: application/json' \
  --data '{"httpsEnabled": true}'
```

Notable settings: `httpsEnabled` (enables HTTPS cert provisioning — after
this, `MapResponse.DNSConfig.CertDomains` is populated and the ACME DNS-01
flow via `/machine/set-dns` can be e2e-tested on an ephemeral tailnet),
`devicesApprovalOn`, `devicesKeyDurationDays`, `regionalRoutingOn`,
`networkFlowLoggingOn`. This removes the old "API-only tailnets can't test
HTTPS" limitation that deferred the ACME order client in port-1.

## Interop e2e (rustscale <-> Go tailscaled)

Cross-client interoperability tests prove rustscale negotiates every path
type (DERP, direct, path upgrade) and wire protocol (disco, WG handshake,
MagicDNS) against the real Go `tailscaled` — the strongest wire-compat check.
All interop tests are `#[ignore]`d and gated on `TS_INTEROP_GO_IP`; they skip
cleanly when that env var is absent, so `cargo test -- --ignored` under plain
`tools/e2e.sh` stays green.

### Local

```bash
source .secrets/tailscale.env && tools/interop.sh
```

`tools/interop.sh` provisions an ephemeral tailnet (reusing `tools/bench/lib.sh`),
starts one Go `tailscaled` in userspace-networking mode (hostname
`go-interop-<pid>`, SOCKS5 on `127.0.0.1:11080`, state in a `mktemp` dir),
exposes a `tailscale serve --tcp` echo forwarder, advertises + approves a
subnet route (`10.99.0.0/24`), exports `TS_INTEROP_*` + `TS_E2E_*` env vars,
then runs `cargo test -p rustscale-tsnet -- --ignored interop_`. Cleanup is
trapped (INT/TERM/EXIT): kill `tailscaled` by PID, delete the tailnet, remove
state dirs.

Requires: `tailscaled` + `tailscale` on `$PATH`, `python3`, `curl`, `jq`.

### CI

The `interop` job in `.github/workflows/e2e.yml` installs the Go tailscale
client via `curl -fsSL https://tailscale.com/install.sh | sh`, mints the WIF
org token (same as core e2e), and runs `tools/interop.sh`. Guarded by
`if: github.repository == 'rajsinghtech/rustscale'`.

### Exported env vars

| Var | Description |
|-----|-------------|
| `TS_INTEROP_GO_IP` | Go node's tailnet IPv4 |
| `TS_INTEROP_GO_NAME` | Go node's MagicDNS FQDN (trailing dot) |
| `TS_INTEROP_GO_ECHO_PORT` | Tailnet port the Go node serves echo on |
| `TS_INTEROP_SOCKS` | Go node's SOCKS5 proxy (`127.0.0.1:11080`) |
| `TS_INTEROP_GO_SUBNET` | Subnet the Go node advertises (`10.99.0.0/24`) |

### Test-support flag: `disable_direct_paths`

`ServerBuilder::disable_direct_paths(true)` (backed by
`MagicsockConfig::disable_direct_paths`) suppresses all direct-path
establishment and forces every send via DERP. Disco pings are not sent,
CallMeMaybe-initiated pings are skipped, and inbound disco Pings over UDP are
not answered — so neither side confirms a direct path. This pins both
directions to DERP, letting `interop_derp_path` assert relayed connectivity
in isolation. Production code should leave this false.

## TUN-mode interop (rustscale TUN <-> Go tailscaled)

TUN-mode interop tests exercise the real OS TUN device + kernel routing +
packet filter on raw IP packets — a different data plane from the netstack
tests. The WG/disco/DERP/MagicDNS wire protocol is shared, so TUN tests
focus on the TUN-specific surface: TUN read/write, OS route installation,
filter-on-raw-IP, and subnet-route OS forwarding.

### Three layers

**Layer 1 — TUN pump unit tests** (no root, no Go): MockTun devices wired
to real WG tunnels via in-memory cross-feeding. Tests the pump logic
(encapsulate/decapsulate/filter) without any OS dependency. Runs as regular
`cargo test` (not ignored).

**Layer 2 — TUN interop with Go in userspace mode** (root for TUN, Go stays
userspace): `tools/interop-tun.sh` provisions a tailnet, starts Go
tailscaled in userspace mode (same as `tools/interop.sh`), then runs the
`interop_tun_` test suite under `sudo` so rustscale can create a real TUN
device and apply OS routes. Tests use OS sockets (`tokio::net::TcpStream`)
instead of `Server::dial`/`Server::listen` — traffic flows through the
kernel TCP stack and the TUN device, exercising the full TUN pump.

```bash
source .secrets/tailscale.env && sudo tools/interop-tun.sh
```

Tests: `interop_tun_rust_dials_go`, `interop_tun_go_dials_rust`,
`interop_tun_os_routes`, `interop_tun_subnet_forward`. All skip cleanly
when `TS_INTEROP_GO_IP` is absent or not running as root.

**Layer 3 — Full TUN both sides** (Linux netns, CI-only):
`tools/interop-tun-full.sh` runs both rustscale and Go tailscaled in real
TUN mode inside isolated network namespaces connected via a veth bridge.
This tests subnet-route forwarding and exit-node data-path where Go also
needs a kernel interface. Linux-only, requires root + `iproute2`.

```bash
sudo tools/interop-tun-full.sh
```

### CI

The `interop-tun` job in `.github/workflows/e2e.yml` runs Layer 2 on Linux
with `sudo -E tools/interop-tun.sh`. Guarded by
`if: github.repository == 'rajsinghtech/rustscale'`.
