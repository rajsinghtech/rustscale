# MagicDNS resolver + LE certs via control + WhoIs (phase 11)

This phase adds three production features to rustscale:

1. **MagicDNS resolver** — `A`/`AAAA` resolution of peer FQDNs and short
   hostnames from the network map, plus an in-process UDP DNS responder at
   the MagicDNS VIP `100.100.100.100:53`.
2. **LE certs via the control plane** — a `ControlCertProvider` implementing
   the existing `CertProvider` trait, with on-disk caching and refresh.
3. **WhoIs** — `Server::whois(ip)` peer-identity lookup, with an FFI export.

## MagicDNS

### Resolver (`crates/dns`)

`MagicDnsResolver` answers queries from the netmap:

- **FQDN match** — `peer.Name` (e.g. `host.tailnet.ts.net.`) compared
  case-insensitively, trailing dot trimmed.
- **Short-name match** — the first label of `peer.Name` (e.g. `host`)
  matches a single-label query. Single-label names are treated as
  tailnet-relative when `DNSConfig.Proxied` is on.
- **Apex / suffix** — names ending in `.<tailnet-domain>` (from
  `MapResponse.Domain`) are tailnet names.

`ResolveOutcome::{Answer, NxDomain, NotTailnet}` drives the responder's
decision: answer from the netmap, NXDOMAIN for unknown tailnet names, or
forward to an upstream resolver. Both `Server::dial("hostname:port")` and
the DNS responder share `MagicDnsResolver` so resolution is unified.

### UDP responder (`100.100.100.100:53`)

`DnsResponder` binds a UDP socket (default `100.100.100.100:53`, the
MagicDNS VIP) and:

- answers `A`/`AAAA` for peer FQDNs and short hostnames,
- returns `NXDOMAIN` (RCODE 3) for unknown `*.ts.net` / tailnet-domain names,
- forwards everything else to the upstream system resolver (from
  `DNSConfig.Resolvers`, falling back to `/etc/resolv.conf`, then
  `1.1.1.1`/`8.8.8.8`).

Binding to `:53` typically requires root and the MagicDNS VIP to be
assigned to a local interface, so the responder is **best-effort** in
`up()`: if the bind fails, `dial` still resolves hostnames via the shared
resolver (the OS-side DNS path is only needed when external processes query
MagicDNS).

### TUN mode — pointing the OS DNS at `100.100.100.100`

In TUN mode (`up_tun`), the OS resolver must be configured to use
`100.100.100.100` for MagicDNS to work for system-wide name resolution.
The responder is implemented; the OS DNS wiring is a follow-up. The
required OS configuration:

- **Linux** (systemd-resolved): `resolvectl dns <tun-iface>
  100.100.100.100` and `resolvectl domain <tun-iface> ~<tailnet-domain>`.
  Or write `/etc/resolv.conf` with `nameserver 100.100.100.100` and
  `search <tailnet-domain>` (the tailscaled approach uses
  `systemd-resolved` DBus when available).
- **macOS**: `scutil --dns` to inspect; set via `networksetup
  -setdnsservers <service> 100.100.100.100`, or via a `resolv.conf`
  override under `/etc/resolver/<tailnet-domain>` containing
  `nameserver 100.100.100.100`.

Because `100.100.100.100` is not assigned to the TUN interface by default,
the TUN bring-up must also add it as a local address (e.g. on macOS
`ifconfig <tun> inet 100.100.100.100/32 alias`, on Linux `ip addr add
100.100.100.100/32 dev <tun>`) so the OS routes queries for the VIP into
the TUN device where the responder reads them. This alias + OS-DNS
configuration is not yet automated by `up_tun`; it will be added with the
netmon/port-mapping phases.

## LE certs via the control plane

### Flow found in Go (`ipn/ipnlocal/cert.go`)

`GetCertPEM(domain)` does **not** fetch the cert through a control-plane
"cert endpoint". The flow is:

1. `resolveCertDomain(domain)` validates `domain` against
   `netmap.DNS.CertDomains` — the DNS names for which control will assist.
   A non-empty `MapResponse.DNSConfig.CertDomains` means the tailnet has
   HTTPS/certs enabled.
2. The client speaks **ACME directly to Let's Encrypt**
   (`acme.Client{DirectoryURL: acme.LetsEncryptURL}`). There is no
   `/machine/cert` endpoint.
3. For `*.ts.net` domains the challenge is **DNS-01**: the client computes
   the `_acme-challenge.<domain>` TXT record and asks control to publish it
   via `POST /machine/set-dns` with a `SetDNSRequest{Name:
   "_acme-challenge.<domain>", Type: "TXT", Value: <record>}`. Control owns
   the `ts.net` DNS zone, so it publishes the TXT record that Let's Encrypt
   then validates.
4. For bring-your-own Funnel domains the challenge is **TLS-ALPN-01**,
   served on the node's own TLS listener (Funnel).

So control's role is **only** the DNS-01 TXT record publication via
`SetDNS`. The ACME protocol (order/authorize/finalize) runs
client↔Let's Encrypt directly.

### What rustscale implements

- **`tailcfg`**: `DNSConfig` (with `CertDomains`, `Resolvers`, `Domains`,
  `Proxied`, `ExtraRecords`), `UserProfile`, `SetDNSRequest`/`SetDNSResponse`,
  `dnstype.Resolver`; `MapResponse.DNSConfig` + `MapResponse.UserProfiles`.
- **`controlclient`**: `ControlClient::set_dns()` — `POST /machine/set-dns`
  (the real control-plane piece of the cert flow).
- **`tsnet::tls`**: `ControlCertProvider` implementing `CertProvider`:
  - caches cert+key PEM in `state_dir` (`<fqdn>.crt.pem` / `<fqdn>.key.pem`
    + `<fqdn>.expiry` sidecar, mirroring Go's `certFileStore`),
  - refreshes when the cached cert is missing or within **14 days** of
    expiry,
  - serves a still-valid stale cache if a refresh fetch fails,
  - uses a pluggable `CertFetcher` trait (mockable for tests).
- **`AcmeCertFetcher`**: detects `CertError::NotEnabled` (FQDN not in
  `CertDomains`) and `CertError::AcmeClientUnavailable` (HTTPS enabled but
  the ACME-to-LE HTTP client is not yet ported). The `SetDNS` call is wired;
  the ACME order/finalize step is a follow-up phase.
- **`Server::listen_tls`** tries `control_cert_provider()` first; on any
  error it falls back to a self-signed per-node cert with a warning, so
  `listen_tls` always works.
- **`Server::control_cert_provider()`** returns the typed `CertError` so
  callers can distinguish "not enabled" from other failures.

Until the ACME HTTP client is ported, real LE certs are not produced; the
value of this phase is the cache/refresh structure, the control-plane
`SetDNS` integration, the "HTTPS enabled?" detection, and the clean
fallback. Ephemeral API-only tailnets do not have HTTPS enabled, so the e2e
test (`e2e_control_cert_not_enabled`) asserts a clean `NotEnabled` (or
`AcmeClientUnavailable`) error.

## WhoIs

`Server::whois(ip: IpAddr) -> Option<WhoIsInfo>` looks up the source IP in
the netmap peers (matching `Node.Addresses`) and returns the peer's
MagicDNS name, tailscale IPs, and the owning user's login/display name
(from `MapResponse.UserProfiles` keyed by `Node.User`).

`WhoIsInfo` is a plain `Serialize` struct of primitives — C-representable.
The FFI export `ts_whois(handle, addr, buf, len)` returns JSON:

```json
{"found":true,"node_name":"host.tailnet.ts.net.",
 "tailscale_ips":["100.64.0.5"],"user_id":7,
 "login_name":"bob@example.com","display_name":"Bob"}
```

`found:false` is returned when no peer matches (or the server is not up).
