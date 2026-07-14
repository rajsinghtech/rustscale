# Wire fixtures

Go-produced wire-protocol byte fixtures for the rustscale wire-compat
regression harness. Each fixture captures Go's `encoding/json` (or binary
encode) output for a specific wire type; the Rust tests in
`tests/wire_compat.rs` deserialize and re-serialize to assert byte-identical
output.

## Regenerating

```bash
tools/gen-wire-fixtures.sh
```

This writes a temporary Go module, downloads the pinned `tailscale.com` module
published from `github.com/tailscale/tailscale`, and writes fixtures to this
directory. Requirements:

- Go 1.26+

Override paths via environment:
```bash
TAILSCALE_GO_VERSION=v1.100.0 GO_BIN=/path/to/go tools/gen-wire-fixtures.sh
```

## Fixture inventory

### Go-generated JSON fixtures (19)

| File | Type | Comparison |
|------|------|------------|
| `node_full.json` | `tailcfg.Node` | byte-identical |
| `hostinfo_full.json` | `tailcfg.Hostinfo` | byte-identical* |
| `derp_map_full.json` | `tailcfg.DERPMap` | byte-identical |
| `dns_config_full.json` | `tailcfg.DNSConfig` | byte-identical |
| `map_request_minimal.json` | `tailcfg.MapRequest` | byte-identical |
| `map_request_full.json` | `tailcfg.MapRequest` | byte-identical |
| `map_response_full.json` | `tailcfg.MapResponse` | byte-identical |
| `map_response_peers_changed.json` | `tailcfg.MapResponse` | byte-identical |
| `map_response_peers_removed.json` | `tailcfg.MapResponse` | byte-identical |
| `map_response_peer_change_patch.json` | `tailcfg.MapResponse` | byte-identical |
| `peer_change_full.json` | `tailcfg.PeerChange` | byte-identical |
| `client_version_full.json` | `tailcfg.ClientVersion` | byte-identical |
| `user_profile_full.json` | `tailcfg.UserProfile` | byte-identical |
| `net_info_full.json` | `tailcfg.NetInfo` | byte-identical |
| `filter_full.json` | `tailcfg.FilterRule` | byte-identical |
| `null_slice.json` | `tailcfg.MapResponse` | byte-identical |
| `register_request_full.json` | `tailcfg.RegisterRequest` | subset† |
| `register_request_minimal.json` | `tailcfg.RegisterRequest` | subset† |
| `register_response_full.json` | `tailcfg.RegisterResponse` | subset† |

### Hand-constructed JSON fixtures (1)

| File | Type | Reason |
|------|------|--------|
| `ssh_policy_full.json` | `tailcfg.SSHPolicy` | Go uses camelCase json keys (`"rules"`, `"principals"`, `"sshUsers"`, `"action"`) but rustscale uses PascalCase (`"Rules"`, `"Principals"`, `"SSHUsers"`, `"Action"`). Fixture uses Rust's PascalCase keys to verify Rust roundtrips its own format. See bug #3 in `tests/wire_compat.rs` module docs. |

### Binary fixtures (5)

| File | Type | Encoder |
|------|------|---------|
| `disco_ping.bin` | `disco.Ping` | `disco.Ping.AppendMarshal` |
| `disco_pong.bin` | `disco.Pong` | `disco.Pong.AppendMarshal` |
| `disco_call_me_maybe.bin` | `disco.CallMeMaybe` | `disco.CallMeMaybe.AppendMarshal` |
| `derp_frame.bin` | DERP frame | manual: type byte + 4-byte BE len + payload |
| `stun_binding_response.bin` | STUN binding response | `stun.Response` |

## Notes

\* **byte-identical** comparison uses `serde_json::Value` (BTreeMap,
alphabetically sorted keys) to canonicalize both the Go fixture and the Rust
re-serialization before comparing. This normalizes key order, so field-order
divergence between Go and Rust structs is NOT caught. See bug #6 in
`tests/wire_compat.rs` module docs for the known Hostinfo field-order
mismatch.

† **subset** comparison only checks keys that Rust produces — extra Go-only
fields (with no `omitempty` tag) are ignored. This is used for types where
rustscale doesn't model all Go fields. See bugs #1, #2 in
`tests/wire_compat.rs` module docs.
