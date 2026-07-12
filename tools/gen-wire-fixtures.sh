#!/usr/bin/env bash
# tools/gen-wire-fixtures.sh — regenerate Go wire-compat fixtures.
#
# Writes a temporary Go program that imports tailscale.com/tailcfg and
# related packages, constructs each wire type with representative values,
# and marshals to crates/wire-fixture/fixtures/*.json and *.bin.
#
# Usage:
#   tools/gen-wire-fixtures.sh
#
# Requirements:
#   - Go 1.26+ at /opt/homebrew/bin/go (or on $PATH)
#   - The Tailscale Go repo at /Users/rajsingh/Documents/GitHub/tailscale
set -euo pipefail

GO_REPO="${TAILSCALE_GO_REPO:-/Users/rajsingh/Documents/GitHub/tailscale}"
GO_BIN="${GO_BIN:-/opt/homebrew/bin/go}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/crates/wire-fixture/fixtures"

GEN_FILE="/tmp/gen_wire_fixtures.go"

cat > "$GEN_FILE" << 'GOEOF'
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
)

func main() {
	outDir := os.Args[1]

	nodePriv := key.NewNode()
	nodePub := nodePriv.Public()
	machinePriv := key.NewMachine()
	machinePub := machinePriv.Public()
	discoPriv := key.NewDisco()
	discoPub := discoPriv.Public()

	ts2025, _ := time.Parse(time.RFC3339, "2025-12-31T23:59:59Z")
	ts2024, _ := time.Parse(time.RFC3339, "2024-01-01T00:00:00Z")
	ts2025jul, _ := time.Parse(time.RFC3339, "2025-07-12T10:00:00Z")

	// ─── JSON fixtures ───

	// 1. node_full.json
	node := tailcfg.Node{
		ID:           42,
		StableID:     "nodeABC",
		Name:         "host.tail-scale.ts.net.",
		User:         7,
		Key:          nodePub,
		KeyExpiry:    ts2025,
		Machine:      machinePub,
		DiscoKey:     discoPub,
		Addresses:    []netip.Prefix{mustPrefix("100.64.0.1/32"), mustPrefix("fd7a:115c:a1e0::1/128")},
		AllowedIPs:   []netip.Prefix{mustPrefix("100.64.0.1/32")},
		Endpoints:    []netip.AddrPort{mustAddrPort("1.2.3.4:5")},
		HomeDERP:     1,
		Hostinfo: (&tailcfg.Hostinfo{
			IPNVersion:  "1.99.0",
			OS:          "linux",
			Hostname:    "host",
			RoutableIPs: []netip.Prefix{mustPrefix("192.168.1.0/24")},
			Services: []tailcfg.Service{
				{Proto: "peerapi4", Port: 1234},
			},
		}).View(),
		Created:  ts2024,
		Cap:      999,
		Tags:     []string{"tag:prod"},
		LastSeen: &ts2025jul,
		Online:   boolPtr(true),
	}
	writeJSON(filepath.Join(outDir, "node_full.json"), node)

	// 2. hostinfo_full.json
	hostinfo := tailcfg.Hostinfo{
		IPNVersion:      "1.99.0",
		FrontendLogID:   "fe-log-id-abc",
		BackendLogID:    "be-log-id-xyz",
		OS:              "linux",
		OSVersion:       "5.15.0-25-generic",
		Container:       opt.True,
		Env:             "k8s",
		Distro:          "ubuntu",
		DistroVersion:   "22.04",
		DistroCodeName:  "jammy",
		App:             "tsnet",
		Desktop:         opt.False,
		Package:         "snap",
		DeviceModel:     "x86_64",
		PushDeviceToken: "abc123token",
		Hostname:        "myhost",
		ShieldsUp:       true,
		WireIngress:     true,
		IngressEnabled:  false,
		AllowsUpdate:    true,
		Machine:         "x86_64",
		GoArch:          "amd64",
		GoArchVar:       "v3",
		GoVersion:       "go1.26.4",
		RoutableIPs:     []netip.Prefix{mustPrefix("10.0.0.0/8")},
		RequestTags:     []string{"tag:server"},
		WoLMACs:         []string{"aa:bb:cc:dd:ee:ff"},
		Services: []tailcfg.Service{
			{Proto: "tcp", Port: 80, Description: "http"},
			{Proto: "peerapi4", Port: 1234},
		},
		Cloud:           "aws",
		Userspace:       opt.True,
		UserspaceRouter: opt.False,
		AppConnector:    opt.False,
		PeerRelay:       true,
		ServicesHash:    "deadbeef1234",
		ExitNodeID:      "nodeXYZ123",
	}
	writeJSON(filepath.Join(outDir, "hostinfo_full.json"), hostinfo)

	// 3. derp_map_full.json
	derpMap := tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "nyc",
				RegionName: "New York City",
				Latitude:   40.71,
				Longitude:  -74.01,
				Nodes: []*tailcfg.DERPNode{
					{Name: "1a", RegionID: 1, HostName: "derp1.tailscale.com", STUNPort: 3478, DERPPort: 443},
					{Name: "1b", RegionID: 1, HostName: "derp2.tailscale.com", STUNOnly: true},
				},
			},
			9: {
				RegionID:   9,
				RegionCode: "sin",
				RegionName: "Singapore",
				Nodes:      nil,
			},
		},
	}
	writeJSON(filepath.Join(outDir, "derp_map_full.json"), derpMap)

	// 4. dns_config_full.json
	dnsConfig := tailcfg.DNSConfig{
		Resolvers:         []*dnstype.Resolver{{Addr: "1.1.1.1"}},
		Routes:            map[string][]*dnstype.Resolver{"corp.example.com.": {{Addr: "10.0.0.53"}}},
		FallbackResolvers: []*dnstype.Resolver{{Addr: "8.8.8.8"}},
		Domains:           []string{"ts.net"},
		Proxied:           true,
		CertDomains:       []string{"node.ts.net"},
		ExtraRecords: []tailcfg.DNSRecord{
			{Name: "app.ts.net", Type: "A", Value: "100.64.0.5"},
		},
	}
	writeJSON(filepath.Join(outDir, "dns_config_full.json"), dnsConfig)

	// 5. map_request_minimal.json
	mapReqMin := tailcfg.MapRequest{
		Version:  1,
		NodeKey:  nodePub,
		DiscoKey: discoPub,
		Hostinfo: &tailcfg.Hostinfo{OS: "linux", Hostname: "host"},
	}
	writeJSON(filepath.Join(outDir, "map_request_minimal.json"), mapReqMin)

	// 6. map_request_full.json
	mapReqFull := tailcfg.MapRequest{
		Version:          999,
		Compress:         "zstd",
		KeepAlive:        true,
		NodeKey:          nodePub,
		DiscoKey:         discoPub,
		Endpoints:        []netip.AddrPort{mustAddrPort("1.2.3.4:5"), mustAddrPort("[::1]:443")},
		EndpointTypes:    []tailcfg.EndpointType{tailcfg.EndpointSTUN, tailcfg.EndpointLocal},
		Stream:           true,
		Hostinfo:         &tailcfg.Hostinfo{OS: "linux", Hostname: "host"},
		OmitPeers:        false,
		ReadOnly:         false,
		DebugFlags:       []string{"warn-ip-forwarding-off"},
		MapSessionHandle: "session-xyz",
		MapSessionSeq:    42,
	}
	writeJSON(filepath.Join(outDir, "map_request_full.json"), mapReqFull)

	// 7. map_response_full.json
	mapRespFull := tailcfg.MapResponse{
		Node:         &node,
		DERPMap:      &derpMap,
		Peers:        []*tailcfg.Node{&node},
		PeersChanged: []*tailcfg.Node{&node},
		Domain:       "example.com",
		DNSConfig:    &dnsConfig,
		UserProfiles: []tailcfg.UserProfile{
			{ID: 7, LoginName: "alice@example.com", DisplayName: "Alice"},
		},
		CollectServices: opt.True,
		ControlTime:     &ts2025jul,
	}
	writeJSON(filepath.Join(outDir, "map_response_full.json"), mapRespFull)

	// 8. map_response_peers_changed.json
	writeJSON(filepath.Join(outDir, "map_response_peers_changed.json"),
		tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{&node}})

	// 9. map_response_peers_removed.json
	writeJSON(filepath.Join(outDir, "map_response_peers_removed.json"),
		tailcfg.MapResponse{PeersRemoved: []tailcfg.NodeID{3, 7, 42}})

	// 10. map_response_peer_change_patch.json
	writeJSON(filepath.Join(outDir, "map_response_peer_change_patch.json"),
		tailcfg.MapResponse{PeersChangedPatch: []*tailcfg.PeerChange{
			{NodeID: 10, DERPRegion: 5},
			{NodeID: 20, Online: boolPtr(false)},
		}})

	// 11. peer_change_full.json
	writeJSON(filepath.Join(outDir, "peer_change_full.json"),
		tailcfg.PeerChange{
			NodeID:     42,
			DERPRegion: 7,
			Cap:        999,
			Endpoints:  []netip.AddrPort{mustAddrPort("1.2.3.4:5")},
			Key:        &nodePub,
			Online:     boolPtr(true),
			LastSeen:   &ts2025jul,
			KeyExpiry:  &ts2025,
		})

	// 12. client_version_full.json
	writeJSON(filepath.Join(outDir, "client_version_full.json"),
		tailcfg.ClientVersion{
			RunningLatest:        false,
			LatestVersion:        "1.99.0",
			UrgentSecurityUpdate: true,
			Notify:               true,
			NotifyURL:            "https://tailscale.com/download",
			NotifyText:           "Update available",
		})

	// 13. user_profile_full.json
	writeJSON(filepath.Join(outDir, "user_profile_full.json"),
		tailcfg.UserProfile{
			ID:            7,
			LoginName:     "alice@example.com",
			DisplayName:   "Alice Smith",
			ProfilePicURL: "https://example.com/a.png",
		})

	// 14. net_info_full.json
	writeJSON(filepath.Join(outDir, "net_info_full.json"),
		tailcfg.NetInfo{
			MappingVariesByDestIP: opt.False,
			WorkingIPv6:           opt.True,
			OSHasIPv6:             opt.True,
			WorkingUDP:            opt.True,
			WorkingICMPv4:         opt.False,
			HavePortMap:           true,
			UPnP:                  opt.False,
			PMP:                   opt.True,
			PCP:                   opt.False,
			PreferredDERP:         3,
			LinkType:              "wifi",
			DERPLatency: map[string]float64{
				"1-v4": 0.012,
				"1-v6": 0.015,
				"9-v4": 0.180,
			},
			FirewallMode: "nft-default",
		})

	// 15. filter_full.json (SrcIPs non-empty to match Rust skip behavior)
	writeJSON(filepath.Join(outDir, "filter_full.json"),
		tailcfg.FilterRule{
			SrcIPs:   []string{"100.64.0.0/10", "*"},
			DstPorts: []tailcfg.NetPortRange{{IP: "1.2.3.4", Ports: tailcfg.PortRange{First: 22, Last: 22}}},
			IPProto:  []int{6, 17},
		})

	// 16. null_slice.json — exercises Go nil slice → null deserialization.
	writeJSON(filepath.Join(outDir, "null_slice.json"),
		tailcfg.MapResponse{Peers: nil, PeersChanged: nil})

	// 17. register_request_full.json — RegisterRequest (has Go-only fields
	// NLKey + NodeKeySignature that rustscale doesn't model; the Rust test
	// uses subset comparison for this fixture).
	regReq := tailcfg.RegisterRequest{
		Version:    999,
		NodeKey:    nodePub,
		OldNodeKey: key.NodePublic{},
		Auth:       &tailcfg.RegisterResponseAuth{AuthKey: "tskey-abc123"},
		Expiry:     ts2025,
		Followup:   "",
		Hostinfo:   &tailcfg.Hostinfo{OS: "linux", Hostname: "host"},
		Ephemeral:  true,
		Tailnet:    "required:example.com",
	}
	writeJSON(filepath.Join(outDir, "register_request_full.json"), regReq)

	// 18. register_request_minimal.json
	regReqMin := tailcfg.RegisterRequest{
		Version:  1,
		NodeKey:  nodePub,
		Hostinfo: &tailcfg.Hostinfo{OS: "linux", Hostname: "host"},
	}
	writeJSON(filepath.Join(outDir, "register_request_minimal.json"), regReqMin)

	// 19. register_response_full.json — RegisterResponse (has Go-only
	// NodeKeySignature field; Rust test uses subset comparison).
	regResp := tailcfg.RegisterResponse{
		User: tailcfg.User{
			ID:          5,
			DisplayName: "Alice",
		},
		Login: tailcfg.Login{
			ID:        9,
			Provider:  "google",
			LoginName: "alice@example.com",
		},
		NodeKeyExpired:    false,
		MachineAuthorized: true,
		AuthURL:           "",
		Error:             "",
	}
	writeJSON(filepath.Join(outDir, "register_response_full.json"), regResp)

	// ─── Binary fixtures ───

	// 17. disco_ping.bin
	ping := disco.Ping{
		TxID:    [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
		NodeKey: nodePub,
	}
	writeBin(filepath.Join(outDir, "disco_ping.bin"), ping.AppendMarshal(nil))

	// 18. disco_pong.bin
	pong := disco.Pong{
		TxID: [12]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		Src:  mustAddrPort("1.2.3.4:443"),
	}
	writeBin(filepath.Join(outDir, "disco_pong.bin"), pong.AppendMarshal(nil))

	// 19. disco_call_me_maybe.bin
	callMe := disco.CallMeMaybe{
		MyNumber: []netip.AddrPort{
			mustAddrPort("1.2.3.4:5"),
			mustAddrPort("[::1]:443"),
		},
	}
	writeBin(filepath.Join(outDir, "disco_call_me_maybe.bin"), callMe.AppendMarshal(nil))

	// 20. derp_frame.bin
	derpPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	derpFrame := make([]byte, 0, 5+len(derpPayload))
	derpFrame = append(derpFrame, 0x06) // FrameKeepAlive
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(derpPayload)))
	derpFrame = append(derpFrame, lenBuf[:]...)
	derpFrame = append(derpFrame, derpPayload...)
	writeBin(filepath.Join(outDir, "derp_frame.bin"), derpFrame)

	// 21. stun_binding_response.bin
	stunTxID := stun.TxID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc}
	writeBin(filepath.Join(outDir, "stun_binding_response.bin"),
		stun.Response(stunTxID, mustAddrPort("91.221.211.0:43962")))

	fmt.Println("Generated all wire fixtures successfully")
}

func writeJSON(path string, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("json.Marshal %s: %v", path, err))
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		panic(fmt.Sprintf("write %s: %v", path, err))
	}
	fmt.Printf("  %s (%d bytes)\n", filepath.Base(path), len(data))
}

func writeBin(path string, data []byte) {
	if err := os.WriteFile(path, data, 0644); err != nil {
		panic(fmt.Sprintf("write %s: %v", path, err))
	}
	fmt.Printf("  %s (%d bytes)\n", filepath.Base(path), len(data))
}

func boolPtr(b bool) *bool { return &b }

func mustPrefix(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

func mustAddrPort(s string) netip.AddrPort {
	return netip.MustParseAddrPort(s)
}
GOEOF

echo "Running Go fixture generator from $GO_REPO ..."
cd "$GO_REPO" && "$GO_BIN" run "$GEN_FILE" "$OUT_DIR"
