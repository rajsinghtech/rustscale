// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func statusWithPeer(target netip.Addr, curAddr, peerRelay, relay string) *ipnstate.Status {
	return &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		{}: {
			TailscaleIPs: []netip.Addr{target},
			CurAddr:      curAddr,
			PeerRelay:    peerRelay,
			Relay:        relay,
		},
	}}
}

func TestPathClassification(t *testing.T) {
	target := netip.MustParseAddr("100.64.0.1")
	other := netip.MustParseAddr("100.64.0.2")
	for _, test := range []struct {
		name   string
		status *ipnstate.Status
		target netip.Addr
		want   string
	}{
		{"direct", statusWithPeer(target, "192.0.2.1:41641", "", "ord"), target, "direct"},
		{"peer relay", statusWithPeer(target, "", "100.64.0.3:123:vni:4", "ord"), target, "relay"},
		{"DERP", statusWithPeer(target, "", "", "ord"), target, "derp"},
		{"no active path", statusWithPeer(target, "", "", ""), target, "none"},
		{"different peer", statusWithPeer(target, "192.0.2.1:41641", "", ""), other, "unknown"},
		{"missing status", nil, target, "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyPath(test.status, test.target); got != test.want {
				t.Fatalf("classifyPath = %q, want %q", got, test.want)
			}
		})
	}
}

func TestDirectionAndBounds(t *testing.T) {
	for value, want := range map[string]byte{"up": directionUp, "down": directionDown, "bidir": directionBidir} {
		got, err := parseDirection(value)
		if err != nil || got != want {
			t.Fatalf("parseDirection(%q) = %d, %v; want %d", value, got, err, want)
		}
	}
	if _, err := parseDirection("reverse"); err == nil {
		t.Fatal("unknown direction passed")
	}
	if _, err := checkedUint32(0); err == nil {
		t.Fatal("zero passed positive wire bound")
	}
}

func TestP100LifecycleRequiresEveryStream(t *testing.T) {
	const streams = 100
	clients := make([]net.Conn, 0, streams)
	var servers sync.WaitGroup
	servers.Add(streams)
	for range streams {
		server, client := net.Pipe()
		clients = append(clients, client)
		go func() {
			defer servers.Done()
			defer server.Close()
			header, err := readHeader(server)
			if err != nil {
				return
			}
			if header.mode != modeThroughput || header.direction != directionDown || header.durationSeconds != 1 {
				return
			}
			if writeAck(server) != nil || readGo(server) != nil {
				return
			}
			_ = writeFull(server, []byte{0xa5})
			time.Sleep(1100 * time.Millisecond)
		}()
	}
	result, err := measureThroughput(clients, "100.64.0.1:5201", "down", 1, "direct", "100.64.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if got := [3]int{result.Established, result.Handshaken, result.Completed}; got != [3]int{streams, streams, streams} {
		t.Fatalf("lifecycle = %v, want exact P100 completion", got)
	}
	if result.TotalBytes == 0 || result.TotalMbps <= 0 {
		t.Fatalf("invalid positive throughput: bytes=%d mbps=%f", result.TotalBytes, result.TotalMbps)
	}
	servers.Wait()
}

func TestPersistentStateIsNonEphemeral(t *testing.T) {
	server, cleanup, err := newTSNetServer(commonOptions{authKey: "fixture", hostname: "fixture", stateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if server.Ephemeral {
		t.Fatal("a supplied state directory must retain one non-ephemeral identity")
	}
	if got, want := server.Hostname, "fixture"; got != want {
		t.Fatalf("hostname = %q, want %q", got, want)
	}
}
