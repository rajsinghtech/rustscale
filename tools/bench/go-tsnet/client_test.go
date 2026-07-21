// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
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

func TestDialAllUsesBoundedAdmission(t *testing.T) {
	const total = 11
	started := make(chan struct{}, total)
	release := make(chan struct{})
	peers := make(chan net.Conn, total)
	var active atomic.Int32
	var maximum atomic.Int32
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for observed := maximum.Load(); current > observed && !maximum.CompareAndSwap(observed, current); observed = maximum.Load() {
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		server, client := net.Pipe()
		peers <- server
		return client, nil
	}

	type outcome struct {
		connections []net.Conn
		err         error
	}
	finished := make(chan outcome, 1)
	go func() {
		connections, err := dialAllWith(context.Background(), "100.64.0.1:5201", total, dial)
		finished <- outcome{connections, err}
	}()

	for range clientSetupWindow {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("initial dial window was not filled")
		}
	}
	if got := maximum.Load(); got != clientSetupWindow {
		t.Fatalf("maximum concurrent dials = %d, want %d", got, clientSetupWindow)
	}
	select {
	case <-started:
		t.Fatal("dial admission exceeded the window")
	default:
	}
	for launched := clientSetupWindow; launched < total; launched++ {
		release <- struct{}{}
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("next bounded dial was not admitted")
		}
	}
	for range clientSetupWindow {
		release <- struct{}{}
	}

	var result outcome
	select {
	case result = <-finished:
	case <-time.After(time.Second):
		t.Fatal("bounded dials did not finish")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	if len(result.connections) != total {
		t.Fatalf("connections = %d, want %d", len(result.connections), total)
	}
	for index, conn := range result.connections {
		if conn == nil {
			t.Fatalf("connection %d is nil", index)
		}
		conn.Close()
	}
	for range total {
		(<-peers).Close()
	}
}

type closeTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestDialAllFailureCancelsPendingAndClosesCompleted(t *testing.T) {
	started := make(chan struct{}, clientSetupWindow+1)
	allowSuccess := make(chan struct{})
	allowFailure := make(chan struct{})
	var calls atomic.Int32
	var completed *closeTrackingConn
	var peer net.Conn
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		call := calls.Add(1)
		started <- struct{}{}
		switch call {
		case 1:
			select {
			case <-allowSuccess:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			peerSide, clientSide := net.Pipe()
			peer = peerSide
			completed = &closeTrackingConn{Conn: clientSide}
			return completed, nil
		case 2:
			select {
			case <-allowFailure:
				return nil, errors.New("fixture dial failure")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		default:
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}

	finished := make(chan error, 1)
	go func() {
		_, err := dialAllWith(context.Background(), "100.64.0.1:5201", 20, dial)
		finished <- err
	}()
	for range clientSetupWindow {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("initial dial window was not filled")
		}
	}
	close(allowSuccess)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("successful dial did not admit its successor")
	}
	close(allowFailure)

	var err error
	select {
	case err = <-finished:
	case <-time.After(time.Second):
		t.Fatal("failed bounded dials did not cancel")
	}
	if err == nil || !strings.Contains(err.Error(), "established 1 of 20") || !strings.Contains(err.Error(), "fixture dial failure") {
		t.Fatalf("unexpected capacity error: %v", err)
	}
	if got := calls.Load(); got != clientSetupWindow+1 {
		t.Fatalf("dial calls = %d, want exactly %d without retries", got, clientSetupWindow+1)
	}
	if completed == nil || !completed.closed.Load() {
		t.Fatal("completed connection was not closed after atomic setup failure")
	}
	if peer != nil {
		peer.Close()
	}
}

func TestHandshakeAllUsesBoundedAdmission(t *testing.T) {
	const total = 11
	clients := make([]net.Conn, 0, total)
	servers := make([]net.Conn, 0, total)
	started := make(chan int, total)
	release := make(chan struct{})
	serverDone := make(chan error, total)
	for index := range total {
		server, client := net.Pipe()
		servers = append(servers, server)
		clients = append(clients, client)
		go func() {
			_, err := readHeader(server)
			if err == nil {
				started <- index
				<-release
				err = writeAck(server)
			}
			serverDone <- err
		}()
	}

	type outcome struct {
		connections []net.Conn
		err         error
	}
	finished := make(chan outcome, 1)
	go func() {
		connections, err := handshakeAll(clients, rsb1Header{mode: modeThroughput, direction: directionDown, durationSeconds: 1})
		finished <- outcome{connections, err}
	}()
	for range clientSetupWindow {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("initial handshake window was not filled")
		}
	}
	select {
	case index := <-started:
		t.Fatalf("handshake %d exceeded the admission window", index)
	default:
	}
	for launched := clientSetupWindow; launched < total; launched++ {
		release <- struct{}{}
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("next bounded handshake was not admitted")
		}
	}
	for range clientSetupWindow {
		release <- struct{}{}
	}

	var result outcome
	select {
	case result = <-finished:
	case <-time.After(time.Second):
		t.Fatal("bounded handshakes did not finish")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	if len(result.connections) != total {
		t.Fatalf("connections = %d, want %d", len(result.connections), total)
	}
	for index, conn := range result.connections {
		if conn != clients[index] {
			t.Fatalf("connection %d was reordered", index)
		}
		conn.Close()
	}
	for range total {
		if err := <-serverDone; err != nil {
			t.Fatal(err)
		}
	}
	for _, server := range servers {
		server.Close()
	}
}
