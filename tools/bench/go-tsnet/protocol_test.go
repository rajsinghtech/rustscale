// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func TestHeaderWireVector(t *testing.T) {
	header := rsb1Header{
		mode:            modeThroughput,
		direction:       directionDown,
		durationSeconds: 10,
		count:           0,
	}
	encoded := header.encode()
	if got, want := hex.EncodeToString(encoded[:]), "5253423100010000000a00000000"; got != want {
		t.Fatalf("header wire bytes = %s, want %s", got, want)
	}
	decoded, err := decodeHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != header {
		t.Fatalf("decoded header = %#v, want %#v", decoded, header)
	}
}

func TestReadyAndGoWireBytes(t *testing.T) {
	var output bytes.Buffer
	if err := writeAck(&output); err != nil {
		t.Fatal(err)
	}
	if err := writeGo(&output); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "RSB1G"; got != want {
		t.Fatalf("ready/GO = %q, want %q", got, want)
	}
}

func TestLatencyExchangeIsComplete(t *testing.T) {
	server, client := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- handleConnection(server) }()

	result, err := measureLatency(client, "100.64.0.1:5201", 8, "direct", "100.64.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if result.Requested != 8 || result.Successful != 8 || result.Count != 8 || len(result.SamplesNS) != 8 {
		t.Fatalf("incomplete latency result: %#v", result)
	}
	for index, sample := range result.SamplesNS {
		if sample == 0 {
			t.Fatalf("sample %d is zero", index)
		}
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not complete the exact latency count")
	}
}

func TestServerCancellationClosesListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- serveUntilCanceled(ctx, listener) }()
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not exit after cancellation")
	}
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), 50*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("listener still accepted connections after cancellation")
	}
}

func TestBadAckFailsHandshake(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		_, _ = readHeader(server)
		_, _ = server.Write([]byte("NOPE"))
	}()
	_, err := handshakeAll([]net.Conn{client}, rsb1Header{mode: modeThroughput, direction: directionDown, durationSeconds: 1})
	if err == nil {
		t.Fatal("bad ACK unexpectedly passed")
	}
}
