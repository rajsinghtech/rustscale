// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

const (
	clientSetupTimeout = 180 * time.Second
	// Setup is outside the measured interval. Pinned gVisor's gonet listener
	// owns a 4096-connection backlog, but an unbounded P100/P1000 burst proved
	// unreliable in the paid harness. Sixteen keeps admission far below that
	// listener capacity while giving P1000 setup room to finish inside the
	// setup and whole-process deadlines.
	clientSetupWindow = 16
)

type throughputSample struct {
	ElapsedSeconds uint64  `json:"elapsed_secs"`
	Mbps           float64 `json:"mbps"`
}

type throughputResult struct {
	Tool         string             `json:"tool"`
	Version      string             `json:"version"`
	Mode         string             `json:"mode"`
	Transport    string             `json:"transport"`
	Protocol     string             `json:"protocol"`
	PayloadBytes int                `json:"payload_bytes"`
	Direction    string             `json:"direction"`
	Duration     uint64             `json:"duration_secs"`
	Parallel     int                `json:"parallel"`
	PathClass    string             `json:"path_class"`
	TailscaleIP  string             `json:"tailscale_ip"`
	Target       string             `json:"target"`
	TotalBytes   uint64             `json:"total_bytes"`
	TotalMbps    float64            `json:"total_mbps"`
	UpBytes      uint64             `json:"up_bytes"`
	UpMbps       float64            `json:"up_mbps"`
	DownBytes    uint64             `json:"down_bytes"`
	DownMbps     float64            `json:"down_mbps"`
	Samples      []throughputSample `json:"samples"`
	Established  int                `json:"established"`
	Handshaken   int                `json:"handshaken"`
	Completed    int                `json:"completed"`
}

type latencyResult struct {
	Tool             string   `json:"tool"`
	Version          string   `json:"version"`
	Mode             string   `json:"mode"`
	Transport        string   `json:"transport"`
	Protocol         string   `json:"protocol"`
	PayloadBytes     int      `json:"payload_bytes"`
	PercentileMethod string   `json:"percentile_method"`
	Requested        int      `json:"requested"`
	Successful       int      `json:"successful"`
	TimedOut         int      `json:"timed_out"`
	Malformed        int      `json:"malformed"`
	Count            int      `json:"count"`
	PathClass        string   `json:"path_class"`
	TailscaleIP      string   `json:"tailscale_ip"`
	Target           string   `json:"target"`
	MinNS            uint64   `json:"min_ns"`
	MaxNS            uint64   `json:"max_ns"`
	MeanNS           float64  `json:"mean_ns"`
	P50NS            uint64   `json:"p50_ns"`
	P95NS            uint64   `json:"p95_ns"`
	P99NS            uint64   `json:"p99_ns"`
	MinUS            float64  `json:"min_us"`
	MaxUS            float64  `json:"max_us"`
	MeanUS           float64  `json:"mean_us"`
	P50US            float64  `json:"p50_us"`
	P95US            float64  `json:"p95_us"`
	P99US            float64  `json:"p99_us"`
	SamplesNS        []uint64 `json:"samples_ns"`
}

type indexedConnection struct {
	index int
	conn  net.Conn
	err   error
}

func dialAll(ctx context.Context, server *tsnet.Server, target string, parallel int) ([]net.Conn, error) {
	return dialAllWith(ctx, target, parallel, server.Dial)
}

type dialConnection func(context.Context, string, string) (net.Conn, error)

func dialAllWith(ctx context.Context, target string, parallel int, dial dialConnection) ([]net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, clientSetupTimeout)
	defer cancel()
	results := make(chan indexedConnection, clientSetupWindow)
	launch := func(index int) {
		go func() {
			conn, err := dial(ctx, "tcp", target)
			if ctx.Err() != nil && conn != nil {
				_ = conn.Close()
				conn = nil
				if err == nil {
					err = ctx.Err()
				}
			}
			results <- indexedConnection{index: index, conn: conn, err: err}
		}()
	}
	ordered := make([]net.Conn, parallel)
	next := 0
	active := 0
	for next < parallel && active < clientSetupWindow {
		launch(next)
		next++
		active++
	}
	established := 0
	var firstError error
	for active > 0 {
		// tsnet.Dial is required to honor the shared bounded context. Drain every
		// result so a connection that races with cancellation is never leaked.
		result := <-results
		active--
		if result.err != nil {
			if firstError == nil {
				firstError = fmt.Errorf("connection %d: %w", result.index, result.err)
				cancel()
			}
		} else {
			ordered[result.index] = result.conn
			established++
		}
		if firstError == nil && next < parallel {
			launch(next)
			next++
			active++
		}
	}
	if firstError != nil {
		for _, opened := range ordered {
			if opened != nil {
				_ = opened.Close()
			}
		}
		return nil, fmt.Errorf("capacity error: established %d of %d requested connections: %w", established, parallel, firstError)
	}
	return ordered, nil
}

func handshakeAll(connections []net.Conn, header rsb1Header) ([]net.Conn, error) {
	deadline := time.Now().Add(clientSetupTimeout)
	results := make(chan indexedConnection, clientSetupWindow)
	launch := func(index int) {
		conn := connections[index]
		go func() {
			if err := conn.SetDeadline(deadline); err != nil {
				results <- indexedConnection{index: index, conn: conn, err: err}
				return
			}
			if err := writeHeader(conn, header); err != nil {
				results <- indexedConnection{index: index, conn: conn, err: fmt.Errorf("header: %w", err)}
				return
			}
			if err := readAck(conn); err != nil {
				results <- indexedConnection{index: index, conn: conn, err: fmt.Errorf("ACK: %w", err)}
				return
			}
			if err := conn.SetDeadline(time.Time{}); err != nil {
				results <- indexedConnection{index: index, conn: conn, err: err}
				return
			}
			results <- indexedConnection{index: index, conn: conn}
		}()
	}
	next := 0
	active := 0
	for next < len(connections) && active < clientSetupWindow {
		launch(next)
		next++
		active++
	}
	ready := make([]indexedConnection, 0, len(connections))
	var firstError error
	for active > 0 {
		result := <-results
		active--
		if result.err != nil {
			if firstError == nil {
				firstError = fmt.Errorf("stream %d protocol setup: %w", result.index, result.err)
			}
		} else {
			ready = append(ready, result)
		}
		if firstError == nil && next < len(connections) {
			launch(next)
			next++
			active++
		}
	}
	if firstError != nil {
		for _, conn := range connections {
			_ = conn.Close()
		}
		return nil, firstError
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].index < ready[j].index })
	result := make([]net.Conn, 0, len(ready))
	for _, opened := range ready {
		result = append(result, opened.conn)
	}
	return result, nil
}

func measureThroughput(connections []net.Conn, target, direction string, durationSeconds uint64, pathClass, tailscaleIP string) (throughputResult, error) {
	directionCode, err := parseDirection(direction)
	if err != nil {
		return throughputResult{}, err
	}
	wireDuration, err := checkedUint32(durationSeconds)
	if err != nil {
		return throughputResult{}, err
	}
	established := len(connections)
	connections, err = handshakeAll(connections, rsb1Header{mode: modeThroughput, direction: directionCode, durationSeconds: wireDuration})
	if err != nil {
		return throughputResult{}, fmt.Errorf("protocol setup failed: established=%d requested=%d: %w", established, established, err)
	}
	handshaken := len(connections)

	var up atomic.Uint64
	var down atomic.Uint64
	duration := time.Duration(durationSeconds) * time.Second
	start := make(chan struct{})
	type workerResult struct {
		index int
		err   error
	}
	workerResults := make(chan workerResult, len(connections))
	for index, conn := range connections {
		go func() {
			defer conn.Close()
			<-start
			if err := conn.SetDeadline(time.Now().Add(duration + 30*time.Second)); err != nil {
				workerResults <- workerResult{index, err}
				return
			}
			if err := writeGo(conn); err != nil {
				workerResults <- workerResult{index, fmt.Errorf("GO: %w", err)}
				return
			}
			workerResults <- workerResult{index, runThroughputWorker(conn, directionCode, duration, &up, &down)}
		}()
	}

	var samplesMu sync.Mutex
	samples := make([]throughputSample, 0, durationSeconds)
	sampleDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var elapsed uint64
		var prior uint64
		for {
			select {
			case <-ticker.C:
				elapsed++
				current := up.Load() + down.Load()
				samplesMu.Lock()
				samples = append(samples, throughputSample{ElapsedSeconds: elapsed, Mbps: bytesToMbps(current-prior, 1)})
				samplesMu.Unlock()
				prior = current
			case <-sampleDone:
				return
			}
		}
	}()
	close(start)
	completed := 0
	var firstWorkerError error
	for range connections {
		result := <-workerResults
		if result.err != nil {
			if firstWorkerError == nil {
				firstWorkerError = fmt.Errorf("stream=%d: %w", result.index, result.err)
				for _, conn := range connections {
					_ = conn.Close()
				}
			}
			continue
		}
		completed++
	}
	close(sampleDone)
	if firstWorkerError != nil {
		return throughputResult{}, fmt.Errorf("throughput stream failed: established=%d handshaken=%d completed=%d requested=%d: %w", established, handshaken, completed, established, firstWorkerError)
	}

	upBytes, downBytes := up.Load(), down.Load()
	totalBytes := upBytes + downBytes
	samplesMu.Lock()
	finalSamples := append([]throughputSample(nil), samples...)
	samplesMu.Unlock()
	return throughputResult{
		Tool:         toolName,
		Version:      toolVersion,
		Mode:         "throughput",
		Transport:    "userspace-tsnet",
		Protocol:     magic,
		PayloadBytes: firehoseBufferLen,
		Direction:    direction,
		Duration:     durationSeconds,
		Parallel:     established,
		PathClass:    pathClass,
		TailscaleIP:  tailscaleIP,
		Target:       target,
		TotalBytes:   totalBytes,
		TotalMbps:    bytesToMbps(totalBytes, float64(durationSeconds)),
		UpBytes:      upBytes,
		UpMbps:       bytesToMbps(upBytes, float64(durationSeconds)),
		DownBytes:    downBytes,
		DownMbps:     bytesToMbps(downBytes, float64(durationSeconds)),
		Samples:      finalSamples,
		Established:  established,
		Handshaken:   handshaken,
		Completed:    completed,
	}, nil
}

func runThroughputWorker(conn net.Conn, direction byte, duration time.Duration, up, down *atomic.Uint64) error {
	switch direction {
	case directionUp:
		return writeUntil(conn, duration, up)
	case directionDown:
		return readUntil(conn, duration, down)
	case directionBidir:
		errors := make(chan error, 2)
		go func() { errors <- writeUntil(conn, duration, up) }()
		go func() { errors <- readUntil(conn, duration, down) }()
		for range 2 {
			if err := <-errors; err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown direction %d", direction)
	}
}

func writeUntil(conn net.Conn, duration time.Duration, counter *atomic.Uint64) error {
	buffer := make([]byte, firehoseBufferLen)
	for i := range buffer {
		buffer[i] = 0xa5
	}
	deadline := time.Now().Add(duration)
	for {
		if time.Until(deadline) <= 0 {
			return nil
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		if err := writeCountedFull(conn, buffer, counter); err != nil {
			if isTimeout(err) && time.Now().After(deadline) {
				return nil
			}
			return err
		}
	}
}

func writeCountedFull(conn net.Conn, value []byte, counter *atomic.Uint64) error {
	for len(value) > 0 {
		written, err := conn.Write(value)
		if written > 0 {
			counter.Add(uint64(written))
			value = value[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readUntil(conn net.Conn, duration time.Duration, counter *atomic.Uint64) error {
	buffer := make([]byte, readBufferLen)
	started := time.Now()
	deadline := started.Add(duration)
	for {
		if time.Until(deadline) <= 0 {
			return nil
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return err
		}
		n, err := conn.Read(buffer)
		if n > 0 {
			counter.Add(uint64(n))
		}
		if err != nil {
			if isTimeout(err) && time.Now().After(deadline) {
				return nil
			}
			if errors.Is(err, io.EOF) && time.Since(started)+100*time.Millisecond >= duration {
				return nil
			}
			return err
		}
		if n == 0 {
			return errors.New("premature zero-length throughput read")
		}
	}
}

func measureLatency(conn net.Conn, target string, count int, pathClass, tailscaleIP string) (latencyResult, error) {
	defer conn.Close()
	wireCount, err := checkedUint32(uint64(count))
	if err != nil {
		return latencyResult{}, err
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return latencyResult{}, err
	}
	if err := writeHeader(conn, rsb1Header{mode: modeLatency, count: wireCount}); err != nil {
		return latencyResult{}, err
	}
	if err := readAck(conn); err != nil {
		return latencyResult{}, err
	}
	if err := writeGo(conn); err != nil {
		return latencyResult{}, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return latencyResult{}, err
	}

	samples := make([]uint64, 0, count)
	timedOut := 0
	malformed := 0
	for sequence := range count {
		var ping [pingLen]byte
		copy(ping[:4], "PING")
		binary.BigEndian.PutUint32(ping[4:], uint32(sequence))
		if err := conn.SetDeadline(time.Now().Add(latencyExchangeTimeout)); err != nil {
			return latencyResult{}, err
		}
		started := time.Now()
		if err := writeFull(conn, ping[:]); err != nil {
			if isTimeout(err) {
				timedOut++
				break
			}
			return latencyResult{}, err
		}
		var pong [pingLen]byte
		if _, err := io.ReadFull(conn, pong[:]); err != nil {
			if isTimeout(err) {
				timedOut++
				break
			}
			return latencyResult{}, err
		}
		elapsed := time.Since(started).Nanoseconds()
		if pong != ping {
			malformed++
			continue
		}
		if elapsed <= 0 {
			elapsed = 1
		}
		samples = append(samples, uint64(elapsed))
	}
	if len(samples) != count || timedOut != 0 || malformed != 0 {
		return latencyResult{}, fmt.Errorf("incomplete latency sample: requested=%d successful=%d timed_out=%d malformed=%d", count, len(samples), timedOut, malformed)
	}

	ordered := append([]uint64(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	percentile := func(value float64) uint64 {
		index := int(math.Round(float64(len(ordered)-1) * value))
		return ordered[index]
	}
	var sum float64
	for _, sample := range ordered {
		sum += float64(sample)
	}
	mean := sum / float64(len(ordered))
	p50, p95, p99 := percentile(.50), percentile(.95), percentile(.99)
	return latencyResult{
		Tool:             toolName,
		Version:          toolVersion,
		Mode:             "latency",
		Transport:        "userspace-tsnet",
		Protocol:         "RSB1-tcp-pingpong",
		PayloadBytes:     pingLen,
		PercentileMethod: "nearest-rank-rounded-index",
		Requested:        count,
		Successful:       len(samples),
		Count:            len(samples),
		PathClass:        pathClass,
		TailscaleIP:      tailscaleIP,
		Target:           target,
		MinNS:            ordered[0],
		MaxNS:            ordered[len(ordered)-1],
		MeanNS:           mean,
		P50NS:            p50,
		P95NS:            p95,
		P99NS:            p99,
		MinUS:            float64(ordered[0]) / 1000,
		MaxUS:            float64(ordered[len(ordered)-1]) / 1000,
		MeanUS:           mean / 1000,
		P50US:            float64(p50) / 1000,
		P95US:            float64(p95) / 1000,
		P99US:            float64(p99) / 1000,
		SamplesNS:        samples,
	}, nil
}

func waitForPeer(ctx context.Context, client *local.Client, target netip.Addr) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := client.Status(ctx)
		if err == nil && statusHasPeer(status, target) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func statusHasPeer(status *ipnstate.Status, target netip.Addr) bool {
	if status == nil {
		return false
	}
	for _, peer := range status.Peer {
		for _, address := range peer.TailscaleIPs {
			if address == target {
				return true
			}
		}
	}
	return false
}

func classifyPath(status *ipnstate.Status, target netip.Addr) string {
	if status == nil {
		return "unknown"
	}
	for _, peer := range status.Peer {
		matched := false
		for _, address := range peer.TailscaleIPs {
			if address == target {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		switch {
		case peer.CurAddr != "":
			return "direct"
		case peer.PeerRelay != "":
			return "relay"
		case peer.Relay != "":
			return "derp"
		default:
			return "none"
		}
	}
	return "unknown"
}

func currentPath(ctx context.Context, client *local.Client, target netip.Addr) string {
	deadline := time.Now().Add(5 * time.Second)
	for {
		statusCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		status, err := client.Status(statusCtx)
		cancel()
		if err == nil {
			path := classifyPath(status, target)
			if path != "unknown" && path != "none" {
				return path
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return "unknown"
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func parseDirection(value string) (byte, error) {
	switch value {
	case "up":
		return directionUp, nil
	case "down":
		return directionDown, nil
	case "bidir":
		return directionBidir, nil
	default:
		return 0, fmt.Errorf("invalid direction %q", value)
	}
}

func checkedUint32(value uint64) (uint32, error) {
	if value == 0 || value > math.MaxUint32 {
		return 0, fmt.Errorf("value %d is outside 1..=%d", value, uint64(math.MaxUint32))
	}
	return uint32(value), nil
}

func bytesToMbps(bytes uint64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return float64(bytes) * 8 / 1_000_000 / seconds
}
