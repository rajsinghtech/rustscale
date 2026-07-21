// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	serverSetupTimeout       = 210 * time.Second
	serverIOGrace            = 30 * time.Second
	latencyExchangeTimeout   = 5 * time.Second
	maximumServerConnections = 2048
)

func serveRSB1(listener net.Listener) error {
	permits := make(chan struct{}, maximumServerConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case permits <- struct{}{}:
		default:
			_ = conn.Close()
			log.Printf("RSB1 connection rejected at %d-handler capacity", maximumServerConnections)
			continue
		}
		go func() {
			defer func() { <-permits }()
			if err := handleConnection(conn); err != nil {
				log.Printf("RSB1 connection handler: %v", err)
			}
		}()
	}
}

func handleConnection(conn net.Conn) error {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(serverSetupTimeout)); err != nil {
		return err
	}
	header, err := readHeader(conn)
	if err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if err := writeAck(conn); err != nil {
		return fmt.Errorf("write ready: %w", err)
	}
	if err := readGo(conn); err != nil {
		return fmt.Errorf("read GO: %w", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	switch header.mode {
	case modeThroughput:
		return handleThroughput(conn, header)
	case modeLatency:
		return handleLatency(conn, header.count)
	default:
		return fmt.Errorf("unknown RSB1 mode %d", header.mode)
	}
}

func handleThroughput(conn net.Conn, header rsb1Header) error {
	duration := time.Duration(header.durationSeconds) * time.Second
	if duration <= 0 {
		return errors.New("throughput duration must be positive")
	}
	deadline := time.Now().Add(duration + serverIOGrace)
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}

	switch header.direction {
	case directionUp:
		_, err := io.Copy(io.Discard, conn)
		return err
	case directionDown:
		return writeForDuration(conn, duration)
	case directionBidir:
		var wg sync.WaitGroup
		wg.Add(2)
		errors := make(chan error, 2)
		go func() {
			defer wg.Done()
			_, err := io.Copy(io.Discard, conn)
			errors <- err
		}()
		go func() {
			defer wg.Done()
			errors <- writeForDuration(conn, duration)
		}()
		wg.Wait()
		close(errors)
		for err := range errors {
			if err != nil && !isExpectedNetworkClose(err) {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown RSB1 direction %d", header.direction)
	}
}

func writeForDuration(conn net.Conn, duration time.Duration) error {
	buffer := make([]byte, firehoseBufferLen)
	for i := range buffer {
		buffer[i] = 0xa5
	}
	deadline := time.Now().Add(duration)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		if err := writeFull(conn, buffer); err != nil {
			if isTimeout(err) && time.Now().After(deadline) {
				break
			}
			return err
		}
	}
	// Match rustscale-bench's bounded userspace drain margin.
	time.Sleep(200 * time.Millisecond)
	return nil
}

func handleLatency(conn net.Conn, count uint32) error {
	if count == 0 {
		return errors.New("latency count must be positive")
	}
	buffer := make([]byte, pingLen)
	for range count {
		if err := conn.SetDeadline(time.Now().Add(latencyExchangeTimeout)); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, buffer); err != nil {
			return err
		}
		if err := writeFull(conn, buffer); err != nil {
			return err
		}
	}
	return nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isExpectedNetworkClose(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || isTimeout(err)
}
