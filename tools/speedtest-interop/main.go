// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

// speedtest-go-peer is a process-level interoperability peer for RustScale.
// It calls the exported tailscale.com/net/speedtest API directly; it does not
// duplicate the speedtest protocol implementation.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"tailscale.com/net/speedtest"
)

const (
	expectedModuleVersion = "v1.100.0"
	expectedModuleSum     = "h1:nm/M/dEaW9RaRsGUjW2HsSDpsZ60Jwd9k4gNW9tTFiE="
	readFragmentSize      = 1009
	maxResults            = 64
)

type startup struct {
	Address string `json:"address"`
	Module  string `json:"module"`
}

type wireResult struct {
	Bytes      int     `json:"bytes"`
	IntervalNS int64   `json:"interval_ns"`
	Total      bool    `json:"total"`
	Mbps       float64 `json:"mbps"`
}

type clientOutput struct {
	Module    string       `json:"module"`
	Direction string       `json:"direction"`
	Results   []wireResult `json:"results"`
}

// fragmentedReadConn makes partial reads deterministic without changing the
// bytes written by upstream. In particular, upstream's single Write per block
// is left intact rather than being replaced with fixture behavior.
type fragmentedReadConn struct {
	net.Conn
}

func (c fragmentedReadConn) Read(p []byte) (int, error) {
	if len(p) > readFragmentSize {
		p = p[:readFragmentSize]
	}
	return c.Conn.Read(p)
}

type fragmentedReadListener struct {
	net.Listener
}

func (l fragmentedReadListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return fragmentedReadConn{Conn: conn}, nil
}

func verifyRuntimeEnvironment(lookup func(string) (string, bool)) error {
	required := map[string]string{
		"GOENV":   "off",
		"GOFLAGS": "",
		"GOWORK":  "off",
		"GOPROXY": "off",
	}
	for name, expected := range required {
		value, ok := lookup(name)
		if !ok || value != expected {
			return fmt.Errorf("untrusted runtime environment %s=%q", name, value)
		}
	}
	for _, name := range []string{"GONOPROXY", "GONOSUMDB", "GOPRIVATE"} {
		if value, ok := lookup(name); ok && value != "" {
			return fmt.Errorf("untrusted runtime environment %s=%q", name, value)
		}
	}

	var cacheParent string
	for _, name := range []string{"HOME", "GOCACHE", "GOMODCACHE", "GOPATH"} {
		value, ok := lookup(name)
		if !ok || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("runtime %s must be a clean absolute path", name)
		}
		parent := filepath.Dir(value)
		if cacheParent == "" {
			cacheParent = parent
		} else if parent != cacheParent {
			return fmt.Errorf("runtime %s is outside the isolated root", name)
		}
	}
	path, ok := lookup("PATH")
	if !ok || !filepath.IsAbs(path) || strings.ContainsRune(path, os.PathListSeparator) {
		return errors.New("runtime PATH must contain exactly one absolute toolchain directory")
	}
	return nil
}

func verifyModuleDependencies(dependencies []*debug.Module) (string, error) {
	if expectedModuleSum == "" {
		return "", errors.New("expected tailscale.com checksum is unavailable")
	}
	var matched *debug.Module
	for _, dependency := range dependencies {
		if dependency.Path != "tailscale.com" {
			continue
		}
		if matched != nil {
			return "", errors.New("multiple tailscale.com build dependencies")
		}
		matched = dependency
	}
	if matched == nil {
		return "", errors.New("tailscale.com is absent from Go build information")
	}
	if matched.Replace != nil {
		return "", errors.New("tailscale.com build replacements are forbidden")
	}
	if matched.Version != expectedModuleVersion {
		return "", fmt.Errorf("unexpected tailscale.com version %q", matched.Version)
	}
	if matched.Sum == "" || matched.Sum != expectedModuleSum {
		return "", fmt.Errorf("unexpected tailscale.com checksum %q", matched.Sum)
	}
	return "tailscale.com@" + matched.Version, nil
}

func moduleVersion() (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", errors.New("Go build information is unavailable")
	}
	return verifyModuleDependencies(info.Deps)
}

func runServer(module string) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()

	if err := json.NewEncoder(os.Stdout).Encode(startup{
		Address: listener.Addr().String(),
		Module:  module,
	}); err != nil {
		return fmt.Errorf("write startup message: %w", err)
	}
	return speedtest.Serve(fragmentedReadListener{Listener: listener})
}

func runClient(module string, args []string) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	address := flags.String("address", "", "loopback server address")
	directionName := flags.String("direction", "", "upload or download")
	duration := flags.Duration("duration", speedtest.MinDuration, "test duration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *address == "" {
		return errors.New("client requires --address and no positional arguments")
	}
	host, _, err := net.SplitHostPort(*address)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("client address must be an IPv4 loopback host:port: %q", *address)
	}
	if *duration < speedtest.MinDuration || *duration > speedtest.MaxDuration {
		return fmt.Errorf("duration must be between %s and %s", speedtest.MinDuration, speedtest.MaxDuration)
	}

	var direction speedtest.Direction
	switch *directionName {
	case "download":
		direction = speedtest.Download
	case "upload":
		direction = speedtest.Upload
	default:
		return fmt.Errorf("invalid direction %q", *directionName)
	}

	results, err := speedtest.RunClient(direction, *duration, *address)
	if err != nil {
		return err
	}
	if len(results) > maxResults {
		return fmt.Errorf("upstream returned %d results, limit is %d", len(results), maxResults)
	}
	output := clientOutput{
		Module:    module,
		Direction: direction.String(),
		Results:   make([]wireResult, 0, len(results)),
	}
	for _, result := range results {
		output.Results = append(output.Results, wireResult{
			Bytes:      result.Bytes,
			IntervalNS: result.Interval().Nanoseconds(),
			Total:      result.Total,
			Mbps:       result.MBitsPerSecond(),
		})
	}
	return json.NewEncoder(os.Stdout).Encode(output)
}

func run() error {
	if err := verifyRuntimeEnvironment(os.LookupEnv); err != nil {
		return err
	}
	module, err := moduleVersion()
	if err != nil {
		return err
	}
	if len(os.Args) < 2 {
		return errors.New("usage: speedtest-go-peer <server|client> [arguments]")
	}
	switch os.Args[1] {
	case "server":
		if len(os.Args) != 2 {
			return errors.New("server takes no arguments")
		}
		return runServer(module)
	case "client":
		return runClient(module, os.Args[2:])
	default:
		return fmt.Errorf("unknown mode %q", os.Args[1])
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "speedtest-go-peer: %v\n", err)
		os.Exit(1)
	}
}
