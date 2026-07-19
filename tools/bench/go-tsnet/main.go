// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

// go-tsnet-rsb1 is the pinned Go tsnet endpoint for matched RustScale RSB1
// benchmarks. It embeds tailscale.com/tsnet; it does not use tailscaled, a
// loopback proxy, Tailscale Serve, or kernel TCP.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

const (
	toolName    = "go-tsnet-rsb1"
	toolVersion = "tailscale.com/v1.100.0"
)

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type commonOptions struct {
	authKey     string
	authKeyFile string
	hostname    string
	controlURL  string
	stateDir    string
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-V" || os.Args[1] == "version") {
		fmt.Printf("%s %s\n", toolName, toolVersion)
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "server":
		err = runServerCommand(ctx, os.Args[2:])
	case "client":
		err = runClientCommand(ctx, os.Args[2:])
	case "latency":
		err = runLatencyCommand(ctx, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  %[1]s server --authkey-file FILE [--port 5201] [--hostname NAME] [--state-dir DIR]
  %[1]s client --authkey-file FILE --target IP:PORT --duration SECONDS --direction down --parallel N --json [--hostname NAME] [--state-dir DIR]
  %[1]s latency --authkey-file FILE --target IP:PORT --count N --json [--hostname NAME] [--state-dir DIR]
  %[1]s --version
`, toolName)
}

func addCommonFlags(flags *flag.FlagSet, defaultHostname string) *commonOptions {
	options := new(commonOptions)
	flags.StringVar(&options.authKey, "authkey", "", "preauthorized Tailscale auth key")
	flags.StringVar(&options.authKeyFile, "authkey-file", "", "owner-only file containing the auth key")
	flags.StringVar(&options.hostname, "hostname", defaultHostname, "tailnet hostname")
	flags.StringVar(&options.controlURL, "control-url", "", "optional coordination server URL")
	flags.StringVar(&options.stateDir, "state-dir", "", "persistent tsnet state directory")
	return options
}

func validateCommon(options *commonOptions) error {
	if options.authKey != "" && options.authKeyFile != "" {
		return errors.New("--authkey and --authkey-file are mutually exclusive")
	}
	if options.authKeyFile != "" {
		info, err := os.Lstat(options.authKeyFile)
		if err != nil {
			return fmt.Errorf("inspect --authkey-file: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("--authkey-file must be an owner-only regular, non-symlink file")
		}
		value, err := os.ReadFile(options.authKeyFile)
		if err != nil {
			return fmt.Errorf("read --authkey-file: %w", err)
		}
		options.authKey = string(value)
		options.authKey = strings.TrimSuffix(strings.TrimSuffix(options.authKey, "\n"), "\r")
		if options.authKey == "" || strings.ContainsAny(options.authKey, "\r\n") {
			return errors.New("--authkey-file must contain exactly one non-empty line")
		}
	}
	if options.authKey == "" {
		return errors.New("--authkey or --authkey-file is required")
	}
	if !hostnamePattern.MatchString(options.hostname) {
		return errors.New("--hostname must be a valid DNS label")
	}
	return nil
}

func newTSNetServer(options commonOptions) (*tsnet.Server, func(), error) {
	stateDir := options.stateDir
	cleanup := func() {}
	ephemeral := false
	if stateDir == "" {
		var err error
		stateDir, err = os.MkdirTemp("", "go-tsnet-rsb1-state.*")
		if err != nil {
			return nil, cleanup, err
		}
		cleanup = func() { _ = os.RemoveAll(stateDir) }
		ephemeral = true
	}
	if !filepath.IsAbs(stateDir) {
		absolute, err := filepath.Abs(stateDir)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		stateDir = absolute
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	server := &tsnet.Server{
		Dir:        stateDir,
		Hostname:   options.hostname,
		Ephemeral:  ephemeral,
		AuthKey:    options.authKey,
		ControlURL: options.controlURL,
		Logf:       func(string, ...any) {},
		UserLogf:   func(format string, args ...any) { log.Printf("tsnet: "+format, args...) },
	}
	return server, cleanup, nil
}

func runServerCommand(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	options := addCommonFlags(flags, "bench-go-tsnet-server")
	port := flags.Uint("port", 5201, "RSB1 listen port")
	jsonOutput := flags.Bool("json", false, "reserved for CLI compatibility")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *port == 0 || *port > 65535 || *jsonOutput {
		return errors.New("invalid server arguments")
	}
	if err := validateCommon(options); err != nil {
		return err
	}
	server, cleanup, err := newTSNetServer(*options)
	if err != nil {
		return err
	}
	defer cleanup()
	serverClosed := false
	defer func() {
		if !serverClosed {
			_ = server.Close()
		}
	}()
	upCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	status, err := server.Up(upCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}
	ip := firstIPv4(status.TailscaleIPs)
	if !ip.IsValid() {
		return errors.New("tsnet is running without an IPv4 tailnet address")
	}
	listener, err := server.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("tsnet listen: %w", err)
	}
	defer listener.Close()
	fmt.Fprintf(os.Stderr, "BENCH_IP %s\nBENCH_PORT %d\nBENCH_READY 1\n", ip, *port)
	serveErr := serveUntilCanceled(ctx, listener)
	closeErr := server.Close()
	serverClosed = true
	if serveErr != nil {
		return serveErr
	}
	if closeErr != nil {
		return fmt.Errorf("tsnet close: %w", closeErr)
	}
	return nil
}

func serveUntilCanceled(ctx context.Context, listener net.Listener) error {
	serveResult := make(chan error, 1)
	go func() { serveResult <- serveRSB1(listener) }()
	select {
	case err := <-serveResult:
		return err
	case <-ctx.Done():
		_ = listener.Close()
		err := <-serveResult
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func runClientCommand(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	options := addCommonFlags(flags, "bench-go-tsnet-client")
	targetText := flags.String("target", "", "IPv4 tailnet endpoint")
	duration := flags.Uint64("duration", 10, "measurement duration in seconds")
	direction := flags.String("direction", "down", "up, down, or bidir")
	parallel := flags.Int("parallel", 1, "parallel RSB1 streams (1..1000)")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*jsonOutput || *parallel < 1 || *parallel > 1000 || *duration == 0 {
		return errors.New("invalid client arguments")
	}
	if _, err := parseDirection(*direction); err != nil {
		return err
	}
	if err := validateCommon(options); err != nil {
		return err
	}
	target, err := netip.ParseAddrPort(*targetText)
	if err != nil || !target.Addr().Is4() {
		return errors.New("--target must be an IPv4 address and port")
	}
	server, cleanup, err := newTSNetServer(*options)
	if err != nil {
		return err
	}
	defer cleanup()
	serverClosed := false
	defer func() {
		if !serverClosed {
			_ = server.Close()
		}
	}()
	ip, client, err := bringUp(ctx, server, target.Addr())
	if err != nil {
		return err
	}
	connections, err := dialAll(ctx, server, target.String(), *parallel)
	if err != nil {
		return err
	}
	result, err := measureThroughput(connections, target.String(), *direction, *duration, "unknown", ip.String())
	if err != nil {
		return err
	}
	result.PathClass = currentPath(ctx, client, target.Addr())
	closeErr := server.Close()
	serverClosed = true
	if closeErr != nil {
		return fmt.Errorf("tsnet close: %w", closeErr)
	}
	return writeJSON(result)
}

func runLatencyCommand(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("latency", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	options := addCommonFlags(flags, "bench-go-tsnet-client")
	targetText := flags.String("target", "", "IPv4 tailnet endpoint")
	count := flags.Int("count", 1000, "ping-pong exchange count")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*jsonOutput || *count < 1 || *count > 1_000_000 {
		return errors.New("invalid latency arguments")
	}
	if err := validateCommon(options); err != nil {
		return err
	}
	target, err := netip.ParseAddrPort(*targetText)
	if err != nil || !target.Addr().Is4() {
		return errors.New("--target must be an IPv4 address and port")
	}
	server, cleanup, err := newTSNetServer(*options)
	if err != nil {
		return err
	}
	defer cleanup()
	serverClosed := false
	defer func() {
		if !serverClosed {
			_ = server.Close()
		}
	}()
	ip, client, err := bringUp(ctx, server, target.Addr())
	if err != nil {
		return err
	}
	setupCtx, cancel := context.WithTimeout(ctx, clientSetupTimeout)
	conn, err := server.Dial(setupCtx, "tcp", target.String())
	cancel()
	if err != nil {
		return fmt.Errorf("latency connection setup: %w", err)
	}
	result, err := measureLatency(conn, target.String(), *count, "unknown", ip.String())
	if err != nil {
		return err
	}
	result.PathClass = currentPath(ctx, client, target.Addr())
	closeErr := server.Close()
	serverClosed = true
	if closeErr != nil {
		return fmt.Errorf("tsnet close: %w", closeErr)
	}
	return writeJSON(result)
}

func bringUp(ctx context.Context, server *tsnet.Server, target netip.Addr) (netip.Addr, *local.Client, error) {
	upCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	status, err := server.Up(upCtx)
	cancel()
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("tsnet up: %w", err)
	}
	ip := firstIPv4(status.TailscaleIPs)
	if !ip.IsValid() {
		return netip.Addr{}, nil, errors.New("tsnet is running without an IPv4 tailnet address")
	}
	client, err := server.LocalClient()
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("tsnet local client: %w", err)
	}
	peerCtx, peerCancel := context.WithTimeout(ctx, 90*time.Second)
	err = waitForPeer(peerCtx, client, target)
	peerCancel()
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("wait for target peer %s: %w", target, err)
	}
	// Match the Rust endpoint's post-netmap direct-path settling interval.
	time.Sleep(3 * time.Second)
	return ip, client, nil
}

func firstIPv4(addresses []netip.Addr) netip.Addr {
	for _, address := range addresses {
		if address.Is4() {
			return address
		}
	}
	return netip.Addr{}
}

func writeJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
