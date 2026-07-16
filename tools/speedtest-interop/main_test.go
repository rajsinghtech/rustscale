// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestVerifyModuleDependencies(t *testing.T) {
	if got, err := verifyModuleDependencies(nil); err == nil {
		t.Fatalf("missing build provenance was accepted as %q", got)
	}

	valid := &debug.Module{
		Path:    "tailscale.com",
		Version: expectedModuleVersion,
		Sum:     expectedModuleSum,
	}
	if got, err := verifyModuleDependencies([]*debug.Module{valid}); err != nil || got != "tailscale.com@"+expectedModuleVersion {
		t.Fatalf("valid dependency: got %q, %v", got, err)
	}

	tests := map[string]*debug.Module{
		"replacement": {
			Path:    "tailscale.com",
			Version: expectedModuleVersion,
			Sum:     expectedModuleSum,
			Replace: &debug.Module{
				Path:    "tailscale.com",
				Version: expectedModuleVersion,
				Sum:     expectedModuleSum,
			},
		},
		"empty checksum": {
			Path:    "tailscale.com",
			Version: expectedModuleVersion,
		},
		"wrong checksum": {
			Path:    "tailscale.com",
			Version: expectedModuleVersion,
			Sum:     "h1:poisoned",
		},
		"wrong version": {
			Path:    "tailscale.com",
			Version: "v1.100.1",
			Sum:     expectedModuleSum,
		},
	}
	for name, dependency := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := verifyModuleDependencies([]*debug.Module{dependency}); err == nil {
				t.Fatalf("accepted untrusted dependency as %q", got)
			}
		})
	}
}

func TestVerifyRuntimeEnvironmentRejectsPoisoning(t *testing.T) {
	valid := map[string]string{
		"HOME":       "/isolated/home",
		"GOCACHE":    "/isolated/gocache",
		"GOMODCACHE": "/isolated/gomodcache",
		"GOPATH":     "/isolated/gopath",
		"PATH":       "/validated/go/bin",
		"GOENV":      "off",
		"GOFLAGS":    "",
		"GOWORK":     "off",
		"GOPROXY":    "off",
	}
	lookup := func(environment map[string]string) func(string) (string, bool) {
		return func(name string) (string, bool) {
			value, ok := environment[name]
			return value, ok
		}
	}
	if err := verifyRuntimeEnvironment(lookup(valid)); err != nil {
		t.Fatalf("valid isolated environment: %v", err)
	}

	for _, name := range []string{"GOENV", "GOFLAGS", "GOWORK", "GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB"} {
		t.Run(name, func(t *testing.T) {
			poisoned := make(map[string]string, len(valid)+1)
			for key, value := range valid {
				poisoned[key] = value
			}
			poisoned[name] = "poisoned"
			if err := verifyRuntimeEnvironment(lookup(poisoned)); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("poisoned %s was not rejected: %v", name, err)
			}
		})
	}
}
