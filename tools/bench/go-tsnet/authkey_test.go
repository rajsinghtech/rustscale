// Copyright (c) 2026 RustScale contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateCommonReadsOnlyOwnerOnlyAuthKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authkey")
	if err := os.WriteFile(path, []byte("fixture-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := commonOptions{authKeyFile: path, hostname: "fixture"}
	if err := validateCommon(&options); err != nil {
		t.Fatal(err)
	}
	if options.authKey != "fixture-secret" {
		t.Fatalf("unexpected auth key: %q", options.authKey)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	options = commonOptions{authKeyFile: path, hostname: "fixture"}
	if err := validateCommon(&options); err == nil {
		t.Fatal("world-readable auth key file unexpectedly accepted")
	}
}
