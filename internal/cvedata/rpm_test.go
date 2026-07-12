//go:build linux

package cvedata

import (
	"context"
	"testing"
)

// TestQueryInstalledRPM_NotAvailable exercises the "rpm not in PATH" guard.
// This repo's containers/CI runners are Debian-family and don't ship rpm, so
// this is a deterministic failure here; guarded so a host that DOES have rpm
// installed skips instead of asserting a false expectation.
func TestQueryInstalledRPM_NotAvailable(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	if _, err := QueryInstalledRPM(context.Background()); err == nil {
		t.Error("expected error when rpm binary is not on PATH")
	}
}
