package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestPrintContainerd_FailedServiceIsCrit: a failed containerd service must render
// as CRIT, matching checkContainerd + the exit code (regression: the display showed
// the WARN icon while the verdict/exit were CRIT — an under-statement).
func TestPrintContainerd_FailedServiceIsCrit(t *testing.T) {
	info := &models.ContainerdInfo{Available: true, ServiceState: "failed", SocketPath: "/run/containerd/containerd.sock"}
	out := captureStdout(t, func() { printContainerd(info, output.ModePlain) })

	if !strings.Contains(out, "CRIT") {
		t.Errorf("failed containerd service should render CRIT:\n%s", out)
	}
	if strings.Contains(out, "WARN") {
		t.Errorf("failed containerd service must not render WARN (under-states the CRIT verdict):\n%s", out)
	}
}

// TestPrintContainerdHumanHeader covers the ModeHuman-only header line, which
// every other test in this file (all ModePlain) doesn't reach.
func TestPrintContainerdHumanHeader(t *testing.T) {
	out := captureStdout(t, func() {
		printContainerd(&models.ContainerdInfo{Available: true, ServiceState: "active"}, output.ModeHuman)
	})
	if !strings.Contains(out, "Containerd") {
		t.Errorf("human mode should print the section header, got:\n%s", out)
	}
}

// TestPrintContainerdAvailableStates exercises the Available=true branch's
// ServiceState switch (active / "" / unknown / other) plus the socket/version/
// namespace lines, which the failed-service test above doesn't reach.
func TestPrintContainerdAvailableStates(t *testing.T) {
	active := captureStdout(t, func() {
		printContainerd(&models.ContainerdInfo{
			Available: true, SocketPath: "/run/containerd/containerd.sock",
			ServiceState: "active", Version: "1.7.13",
			CtrBinaryFound:  true,
			TotalContainers: 3,
			Namespaces:      []models.ContainerdNamespace{{Name: "default", ContainerCount: 3}},
		}, output.ModePlain)
	})
	if !strings.Contains(active, "active") || !strings.Contains(active, "1.7.13") {
		t.Errorf("an active service should show its state and version, got:\n%s", active)
	}
	if !strings.Contains(active, "default") || !strings.Contains(active, "3 container(s)") {
		t.Errorf("namespaces should be listed with their container counts, got:\n%s", active)
	}

	unknownEmpty := captureStdout(t, func() {
		printContainerd(&models.ContainerdInfo{Available: true, ServiceState: ""}, output.ModePlain)
	})
	if !strings.Contains(unknownEmpty, "state unknown") {
		t.Errorf("an empty service state should read unknown, got:\n%s", unknownEmpty)
	}

	other := captureStdout(t, func() {
		printContainerd(&models.ContainerdInfo{Available: true, ServiceState: "inactive"}, output.ModePlain)
	})
	if !strings.Contains(other, "inactive") {
		t.Errorf("an unrecognized service state should be shown verbatim, got:\n%s", other)
	}
}

// TestPrintContainerdCtrBinaryMissing is a regression guard for
// internal-collectors-05-01: when no ctr/containerd-ctr binary was found, the
// Containers line used to print "0 across 0 namespace(s)" with an "ok" icon
// — indistinguishable from a genuinely idle containerd. Must disclose that
// enumeration was never attempted instead.
func TestPrintContainerdCtrBinaryMissing(t *testing.T) {
	out := captureStdout(t, func() {
		printContainerd(&models.ContainerdInfo{
			Available: true, ServiceState: "active", CtrBinaryFound: false,
		}, output.ModePlain)
	})
	if !strings.Contains(out, "could not be enumerated") {
		t.Errorf("a missing ctr binary must disclose containers could not be enumerated, got:\n%s", out)
	}
	if strings.Contains(out, "0 across 0 namespace(s)") {
		t.Errorf("must not render the fabricated '0 across 0 namespace(s)' OK line, got:\n%s", out)
	}
}

// TestPrintContainerdUnavailable exercises the Available=false branch, both
// with and without a StatusReason (the reason falls back to a default message
// when the collector didn't set one).
func TestPrintContainerdUnavailable(t *testing.T) {
	withReason := captureStdout(t, func() {
		printContainerd(&models.ContainerdInfo{Available: false, StatusReason: "custom reason"}, output.ModePlain)
	})
	if !strings.Contains(withReason, "custom reason") {
		t.Errorf("a set StatusReason should be shown verbatim, got:\n%s", withReason)
	}

	noReason := captureStdout(t, func() {
		printContainerd(&models.ContainerdInfo{Available: false}, output.ModePlain)
	})
	if !strings.Contains(noReason, "not found") {
		t.Errorf("an empty StatusReason should fall back to the default message, got:\n%s", noReason)
	}
}

// TestRunContainerd exercises runContainerd's real (read-only) socket-detection
// gate in both --plain and --json mode. On this test host containerd is not
// installed, so both must take the "not detected" short-circuit path without
// error — the same real-I/O precedent as cpu_report_test.go / hardware_test.go.
func TestRunContainerd(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runContainerd(plainCmd, nil); err != nil {
			t.Fatalf("runContainerd (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "containerd") {
		t.Errorf("plain mode should mention containerd, got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runContainerd(jsonCmd, nil); err != nil {
			t.Fatalf("runContainerd (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}
