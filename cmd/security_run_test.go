package cmd

import (
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// newBareSecurityCmd builds a bare cobra.Command with the flags runSecurity
// reads via cmd.Flags().GetBool, following the same pattern as
// newBareCloudCmd (oci_test.go).
func newBareSecurityCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", false, "")
	f.Bool("json", false, "")
	f.Bool("deep", false, "")
	f.Bool("suid", false, "")
	f.Bool("save-baseline", false, "")
	f.Bool("drift", false, "")
	return c
}

// TestRunSecurity exercises runSecurity's real (read-only) SecurityCollector
// wiring in --plain and --json mode — the same real-I/O precedent as
// cpu_report_test.go / net_test.go's TestRunNet.
func TestRunSecurity(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	plainCmd := newBareSecurityCmd()
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runSecurity(plainCmd, nil); err != nil {
			t.Fatalf("runSecurity (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "SSH Configuration") {
		t.Errorf("plain mode should render the security report, got: %q", plainOut)
	}

	pendingExitCode = 0
	jsonCmd := newBareSecurityCmd()
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runSecurity(jsonCmd, nil); err != nil {
			t.Fatalf("runSecurity (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}

// TestRunSecurityDeep exercises the --deep path (SUID scan runs explicitly)
// separately from --save-baseline/--drift so it still reaches the normal
// report render. The SUID scan is redirected to an empty temp dir so it
// doesn't walk /opt/hostedtoolcache or /usr/local (GBs on CI runners).
// No t.Parallel() — swaps SUIDBinScanPaths (package global) and captureStdout.
func TestRunSecurityDeep(t *testing.T) {
	if runtime.GOOS == "linux" {
		orig := collectors.SUIDBinScanPaths
		collectors.SUIDBinScanPaths = []string{t.TempDir()}
		defer func() { collectors.SUIDBinScanPaths = orig }()
	}
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareSecurityCmd()
	_ = c.Flags().Set("plain", "true")
	_ = c.Flags().Set("deep", "true")
	out := captureStdout(t, func() {
		if err := runSecurity(c, nil); err != nil {
			t.Fatalf("runSecurity --deep: %v", err)
		}
	})
	if !strings.Contains(out, "SSH Configuration") {
		t.Errorf("--deep should still render the normal report, got: %q", out)
	}
}

// TestRunSecuritySaveBaselineAndDrift exercises the --save-baseline and
// --drift dispatch paths end to end against an isolated $HOME (per the
// baseline package's own test pattern — internal/baseline/security_baseline_test.go).
func TestRunSecuritySaveBaselineAndDrift(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0
	if runtime.GOOS == "linux" {
		orig := collectors.SUIDBinScanPaths
		collectors.SUIDBinScanPaths = []string{t.TempDir()}
		defer func() { collectors.SUIDBinScanPaths = orig }()
	}
	t.Setenv("HOME", t.TempDir())

	// No baseline yet: --drift should say so, not error.
	driftNone := newBareSecurityCmd()
	_ = driftNone.Flags().Set("plain", "true")
	_ = driftNone.Flags().Set("drift", "true")
	outNone := captureStdout(t, func() {
		if err := runSecurity(driftNone, nil); err != nil {
			t.Fatalf("runSecurity --drift with no baseline: %v", err)
		}
	})
	if !strings.Contains(outNone, "No security baseline found") {
		t.Errorf("no saved baseline should say so, got: %q", outNone)
	}

	// Save a baseline.
	saveCmd := newBareSecurityCmd()
	_ = saveCmd.Flags().Set("plain", "true")
	_ = saveCmd.Flags().Set("save-baseline", "true")
	outSave := captureStdout(t, func() {
		if err := runSecurity(saveCmd, nil); err != nil {
			t.Fatalf("runSecurity --save-baseline: %v", err)
		}
	})
	if !strings.Contains(outSave, "Security baseline saved") {
		t.Errorf("saving a baseline should confirm it, got: %q", outSave)
	}

	// Drift against the just-saved (identical) baseline should report clean.
	driftClean := newBareSecurityCmd()
	_ = driftClean.Flags().Set("plain", "true")
	_ = driftClean.Flags().Set("drift", "true")
	outClean := captureStdout(t, func() {
		if err := runSecurity(driftClean, nil); err != nil {
			t.Fatalf("runSecurity --drift against a fresh baseline: %v", err)
		}
	})
	if !strings.Contains(outClean, "No security drift detected") {
		t.Errorf("an unchanged host should report no drift, got: %q", outClean)
	}
}

// TestRunSaveBaselineAndDrift_RealDrift exercises runSaveBaseline/runDrift
// directly against a hand-built SecurityInfo (not runSecurity's live collector),
// so a genuine change (a new SUID binary) can be injected between save and
// drift — the runDrift branch that calls printSecurityDrift, not exercised by
// TestRunSecuritySaveBaselineAndDrift's identical-baseline case above.
func TestRunSaveBaselineAndDrift_RealDrift(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	before := &models.SecurityInfo{SUIDBinaries: []string{"/usr/bin/passwd"}}
	if err := runSaveBaseline(before, output.ModePlain); err != nil {
		t.Fatalf("runSaveBaseline: %v", err)
	}

	after := &models.SecurityInfo{SUIDBinaries: []string{"/usr/bin/passwd", "/tmp/evil-suid"}}
	out := captureStdout(t, func() {
		if err := runDrift(after, output.ModePlain); err != nil {
			t.Fatalf("runDrift: %v", err)
		}
	})
	if strings.Contains(out, "No security drift detected") {
		t.Errorf("a new SUID binary must be detected as drift, got: %q", out)
	}
	if !strings.Contains(out, "evil-suid") {
		t.Errorf("the new SUID binary should be named in the drift report, got: %q", out)
	}
}
