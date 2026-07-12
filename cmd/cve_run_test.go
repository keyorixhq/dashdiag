package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newBareCVECmd builds a bare cobra.Command with the flags runCVE reads via
// cmd.Flags().GetBool/GetString, following the same pattern as
// newBareCloudCmd (oci_test.go) / TestRunNet (net_test.go).
func newBareCVECmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("json", false, "")
	f.Bool("all", false, "")
	f.String("oval", "", "")
	f.Bool("oval-scan", false, "")
	return c
}

// TestRunCVENoArgs guards the "nothing to check" error path: no CVE IDs, no
// --all, no --oval, no --oval-scan.
func TestRunCVENoArgs(t *testing.T) {
	t.Parallel()
	c := newBareCVECmd()
	err := runCVE(c, nil)
	if err == nil || !strings.Contains(err.Error(), "specify at least one CVE ID") {
		t.Errorf("runCVE with no args/flags should error asking for a CVE ID or --all, got: %v", err)
	}
}

// TestRunCVEOvalNoArgs guards --oval requiring at least one CVE ID.
func TestRunCVEOvalNoArgs(t *testing.T) {
	t.Parallel()
	c := newBareCVECmd()
	_ = c.Flags().Set("oval", "/nonexistent/path.oval.xml")
	err := runCVE(c, nil)
	if err == nil || !strings.Contains(err.Error(), "specify at least one CVE ID with --oval") {
		t.Errorf("runCVE --oval with no CVE IDs should error, got: %v", err)
	}
}

// TestRunCVEOvalInvalidPath exercises the --oval per-CVE loop against a file
// that doesn't exist: CheckCVEFromOVAL fails, the loop prints the error to
// stderr and continues rather than aborting the whole command.
func TestRunCVEOvalInvalidPath(t *testing.T) {
	c := newBareCVECmd()
	_ = c.Flags().Set("oval", "/nonexistent/path.oval.xml")
	out := captureStdout(t, func() {
		if err := runCVE(c, []string{"CVE-2024-1234", "CVE-2024-5678"}); err != nil {
			t.Fatalf("runCVE --oval with a bad file should not itself error (per-CVE errors are logged), got: %v", err)
		}
	})
	if !strings.Contains(out, "Using OVAL file") {
		t.Errorf("should announce the OVAL file in use, got:\n%s", out)
	}
	if !strings.Contains(out, "CVE-2024-1234") {
		t.Errorf("should announce each CVE being checked, got:\n%s", out)
	}
}

// TestRunCVEOvalInvalidPathJSON exercises the same --oval loop in --json mode
// (skips the "Checking..." human announcements).
func TestRunCVEOvalInvalidPathJSON(t *testing.T) {
	c := newBareCVECmd()
	_ = c.Flags().Set("oval", "/nonexistent/path.oval.xml")
	_ = c.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runCVE(c, []string{"CVE-2024-1234"}); err != nil {
			t.Fatalf("runCVE --oval --json with a bad file should not error, got: %v", err)
		}
	})
	// A load failure produces no JSON-encodable result — nothing should be
	// printed to stdout for that CVE.
	if strings.Contains(out, "CVE-2024-1234") {
		t.Errorf("a failed OVAL load must not print anything for that CVE on stdout, got:\n%s", out)
	}
}

// TestRunCVEArgs exercises runCVE / runCVEChecks with real CVE IDs against
// whatever package manager this host has (apt-get, per CLAUDE.md's
// established real-I/O precedent for cmd-level wiring tests). Read-only.
func TestRunCVEArgs(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareCVECmd()
	out := captureStdout(t, func() {
		if err := runCVE(c, []string{"CVE-2024-3094", "CVE-2024-9999999"}); err != nil {
			t.Fatalf("runCVE with real CVE IDs: %v", err)
		}
	})
	if !strings.Contains(out, "CVE-2024-3094") {
		t.Errorf("should print a per-CVE block for each ID, got:\n%s", out)
	}
	if !strings.Contains(out, "Summary:") {
		t.Errorf("multiple CVE IDs should print a summary line, got:\n%s", out)
	}
}

// TestRunCVEArgsJSON exercises the JSON-array-of-results path (>1 CVE ID).
func TestRunCVEArgsJSON(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareCVECmd()
	_ = c.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runCVE(c, []string{"CVE-2024-3094", "CVE-2024-9999999"}); err != nil {
			t.Fatalf("runCVE --json with real CVE IDs: %v", err)
		}
	})
	if !strings.Contains(out, "[") {
		t.Errorf("more than one CVE ID in --json mode should emit a JSON array, got:\n%s", out)
	}

	c2 := newBareCVECmd()
	_ = c2.Flags().Set("json", "true")
	out2 := captureStdout(t, func() {
		if err := runCVE(c2, []string{"CVE-2024-3094"}); err != nil {
			t.Fatalf("runCVE --json with a single CVE ID: %v", err)
		}
	})
	if !strings.Contains(out2, `"cve"`) && !strings.Contains(out2, `"CVE"`) {
		t.Errorf("a single CVE ID in --json mode should emit a single JSON object, got:\n%s", out2)
	}
}

// TestRunCVEAllFlag exercises the --all pending-advisories scan, plain and JSON.
func TestRunCVEAllFlag(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareCVECmd()
	_ = c.Flags().Set("all", "true")
	out := captureStdout(t, func() {
		if err := runCVE(c, nil); err != nil {
			t.Fatalf("runCVE --all: %v", err)
		}
	})
	if out == "" {
		t.Error("runCVE --all should produce output")
	}

	pendingExitCode = 0
	c2 := newBareCVECmd()
	_ = c2.Flags().Set("all", "true")
	_ = c2.Flags().Set("json", "true")
	out2 := captureStdout(t, func() {
		if err := runCVE(c2, nil); err != nil {
			t.Fatalf("runCVE --all --json: %v", err)
		}
	})
	if !strings.Contains(out2, "{") {
		t.Errorf("runCVE --all --json should emit JSON, got:\n%s", out2)
	}
}

// TestRunCVEOvalScanNoFile exercises the --oval-scan dispatch (via runCVE)
// when no OVAL file can be found (none present on this host/container) —
// must return an actionable error, not silently succeed.
func TestRunCVEOvalScanNoFile(t *testing.T) {
	t.Parallel()
	c := newBareCVECmd()
	_ = c.Flags().Set("oval-scan", "true")
	err := runCVE(c, nil)
	if err == nil || !strings.Contains(err.Error(), "no OVAL file found") {
		t.Errorf("runCVE --oval-scan with no OVAL file available should error, got: %v", err)
	}
}

// TestRunOVALScanExplicitMissingPath exercises runOVALScan directly with an
// explicit but nonexistent --oval path, taking the ScanOVALPackages error path
// rather than the auto-detect-failed path.
func TestRunOVALScanExplicitMissingPath(t *testing.T) {
	t.Parallel()
	err := runOVALScan(context.Background(), "/nonexistent/path.oval.xml", false)
	if err == nil {
		t.Error("runOVALScan with a nonexistent explicit path should error")
	}
}

// TestRunCVEInfo exercises runCVEInfo's real (read-only) filesystem/exec
// probes: package manager detection, OVAL sidecar discovery, KEV catalog
// discovery, and pre-converted snapshot discovery. None of these standard
// paths exist in this container, so every section should render its "none
// found" branch alongside guidance.
func TestRunCVEInfo(t *testing.T) {
	out := captureStdout(t, func() { runCVEInfo() })
	if !strings.Contains(out, "CVE data sources") {
		t.Errorf("should print the section header, got:\n%s", out)
	}
	if !strings.Contains(out, "OVAL files") {
		t.Errorf("should print the OVAL section, got:\n%s", out)
	}
	if !strings.Contains(out, "CISA KEV catalog") {
		t.Errorf("should print the KEV section, got:\n%s", out)
	}
	if !strings.Contains(out, "Pre-converted snapshot") {
		t.Errorf("should print the snapshot section, got:\n%s", out)
	}
}

// TestCVEInfoCmdRun exercises the cveInfoCmd.Run wrapper directly (a one-line
// closure with no branches of its own, but currently 0% covered).
func TestCVEInfoCmdRun(t *testing.T) {
	out := captureStdout(t, func() { cveInfoCmd.Run(cveInfoCmd, nil) })
	if !strings.Contains(out, "CVE data sources") {
		t.Errorf("cveInfoCmd.Run should invoke runCVEInfo, got:\n%s", out)
	}
}
