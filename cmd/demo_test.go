package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/demo"
)

// newBareDemoCmd returns a cobra.Command with the flags runDemo reads, without
// going through rootCmd's PersistentPreRun (which would print the real brand
// header and touch package-level flag state shared with other tests).
func newBareDemoCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("list", false, "")
	f.Bool("json", false, "")
	f.Bool("plain", false, "")
	return c
}

// No t.Parallel() anywhere in this file — captureStdout/captureStderr swap the
// shared global os.Stdout/os.Stderr (same convention as
// internal/render/health_mock_test.go's quietStdout), and runDemo's exit-code
// tests read/write the shared pendingExitCode package var.
func TestDemoList(t *testing.T) {
	c := newBareDemoCmd()
	if err := c.Flags().Set("list", "true"); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runDemo(c, nil); err != nil {
			t.Errorf("runDemo(--list): %v", err)
		}
	})
	for _, name := range demo.Names() {
		if !strings.Contains(out, name) {
			t.Errorf("--list output missing scenario %q:\n%s", name, out)
		}
	}
	if !strings.Contains(out, demo.Default()) {
		t.Errorf("--list output missing default scenario %q:\n%s", demo.Default(), out)
	}
}

func TestDemoDefaultScenario(t *testing.T) {
	c := newBareDemoCmd()
	var stdout, stderr string
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := runDemo(c, nil); err != nil {
				t.Errorf("runDemo(): %v", err)
			}
		})
	})
	if !strings.Contains(stderr, "DEMO") {
		t.Errorf("stderr missing DEMO banner:\n%s", stderr)
	}
	if !strings.Contains(stdout, "Drives") {
		t.Errorf("stdout missing expected failing-drive row:\n%s", stdout)
	}
}

func TestDemoNamedScenario(t *testing.T) {
	c := newBareDemoCmd()
	stdout := captureStdout(t, func() {
		if err := runDemo(c, []string{"docker-host-meltdown"}); err != nil {
			t.Errorf("runDemo(docker-host-meltdown): %v", err)
		}
	})
	if !strings.Contains(stdout, "Docker") {
		t.Errorf("stdout missing expected Docker row for docker-host-meltdown:\n%s", stdout)
	}
}

func TestDemoUnknownScenario(t *testing.T) {
	c := newBareDemoCmd()
	err := captureStderrErr(t, func() error {
		return runDemo(c, []string{"does-not-exist"})
	})
	if err == nil {
		t.Fatal("runDemo(does-not-exist) = nil error, want an error")
	}
}

// captureStderrErr runs f with stderr suppressed and returns f's error.
func captureStderrErr(t *testing.T, f func() error) error {
	t.Helper()
	var err error
	captureStderr(t, func() { err = f() })
	return err
}

func TestDemoJSONHasDemoTrueAndHealthSchema(t *testing.T) {
	c := newBareDemoCmd()
	if err := c.Flags().Set("json", "true"); err != nil {
		t.Fatal(err)
	}
	stdout := captureStdout(t, func() {
		if err := runDemo(c, nil); err != nil {
			t.Errorf("runDemo(--json): %v", err)
		}
	})

	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", err, stdout)
	}
	if demoVal, ok := out["demo"]; !ok || demoVal != true {
		t.Errorf("json output missing top-level demo:true, got demo=%v", out["demo"])
	}
	for _, field := range []string{"hostname", "os", "verdict", "counts", "checks", "insights"} {
		if _, ok := out[field]; !ok {
			t.Errorf("json output missing dsd health --json contract field %q: %s", field, stdout)
		}
	}
	if out["hostname"] != "db-prod-02" {
		t.Errorf("json hostname = %v, want the failing-drive fixture's simulated host, not this machine's", out["hostname"])
	}
}

// TestDemoAlwaysExitsZero: `dsd demo` renders a scenario carrying a real CRIT
// insight, but must never raise pendingExitCode — it's simulated data, not a
// live host gate a script could mistake for a real result (see this file's
// package doc and contract_test.go's exitCodeContract entry for "demo").
func TestDemoAlwaysExitsZero(t *testing.T) {
	prev := pendingExitCode
	pendingExitCode = 0
	defer func() { pendingExitCode = prev }()

	c := newBareDemoCmd()
	captureStderr(t, func() {
		captureStdout(t, func() {
			// failing-drive carries a CRIT insight (Drives: SMART FAILED).
			if err := runDemo(c, []string{"failing-drive"}); err != nil {
				t.Errorf("runDemo(failing-drive): %v", err)
			}
		})
	})
	if pendingExitCode != 0 {
		t.Errorf("pendingExitCode = %d after a CRIT demo scenario, want 0 — dsd demo must always exit 0", pendingExitCode)
	}
}
