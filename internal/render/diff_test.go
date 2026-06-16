package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func diffSnap(host string, checks ...baseline.CheckResult) *baseline.Snapshot {
	return &baseline.Snapshot{
		Hostname:  host,
		Timestamp: time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC),
		Checks:    checks,
	}
}

// TestPrintDiffPlainChange covers the support-workflow core: a degraded check is
// surfaced with its before→after status, and an unchanged check is summarised.
func TestPrintDiffPlainChange(t *testing.T) {
	before := diffSnap("host1",
		baseline.CheckResult{Name: "Disk", Status: "OK", Value: "/ 24%"},
		baseline.CheckResult{Name: "Memory", Status: "OK", Value: "8%"},
	)
	after := diffSnap("host1",
		baseline.CheckResult{Name: "Disk", Status: "CRIT", Value: "/ 94%"},
		baseline.CheckResult{Name: "Memory", Status: "OK", Value: "8%"},
	)

	var buf bytes.Buffer
	if err := PrintDiff(&buf, before, after, output.ModePlain); err != nil {
		t.Fatalf("PrintDiff: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Disk") || !strings.Contains(out, "OK") || !strings.Contains(out, "CRIT") {
		t.Errorf("expected Disk OK -> CRIT change in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Unchanged") || !strings.Contains(out, "Memory") {
		t.Errorf("expected Memory listed as unchanged, got:\n%s", out)
	}
}

// TestPrintDiffNoChange: identical snapshots report no changes (not a false diff).
func TestPrintDiffNoChange(t *testing.T) {
	s := diffSnap("host1", baseline.CheckResult{Name: "Disk", Status: "OK", Value: "/ 24%"})
	var buf bytes.Buffer
	if err := PrintDiff(&buf, s, s, output.ModePlain); err != nil {
		t.Fatalf("PrintDiff: %v", err)
	}
	if !strings.Contains(buf.String(), "No changes detected") {
		t.Errorf("expected 'No changes detected', got:\n%s", buf.String())
	}
}

// TestPrintDiffJSON: --json emits a machine-readable DiffEntry array with the
// changed entry flagged.
func TestPrintDiffJSON(t *testing.T) {
	before := diffSnap("h", baseline.CheckResult{Name: "Disk", Status: "OK", Value: "/ 24%"})
	after := diffSnap("h", baseline.CheckResult{Name: "Disk", Status: "CRIT", Value: "/ 94%"})

	var buf bytes.Buffer
	if err := PrintDiff(&buf, before, after, output.ModeJSON); err != nil {
		t.Fatalf("PrintDiff: %v", err)
	}
	var entries []baseline.DiffEntry
	if err := json.Unmarshal(buf.Bytes(), &entries); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	var found bool
	for _, e := range entries {
		if e.Name == "Disk" {
			found = true
			if !e.Changed || e.Improved {
				t.Errorf("Disk should be Changed and not Improved, got %+v", e)
			}
			if e.StatusChange != "OK->CRIT" {
				t.Errorf("StatusChange = %q, want OK->CRIT", e.StatusChange)
			}
		}
	}
	if !found {
		t.Errorf("Disk entry missing from JSON diff: %s", buf.String())
	}
}
