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
	t.Parallel()
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

// TestPrintDiffSanitizesControlChars guards Finding internal-render-01-02:
// DiffEntry.Name/Before/After ultimately derive from analysis heuristics that
// can embed raw collector-reported identifiers (e.g. an NVMe/disk/pool device
// name) with no character filtering upstream. A crafted Value containing an
// ESC byte must not reach PrintDiff's output verbatim in either ModePlain or
// ModeHuman (whose lipgloss .Render does not strip embedded escapes either).
func TestPrintDiffSanitizesControlChars(t *testing.T) {
	t.Parallel()
	evilPayload := "\x1b[2Jevildevice"
	before := diffSnap("host1", baseline.CheckResult{Name: "Disk", Status: "OK", Value: "/ 24%"})
	after := diffSnap("host1", baseline.CheckResult{Name: "Disk", Status: "CRIT", Value: "94% " + evilPayload})

	// ModePlain never wraps output in lipgloss styling, so the strict
	// "no raw ESC byte anywhere" check applies cleanly here.
	var plainBuf bytes.Buffer
	if err := PrintDiff(&plainBuf, before, after, output.ModePlain); err != nil {
		t.Fatalf("PrintDiff(ModePlain): %v", err)
	}
	plainOut := plainBuf.String()
	if strings.ContainsRune(plainOut, 0x1b) {
		t.Errorf("ModePlain: output still contains a raw ESC byte: %q", plainOut)
	}
	if !strings.Contains(plainOut, "evildevice") {
		t.Errorf("ModePlain: expected printable payload to survive sanitization, got:\n%s", plainOut)
	}

	// ModeHuman legitimately wraps the line in lipgloss ANSI styling (which
	// also starts with ESC), so this mode can't assert "no ESC anywhere" —
	// instead assert the attacker's specific payload no longer appears intact
	// as a contiguous sequence.
	var humanBuf bytes.Buffer
	if err := PrintDiff(&humanBuf, before, after, output.ModeHuman); err != nil {
		t.Fatalf("PrintDiff(ModeHuman): %v", err)
	}
	humanOut := humanBuf.String()
	if strings.Contains(humanOut, evilPayload) {
		t.Errorf("ModeHuman: attacker's raw escape payload survived intact: %q", humanOut)
	}
	if !strings.Contains(humanOut, "evildevice") {
		t.Errorf("ModeHuman: expected printable payload to survive sanitization, got:\n%s", humanOut)
	}
}

// TestPrintDiffNoChange: identical snapshots report no changes (not a false diff).
func TestPrintDiffNoChange(t *testing.T) {
	t.Parallel()
	s := diffSnap("host1", baseline.CheckResult{Name: "Disk", Status: "OK", Value: "/ 24%"})
	var buf bytes.Buffer
	if err := PrintDiff(&buf, s, s, output.ModePlain); err != nil {
		t.Fatalf("PrintDiff: %v", err)
	}
	if !strings.Contains(buf.String(), "No changes detected") {
		t.Errorf("expected 'No changes detected', got:\n%s", buf.String())
	}
}

// TestPrintDiffNoChangeHumanMode covers the styled (ModeHuman) "No changes
// detected" branch — TestPrintDiffNoChange above only exercises ModePlain.
func TestPrintDiffNoChangeHumanMode(t *testing.T) {
	t.Parallel()
	s := diffSnap("host1", baseline.CheckResult{Name: "Disk", Status: "OK", Value: "/ 24%"})
	var buf bytes.Buffer
	if err := PrintDiff(&buf, s, s, output.ModeHuman); err != nil {
		t.Fatalf("PrintDiff: %v", err)
	}
	if !strings.Contains(buf.String(), "No changes detected") {
		t.Errorf("expected styled 'No changes detected', got:\n%s", buf.String())
	}
}

// TestPrintDiffHumanMode exercises the styled (ModeHuman) branches: a CRIT->OK
// improvement (styled OK, not the raw target level), a degradation, and the
// dim "Unchanged" summary line — none of which the plain-mode tests above touch.
func TestPrintDiffHumanMode(t *testing.T) {
	t.Parallel()
	before := diffSnap("host1",
		baseline.CheckResult{Name: "Disk", Status: "CRIT", Value: "/ 94%"},
		baseline.CheckResult{Name: "Memory", Status: "OK", Value: "8%"},
	)
	after := diffSnap("host1",
		baseline.CheckResult{Name: "Disk", Status: "OK", Value: "/ 20%"},
		baseline.CheckResult{Name: "Memory", Status: "OK", Value: "8%"},
	)
	var buf bytes.Buffer
	if err := PrintDiff(&buf, before, after, output.ModeHuman); err != nil {
		t.Fatalf("PrintDiff: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Disk") {
		t.Errorf("expected Disk change line, got:\n%s", out)
	}
	if !strings.Contains(out, "Unchanged") || !strings.Contains(out, "Memory") {
		t.Errorf("expected dim Unchanged summary with Memory, got:\n%s", out)
	}
	if !strings.Contains(out, "Run: dsd health deep") {
		t.Errorf("expected trailing hint line, got:\n%s", out)
	}
}

// TestPrintDiffUnverifiedTransition covers the e.Unverified branches: a
// check whose after-side reading came from an Unverified CheckResult (e.g.
// re-run non-root, data couldn't be measured) must render "(unverified —
// not confirmed this run)" in ModeHuman — the only mode that renders the
// styled diff string carrying that suffix (ModePlain's branch rebuilds its
// line from the raw before/after values instead, without it).
func TestPrintDiffUnverifiedTransition(t *testing.T) {
	t.Parallel()
	before := diffSnap("host1", baseline.CheckResult{Name: "Disk", Status: "CRIT", Value: "/ 94%"})
	after := diffSnap("host1", baseline.CheckResult{Name: "Disk", Status: "INFO", Value: "unmeasured", Unverified: true})

	var humanBuf bytes.Buffer
	if err := PrintDiff(&humanBuf, before, after, output.ModeHuman); err != nil {
		t.Fatalf("PrintDiff(ModeHuman): %v", err)
	}
	if !strings.Contains(humanBuf.String(), "(unverified — not confirmed this run)") {
		t.Errorf("ModeHuman: expected the unverified suffix, got:\n%s", humanBuf.String())
	}
}

// TestTimeAgo covers each of the three buckets (minutes, hours[+minutes], days)
// plus the "at least 1 minute" floor for a just-now timestamp.
func TestTimeAgo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ago  time.Duration
		want string
	}{
		{"just now floors to 1 min", 0, "1 min ago"},
		{"partial minute floors to 1 min", 30 * time.Second, "1 min ago"},
		{"whole minutes", 5 * time.Minute, "5 min ago"},
		{"hours with remainder minutes", 2*time.Hour + 15*time.Minute, "2h 15m ago"},
		{"exact hours, no minute remainder", 3 * time.Hour, "3h ago"},
		{"days", 50 * time.Hour, "2 days ago"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := timeAgo(time.Now().Add(-tc.ago))
			if got != tc.want {
				t.Errorf("timeAgo(-%v) = %q, want %q", tc.ago, got, tc.want)
			}
		})
	}
}

// TestAfterLevel covers the malformed-input fallback: a StatusChange string
// without the "->" separator must default to "OK" rather than panicking or
// mis-parsing.
func TestAfterLevel(t *testing.T) {
	t.Parallel()
	if got := afterLevel("OK->CRIT"); got != "CRIT" {
		t.Errorf("afterLevel(OK->CRIT) = %q, want CRIT", got)
	}
	if got := afterLevel("garbage"); got != "OK" {
		t.Errorf("afterLevel(malformed) = %q, want OK fallback", got)
	}
}

// TestPrintDiffJSON_WriteError covers the w.Write error path in ModeJSON: when the
// writer fails after a successful marshal, PrintDiff propagates the error.
func TestPrintDiffJSON_WriteError(t *testing.T) {
	t.Parallel()
	before := diffSnap("h", baseline.CheckResult{Name: "Disk", Status: "OK", Value: "/ 24%"})
	after := diffSnap("h", baseline.CheckResult{Name: "Disk", Status: "CRIT", Value: "/ 94%"})

	if err := PrintDiff(&errWriter{}, before, after, output.ModeJSON); err == nil {
		t.Error("expected error from failing writer, got nil")
	}
}

// TestPrintDiffJSON: --json emits a machine-readable DiffEntry array with the
// changed entry flagged.
func TestPrintDiffJSON(t *testing.T) {
	t.Parallel()
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
