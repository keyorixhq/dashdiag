package cmd

// capture_test.go — covers runCapture (stdin -> fixture YAML), the row-ordering
// helper buildInputFixtureRows, attachOptionalReports, and readReportJSON.
// Reuses withHookStdin (hook_run_test.go) and captureStdout (net_dns_test.go),
// both already shared package-wide. No t.Parallel() on the stdin-swap tests —
// os.Stdin is a shared global, same reasoning as captureStdout's tests.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// newBareCaptureCmd builds a standalone *cobra.Command with the flags runCapture
// and attachOptionalReports read via cmd.Flags().Get*.
func newBareCaptureCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.String("cve", "", "")
	f.Bool("cve-scan", false, "")
	f.String("timeline", "", "")
	f.Bool("include-identity", false, "")
	f.Bool("raw", false, "")
	f.StringP("out", "o", "", "")
	f.Bool("sanitize", false, "")
	f.Bool("identifiers", false, "")
	f.Bool("deep", false, "")
	f.Bool("pkg", false, "")
	return c
}

const captureValidJSON = `{
	"hostname": "web01.example.com",
	"os": "Ubuntu 24.04",
	"version": "1.2.3",
	"checks": [
		{"name": "CPU Load", "status": "OK", "inline": "12%"},
		{"name": "Disk", "status": "WARN", "inline": "80% full"}
	],
	"insights": [
		{"check": "Disk", "level": "WARN", "message": "80% full", "hints": ["clean up /var/log"]}
	]
}`

func TestRunCapture_InvalidJSON(t *testing.T) {
	withHookStdin(t, "not json at all")
	cmd := newBareCaptureCmd()
	if err := runCapture(cmd, nil); err == nil {
		t.Fatal("invalid JSON on stdin should error")
	}
}

// TestRunCapture_RejectsOversizedStdin covers cmd-01-05: runCapture must not
// buffer an unbounded amount of stdin. Before this fix a piped stream far
// larger than any real `dsd health --json` output (a misbehaving upstream
// command, a malicious/corrupted pipe source) would be read fully into
// memory before JSON parsing even started.
func TestRunCapture_RejectsOversizedStdin(t *testing.T) {
	huge := strings.Repeat("a", maxCaptureInputBytes+(2<<20))
	withHookStdin(t, huge)
	cmd := newBareCaptureCmd()
	err := runCapture(cmd, nil)
	if err == nil {
		t.Fatal("expected an error for stdin exceeding maxCaptureInputBytes, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("expected a size-cap error, got: %v", err)
	}
}

func TestRunCapture_NoChecks(t *testing.T) {
	withHookStdin(t, `{"hostname":"h","checks":[]}`)
	cmd := newBareCaptureCmd()
	err := runCapture(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "no checks found") {
		t.Fatalf("empty checks should error with 'no checks found', got: %v", err)
	}
}

func TestRunCapture_ValidRedactsHostByDefault(t *testing.T) {
	withHookStdin(t, captureValidJSON)
	cmd := newBareCaptureCmd()
	out := captureStdout(t, func() {
		if err := runCapture(cmd, nil); err != nil {
			t.Fatalf("runCapture: %v", err)
		}
	})
	if !strings.Contains(out, "redacted-host") {
		t.Errorf("hostname should be redacted by default, got:\n%s", out)
	}
	if strings.Contains(out, "web01.example.com") {
		t.Errorf("real hostname must not leak by default, got:\n%s", out)
	}
	if !strings.Contains(out, "CPU Load") || !strings.Contains(out, "Disk") {
		t.Errorf("fixture rows should carry both checks, got:\n%s", out)
	}
}

func TestRunCapture_IncludeIdentityKeepsHost(t *testing.T) {
	withHookStdin(t, captureValidJSON)
	cmd := newBareCaptureCmd()
	_ = cmd.Flags().Set("include-identity", "true")
	out := captureStdout(t, func() {
		if err := runCapture(cmd, nil); err != nil {
			t.Fatalf("runCapture: %v", err)
		}
	})
	if !strings.Contains(out, "web01.example.com") {
		t.Errorf("--include-identity should keep the real hostname, got:\n%s", out)
	}
}

func TestRunCapture_BadCVEFileErrors(t *testing.T) {
	withHookStdin(t, captureValidJSON)
	cmd := newBareCaptureCmd()
	_ = cmd.Flags().Set("cve", filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err := runCapture(cmd, nil); err == nil {
		t.Fatal("a --cve path that doesn't exist should error")
	}
}

func TestRunCapture_ValidCVEAndTimelineFoldIn(t *testing.T) {
	dir := t.TempDir()
	cvePath := filepath.Join(dir, "cve.json")
	tlPath := filepath.Join(dir, "timeline.json")
	if err := os.WriteFile(cvePath, []byte(cveAllJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tlPath, []byte(timelineJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	withHookStdin(t, captureValidJSON)
	cmd := newBareCaptureCmd()
	_ = cmd.Flags().Set("cve", cvePath)
	_ = cmd.Flags().Set("timeline", tlPath)
	out := captureStdout(t, func() {
		if err := runCapture(cmd, nil); err != nil {
			t.Fatalf("runCapture: %v", err)
		}
	})
	if !strings.Contains(out, "cve:") || !strings.Contains(out, "timeline:") {
		t.Errorf("valid --cve/--timeline sections should be folded into the fixture YAML, got:\n%s", out)
	}
}

// TestRunCapture_RawDelegates covers the --raw branch's delegation to
// runCaptureRaw (line coverage only here; runCaptureRaw's own behavior is
// covered in capture_raw_test.go). This performs one real (terse) health
// collection — same established real-I/O precedent as this package's other
// cmd-wiring tests.
func TestRunCapture_RawDelegates(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.tar.gz")
	cmd := newBareCaptureCmd()
	_ = cmd.Flags().Set("raw", "true")
	_ = cmd.Flags().Set("out", out)
	captureStdout(t, func() {
		if err := runCapture(cmd, nil); err != nil {
			t.Fatalf("runCapture (raw delegate): %v", err)
		}
	})
	if _, err := os.Stat(out); err != nil {
		t.Errorf("--raw should write a bundle at --out, got: %v", err)
	}
}

// TestBuildInputFixtureRows_OrderingAndUnordered covers the canonical
// display-order sort plus the fallback bucket for names absent from
// render.DisplayOrder().
// TestBuildFixtureRow_EmptyStatusDefaultsToOK covers the level=="" -> "OK"
// normalization branch (a check whose Status field was omitted).
func TestBuildFixtureRow_EmptyStatusDefaultsToOK(t *testing.T) {
	t.Parallel()
	c := captureCheck{Name: "Whatever", Status: "", Inline: "fine"}
	row := buildFixtureRow(c, map[string]captureInsight{})
	if row.Level != "" || row.Inline != "fine" {
		t.Errorf("empty status should behave like OK (no Level, keep Inline), got %+v", row)
	}
}

func TestBuildInputFixtureRows_OrderingAndUnordered(t *testing.T) {
	t.Parallel()
	input := captureInput{
		Checks: []captureCheck{
			{Name: "ZZZ-Unknown-Check", Status: "OK"},
			{Name: "Disk", Status: "OK"},
			{Name: "CPU Load", Status: "OK"},
		},
	}
	rows := buildInputFixtureRows(input)
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	// "CPU Load" precedes "Disk" in render.DisplayOrder(); the unknown name
	// must be appended after all known-order rows.
	if rows[0].Name != "CPU Load" || rows[1].Name != "Disk" {
		t.Errorf("known checks should follow DisplayOrder, got: %v, %v", rows[0].Name, rows[1].Name)
	}
	if rows[2].Name != "ZZZ-Unknown-Check" {
		t.Errorf("unordered/unknown check should be appended last, got: %v", rows[2].Name)
	}
}

func TestCaptureInsights_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	if got := captureInsights(nil); got != nil {
		t.Errorf("captureInsights(nil) should return nil, got %v", got)
	}
	if got := captureInsights([]captureInsight{}); got != nil {
		t.Errorf("captureInsights of an empty slice should return nil, got %v", got)
	}
}

// TestBuildFixtureRow_PrefixMatchFallback covers the no-exact-match branch:
// a check like "Sysctl" with no insight keyed exactly "Sysctl" but one keyed
// "Sysctl: swappiness" (prefix match) or "Sysctl/foo" (slash match) — and
// picks the highest-severity candidate among several matches.
func TestBuildFixtureRow_PrefixMatchFallback(t *testing.T) {
	t.Parallel()
	c := captureCheck{Name: "Sysctl", Status: "WARN"}
	insights := map[string]captureInsight{
		"Sysctl: swappiness": {Check: "Sysctl: swappiness", Level: "INFO", Message: "low sev"},
		"Sysctl/other":       {Check: "Sysctl/other", Level: "WARN", Message: "the real one"},
	}
	row := buildFixtureRow(c, insights)
	if row.Message != "the real one" {
		t.Errorf("prefix/slash match should pick the highest-severity candidate, got %q", row.Message)
	}
}

// TestBuildFixtureRow_NonOKNoMatchingInsight covers the case where a non-OK
// check has no matching insight at all (exact or prefix) — Message/Hints must
// stay empty rather than panicking or picking an unrelated insight.
func TestBuildFixtureRow_NonOKNoMatchingInsight(t *testing.T) {
	t.Parallel()
	c := captureCheck{Name: "Orphan", Status: "CRIT"}
	row := buildFixtureRow(c, map[string]captureInsight{"Unrelated": {Check: "Unrelated", Level: "WARN"}})
	if row.Message != "" || len(row.Hints) != 0 {
		t.Errorf("no matching insight should leave Message/Hints empty, got %+v", row)
	}
	if row.Level != "CRIT" {
		t.Errorf("row level should still be set from the check status, got %q", row.Level)
	}
}

func TestBuildInputFixtureRows_PicksHighestSeverityInsight(t *testing.T) {
	t.Parallel()
	input := captureInput{
		Checks: []captureCheck{{Name: "Hardening", Status: "WARN"}},
		Insights: []captureInsight{
			{Check: "Hardening", Level: "INFO", Message: "low sev"},
			{Check: "Hardening", Level: "WARN", Message: "the real one"},
		},
	}
	rows := buildInputFixtureRows(input)
	if len(rows) != 1 || rows[0].Message != "the real one" {
		t.Fatalf("row should carry the highest-severity insight, got: %+v", rows)
	}
}

func TestAttachOptionalReports_NoFlagsIsNoop(t *testing.T) {
	t.Parallel()
	cmd := newBareCaptureCmd()
	var fix MockFixture
	if err := attachOptionalReports(cmd, &fix); err != nil {
		t.Fatalf("no --cve/--timeline flags should be a no-op, got: %v", err)
	}
	if fix.CVEJSON != "" || fix.TimelineJSON != "" {
		t.Errorf("fixture should carry no optional sections, got: %+v", fix)
	}
}

func TestAttachOptionalReports_ValidBothSections(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cvePath := filepath.Join(dir, "cve.json")
	tlPath := filepath.Join(dir, "timeline.json")
	if err := os.WriteFile(cvePath, []byte(cveAllJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tlPath, []byte(timelineJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newBareCaptureCmd()
	_ = cmd.Flags().Set("cve", cvePath)
	_ = cmd.Flags().Set("timeline", tlPath)
	var fix MockFixture
	if err := attachOptionalReports(cmd, &fix); err != nil {
		t.Fatalf("valid sections should attach cleanly: %v", err)
	}
	if fix.CVEJSON != cveAllJSON {
		t.Errorf("CVEJSON not carried through verbatim, got: %q", fix.CVEJSON)
	}
	if fix.TimelineJSON != timelineJSON {
		t.Errorf("TimelineJSON not carried through verbatim, got: %q", fix.TimelineJSON)
	}
}

func TestAttachOptionalReports_MalformedTimelineErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tlPath := filepath.Join(dir, "timeline.json")
	// Feed CVE JSON to the --timeline flag: cross-fed, must be rejected.
	if err := os.WriteFile(tlPath, []byte(cveAllJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newBareCaptureCmd()
	_ = cmd.Flags().Set("timeline", tlPath)
	var fix MockFixture
	if err := attachOptionalReports(cmd, &fix); err == nil {
		t.Fatal("cross-fed CVE JSON as --timeline should be rejected")
	}
}

func TestReadReportJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	validate := func(b []byte) error {
		return strictUnmarshal(b, &models.TimelineInfo{})
	}

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, err := readReportJSON(filepath.Join(dir, "nope.json"), validate)
		if err == nil {
			t.Fatal("missing file should error")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(dir, "empty.json")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readReportJSON(p, validate)
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("empty file should error with 'empty', got: %v", err)
		}
	})

	t.Run("invalid per validator", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(p, []byte(cveAllJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readReportJSON(p, validate)
		if err == nil {
			t.Fatal("a file that fails validate() should error")
		}
	})

	t.Run("valid returns raw string", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(dir, "good.json")
		if err := os.WriteFile(p, []byte(timelineJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readReportJSON(p, validate)
		if err != nil {
			t.Fatalf("valid file should not error: %v", err)
		}
		if got != timelineJSON {
			t.Errorf("readReportJSON should return the raw bytes verbatim, got: %q", got)
		}
	})
}
