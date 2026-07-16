package render

import (
	"html/template"
	"os"
	"strings"
	"testing"
)

func TestGenerateFleetHTMLReport_Structure(t *testing.T) {
	t.Parallel()
	report := FleetReport{
		Date:             "2026-07-16 12:00:00 UTC",
		Version:          "v1.19.1",
		Verdict:          "CRIT",
		VerdictClass:     "crit",
		VerdictText:      "2 host(s) have critical issues or are unreachable.",
		Total:            3,
		CountOK:          1,
		CountWarn:        0,
		CountCrit:        1,
		CountUnreachable: 1,
		Year:             2026,
		Hosts: []FleetHostRow{
			{Host: "db01", Hostname: "db01.internal", Status: "CRIT", StatusClass: "crit", Crit: 2, Warn: 1, TopIssue: "disk at 98%", ElapsedMs: 1234},
			{Host: "web01", Status: "OK", StatusClass: "ok", ElapsedMs: 800},
			{Host: "10.0.0.9", Status: "UNREACHABLE", StatusClass: "error", TopIssue: "connection refused"},
		},
		Issues: []FleetIssueRow{
			{Scope: "fleet-wide", ScopeClass: "fleetwide", Level: "CRIT", LevelClass: "crit", Check: "Disk", Where: "1/2", Sample: "disk at 98%"},
			{Scope: "outlier", ScopeClass: "outlier", Level: "WARN", LevelClass: "warn", Check: "Memory", Where: "db01", Sample: "RAM at 87%"},
		},
	}

	html, err := buildFleetHTML(report)
	if err != nil {
		t.Fatalf("buildFleetHTML error: %v", err)
	}

	for _, want := range []string{
		"Fleet Health Report",
		"db01",
		"web01",
		"10.0.0.9",
		"CRIT",
		"disk at 98%",
		"connection refused",
		"fleet-wide",
		"fleetwide",
		"DashDiag",
		"v1.19.1",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in fleet HTML output", want)
		}
	}
}

func TestGenerateFleetHTMLReport_AllOK(t *testing.T) {
	t.Parallel()
	report := FleetReport{
		Date:         "2026-07-16 12:00:00 UTC",
		Version:      "v1.19.1",
		Verdict:      "OK",
		VerdictClass: "ok",
		VerdictText:  "All hosts are healthy.",
		Total:        2,
		CountOK:      2,
		Year:         2026,
		Hosts: []FleetHostRow{
			{Host: "web01", Status: "OK", StatusClass: "ok", ElapsedMs: 500},
			{Host: "web02", Status: "OK", StatusClass: "ok", ElapsedMs: 600},
		},
	}

	html, err := buildFleetHTML(report)
	if err != nil {
		t.Fatalf("buildFleetHTML error: %v", err)
	}
	if !strings.Contains(html, "All hosts are healthy") {
		t.Errorf("expected healthy verdict text in fleet HTML")
	}
	// No issues section when Issues slice is empty.
	if strings.Contains(html, "Fleet Issues") {
		t.Errorf("Fleet Issues section should be absent when there are no issues")
	}
}

// Not parallel — swaps the package-level brandOverride via SetBrand.
func TestGenerateFleetHTMLReport_Branded(t *testing.T) {
	prev := brandOverride
	SetBrand(Brand{Company: "Acme MSP"})
	defer SetBrand(prev)

	report := FleetReport{
		Date:         "2026-07-16 12:00:00 UTC",
		Version:      "v1.19.1",
		Verdict:      "OK",
		VerdictClass: "ok",
		VerdictText:  "All hosts are healthy.",
		Total:        1,
		CountOK:      1,
		Year:         2026,
		Hosts:        []FleetHostRow{{Host: "web01", Status: "OK", StatusClass: "ok"}},
	}

	html, err := buildFleetHTML(report)
	if err != nil {
		t.Fatalf("buildFleetHTML error: %v", err)
	}
	if !strings.Contains(html, "Acme MSP") {
		t.Errorf("branded report should contain company name")
	}
	if !strings.Contains(html, "powered by") {
		t.Errorf("branded report should retain DashDiag attribution")
	}
}

// TestBuildFleetHTML_YearDefault covers fleet_html.go:59-61: when Year is 0,
// buildFleetHTML fills it with the current year so the footer is never blank.
func TestBuildFleetHTML_YearDefault(t *testing.T) {
	t.Parallel()
	report := FleetReport{
		Date:    "2026-07-16 12:00:00 UTC",
		Version: "v1.19.1",
		Verdict: "OK", VerdictClass: "ok",
		VerdictText: "All hosts are healthy.",
		Total:       1, CountOK: 1,
		// Year intentionally zero — should be auto-filled by buildFleetHTML.
		Hosts: []FleetHostRow{{Host: "web01", Status: "OK", StatusClass: "ok"}},
	}

	html, err := buildFleetHTML(report)
	if err != nil {
		t.Fatalf("buildFleetHTML error: %v", err)
	}
	// The current year should appear somewhere in the output.
	if !strings.Contains(html, "202") {
		t.Errorf("expected a year in the footer, got no 202x string in output")
	}
}

// TestBuildFleetHTML_TemplateExecuteError covers fleet_html.go:68-70: the
// template execute error branch inside buildFleetHTML.
// Not parallel — swaps the package-level fleetHTMLTmpl.
func TestBuildFleetHTML_TemplateExecuteError(t *testing.T) {
	orig := fleetHTMLTmpl
	fleetHTMLTmpl = template.Must(template.New("bad").Parse(`{{template "missing" .}}`))
	defer func() { fleetHTMLTmpl = orig }()

	report := FleetReport{Year: 2026, Hosts: []FleetHostRow{{Host: "h1", Status: "OK", StatusClass: "ok"}}}
	if _, err := buildFleetHTML(report); err == nil {
		t.Error("expected error from broken template, got nil")
	}
}

// TestGenerateFleetHTMLReport_WritesFile covers fleet_html.go:77-88: the happy
// path writes a self-contained HTML file whose name embeds the timestamp.
func TestGenerateFleetHTMLReport_WritesFile(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old) //nolint:errcheck

	report := FleetReport{
		Date:    "2026-07-16 12:00:00 UTC",
		Version: "v1.19.1",
		Verdict: "OK", VerdictClass: "ok",
		VerdictText: "All hosts are healthy.",
		Total:       1, CountOK: 1,
		Year:  2026,
		Hosts: []FleetHostRow{{Host: "web01", Status: "OK", StatusClass: "ok"}},
	}

	path, err := GenerateFleetHTMLReport(report)
	if err != nil {
		t.Fatalf("GenerateFleetHTMLReport: %v", err)
	}
	if !strings.Contains(path, "dsd-fleet-report-") || !strings.HasSuffix(path, ".html") {
		t.Errorf("unexpected report path %q", path)
	}
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path in t.TempDir()
	if err != nil {
		t.Fatalf("report file not written: %v", err)
	}
	if !strings.Contains(string(data), "<!DOCTYPE html>") {
		t.Errorf("written file does not look like HTML")
	}
}

// TestGenerateFleetHTMLReport_WriteFails covers fleet_html.go:85-87: the
// os.WriteFile error path in GenerateFleetHTMLReport. The CWD is set to a
// read-only (but still traversable) directory so any write attempt fails.
// The generated filename is time-based (unlike html.go's snapshot-timestamp
// name), so it can't be pre-occupied by a directory the way html_test.go's
// WriteFails test does — a read-only directory is used instead. Skipped when
// running as root since root can write regardless of permission bits.
func TestGenerateFleetHTMLReport_WriteFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping write-fail test: running as root can write to read-only dirs")
	}

	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	roDir := t.TempDir()
	// r-xr-xr-x: keep execute (traversable, chdir succeeds) but drop write.
	if err := os.Chmod(roDir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(roDir, 0o755) //nolint:errcheck
	if err := os.Chdir(roDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old) //nolint:errcheck

	report := FleetReport{
		Year:    2026,
		Verdict: "OK", VerdictClass: "ok",
		Hosts: []FleetHostRow{{Host: "web01", Status: "OK", StatusClass: "ok"}},
	}
	if _, err := GenerateFleetHTMLReport(report); err == nil {
		t.Error("expected error when write is blocked, got nil")
	}
}
