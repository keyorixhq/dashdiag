package render

import (
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
