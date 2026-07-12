package cmd

import (
	"strings"
	"testing"
)

// Golden-output tests for compare.go's printCompare/printOutlierAnalysis (the
// pure helpers they call — collectCheckNames/buildStatusMatrix/
// statusesDiffer/statusSymbol — already had coverage from an earlier round).
// No t.Parallel() (corrupts captureStdout's shared os.Stdout swap).

func TestPrintCompareIdentical(t *testing.T) {
	snaps := []*compareSnapshot{
		{Hostname: "web01", Timestamp: "2026-01-01T00:00:00Z", Checks: []compareCheck{{Name: "Disk", Status: "OK"}}},
		{Hostname: "web02", Timestamp: "2026-01-01T00:00:00Z", Checks: []compareCheck{{Name: "Disk", Status: "OK"}}},
	}
	out := captureStdout(t, func() { printCompare(snaps, true, false) })
	if !strings.Contains(out, "All checks identical") {
		t.Errorf("identical checks across hosts should say so, got:\n%s", out)
	}
}

func TestPrintCompareDiverging(t *testing.T) {
	snaps := []*compareSnapshot{
		{Hostname: "web01", Timestamp: "2026-01-01T00:00:00Z", Checks: []compareCheck{{Name: "Disk", Status: "OK"}}},
		{Hostname: "web02", Timestamp: "2026-01-01T00:00:00Z", Checks: []compareCheck{{Name: "Disk", Status: "CRIT"}}},
	}
	// showAll=false: only the diverging check should be shown, with the "←" marker.
	out := captureStdout(t, func() { printCompare(snaps, true, false) })
	if !strings.Contains(out, "1 check(s) differ") {
		t.Errorf("one diverging check should be counted, got:\n%s", out)
	}
	if !strings.Contains(out, "← ") {
		t.Errorf("a diverging row should be marked, got:\n%s", out)
	}
}

// TestPrintCompareShowAllAndEmoji covers the showAll=true branch (all checks
// printed, including non-diverging ones, with the "use --all" hint suppressed)
// and the plain=false emoji statusSymbol branch.
func TestPrintCompareShowAllAndEmoji(t *testing.T) {
	snaps := []*compareSnapshot{
		{Hostname: "web01", Timestamp: "2026-01-01T00:00:00Z", Checks: []compareCheck{
			{Name: "Disk", Status: "OK"}, {Name: "CPU", Status: "WARN"},
		}},
		{Hostname: "web02", Timestamp: "2026-01-01T00:00:00Z", Checks: []compareCheck{
			{Name: "Disk", Status: "OK"}, {Name: "CPU", Status: "CRIT"},
		}},
	}
	out := captureStdout(t, func() { printCompare(snaps, false, true) })
	if !strings.Contains(out, "Disk") {
		t.Errorf("showAll=true should include the non-diverging Disk check, got:\n%s", out)
	}
	if strings.Contains(out, "use --all") {
		t.Errorf("showAll=true should not print the --all hint, got:\n%s", out)
	}
	if !strings.Contains(out, "⚠️  WARN") || !strings.Contains(out, "❌ CRIT") {
		t.Errorf("plain=false should render emoji status symbols, got:\n%s", out)
	}
}

// TestPrintCompareIdenticalShowAllHint covers the "(use --all to show all N
// checks)" hint printed when nothing diverges and showAll is false.
func TestPrintCompareIdenticalShowAllHint(t *testing.T) {
	snaps := []*compareSnapshot{
		{Hostname: "web01", Checks: []compareCheck{{Name: "Disk", Status: "OK"}}},
		{Hostname: "web02", Checks: []compareCheck{{Name: "Disk", Status: "OK"}}},
	}
	out := captureStdout(t, func() { printCompare(snaps, true, false) })
	if !strings.Contains(out, "use --all to show all 1 checks") {
		t.Errorf("expected the --all hint naming the total check count, got:\n%s", out)
	}
}

func TestPrintOutlierAnalysis(t *testing.T) {
	// Fewer than 3 hosts: outlier detection is skipped entirely (needs a
	// baseline to detect a minority-of-one against).
	snaps2 := []*compareSnapshot{{Hostname: "web01"}, {Hostname: "web02"}}
	if out := captureStdout(t, func() {
		printOutlierAnalysis(snaps2, map[string][]string{"Disk": {"OK", "CRIT"}}, []string{"Disk"}, true)
	}); out != "" {
		t.Errorf("fewer than 3 hosts should skip outlier detection, got:\n%s", out)
	}

	// 3 hosts, one with a uniquely bad status on every check — must be named
	// as the outlier.
	snaps3 := []*compareSnapshot{{Hostname: "web01"}, {Hostname: "web02"}, {Hostname: "web03"}}
	matrix := map[string][]string{
		"Disk":     {"OK", "OK", "CRIT"},
		"Services": {"OK", "OK", "WARN"},
	}
	out := captureStdout(t, func() { printOutlierAnalysis(snaps3, matrix, []string{"Disk", "Services"}, true) })
	if !strings.Contains(out, "web03") {
		t.Errorf("the host with unique bad statuses on every check should be named the outlier, got:\n%s", out)
	}
	if !strings.Contains(out, "2 check(s)") {
		t.Errorf("the outlier score should count both diverging checks, got:\n%s", out)
	}
}
