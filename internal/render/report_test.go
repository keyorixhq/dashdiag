package render

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TestBuildMarkdown_AllHealthy covers the "all checks passed" summary branch
// (no CRIT/WARN insights) — the CRIT/WARN summary lines and Issues section
// must both be absent.
func TestBuildMarkdown_AllHealthy(t *testing.T) {
	t.Parallel()
	snap := &baseline.Snapshot{
		Hostname:  "host1",
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Checks:    []baseline.CheckResult{{Name: "Memory", Status: "OK", Value: "10%"}},
	}
	md := buildMarkdown(snap, nil, time.Second, nil)
	if !strings.Contains(md, "All checks passed") {
		t.Errorf("expected all-healthy summary, got:\n%s", md)
	}
	if strings.Contains(md, "## Issues") {
		t.Errorf("no actionable insights — Issues section should be absent:\n%s", md)
	}
}

// TestBuildMarkdown_CVESection covers every severity bucket of the CVE section
// (Critical/Important/Moderate/Low) plus pluralY's singular/plural forms and
// the "no pending advisories" branch.
func TestBuildMarkdown_CVESection(t *testing.T) {
	t.Parallel()
	snap := &baseline.Snapshot{
		Hostname:  "host1",
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Checks:    []baseline.CheckResult{{Name: "Memory", Status: "OK", Value: "10%"}},
	}

	t.Run("all severities present, plural", func(t *testing.T) {
		cve := &models.CVEAllResult{
			PackageManager: "apt",
			Critical:       []models.CVEAdvisory{{ID: "CVE-1", Summary: "rce"}},
			Important:      []models.CVEAdvisory{{ID: "CVE-2", Summary: "priv-esc"}},
			Moderate:       []models.CVEAdvisory{{ID: "CVE-3", Summary: "dos"}},
			Low:            []models.CVEAdvisory{{ID: "CVE-4", Summary: "info-leak"}},
			FixCommand:     "apt upgrade",
		}
		md := buildMarkdown(snap, nil, time.Second, cve)
		for _, want := range []string{
			"pending security advisories", // plural (n=4)
			"### 🔴 Critical (1)", "CVE-1",
			"### ⚠️  Important (1)", "CVE-2",
			"### Moderate (1)", "CVE-3",
			"### Low (1)", "CVE-4",
			"To fix all: `apt upgrade`",
		} {
			if !strings.Contains(md, want) {
				t.Errorf("CVE section missing %q\n---\n%s", want, md)
			}
		}
	})

	t.Run("single advisory, singular pluralY", func(t *testing.T) {
		cve := &models.CVEAllResult{
			PackageManager: "apt",
			Critical:       []models.CVEAdvisory{{ID: "CVE-1", Summary: "rce"}},
			FixCommand:     "apt upgrade",
		}
		md := buildMarkdown(snap, nil, time.Second, cve)
		if !strings.Contains(md, "1 pending security advisory") {
			t.Errorf("expected singular 'advisory' wording, got:\n%s", md)
		}
		if strings.Contains(md, "1 pending security advisories") {
			t.Errorf("expected singular form for n=1, got plural wording:\n%s", md)
		}
	})

	t.Run("no pending advisories", func(t *testing.T) {
		cve := &models.CVEAllResult{PackageManager: "apt"}
		md := buildMarkdown(snap, nil, time.Second, cve)
		if !strings.Contains(md, "No pending security advisories") {
			t.Errorf("expected no-advisories note, got:\n%s", md)
		}
	})
}

// TestGenerateReport_NilSnap covers the nil-snapshot error guard.
func TestGenerateReport_NilSnap(t *testing.T) {
	t.Parallel()
	if _, err := GenerateReport(nil, nil, 0, nil); err == nil {
		t.Error("expected error on nil snapshot")
	}
}

// TestGenerateReport_WriteFails covers the os.WriteFile error branch: a
// directory already occupies the exact path the report would write to, so
// the write fails portably (works identically as root or non-root, unlike a
// permission-bit trick) and the error is wrapped rather than swallowed.
func TestGenerateReport_WriteFails(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old) //nolint:errcheck

	s := snap("host1")
	timestamp := s.Timestamp.Format("20060102-150405")
	filename := "dsd-report-" + s.Hostname + "-" + timestamp + ".md"
	if err := os.Mkdir(filename, 0o750); err != nil {
		t.Fatal(err)
	}

	if _, err := GenerateReport(s, nil, time.Second, nil); err == nil {
		t.Error("expected an error when the report path is occupied by a directory")
	}
}

// A subsystem-qualified CRIT ("Network/DNS") must surface as a CRIT row for its
// collector ("Network") in the --report Check Results table. The table used to
// re-derive status from the raw insights keyed by the qualified Check name and
// look it up by the base collector name, so a DNS-only CRIT rendered "Network ✅ OK"
// even though the Issues section above listed the CRIT — a false-OK in the report.
func TestReport_QualifiedCheckCritShowsInTable(t *testing.T) {
	results := []runner.Result{
		{Name: "Network", Data: &models.NetworkInfo{}},
		{Name: "Memory", Data: &models.MemoryInfo{TotalGB: 1}},
	}
	insights := []models.Insight{
		{Check: "Network/DNS", Level: "CRIT", Message: "resolver unreachable"},
		// Memory: an earlier WARN then a worse CRIT for the same base check.
		{Check: "Memory", Level: "WARN", Message: "high usage"},
		{Check: "Memory/Slab", Level: "CRIT", Message: "slab leak"},
	}
	snap := baseline.BuildSnapshot(results, insights)

	md := buildMarkdown(snap, insights, time.Second, nil)

	tbl := md[strings.Index(md, "## Check Results"):]
	for _, want := range []string{
		"| Network | 🔴 CRIT |",
		"| Memory | 🔴 CRIT |",
	} {
		if !strings.Contains(tbl, want) {
			t.Errorf("Check Results table missing %q\n--- table ---\n%s", want, tbl)
		}
	}
	if strings.Contains(tbl, "| Network | ✅ OK |") {
		t.Errorf("Network rendered as OK despite a DNS CRIT (false-OK regression)\n%s", tbl)
	}
}
