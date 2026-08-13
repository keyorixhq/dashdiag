package render

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
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

// TestBuildMarkdown_SanitizesControlChars guards Finding internal-render-03-05:
// ins.Message/Hints and check.Name/Hostname can carry attacker-controlled
// substrings (e.g. a process name set via prctl(PR_SET_NAME), surfaced
// through an FD-limit or similar heuristic) with no character filtering.
// Markdown doesn't escape raw control/ANSI bytes any more than a terminal
// does, and this report is explicitly meant to be pasted into incident
// channels/tickets, so control bytes must be stripped before they reach the
// generated document.
func TestBuildMarkdown_SanitizesControlChars(t *testing.T) {
	t.Parallel()
	evil := "process evil\x1b[2Jname (PID 1234) has too many FDs open"
	snap := &baseline.Snapshot{
		Hostname:  "host\x1b[2Jevil",
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Checks:    []baseline.CheckResult{{Name: "FDLimits\x1b[2J", Status: "WARN", Value: evil}},
	}
	insights := []models.Insight{
		{Level: "WARN", Check: "FDLimits\x1b[2J", Message: evil, Hints: []string{"lsof -p 1234\x1b[2J"}},
	}
	md := buildMarkdown(snap, insights, time.Second, nil)
	if strings.ContainsRune(md, 0x1b) {
		t.Errorf("buildMarkdown output still contains a raw ESC byte:\n%s", md)
	}
	// SanitizeControl removes only the ESC byte, not the printable "[2J" text
	// that followed it, so the surviving payload is "evil[2Jname" — assert the
	// printable characters around the stripped byte survived, not that they
	// got glued back together.
	if !strings.Contains(md, "evil[2Jname") {
		t.Errorf("expected printable payload to survive sanitization, got:\n%s", md)
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

// TestGenerateReport_HostnamePathTraversalSanitized is the markdown-report
// sibling of TestGenerateHTMLReport_HostnamePathTraversalSanitized (same
// critical path-traversal write, same fix — see that test's doc comment for
// the full threat description). Not parallel — mutates the process CWD.
func TestGenerateReport_HostnamePathTraversalSanitized(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old) //nolint:errcheck

	s := snap("host1")
	s.Hostname = "../../../../../../../../tmp/evil"

	path, err := GenerateReport(s, nil, time.Second, nil)
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}

	wantName := "dsd-report-" + baseline.SafeHostname(s.Hostname) + "-" +
		s.Timestamp.Format("20060102-150405") + ".md"
	if path != filepath.Join(".", wantName) {
		t.Errorf("path = %q, want %q (hostname must be sanitized, not just embedded raw)", path, filepath.Join(".", wantName))
	}
	if strings.ContainsAny(filepath.Base(path), `/\`) {
		t.Errorf("filename %q still contains a path separator — traversal not blocked", filepath.Base(path))
	}
	if _, err := os.Stat(filepath.Join(work, wantName)); err != nil {
		t.Errorf("expected report file at %q inside the working directory: %v", wantName, err)
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

// Table-driven over the full pipeline (analysis.ApplyThresholds ->
// baseline.BuildSnapshot -> buildMarkdown) per collector state: succeeded,
// failed (a Go error — surfaced as INFO by analysis.ApplyThresholds since
// commit 9aba5194), and not-applicable (nil data, nil error). Before this
// change, --report collapsed the "failed" case to "✅ OK" in the table, left
// it out of the Issues section entirely, and counted it as healthy in the
// Summary — indistinguishable from both "succeeded" and "not-applicable" in
// every part of the document.
func TestReport_FailedVsNotApplicableVsOK(t *testing.T) {
	t.Parallel()
	thresh := analysis.DefaultThresholds(platform.CloudEnvironment(0))
	noCloud := platform.CloudEnvironment(0)

	cases := []struct {
		name         string
		results      []runner.Result
		wantTableHas []string
		wantTableNot []string
		wantIssueHas []string
	}{
		{
			name: "all succeed",
			results: []runner.Result{
				{Name: "CPU Load", Data: &models.CPUInfo{}},
			},
			wantTableHas: []string{"| CPU Load | ✅ OK |"},
			wantTableNot: []string{"ℹ️ INFO"},
		},
		{
			name: "one collector failed",
			results: []runner.Result{
				{Name: "CPU Load", Data: &models.CPUInfo{}},
				{Name: "Sessions", Data: nil, Err: errors.New("reading utmp: permission denied")},
			},
			wantTableHas: []string{"| CPU Load | ✅ OK |", "| Sessions | ℹ️ INFO |"},
			wantTableNot: []string{"| Sessions | ✅ OK |"},
			wantIssueHas: []string{"check could not run", "permission denied"},
		},
		{
			name: "one collector not applicable",
			results: []runner.Result{
				{Name: "CPU Load", Data: &models.CPUInfo{}},
				{Name: "BIND", Data: nil, Err: nil},
			},
			wantTableHas: []string{"| CPU Load | ✅ OK |"},
			wantTableNot: []string{"BIND"},
		},
		{
			name: "mixed: OK, failed, and not-applicable together",
			results: []runner.Result{
				{Name: "CPU Load", Data: &models.CPUInfo{}},
				{Name: "Sessions", Data: nil, Err: errors.New("reading utmp: permission denied")},
				{Name: "BIND", Data: nil, Err: nil},
			},
			wantTableHas: []string{"| CPU Load | ✅ OK |", "| Sessions | ℹ️ INFO |"},
			wantTableNot: []string{"| Sessions | ✅ OK |", "BIND"},
			wantIssueHas: []string{"check could not run"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			insights := analysis.ApplyThresholds(c.results, thresh, noCloud, platform.ContainerContext{})
			snap := baseline.BuildSnapshot(c.results, insights)
			md := buildMarkdown(snap, insights, time.Second, nil)

			// The Summary must never claim a clean pass is the same thing as
			// "nothing to show" — but per health.go:1520-1531's deliberate
			// design (do not change), the top-line stays keyed on CRIT/WARN
			// only; a collector failure (INFO) must be visible elsewhere in
			// the document instead, which the table/Issues assertions below
			// cover.
			if !strings.Contains(md, "All checks passed") {
				t.Errorf("expected the healthy summary line (no CRIT/WARN present)\n%s", md)
			}
			for _, want := range c.wantTableHas {
				if !strings.Contains(md, want) {
					t.Errorf("table missing %q\n--- report ---\n%s", want, md)
				}
			}
			for _, notWant := range c.wantTableNot {
				if strings.Contains(md, notWant) {
					t.Errorf("report should not contain %q\n--- report ---\n%s", notWant, md)
				}
			}
			for _, want := range c.wantIssueHas {
				if !strings.Contains(md, want) {
					t.Errorf("Issues section missing %q\n--- report ---\n%s", want, md)
				}
			}
		})
	}
}
