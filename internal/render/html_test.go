package render

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

func sampleSnap(status string) *baseline.Snapshot {
	return &baseline.Snapshot{
		Hostname:  "host1",
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Version:   "1.4.3",
		Checks: []baseline.CheckResult{
			{Name: "Memory", Status: status, Value: "47% used"},
			{Name: "Disk", Status: "OK", Value: "30% used"},
		},
	}
}

func TestBuildHTML_StructureAndContent(t *testing.T) {
	t.Parallel()
	snap := sampleSnap("CRIT")
	insights := []models.Insight{
		{Check: "Memory", Level: "CRIT", Message: "out of memory", Hints: []string{"free up RAM"}},
		{Check: "Disk", Level: "WARN", Message: "disk filling up"},
	}
	cve := &models.CVEAllResult{
		PackageManager: "apt",
		Critical:       []models.CVEAdvisory{{ID: "CVE-2026-1", Summary: "rce in foo"}},
		FixCommand:     "apt upgrade",
	}

	html, err := buildHTML(snap, insights, 2*time.Second, cve)
	if err != nil {
		t.Fatalf("buildHTML: %v", err)
	}

	for _, want := range []string{
		"<!DOCTYPE html>", "</html>",
		"host1",           // hostname
		"CRITICAL",        // verdict banner (crit present)
		"out of memory",   // CRIT insight message
		"free up RAM",     // remediation hint
		"disk filling up", // WARN insight message
		"47% used",        // check detail from snapshot Value
		"apt",             // CVE package manager
		"CVE-2026-1",      // advisory id
		"apt upgrade",     // fix command
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

// SECURITY: host-derived data (insight messages, check names, hostnames, CVE
// summaries) is rendered into HTML. It MUST be escaped or a malicious/garbled
// value becomes stored XSS in a report a customer opens in a browser. html/template
// does this; this test guards that we never switch to unsafe string concatenation.
func TestBuildHTML_EscapesHostData(t *testing.T) {
	t.Parallel()
	snap := sampleSnap("WARN")
	snap.Hostname = "<script>alert('host')</script>"
	insights := []models.Insight{
		{Check: "X", Level: "WARN", Message: "<script>alert('msg')</script>", Hints: []string{"<script>alert('hint')</script>"}},
	}
	html, err := buildHTML(snap, insights, time.Second, nil)
	if err != nil {
		t.Fatalf("buildHTML: %v", err)
	}
	if strings.Contains(html, "<script>alert(") {
		t.Errorf("unescaped <script> in HTML report — XSS vector")
	}
	// The escaped form must be present (proves the data was rendered, just safely).
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("expected escaped script tag in output")
	}
}

func TestBuildHTML_HealthyVerdict(t *testing.T) {
	t.Parallel()
	html, err := buildHTML(sampleSnap("OK"), nil, time.Second, nil)
	if err != nil {
		t.Fatalf("buildHTML: %v", err)
	}
	if !strings.Contains(html, "HEALTHY") {
		t.Errorf("expected HEALTHY verdict for no actionable insights")
	}
	if !strings.Contains(html, "No critical or warning issues found.") {
		t.Errorf("expected clean-issues note")
	}
}

// A collector that errored (INFO status/level) must render with its own
// "info" class in both the Check Results table and the Issues list — not
// silently collapse into the "ok"/"warn" styling the way the markdown
// report's table used to collapse INFO to "✅ OK". The verdict itself stays
// HEALTHY (mirrors PrintSummary's deliberate CRIT/WARN-only top line).
func TestBuildHTML_FailedCollectorRendersAsInfo(t *testing.T) {
	t.Parallel()
	snap := &baseline.Snapshot{
		Hostname:  "host1",
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Checks: []baseline.CheckResult{
			{Name: "CPU Load", Status: "OK", Value: "5% load"},
			{Name: "Sessions", Status: "INFO", Value: "check could not run — permission denied"},
		},
	}
	insights := []models.Insight{
		{Check: "Sessions", Level: "INFO", Message: "check could not run — permission denied"},
	}
	html, err := buildHTML(snap, insights, time.Second, nil)
	if err != nil {
		t.Fatalf("buildHTML: %v", err)
	}
	if !strings.Contains(html, "HEALTHY") {
		t.Errorf("expected HEALTHY verdict — INFO must not affect the pass/fail verdict")
	}
	if !strings.Contains(html, `<span class="st info">INFO</span>`) {
		t.Errorf("expected the Sessions row styled with the info status class, got:\n%s", html)
	}
	if got := strings.Count(html, `<span class="st ok">OK</span>`); got != 1 {
		t.Errorf("expected exactly 1 OK row (CPU Load only), got %d:\n%s", got, html)
	}
	if !strings.Contains(html, `<div class="issue info">`) {
		t.Errorf("expected the Sessions insight in the Issues section with the info class, got:\n%s", html)
	}
	if !strings.Contains(html, "check could not run — permission denied") {
		t.Errorf("expected the collector-failure message to be visible, got:\n%s", html)
	}
}

// TestBuildHTML_SanitizesControlChars guards Finding internal-analysis-11-02:
// buildHTML relied solely on html/template's auto-escaping ("&'\"<>+), which
// does not strip control/ANSI bytes (e.g. ESC 0x1B) embedded in
// attacker-influenced text (a process name, a replayed capture bundle).
// Those bytes would survive into the generated .html file and fire if it's
// later `cat`'d to a terminal. output.SanitizeControl must run on
// ins.Message/Hints in addition to (not instead of) the template's own HTML
// escaping — mirrors TestBuildMarkdown_SanitizesControlChars in report_test.go.
func TestBuildHTML_SanitizesControlChars(t *testing.T) {
	t.Parallel()
	evil := "process evil\x1b[2Jname (PID 1234) has too many FDs open"
	snap := sampleSnap("WARN")
	insights := []models.Insight{
		{Check: "X", Level: "WARN", Message: evil, Hints: []string{"lsof -p 1234\x1b[2J"}},
	}
	html, err := buildHTML(snap, insights, time.Second, nil)
	if err != nil {
		t.Fatalf("buildHTML: %v", err)
	}
	if strings.ContainsRune(html, 0x1b) {
		t.Errorf("buildHTML output still contains a raw ESC byte:\n%s", html)
	}
	// SanitizeControl removes only the ESC byte, not the printable "[2J" text
	// that followed it — assert the printable payload around the stripped
	// byte survived.
	if !strings.Contains(html, "evil[2Jname") {
		t.Errorf("expected printable payload to survive sanitization, got:\n%s", html)
	}
}

func TestGenerateHTMLReport_NilSnap(t *testing.T) {
	t.Parallel()
	if _, err := GenerateHTMLReport(nil, nil, 0, nil); err == nil {
		t.Errorf("expected error on nil snapshot")
	}
}

// TestBuildHTML_TemplateExecuteError covers html.go:143-145: the template
// execute error branch inside buildHTML, and by extension html.go:29-31 where
// GenerateHTMLReport propagates a buildHTML failure.
// Not parallel — swaps the package-level htmlReportTmpl.
func TestBuildHTML_TemplateExecuteError(t *testing.T) {
	orig := htmlReportTmpl
	htmlReportTmpl = template.Must(template.New("bad").Parse(`{{template "missing" .}}`))
	defer func() { htmlReportTmpl = orig }()

	if _, err := buildHTML(sampleSnap("OK"), nil, time.Second, nil); err == nil {
		t.Error("expected error from broken template, got nil")
	}
}

// TestGenerateHTMLReport_BuildError covers html.go:29-31: GenerateHTMLReport
// propagates a buildHTML error when the report template is broken.
// Not parallel — swaps the package-level htmlReportTmpl.
func TestGenerateHTMLReport_BuildError(t *testing.T) {
	orig := htmlReportTmpl
	htmlReportTmpl = template.Must(template.New("bad").Parse(`{{template "missing" .}}`))
	defer func() { htmlReportTmpl = orig }()

	if _, err := GenerateHTMLReport(sampleSnap("OK"), nil, time.Second, nil); err == nil {
		t.Error("expected error propagated from buildHTML, got nil")
	}
}

// TestGenerateHTMLReport_WritesFile covers the happy path: a valid snapshot
// produces a self-contained HTML file on disk at the expected name. Writes
// into a temp CWD so the test never litters the source tree.
func TestGenerateHTMLReport_WritesFile(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old) //nolint:errcheck

	snap := sampleSnap("OK")
	path, err := GenerateHTMLReport(snap, nil, time.Second, nil)
	if err != nil {
		t.Fatalf("GenerateHTMLReport: %v", err)
	}
	if !strings.Contains(path, "dsd-report-host1-") || !strings.HasSuffix(path, ".html") {
		t.Errorf("unexpected report path %q", path)
	}
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path in t.TempDir()
	if err != nil {
		t.Fatalf("report file not written: %v", err)
	}
	if !strings.Contains(string(data), "<!DOCTYPE html>") {
		t.Errorf("written file does not look like HTML:\n%s", data)
	}
}

// TestGenerateHTMLReport_WriteFails covers the os.WriteFile error branch: a
// directory already occupies the exact path the report would write to, so
// the write fails portably (works identically as root or non-root, unlike a
// permission-bit trick) and the error is wrapped rather than swallowed.
func TestGenerateHTMLReport_WriteFails(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old) //nolint:errcheck

	snap := sampleSnap("OK")
	timestamp := snap.Timestamp.Format("20060102-150405")
	filename := "dsd-report-" + snap.Hostname + "-" + timestamp + ".html"
	if err := os.Mkdir(filename, 0o750); err != nil {
		t.Fatal(err)
	}

	if _, err := GenerateHTMLReport(snap, nil, time.Second, nil); err == nil {
		t.Error("expected an error when the report path is occupied by a directory")
	}
}

// TestGenerateHTMLReport_HostnamePathTraversalSanitized is the regression
// guard for a critical path-traversal write: during `dsd replay <bundle>
// --report`, snap.Hostname is platform.Hostname(), which honors the replay
// identity override read straight out of the bundle manifest's Host field
// with no validation. A hostname of "../../../../tmp/evil" previously
// survived filepath.Join(".", filename) unmodified and could overwrite an
// arbitrary file outside the working directory (os.WriteFile truncates).
// Not parallel — mutates the process CWD via os.Chdir.
func TestGenerateHTMLReport_HostnamePathTraversalSanitized(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old) //nolint:errcheck

	snap := sampleSnap("OK")
	snap.Hostname = "../../../../../../../../tmp/evil"

	path, err := GenerateHTMLReport(snap, nil, time.Second, nil)
	if err != nil {
		t.Fatalf("GenerateHTMLReport: %v", err)
	}

	// The written path must be a plain filename directly under the CWD — a
	// slash surviving anywhere in it means sanitization was bypassed.
	wantName := "dsd-report-" + baseline.SafeHostname(snap.Hostname) + "-" +
		snap.Timestamp.Format("20060102-150405") + ".html"
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
