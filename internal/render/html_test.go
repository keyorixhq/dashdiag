package render

import (
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

func TestGenerateHTMLReport_NilSnap(t *testing.T) {
	if _, err := GenerateHTMLReport(nil, nil, 0, nil); err == nil {
		t.Errorf("expected error on nil snapshot")
	}
}
