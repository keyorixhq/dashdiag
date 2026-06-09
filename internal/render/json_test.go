package render

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestSummarizeInsights(t *testing.T) {
	cases := []struct {
		name        string
		insights    []models.Insight
		wantVerdict string
		wantCounts  JSONCounts
	}{
		{"empty -> OK", nil, "OK", JSONCounts{}},
		{"only OK/INFO -> OK", []models.Insight{
			{Level: "OK"}, {Level: "INFO"}, {Level: "INFO"},
		}, "OK", JSONCounts{Info: 2}},
		{"warn -> WARN", []models.Insight{
			{Level: "WARN"}, {Level: "INFO"},
		}, "WARN", JSONCounts{Warn: 1, Info: 1}},
		{"crit outranks warn", []models.Insight{
			{Level: "WARN"}, {Level: "CRIT"}, {Level: "WARN"},
		}, "CRIT", JSONCounts{Crit: 1, Warn: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, c := summarizeInsights(tc.insights)
			if v != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q", v, tc.wantVerdict)
			}
			if c != tc.wantCounts {
				t.Errorf("counts = %+v, want %+v", c, tc.wantCounts)
			}
		})
	}
}

// The JSON contract must carry verdict + counts at the top level so automation
// can branch with `jq -r .verdict` instead of iterating .insights, and the
// verdict must be consistent with the counts.
func TestRenderJSON_VerdictField(t *testing.T) {
	insights := []models.Insight{
		{Check: "Disk", Level: "CRIT", Message: "full"},
		{Check: "SSH", Level: "WARN", Message: "password auth"},
		{Check: "VMware", Level: "INFO", Message: "guest"},
	}
	data, err := RenderJSON(nil, insights)
	if err != nil {
		t.Fatal(err)
	}
	var out JSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.Verdict != "CRIT" {
		t.Errorf("verdict = %q, want CRIT", out.Verdict)
	}
	if out.Counts.Crit != 1 || out.Counts.Warn != 1 || out.Counts.Info != 1 {
		t.Errorf("counts = %+v, want crit=1 warn=1 info=1", out.Counts)
	}
}

// --json / --yaml must hide the same not-applicable collectors that live health
// and --report hide: a gated-off (nil-data) collector and an Available=false
// collector with no insight are absent, not phantom "OK" checks. Errors and
// available collectors are always kept. Keeps the three surfaces consistent.
func TestRenderJSON_SkipsAbsentChecks(t *testing.T) {
	results := []runner.Result{
		{Name: "CPU Load", Data: models.CPUInfo{UsagePct: 5}},        // no Available field → kept
		{Name: "Launchd", Data: nil},                                 // gated off (nil) → skipped
		{Name: "Ceph", Data: &models.CephInfo{Available: false}},     // unavailable, no insight → skipped
		{Name: "Docker", Data: &models.DockerInfo{Available: false}}, // unavailable BUT has insight → kept
		{Name: "Disk", Data: nil, Err: errors.New("read failed")},    // error → kept
	}
	insights := []models.Insight{{Check: "Docker", Level: "WARN", Message: "container exited"}}

	data, err := RenderJSON(results, insights)
	if err != nil {
		t.Fatal(err)
	}
	var out JSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	got := map[string]string{}
	for _, c := range out.Checks {
		got[c.Name] = c.Status
	}
	for _, absent := range []string{"Launchd", "Ceph"} {
		if _, ok := got[absent]; ok {
			t.Errorf("absent collector %q must be skipped, got checks %+v", absent, out.Checks)
		}
	}
	if got["CPU Load"] != "OK" {
		t.Errorf("present collector should be OK, got %q", got["CPU Load"])
	}
	if got["Docker"] != "WARN" {
		t.Errorf("unavailable collector with an insight must be kept (WARN), got %q", got["Docker"])
	}
	if got["Disk"] != "ERROR" {
		t.Errorf("errored collector must be kept (ERROR), got %q", got["Disk"])
	}
	if len(out.Checks) != 3 {
		t.Errorf("want 3 checks (Launchd+Ceph skipped), got %d: %+v", len(out.Checks), out.Checks)
	}
}
