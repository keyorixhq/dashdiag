package render

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
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

// TestRenderJSON_ErroredCountsField is the regression test for
// internal-render-03-04: a failed collector (r.Err != nil) typically produces
// only an INFO-level "couldn't measure" insight, which never raises
// Verdict/Crit/Warn on its own — Counts.Errored must still surface that a
// check didn't run at all, so a machine consumer branching on
// Verdict/Counts alone (not iterating checks[]) can see it.
func TestRenderJSON_ErroredCountsField(t *testing.T) {
	results := []runner.Result{
		{Name: "Disk", Data: models.DiskInfo{}},
		{Name: "Kafka", Err: errors.New("collector timed out")},
	}
	insights := []models.Insight{
		{Check: "Kafka", Level: "INFO", Message: "kafka check could not run"},
	}
	data, err := RenderJSON(results, insights)
	if err != nil {
		t.Fatal(err)
	}
	var out JSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.Verdict != "OK" {
		t.Errorf("verdict = %q, want OK (an INFO insight alone must not raise verdict)", out.Verdict)
	}
	if out.Counts.Errored != 1 {
		t.Errorf("Counts.Errored = %d, want 1", out.Counts.Errored)
	}
}

// TestRenderJSON_ErroredCountsField_NoErrors confirms Errored stays 0 (and is
// omitted from the JSON via omitempty) when nothing failed — must not
// introduce noise for the common healthy-run case.
func TestRenderJSON_ErroredCountsField_NoErrors(t *testing.T) {
	results := []runner.Result{
		{Name: "Disk", Data: models.DiskInfo{}},
	}
	data, err := RenderJSON(results, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out JSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.Counts.Errored != 0 {
		t.Errorf("Counts.Errored = %d, want 0", out.Counts.Errored)
	}
	if strings.Contains(string(data), `"errored"`) {
		t.Error(`expected "errored" to be omitted from JSON via omitempty when zero`)
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

// TestRenderJSON_QualifiedInsightRollsUpToBaseCheckStatus covers buildOutput's
// prefix-match fallback: a subsystem-qualified insight ("Network/DNS") with no
// exact "Network" insight in the map must still roll its severity up onto the
// "Network" JSON check row (mirrors the markdown/HTML report's snapshot-status
// trust, but here it's re-derived directly from insights since no baseline
// snapshot is involved in the JSON/YAML path).
func TestRenderJSON_QualifiedInsightRollsUpToBaseCheckStatus(t *testing.T) {
	results := []runner.Result{
		{Name: "Network", Data: &models.NetworkInfo{}},
	}
	insights := []models.Insight{
		{Check: "Network/DNS", Level: "CRIT", Message: "resolver unreachable"},
	}
	data, err := RenderJSON(results, insights)
	if err != nil {
		t.Fatal(err)
	}
	var out JSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(out.Checks) != 1 || out.Checks[0].Name != "Network" {
		t.Fatalf("expected a single Network check, got %+v", out.Checks)
	}
	if out.Checks[0].Status != "CRIT" {
		t.Errorf("Network status = %q, want CRIT rolled up from Network/DNS", out.Checks[0].Status)
	}
}

// TestRenderJSON_SkipsOKInsights covers the OK-level skip in buildOutput's
// jsonInsights loop — an OK insight must not appear in the .insights array
// (only actionable/informational levels do).
func TestRenderJSON_SkipsOKInsights(t *testing.T) {
	insights := []models.Insight{
		{Check: "Disk", Level: "OK", Message: "clean"},
		{Check: "Memory", Level: "WARN", Message: "high"},
	}
	data, err := RenderJSON(nil, insights)
	if err != nil {
		t.Fatal(err)
	}
	var out JSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Insights) != 1 || out.Insights[0].Check != "Memory" {
		t.Errorf("expected only the WARN insight, got %+v", out.Insights)
	}
}

// TestRenderJSON_InsightOrderMessageTiebreak covers the final sort tiebreak:
// same level, same check — order falls back to comparing Message.
func TestRenderJSON_InsightOrderMessageTiebreak(t *testing.T) {
	insights := []models.Insight{
		{Check: "Disk", Level: "WARN", Message: "zzz second"},
		{Check: "Disk", Level: "WARN", Message: "aaa first"},
	}
	data, err := RenderJSON(nil, insights)
	if err != nil {
		t.Fatal(err)
	}
	var out JSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Insights) != 2 || out.Insights[0].Message != "aaa first" || out.Insights[1].Message != "zzz second" {
		t.Errorf("expected message-tiebreak order [aaa first, zzz second], got %+v", out.Insights)
	}
}

// TestRenderJSON_StableOrdering guards TRIAGE §I: checks[] and insights[] must come
// out in a deterministic order regardless of collector completion order, so
// `dsd health --json` / `capture` / `replay` are byte-stable and cleanly diffable.
func TestRenderJSON_StableOrdering(t *testing.T) {
	results := []runner.Result{
		{Name: "Zebra", Data: models.CPUInfo{}},
		{Name: "Apple", Data: models.CPUInfo{}},
		{Name: "Mango", Data: models.CPUInfo{}},
	}
	insights := []models.Insight{
		{Check: "Mango", Level: "WARN", Message: "m warn"},
		{Check: "Apple", Level: "CRIT", Message: "a crit"},
		{Check: "Zebra", Level: "WARN", Message: "z warn"},
		{Check: "Apple", Level: "WARN", Message: "a warn"},
	}

	data, err := RenderJSON(results, insights)
	if err != nil {
		t.Fatal(err)
	}
	var out JSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}

	// checks[] alphabetical by name
	gotChecks := make([]string, len(out.Checks))
	for i, c := range out.Checks {
		gotChecks[i] = c.Name
	}
	wantChecks := []string{"Apple", "Mango", "Zebra"}
	if !reflect.DeepEqual(gotChecks, wantChecks) {
		t.Errorf("checks order = %v, want %v", gotChecks, wantChecks)
	}

	// insights[] worst-first, then by check, then message
	type ci struct{ check, level, msg string }
	gotIns := make([]ci, len(out.Insights))
	for i, in := range out.Insights {
		gotIns[i] = ci{in.Check, in.Level, in.Message}
	}
	wantIns := []ci{
		{"Apple", "CRIT", "a crit"},
		{"Apple", "WARN", "a warn"},
		{"Mango", "WARN", "m warn"},
		{"Zebra", "WARN", "z warn"},
	}
	if !reflect.DeepEqual(gotIns, wantIns) {
		t.Errorf("insights order = %+v, want %+v", gotIns, wantIns)
	}
}
