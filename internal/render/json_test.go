package render

import (
	"encoding/json"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
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
