package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ── timeline_incidents.go:36 ─────────────────────────────────────────────────

// TestBuildIncident_AllSameLevelUsesFirstAsHeadline covers the
// `if headline.Message == ""` branch (line 55 of timeline_incidents.go):
// when every event has the same level (e.g. all INFO), timelineLevelRank never
// exceeds the initial worst="INFO", so headline stays zero-value and the
// fallback `headline = evs[0]` fires.
func TestBuildIncident_AllSameLevelUsesFirstAsHeadline(t *testing.T) {
	t.Parallel()
	evs := []models.TimelineEvent{
		{TimestampUnix: 100, TimeStr: "t1", Level: "INFO", Unit: "a.service", Message: "first"},
		{TimestampUnix: 110, TimeStr: "t2", Level: "INFO", Unit: "b.service", Message: "second"},
	}
	inc := buildIncident(evs)
	if inc.Summary != "a.service: first" {
		t.Errorf("Summary = %q, want first-event headline when all same level", inc.Summary)
	}
	if inc.Level != "INFO" {
		t.Errorf("Level = %q, want INFO", inc.Level)
	}
	if inc.EventCount != 2 {
		t.Errorf("EventCount = %d, want 2", inc.EventCount)
	}
}

// TestBuildIncident_NoUnit covers the headline-without-unit path in
// buildIncident: when the headline event has no Unit, Summary should be just
// the Message (no "unit: " prefix).
func TestBuildIncident_NoUnit(t *testing.T) {
	t.Parallel()
	evs := []models.TimelineEvent{
		{TimestampUnix: 100, TimeStr: "t1", Level: "CRIT", Unit: "", Message: "kernel oops"},
	}
	inc := buildIncident(evs)
	if inc.Summary != "kernel oops" {
		t.Errorf("Summary = %q, want bare message when Unit is empty", inc.Summary)
	}
}

// TestBuildIncident_CountFieldAccumulates guards that e.Count is summed into
// EventCount (Count=0 is treated as 1; non-zero Count is used as-is).
func TestBuildIncident_CountFieldAccumulates(t *testing.T) {
	t.Parallel()
	evs := []models.TimelineEvent{
		{TimestampUnix: 100, Level: "WARN", Message: "x", Count: 3},
		{TimestampUnix: 110, Level: "CRIT", Message: "y", Count: 0}, // Count=0 → +1
	}
	inc := buildIncident(evs)
	if inc.EventCount != 4 {
		t.Errorf("EventCount = %d, want 4 (3 + 1)", inc.EventCount)
	}
}
