package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func ev(ts int64, level, unit, msg string) models.TimelineEvent {
	return models.TimelineEvent{TimestampUnix: ts, TimeStr: "t", Level: level, Unit: unit, Message: msg}
}

func TestGroupIncidents_GapSplitsClusters(t *testing.T) {
	events := []models.TimelineEvent{
		ev(1000, "WARN", "nginx.service", "reloading"),
		ev(1030, "CRIT", "nginx.service", "main process exited code=killed"),
		ev(1050, "WARN", "nginx.service", "restarting"),
		// >gap later — a separate incident
		ev(5000, "CRIT", "kernel", "Out of memory: Killed process 1234"),
	}
	inc := GroupIncidents(events, 120)
	if len(inc) != 2 {
		t.Fatalf("want 2 incidents, got %d: %+v", len(inc), inc)
	}
	// First incident: worst is CRIT, headlined by the killed nginx, 3 events, 1 unit, 50s span.
	a := inc[0]
	if a.Level != "CRIT" {
		t.Errorf("incident 1 level = %q, want CRIT", a.Level)
	}
	if a.Summary != "nginx.service: main process exited code=killed" {
		t.Errorf("incident 1 summary = %q", a.Summary)
	}
	if a.EventCount != 3 || a.Sources != 1 || a.DurationSec != 50 {
		t.Errorf("incident 1 = %+v (want 3 events / 1 source / 50s)", a)
	}
	if inc[1].Level != "CRIT" || inc[1].Summary != "kernel: Out of memory: Killed process 1234" {
		t.Errorf("incident 2 = %+v", inc[1])
	}
}

func TestGroupIncidents_RepeatCountsAndSources(t *testing.T) {
	events := []models.TimelineEvent{
		{TimestampUnix: 100, Level: "WARN", Unit: "a.service", Message: "x", Count: 5},
		{TimestampUnix: 110, Level: "WARN", Unit: "b.service", Message: "y"}, // Count 0 → 1
	}
	inc := GroupIncidents(events, 120)
	if len(inc) != 1 || inc[0].EventCount != 6 || inc[0].Sources != 2 {
		t.Fatalf("want 1 incident, 6 events, 2 sources; got %+v", inc)
	}
}

func TestGroupIncidents_Empty(t *testing.T) {
	if GroupIncidents(nil, 120) != nil {
		t.Error("empty input should return nil")
	}
}
