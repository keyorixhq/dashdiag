package render

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
)

func TestDegradeArrow(t *testing.T) {
	tests := []struct {
		from, to, want string
	}{
		{"OK", "CRIT", "↓"},   // worse
		{"OK", "WARN", "↓"},   // worse
		{"WARN", "CRIT", "↓"}, // worse
		{"CRIT", "WARN", "↑"}, // better
		{"WARN", "OK", "↑"},   // better
		{"CRIT", "OK", "↑"},   // better
		// QUIRK: OK and INFO share rank 0, so an OK->INFO change shows "↑"
		// (improved) even though it is not an improvement. Pinned as current
		// behavior — cosmetic only (the event still renders with the right "to").
		{"OK", "INFO", "↑"},
		{"INFO", "OK", "↑"},
	}
	for _, tt := range tests {
		if got := degradeArrow(tt.from, tt.to); got != tt.want {
			t.Errorf("degradeArrow(%q, %q) = %q, want %q", tt.from, tt.to, got, tt.want)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	if !(severityOrder("CRIT") > severityOrder("WARN") && severityOrder("WARN") > severityOrder("INFO")) {
		t.Error("severityOrder must rank CRIT > WARN > INFO/OK")
	}
	if severityOrder("INFO") != 0 || severityOrder("OK") != 0 {
		t.Error("INFO and OK should both rank 0 in severityOrder")
	}
}

func TestExtractZombieOffender(t *testing.T) {
	// Raw arrives as a JSON-decoded map after a snapshot round-trip.
	raw := map[string]interface{}{
		"zombie_procs": []interface{}{
			map[string]interface{}{"parent_name": "/usr/sbin/cron"},
			map[string]interface{}{"parent_name": "cron"}, // dedup after path-strip
			map[string]interface{}{"parent_name": "nginx"},
		},
	}
	got := extractZombieOffender(raw)
	if !strings.Contains(got, "cron") || !strings.Contains(got, "nginx") {
		t.Errorf("extractZombieOffender = %q, want cron + nginx", got)
	}
	if strings.Count(got, "cron") != 1 {
		t.Errorf("cron should be de-duplicated after path-stripping: %q", got)
	}
	// Non-map / missing field → empty.
	if extractZombieOffender("not a map") != "" {
		t.Error("non-map raw should yield empty")
	}
	if extractZombieOffender(map[string]interface{}{}) != "" {
		t.Error("missing zombie_procs should yield empty")
	}
}

func snapAt(ts time.Time, checks ...baseline.CheckResult) *baseline.Snapshot {
	return &baseline.Snapshot{Hostname: "h1", Timestamp: ts, Checks: checks}
}

func TestRenderStoryFromHistory(t *testing.T) {
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	// Memory degrades OK -> WARN between the two snapshots.
	hist := []*baseline.Snapshot{
		snapAt(t0, baseline.CheckResult{Name: "Memory", Status: "OK", Value: "50%"}),
		snapAt(t1, baseline.CheckResult{Name: "Memory", Status: "WARN", Value: "85%"}),
	}
	out := renderStoryFromHistory(hist)
	if !strings.Contains(out, "Events:") {
		t.Errorf("expected an Events section, got:\n%s", out)
	}
	if !strings.Contains(out, "Memory") || !strings.Contains(out, "↓") || !strings.Contains(out, "WARN") {
		t.Errorf("expected a Memory ↓ WARN event, got:\n%s", out)
	}
	// Last snapshot has a WARN → "Current issues".
	if !strings.Contains(out, "Current issues") {
		t.Errorf("expected Current issues section, got:\n%s", out)
	}

	// All-healthy history: no events, no issues.
	healthy := []*baseline.Snapshot{
		snapAt(t0, baseline.CheckResult{Name: "Memory", Status: "OK"}),
		snapAt(t1, baseline.CheckResult{Name: "Memory", Status: "OK"}),
	}
	if got := renderStoryFromHistory(healthy); !strings.Contains(got, "remained healthy") {
		t.Errorf("all-OK history should say remained healthy, got:\n%s", got)
	}

	// Empty history.
	if got := renderStoryFromHistory(nil); !strings.Contains(got, "No baseline history") {
		t.Errorf("empty history message wrong: %s", got)
	}
}
