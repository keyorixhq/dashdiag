package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestActiveInsightsDeterministicOrder(t *testing.T) {
	// seen is a map; activeInsights must return a name-sorted slice so the narrated
	// story line order is stable run-to-run (TRIAGE §I). OK-level is dropped.
	ins := []models.Insight{
		{Check: "Zebra", Level: "WARN", Message: "z"},
		{Check: "Apple", Level: "CRIT", Message: "a"},
		{Check: "Mango", Level: "WARN", Message: "m"},
		{Check: "Healthy", Level: "OK", Message: "ok"},
	}
	for range 50 {
		got := activeInsights(ins)
		if len(got) != 3 {
			t.Fatalf("expected 3 active insights, got %d", len(got))
		}
		if got[0].Check != "Apple" || got[1].Check != "Mango" || got[2].Check != "Zebra" {
			t.Fatalf("expected stable order [Apple Mango Zebra], got [%s %s %s]",
				got[0].Check, got[1].Check, got[2].Check)
		}
	}
}

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
	if severityOrder("CRIT") <= severityOrder("WARN") || severityOrder("WARN") <= severityOrder("INFO") {
		t.Error("severityOrder must rank CRIT > WARN > INFO/OK")
	}
	if severityOrder("INFO") != 0 || severityOrder("OK") != 0 {
		t.Error("INFO and OK should both rank 0 in severityOrder")
	}
}

func TestExtractZombieOffender(t *testing.T) {
	// Raw arrives as a JSON-decoded map after a snapshot round-trip.
	raw := map[string]any{
		"zombie_procs": []any{
			map[string]any{"parent_name": "/usr/sbin/cron"},
			map[string]any{"parent_name": "cron"}, // dedup after path-strip
			map[string]any{"parent_name": "nginx"},
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
	if extractZombieOffender(map[string]any{}) != "" {
		t.Error("missing zombie_procs should yield empty")
	}
	// zombie_procs present but wrong element type / missing parent_name → those
	// entries are skipped, not fatal to the whole extraction.
	mixed := map[string]any{
		"zombie_procs": []any{
			"not a map",                           // wrong element type — skipped
			map[string]any{"parent_name": ""},     // empty name — skipped
			map[string]any{"other_field": "x"},    // missing parent_name — skipped
			map[string]any{"parent_name": "cron"}, // the one valid entry
		},
	}
	if got := extractZombieOffender(mixed); got != "cron" {
		t.Errorf("extractZombieOffender(mixed) = %q, want only the valid entry (cron)", got)
	}
	// zombie_procs present but empty slice → empty.
	if extractZombieOffender(map[string]any{"zombie_procs": []any{}}) != "" {
		t.Error("empty zombie_procs slice should yield empty")
	}
}

func snapAt(ts time.Time, checks ...baseline.CheckResult) *baseline.Snapshot {
	return &baseline.Snapshot{Hostname: "h1", Timestamp: ts, Checks: checks}
}

// writeHistorySnap writes a timestamped baseline file directly into the
// isolated $HOME/.dsd/baselines dir — the same shape baseline.LoadHistory
// globs for (hostname-YYYYMMDD-HHMMSS.json). Mirrors
// internal/baseline/since_deploy_test.go's TestLoadHistory pattern.
func writeHistorySnap(t *testing.T, dir, hostname string, ts time.Time, checks ...baseline.CheckResult) {
	t.Helper()
	bdir := filepath.Join(dir, ".dsd", "baselines")
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	snap := baseline.Snapshot{Hostname: hostname, Timestamp: ts, Checks: checks}
	data, err := json.MarshalIndent(&snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fname := hostname + "-" + ts.Format("20060102-150405") + ".json"
	if err := os.WriteFile(filepath.Join(bdir, fname), data, 0o644); err != nil { //nolint:gosec // test fixture, world-readable is fine
		t.Fatal(err)
	}
}

// TestRenderStory covers both of RenderStory's branches: with 2+ saved
// history snapshots it narrates via RenderStoryFromHistory; with fewer than
// 2 (or none) it falls back to renderStorySinglePoint. $HOME is isolated to a
// temp dir per the baseline package's own test convention — never touches a
// real ~/.dsd.
func TestRenderStory(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("falls back to single point with no history", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		snap := &baseline.Snapshot{Hostname: hostname, Timestamp: time.Now(), Checks: []baseline.CheckResult{{Name: "CPU Load", Status: "OK"}}}
		got := RenderStory(nil, snap)
		if !strings.Contains(got, "all 1 checks passed") {
			t.Errorf("expected single-point fallback narration, got:\n%s", got)
		}
	})

	t.Run("narrates from history when 2+ snapshots exist", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		t0 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
		t1 := t0.Add(time.Hour)
		writeHistorySnap(t, dir, hostname, t0, baseline.CheckResult{Name: "Memory", Status: "OK", Value: "50%"})
		writeHistorySnap(t, dir, hostname, t1, baseline.CheckResult{Name: "Memory", Status: "WARN", Value: "85%"})

		got := RenderStory(nil, &baseline.Snapshot{Hostname: hostname, Timestamp: t1})
		if !strings.Contains(got, "Events:") || !strings.Contains(got, "snapshots") {
			t.Errorf("expected history narration (Events/snapshot count), got:\n%s", got)
		}
	})
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

// TestRenderStoryFromHistory_EmptyMessageEvent covers the event.message==""
// branch — a status change whose Value is blank prints without the trailing
// "— message" suffix.
func TestRenderStoryFromHistory_EmptyMessageEvent(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	hist := []*baseline.Snapshot{
		snapAt(t0, baseline.CheckResult{Name: "Systemd", Status: "OK", Value: ""}),
		snapAt(t1, baseline.CheckResult{Name: "Systemd", Status: "WARN", Value: ""}),
	}
	out := renderStoryFromHistory(hist)
	if !strings.Contains(out, "Systemd") || strings.Contains(out, "—  ") {
		t.Errorf("expected an event line with no dangling message separator, got:\n%s", out)
	}
}

// TestRenderStoryFromHistory_ZombieOffenderAndRecovered covers two branches
// TestRenderStoryFromHistory above doesn't reach: (1) a Processes event
// carries the zombie parent-process offender appended to its message, and
// (2) when events occurred but the LAST snapshot is fully healthy again, the
// story says "All checks currently healthy" rather than "Current issues".
func TestRenderStoryFromHistory_ZombieOffenderAndRecovered(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t1.Add(time.Hour)

	zombieRaw := map[string]any{
		"zombie_procs": []any{map[string]any{"parent_name": "/usr/sbin/cron"}},
	}
	hist := []*baseline.Snapshot{
		snapAt(t0, baseline.CheckResult{Name: "Processes", Status: "OK", Value: "120 running"}),
		snapAt(t1, baseline.CheckResult{Name: "Processes", Status: "CRIT", Value: "3 zombie", Raw: zombieRaw}),
		snapAt(t2, baseline.CheckResult{Name: "Processes", Status: "OK", Value: "118 running"}),
	}
	out := renderStoryFromHistory(hist)

	if !strings.Contains(out, "offender: cron") {
		t.Errorf("expected zombie offender annotation on the Processes event, got:\n%s", out)
	}
	if !strings.Contains(out, "All checks currently healthy") {
		t.Errorf("last snapshot is fully OK after prior events — expected recovered note, got:\n%s", out)
	}
	if strings.Contains(out, "Current issues") {
		t.Errorf("no WARN/CRIT in last snapshot — Current issues section should be absent:\n%s", out)
	}
}

// TestRenderStorySanitizesControlChars guards Finding internal-render-04-01:
// ins.Message/c.Value and extractZombieOffender's ParentName (sourced from
// /proc/PID/comm, attacker-settable via prctl(PR_SET_NAME)) reach the
// terminal with no control-character stripping in either narration path.
func TestRenderStorySanitizesControlChars(t *testing.T) {
	t.Parallel()
	evil := "evil\x1b[2Jname"

	// Single-point path: ins.Message.
	s := snapAt(time.Date(2026, 6, 6, 15, 4, 0, 0, time.UTC), baseline.CheckResult{Name: "CPU Load", Status: "OK"})
	insights := []models.Insight{{Check: "CPU Load", Level: "CRIT", Message: evil}}
	got := renderStorySinglePoint(insights, s)
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("renderStorySinglePoint: control byte survived: %q", got)
	}

	// History path: c.Value and the zombie-offender ParentName.
	t0 := time.Date(2026, 6, 6, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	zombieRaw := map[string]any{
		"zombie_procs": []any{map[string]any{"parent_name": evil}},
	}
	hist := []*baseline.Snapshot{
		snapAt(t0, baseline.CheckResult{Name: "Processes", Status: "OK", Value: "120 running"}),
		snapAt(t1, baseline.CheckResult{Name: "Processes", Status: "CRIT", Value: evil, Raw: zombieRaw}),
	}
	out := renderStoryFromHistory(hist)
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("renderStoryFromHistory: control byte survived: %q", out)
	}

	// extractZombieOffender directly.
	if got := extractZombieOffender(zombieRaw); strings.ContainsRune(got, 0x1b) {
		t.Errorf("extractZombieOffender: control byte survived: %q", got)
	}
}

// renderStorySinglePoint is the fallback RenderStory uses when no baseline
// history exists yet (fewer than 2 saved snapshots).
func TestRenderStorySinglePoint(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 6, 6, 15, 4, 0, 0, time.UTC)
	s := snapAt(ts, baseline.CheckResult{Name: "CPU Load", Status: "OK"}, baseline.CheckResult{Name: "Memory", Status: "OK"})

	t.Run("all OK", func(t *testing.T) {
		t.Parallel()
		got := renderStorySinglePoint(nil, s)
		if !strings.Contains(got, "all 2 checks passed") {
			t.Errorf("expected all-passed message, got: %s", got)
		}
		if !strings.Contains(got, s.Hostname) {
			t.Errorf("expected hostname in output, got: %s", got)
		}
	})

	t.Run("active insights", func(t *testing.T) {
		t.Parallel()
		insights := []models.Insight{
			{Check: "CPU Load", Level: "CRIT", Message: "95% CPU"},
			{Check: "Memory", Level: "OK", Message: "fine"}, // dropped — OK is not active
		}
		got := renderStorySinglePoint(insights, s)
		if !strings.Contains(got, "CPU Load: 95% CPU") {
			t.Errorf("expected active insight line, got: %s", got)
		}
		if strings.Contains(got, "Memory: fine") {
			t.Errorf("OK insight should not be narrated, got: %s", got)
		}
	})
}
