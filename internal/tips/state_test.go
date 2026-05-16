package tips

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── State load / save ────────────────────────────────────────────────────────

func TestLoadState_Default(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	s, err := LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !s.TipsEnabled {
		t.Error("expected TipsEnabled=true for new state")
	}
	if s.TotalRuns != 0 {
		t.Errorf("expected TotalRuns=0, got %d", s.TotalRuns)
	}
	if s.CommandCounts == nil {
		t.Error("expected CommandCounts to be initialized")
	}
}

func TestLoadState_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_ = os.MkdirAll(filepath.Join(dir, ".dsd"), 0755)
	existing := &State{TotalRuns: 42, TipsEnabled: false, CommandCounts: map[string]int{"health": 10}}
	data, _ := json.MarshalIndent(existing, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, ".dsd", "state.json"), data, 0644)

	s, err := LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if s.TotalRuns != 42 {
		t.Errorf("expected TotalRuns=42, got %d", s.TotalRuns)
	}
	if s.TipsEnabled {
		t.Error("expected TipsEnabled=false from stored value")
	}
	if s.CommandCounts["health"] != 10 {
		t.Errorf("expected CommandCounts[health]=10, got %d", s.CommandCounts["health"])
	}
}

func TestSave_Atomic(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	s := &State{TotalRuns: 7, TipsEnabled: true, CommandCounts: map[string]int{"health": 3}}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Temp file must be gone after atomic rename
	tmp := filepath.Join(dir, ".dsd", "state.json.tmp")
	if _, err := os.Stat(tmp); err == nil {
		t.Error("temp file still exists after Save — not atomic")
	}

	// Round-trip: reload and verify
	loaded, err := LoadState()
	if err != nil {
		t.Fatalf("LoadState after Save: %v", err)
	}
	if loaded.TotalRuns != 7 {
		t.Errorf("expected TotalRuns=7 after reload, got %d", loaded.TotalRuns)
	}
	if !loaded.TipsEnabled {
		t.Error("expected TipsEnabled=true after reload")
	}
}

// ── Milestone helpers ────────────────────────────────────────────────────────

func TestHasShownMilestone(t *testing.T) {
	s := &State{ShownMilestones: []int{10, 50}}
	if !s.HasShownMilestone(10) {
		t.Error("expected HasShownMilestone(10)=true")
	}
	if s.HasShownMilestone(100) {
		t.Error("expected HasShownMilestone(100)=false")
	}
}

func TestMarkMilestone_Idempotent(t *testing.T) {
	s := &State{}
	s.MarkMilestone(10)
	s.MarkMilestone(10)
	if len(s.ShownMilestones) != 1 {
		t.Errorf("expected 1 entry after double MarkMilestone, got %d", len(s.ShownMilestones))
	}
}

func TestStreakTracking(t *testing.T) {
	s := &State{}
	s.MarkStreak(7)
	if !s.HasShownStreak(7) {
		t.Error("expected HasShownStreak(7)=true after MarkStreak(7)")
	}
	if s.HasShownStreak(30) {
		t.Error("expected HasShownStreak(30)=false")
	}
	if s.HasShownMilestone(7) {
		t.Error("streak and run milestone 7 must not collide")
	}
}

func TestIncrementCommand(t *testing.T) {
	s := &State{}
	s.IncrementCommand("health")
	s.IncrementCommand("health")
	s.IncrementCommand("net")
	if s.CommandCounts["health"] != 2 {
		t.Errorf("expected health=2, got %d", s.CommandCounts["health"])
	}
	if s.CommandCounts["net"] != 1 {
		t.Errorf("expected net=1, got %d", s.CommandCounts["net"])
	}
}

// ── Milestone fire logic ──────────────────────────────────────────────────────

func TestMilestoneFiresAtCorrectCount(t *testing.T) {
	cases := []struct {
		runs      int
		wantFired []int
	}{
		{9, nil},
		{10, []int{10}},
		{11, nil},
		{49, nil},
		{50, []int{50}},
		{100, []int{100}},
		{500, []int{500}},
	}
	for _, tc := range cases {
		fired := firedRunMilestones(tc.runs, nil)
		if len(fired) != len(tc.wantFired) {
			t.Errorf("runs=%d: firedRunMilestones=%v, want %v", tc.runs, fired, tc.wantFired)
			continue
		}
		for i, m := range tc.wantFired {
			if fired[i] != m {
				t.Errorf("runs=%d: fired[%d]=%d, want %d", tc.runs, i, fired[i], m)
			}
		}
	}
}

func TestMilestoneNotFiredIfAlreadyShown(t *testing.T) {
	fired := firedRunMilestones(10, []int{10})
	if len(fired) != 0 {
		t.Errorf("expected no milestones when already shown, got %v", fired)
	}
}

// ── Streak calculation ────────────────────────────────────────────────────────

func TestStreakCalculation(t *testing.T) {
	cases := []struct {
		name        string
		current     int
		longest     int
		today       string
		lastRun     string
		wantStreak  int
		wantLongest int
	}{
		{"first run ever", 0, 0, "2025-01-10", "", 1, 1},
		{"same day no-op", 3, 5, "2025-01-10", "2025-01-10", 3, 5},
		{"gap=1 increments", 3, 5, "2025-01-10", "2025-01-09", 4, 5},
		{"gap=1 beats longest", 4, 4, "2025-01-10", "2025-01-09", 5, 5},
		{"gap=2 resets", 3, 5, "2025-01-10", "2025-01-08", 1, 5},
		{"gap=7 resets", 10, 10, "2025-01-10", "2025-01-03", 1, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotStreak, gotLongest := computeStreak(tc.current, tc.longest, tc.today, tc.lastRun)
			if gotStreak != tc.wantStreak {
				t.Errorf("streak: got %d, want %d", gotStreak, tc.wantStreak)
			}
			if gotLongest != tc.wantLongest {
				t.Errorf("longest: got %d, want %d", gotLongest, tc.wantLongest)
			}
		})
	}
}

func TestDaysBetween(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2025-01-01", "2025-01-01", 0},
		{"2025-01-01", "2025-01-02", 1},
		{"2025-01-01", "2025-01-08", 7},
		{"", "2025-01-08", 0},
		{"2025-01-08", "", 0},
	}
	for _, tc := range cases {
		got := daysBetween(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("daysBetween(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// ── Re-engagement ─────────────────────────────────────────────────────────────

func TestReengagementAfterGap(t *testing.T) {
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	weekAgo := time.Now().AddDate(0, 0, -7).Format("2006-01-02")

	cases := []struct {
		name        string
		lastRun     string
		wantMessage bool
	}{
		{"same day", today, false},
		{"gap=1 day", yesterday, false},
		{"gap=7 days", weekAgo, true},
		{"never ran", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gap := daysBetween(tc.lastRun, today)
			got := gap >= 7
			if got != tc.wantMessage {
				t.Errorf("lastRun=%q: gap=%d, wantMessage=%v, got=%v", tc.lastRun, gap, tc.wantMessage, got)
			}
		})
	}
}

// ── Streak milestones ─────────────────────────────────────────────────────────

func TestFiredStreakMilestones(t *testing.T) {
	cases := []struct {
		name      string
		streak    int
		shown     []int // negative values = streak milestones
		wantFired []int
	}{
		{"streak=6 no fire", 6, nil, nil},
		{"streak=7 fires", 7, nil, []int{7}},
		{"streak=7 already shown", 7, []int{-7}, nil},
		{"streak=30 fires both", 30, nil, []int{7, 30}},
		{"streak=30 7-already shown", 30, []int{-7}, []int{30}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &State{ShownMilestones: tc.shown}
			fired := firedStreakMilestones(tc.streak, s)
			if len(fired) != len(tc.wantFired) {
				t.Errorf("streak=%d: fired=%v, want %v", tc.streak, fired, tc.wantFired)
				return
			}
			for i, d := range tc.wantFired {
				if fired[i] != d {
					t.Errorf("streak=%d: fired[%d]=%d, want %d", tc.streak, i, fired[i], d)
				}
			}
		})
	}
}
