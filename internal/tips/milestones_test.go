package tips

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/version"
)

func TestMaybePrintReengagement(t *testing.T) {
	weekAgo := time.Now().AddDate(0, 0, -7).Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	cases := []struct {
		name       string
		lastRun    string
		mode       output.OutputMode
		plain      bool
		wantOutput bool
	}{
		{"gap>=7 human mode", weekAgo, output.ModeHuman, false, true},
		{"gap=1 no message", yesterday, output.ModeHuman, false, false},
		{"never ran no message", "", output.ModeHuman, false, false},
		{"non-human mode suppressed", weekAgo, output.ModeJSON, false, false},
		{"plain mode suppressed", weekAgo, output.ModeHuman, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPlainMode(t, tc.plain, func() {
				s := &State{LastRunDate: tc.lastRun}
				out := captureStdout(t, func() { MaybePrintReengagement(s, tc.mode, "1.0.0") })
				got := out != ""
				if got != tc.wantOutput {
					t.Errorf("wantOutput=%v, got output=%q", tc.wantOutput, out)
				}
				if tc.wantOutput && !strings.Contains(out, "Welcome back") {
					t.Errorf("expected welcome-back message, got: %s", out)
				}
			})
		})
	}
}

func TestMaybePrintChangelog(t *testing.T) {
	cases := []struct {
		name        string
		lastVersion string
		ver         string
		mode        output.OutputMode
		plain       bool
		wantOutput  bool
	}{
		{"version changed", "1.0.0", "1.1.0", output.ModeHuman, false, true},
		{"first run, no last version", "", "1.1.0", output.ModeHuman, false, false},
		{"same version", "1.1.0", "1.1.0", output.ModeHuman, false, false},
		{"non-human mode suppressed", "1.0.0", "1.1.0", output.ModeJSON, false, false},
		{"plain mode suppressed", "1.0.0", "1.1.0", output.ModeHuman, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPlainMode(t, tc.plain, func() {
				s := &State{LastVersion: tc.lastVersion}
				out := captureStdout(t, func() { MaybePrintChangelog(s, tc.mode, tc.ver) })
				got := out != ""
				if got != tc.wantOutput {
					t.Errorf("wantOutput=%v, got output=%q", tc.wantOutput, out)
				}
				if tc.wantOutput && !strings.Contains(out, tc.ver) {
					t.Errorf("expected version %q in output, got: %s", tc.ver, out)
				}
			})
		})
	}
}

func TestMaybePrintMilestone_AlwaysUpdatesCountersRegardlessOfMode(t *testing.T) {
	withPlainMode(t, true, func() {
		s := &State{TotalRuns: 4}
		captureStdout(t, func() { MaybePrintMilestone(s, output.ModeJSON) })

		if s.TotalRuns != 5 {
			t.Errorf("expected TotalRuns incremented to 5, got %d", s.TotalRuns)
		}
		if s.LastRunDate == "" {
			t.Error("expected LastRunDate to be set")
		}
		if s.LastVersion != version.Version {
			t.Errorf("expected LastVersion=%q, got %q", version.Version, s.LastVersion)
		}
	})
}

func TestMaybePrintMilestone_StreakNotDoubleCountedSameDay(t *testing.T) {
	withPlainMode(t, true, func() {
		today := time.Now().Format("2006-01-02")
		s := &State{TotalRuns: 1, LastRunDate: today, CurrentStreak: 3, LongestStreak: 3}
		captureStdout(t, func() { MaybePrintMilestone(s, output.ModeJSON) })

		if s.CurrentStreak != 3 {
			t.Errorf("expected streak unchanged on same-day rerun, got %d", s.CurrentStreak)
		}
	})
}

func TestMaybePrintMilestone_RunCountFires(t *testing.T) {
	withPlainMode(t, false, func() {
		s := &State{TotalRuns: 9}
		out := captureStdout(t, func() { MaybePrintMilestone(s, output.ModeHuman) })

		if !strings.Contains(out, "10 runs") {
			t.Errorf("expected 10-run milestone message, got: %s", out)
		}
		if !s.HasShownMilestone(10) {
			t.Error("expected milestone 10 marked as shown")
		}
	})
}

func TestMaybePrintMilestone_RunCountNotRefiredWhenAlreadyShown(t *testing.T) {
	withPlainMode(t, false, func() {
		s := &State{TotalRuns: 9, ShownMilestones: []int{10}}
		out := captureStdout(t, func() { MaybePrintMilestone(s, output.ModeHuman) })

		if strings.Contains(out, "10 runs") {
			t.Errorf("expected no re-fire of already-shown milestone, got: %s", out)
		}
	})
}

func TestMaybePrintMilestone_AllRunCountMessages(t *testing.T) {
	cases := []struct {
		runsBefore int
		wantText   string
	}{
		{49, "50 runs"},
		{99, "100 runs"},
		{499, "500 runs"},
	}
	for _, tc := range cases {
		t.Run(tc.wantText, func(t *testing.T) {
			withPlainMode(t, false, func() {
				s := &State{TotalRuns: tc.runsBefore}
				out := captureStdout(t, func() { MaybePrintMilestone(s, output.ModeHuman) })
				if !strings.Contains(out, tc.wantText) {
					t.Errorf("expected %q in output, got: %s", tc.wantText, out)
				}
			})
		})
	}
}

func TestMaybePrintMilestone_ThirtyDayStreakFires(t *testing.T) {
	withPlainMode(t, false, func() {
		yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		s := &State{TotalRuns: 1, CurrentStreak: 29, LongestStreak: 29, LastRunDate: yesterday, ShownMilestones: []int{-7}}
		out := captureStdout(t, func() { MaybePrintMilestone(s, output.ModeHuman) })

		if !strings.Contains(out, "30-day streak") {
			t.Errorf("expected 30-day streak message, got: %s", out)
		}
		if !s.HasShownStreak(30) {
			t.Error("expected streak milestone 30 marked as shown")
		}
	})
}

func TestMaybePrintMilestone_StreakFires(t *testing.T) {
	withPlainMode(t, false, func() {
		yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		s := &State{TotalRuns: 1, CurrentStreak: 6, LongestStreak: 6, LastRunDate: yesterday}
		out := captureStdout(t, func() { MaybePrintMilestone(s, output.ModeHuman) })

		if !strings.Contains(out, "7-day streak") {
			t.Errorf("expected 7-day streak message, got: %s", out)
		}
		if !s.HasShownStreak(7) {
			t.Error("expected streak milestone 7 marked as shown")
		}
	})
}

func TestMaybePrintMilestone_ProTrialOffer(t *testing.T) {
	withPlainMode(t, false, func() {
		today := time.Now().Format("2006-01-02")
		// LastRunDate=today keeps the streak-update block a no-op, so
		// CurrentStreak stays exactly at the >=5 trial threshold.
		s := &State{TotalRuns: 10, CurrentStreak: 5, LongestStreak: 5, LastRunDate: today}
		out := captureStdout(t, func() { MaybePrintMilestone(s, output.ModeHuman) })

		if !strings.Contains(out, "DashDiag Pro") {
			t.Errorf("expected pro trial offer, got: %s", out)
		}
		if !s.TrialOffered {
			t.Error("expected TrialOffered=true")
		}
	})
}

func TestMaybePrintMilestone_ProTrialOfferNotRepeated(t *testing.T) {
	withPlainMode(t, false, func() {
		today := time.Now().Format("2006-01-02")
		s := &State{TotalRuns: 10, CurrentStreak: 5, LongestStreak: 5, LastRunDate: today, TrialOffered: true}
		out := captureStdout(t, func() { MaybePrintMilestone(s, output.ModeHuman) })

		if strings.Contains(out, "DashDiag Pro") {
			t.Errorf("expected no repeat trial offer, got: %s", out)
		}
	})
}

func TestMaybePrintMilestone_PlainModeSuppressesPrintsButStillUpdatesState(t *testing.T) {
	withPlainMode(t, true, func() {
		s := &State{TotalRuns: 9}
		out := captureStdout(t, func() { MaybePrintMilestone(s, output.ModeHuman) })

		if out != "" {
			t.Errorf("expected no output in plain mode, got: %s", out)
		}
		if s.TotalRuns != 10 {
			t.Errorf("expected TotalRuns still incremented, got %d", s.TotalRuns)
		}
		if s.HasShownMilestone(10) {
			t.Error("milestone must not be marked shown when never printed")
		}
	})
}
