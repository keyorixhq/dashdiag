package tips

import (
	"fmt"
	"os"
	"time"

	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/version"
)

var runMilestones = []int{10, 50, 100, 500}
var streakMilestones = []int{7, 30}

// daysBetween returns the number of calendar days from a to b.
// Returns 0 if either date is empty or unparseable.
func daysBetween(a, b string) int {
	if a == "" || b == "" {
		return 0
	}
	ta, err1 := time.Parse("2006-01-02", a)
	tb, err2 := time.Parse("2006-01-02", b)
	if err1 != nil || err2 != nil {
		return 0
	}
	return int(tb.Sub(ta).Hours() / 24)
}

// computeStreak calculates the updated streak given current streak, longest streak,
// today's date, and the last run date.
func computeStreak(current, longest int, today, lastRun string) (newStreak, newLongest int) {
	switch lastRun {
	case "":
		newStreak = 1
	case today:
		newStreak = current
	default:
		gap := daysBetween(lastRun, today)
		if gap == 1 {
			newStreak = current + 1
		} else {
			newStreak = 1
		}
	}
	return newStreak, max(longest, newStreak)
}

// firedRunMilestones returns which run-count milestones should fire for this run.
func firedRunMilestones(runs int, shown []int) []int {
	shownSet := make(map[int]bool, len(shown))
	for _, v := range shown {
		shownSet[v] = true
	}
	var out []int
	for _, m := range runMilestones {
		if runs == m && !shownSet[m] {
			out = append(out, m)
		}
	}
	return out
}

// firedStreakMilestones returns which streak milestones should fire.
func firedStreakMilestones(streak int, state *State) []int {
	var out []int
	for _, days := range streakMilestones {
		if streak >= days && !state.HasShownStreak(days) {
			out = append(out, days)
		}
	}
	return out
}

func MaybePrintReengagement(state *State, mode output.OutputMode, ver string) {
	if mode != output.ModeHuman || output.IsPlain(false) {
		return
	}
	today := time.Now().Format("2006-01-02")
	gap := daysBetween(state.LastRunDate, today)
	if gap >= 7 {
		fmt.Fprintf(os.Stderr, "\n👋 Welcome back! %d days since your last check.\n", gap)
	}
}

// MaybePrintChangelog prints a conversational nudge after results when the version changed.
func MaybePrintChangelog(state *State, mode output.OutputMode, ver string) {
	if mode != output.ModeHuman || output.IsPlain(false) {
		return
	}
	if state.LastVersion != "" && state.LastVersion != ver {
		fmt.Fprintf(os.Stderr, "   What's new in %s? Run dsd --changelog\n", ver)
	}
}

func MaybePrintMilestone(state *State, mode output.OutputMode) {
	today := time.Now().Format("2006-01-02")

	state.TotalRuns++

	// Update streak (always, regardless of mode)
	if state.LastRunDate != today {
		state.CurrentStreak, state.LongestStreak = computeStreak(
			state.CurrentStreak, state.LongestStreak, today, state.LastRunDate,
		)
	}

	state.LastRunDate = today
	state.LastVersion = version.Version

	if mode != output.ModeHuman || output.IsPlain(false) {
		return
	}

	// Streak milestones
	for _, days := range firedStreakMilestones(state.CurrentStreak, state) {
		switch days {
		case 7:
			fmt.Fprintln(os.Stderr, "\n⚡ 7-day streak — consistency is key!")
		case 30:
			fmt.Fprintln(os.Stderr, "\n🔥 30-day streak — you're a DashDiag pro!")
		}
		state.MarkStreak(days)
	}

	// Run-count milestones
	for _, m := range firedRunMilestones(state.TotalRuns, state.ShownMilestones) {
		switch m {
		case 10:
			fmt.Fprintln(os.Stderr, "\n⚡ 10 runs — you're getting the hang of this!")
		case 50:
			fmt.Fprintln(os.Stderr, "\n🚀 50 runs — you're a power user!")
		case 100:
			fmt.Fprintln(os.Stderr, "\n🎯 100 runs — seriously impressive!")
		case 500:
			fmt.Fprintln(os.Stderr, "\n💎 500 runs — legendary.")
		}
		state.MarkMilestone(m)
	}

	// Pro trial offer
	if state.TotalRuns >= 10 && state.CurrentStreak >= 5 && !state.TrialOffered {
		fmt.Fprintln(os.Stderr, "\n✨ Based on your usage, you'd love DashDiag Pro.")
		fmt.Fprintln(os.Stderr, "   Run 'dsd trial start' to try free for 14 days.")
		state.TrialOffered = true
	}
}
