package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/tips"
)

func TestWeeklyTooFewRuns(t *testing.T) {
	cases := []int{0, 1, 6}
	for _, n := range cases {
		state := &tips.State{TotalRuns: n}
		got := RenderWeekly(state, "weekly")
		if !strings.Contains(got, "Not enough data") {
			t.Errorf("TotalRuns=%d: expected 'Not enough data' message, got %q", n, got)
		}
	}
}

func TestWeeklyAtBoundary(t *testing.T) {
	// Exactly 7 runs should produce the report (not the "not enough data" message).
	state := &tips.State{TotalRuns: 7}
	got := RenderWeekly(state, "weekly")
	if strings.Contains(got, "Not enough data") {
		t.Error("TotalRuns=7: expected weekly report, got 'not enough data' message")
	}
	if !strings.Contains(got, "Checks run:") {
		t.Errorf("TotalRuns=7: expected weekly report header, got %q", got)
	}
}

func TestWeeklyNormalUsage(t *testing.T) {
	state := &tips.State{TotalRuns: 14, ErrorExits: 0}
	got := RenderWeekly(state, "weekly")
	if !strings.Contains(got, "Checks run:       14") {
		t.Errorf("expected '14' run count, got %q", got)
	}
	if !strings.Contains(got, "(2.0 / day avg)") {
		t.Errorf("expected 2.0/day average for 14 runs, got %q", got)
	}
	if !strings.Contains(got, "Issues detected:  0") {
		t.Errorf("expected 0 issues, got %q", got)
	}
}

func TestWeeklyWithErrors(t *testing.T) {
	state := &tips.State{TotalRuns: 21, ErrorExits: 3}
	got := RenderWeekly(state, "weekly")
	if !strings.Contains(got, "Issues detected:  3") {
		t.Errorf("expected 3 issues, got %q", got)
	}
	if !strings.Contains(got, "Checks run:       21") {
		t.Errorf("expected 21 runs, got %q", got)
	}
}

func TestWeeklyHeavyUsage(t *testing.T) {
	// 100 runs/week — power user. Verify formatting doesn't break.
	state := &tips.State{TotalRuns: 100, ErrorExits: 5}
	got := RenderWeekly(state, "weekly")
	if !strings.Contains(got, "Checks run:       100") {
		t.Errorf("expected 100 runs, got %q", got)
	}
	if !strings.Contains(got, "(14.3 / day avg)") {
		t.Errorf("expected 14.3/day average, got %q", got)
	}
}

// TestCapitalize covers the empty-string guard alongside normal capitalization.
func TestCapitalize(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"", ""},
		{"weekly", "Weekly"},
		{"a", "A"},
	}
	for _, tc := range cases {
		if got := capitalize(tc.in); got != tc.want {
			t.Errorf("capitalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCenterPadAndPadRightTruncate cover the truncation branch (input already
// at/over width) alongside normal padding, for both helpers.
func TestCenterPadAndPadRightTruncate(t *testing.T) {
	t.Parallel()
	long := "this string is definitely longer than ten chars"
	if got := centerPad(long, 10); got != long[:10] {
		t.Errorf("centerPad truncation = %q, want %q", got, long[:10])
	}
	if got := padRight(long, 10); got != long[:10] {
		t.Errorf("padRight truncation = %q, want %q", got, long[:10])
	}
	// Exact-width input also hits the truncation branch (len(s) >= width).
	exact := "1234567890"
	if got := centerPad(exact, 10); got != exact {
		t.Errorf("centerPad exact-width = %q, want %q", got, exact)
	}
	if got := padRight(exact, 10); got != exact {
		t.Errorf("padRight exact-width = %q, want %q", got, exact)
	}
	// Normal padding still works.
	if got := centerPad("hi", 6); got != "  hi  " {
		t.Errorf("centerPad short = %q, want %q", got, "  hi  ")
	}
	if got := padRight("hi", 6); got != "hi    " {
		t.Errorf("padRight short = %q, want %q", got, "hi    ")
	}
}

func TestWeeklyTitleVariants(t *testing.T) {
	state := &tips.State{TotalRuns: 14}
	cases := []struct {
		period string
		want   string
	}{
		{"weekly", "Weekly Report"},
		{"monthly", "Monthly Report"},
		{"daily", "Daily Report"},
	}
	for _, tc := range cases {
		got := RenderWeekly(state, tc.period)
		if !strings.Contains(got, tc.want) {
			t.Errorf("period=%q: expected title to contain %q, got %q", tc.period, tc.want, got)
		}
	}
}
