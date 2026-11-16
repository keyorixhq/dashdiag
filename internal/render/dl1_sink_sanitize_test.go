package render

// DH1 — table tests for the render sinks DL1 §3 reported as NOT sanitizing
// host-influenced check names (findings #3, #4, #5). Each test plants a raw ESC
// and a right-to-left override (U+202E) in the check name / title and asserts the
// rendered output is terminal-safe using the SAME oracle the DL1 funnel fuzz uses
// (assertNoTerminalInjection: valid UTF-8, no ESC, no control rune except '\n',
// no bidi formatting rune), plus a positive check that the cleaned name survives.
//
// Bidi runes are built with string(rune(...)) so none is embedded literally here.

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

const (
	testESC = "\x1b[31m"
	testRLO = string(rune(0x202E))
	testLRI = string(rune(0x2066))
)

// hostile returns a check-name fragment carrying an ESC sequence and an RLO
// override around a readable label.
func hostile(label string) string { return label + testRLO + testESC + testLRI }

// --- Finding #3: RenderStory (ins.Check and CheckResult.Name) ----------------

func TestRenderStorySinglePointSanitizesCheckName(t *testing.T) {
	snap := &baseline.Snapshot{
		Hostname:  "host" + testRLO,
		Timestamp: time.Unix(0, 0).UTC(),
		Version:   "test",
		Checks:    []baseline.CheckResult{{Name: "Disk", Status: "CRIT", Value: "full"}},
	}
	insights := []models.Insight{
		{Level: "CRIT", Check: hostile("Disk"), Message: "disk full"},
	}
	out := renderStorySinglePoint(insights, snap)
	assertNoTerminalInjection(t, "story/single", out)
	if !strings.Contains(out, "Disk") {
		t.Errorf("sanitized check name missing from story output: %q", out)
	}
}

func TestRenderStoryFromHistorySanitizesCheckName(t *testing.T) {
	mk := func(ts int64, status string) *baseline.Snapshot {
		return &baseline.Snapshot{
			Hostname:  "h",
			Timestamp: time.Unix(ts, 0).UTC(),
			Version:   "test",
			Checks: []baseline.CheckResult{
				{Name: hostile("Memory"), Status: status, Value: "swap" + testRLO},
			},
		}
	}
	// Two snapshots with a status change so both the events path (e.check) and the
	// current-issues path (c.Name, line 80) are exercised.
	history := []*baseline.Snapshot{mk(0, "OK"), mk(100, "CRIT")}
	out := renderStoryFromHistory(history)
	assertNoTerminalInjection(t, "story/history", out)
	if !strings.Contains(out, "Memory") {
		t.Errorf("sanitized check name missing from history story output: %q", out)
	}
}

// --- Finding #4: RenderPostMortem title --------------------------------------

func TestRenderPostMortemSanitizesTitle(t *testing.T) {
	snap := &baseline.Snapshot{
		Hostname:  "h",
		Timestamp: time.Unix(0, 0).UTC(),
		Version:   "test",
		Checks:    []baseline.CheckResult{{Name: "CPU", Status: "OK", Value: "idle"}},
	}
	tests := []struct {
		name, title, mustContain string
	}{
		{"esc+rlo in title", hostile("INC-1"), "INC-1"},
		{"plain title unchanged", "INC-2 outage", "INC-2 outage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := RenderPostMortem(tt.title, snap, nil, output.ModeHuman)
			assertNoTerminalInjection(t, "postmortem", out)
			if !strings.Contains(out, tt.mustContain) {
				t.Errorf("title content missing: want %q in %q", tt.mustContain, out)
			}
		})
	}
}

// --- Finding #5: NagiosLine check names --------------------------------------

func TestNagiosTextStripsControlBidiAndPipe(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"strips esc", "Disk" + testESC, "Disk[31m"},
		{"strips rlo", "Disk" + testRLO, "Disk"},
		{"pipe becomes slash", "Disk|evil", "Disk/evil"},
		{"newline stripped (no forged line)", "Disk\nFAKE", "DiskFAKE"},
		{"plain unchanged", "CPU Load", "CPU Load"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := nagiosText(tt.in); got != tt.want {
				t.Errorf("nagiosText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNagiosLineSanitizesCheckNames(t *testing.T) {
	res := []runner.Result{{Name: "CPU"}, {Name: "Disk"}}
	ins := []models.Insight{
		{Level: "CRIT", Check: hostile("Disk") + "|perf"},
		{Level: "WARN", Check: hostile("Swap")},
	}
	line, code := NagiosLine(res, ins)
	if code != 2 {
		t.Fatalf("expected CRITICAL exit 2, got %d (%q)", code, line)
	}
	assertNoTerminalInjection(t, "nagios", line)
	if !strings.Contains(line, "Disk") || !strings.Contains(line, "Swap") {
		t.Errorf("sanitized check names missing: %q", line)
	}
	// The '|' embedded in the check name must have become '/', not leaked as a
	// second perfdata separator (the legitimate perfdata pipe is " | checked=").
	if strings.Contains(line, "|perf") || !strings.Contains(line, "/perf") {
		t.Errorf("check-name pipe not neutralized: %q", line)
	}
}

// --- Finding #5 (Prometheus): labels are safe by construction ----------------

func TestPrometheusLabelsAreControlAndBidiSafe(t *testing.T) {
	// promLabel collapses everything outside [a-z0-9] to '_', so a control/ANSI or
	// bidi rune in a check name cannot survive into a label value. This asserts
	// that documented property directly (no production change was needed here).
	t.Run("promLabel neutralizes", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{"Disk" + testESC, "Mem" + testRLO, "CPU|Load", "a\nb"} {
			got := promLabel(in)
			for _, r := range got {
				if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
					t.Fatalf("promLabel(%q) = %q leaked rune %U", in, got, r)
				}
			}
		}
	})
	t.Run("full metrics output has no control or bidi", func(t *testing.T) {
		t.Parallel()
		res := []runner.Result{{Name: hostile("Disk"), Data: struct{ X int }{1}}}
		ins := []models.Insight{{Level: "CRIT", Check: hostile("Disk")}}
		out := PrometheusMetrics(res, ins)
		assertNoTerminalInjection(t, "prometheus", out)
	})
}
