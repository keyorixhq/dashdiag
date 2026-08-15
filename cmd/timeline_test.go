package cmd

// timeline_test.go covers cmd/timeline.go: the pure renderers (printTimeline,
// printTimelineIncidents, printTimelineLoad, printTimelineEvents) with
// constructed models.TimelineInfo values, and runTimeline's real (read-only)
// collector wiring in --plain and --json mode — same real-I/O precedent as
// cpu_report_test.go (TestRunCPU). No t.Parallel() on the printX tests
// (captureStdout swaps the shared os.Stdout).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/spf13/cobra"
)

// newBareTimelineCmd builds a bare cobra.Command with the flags runTimeline
// reads via cmd.Flags().Get*.
func newBareTimelineCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", false, "")
	f.Bool("json", false, "")
	f.String("since", "1h", "")
	return c
}

func TestPrintTimelineLoad(t *testing.T) {
	if out := captureStdout(t, func() { printTimelineLoad(&models.TimelineInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no load spikes should print nothing, got: %q", out)
	}

	out := captureStdout(t, func() {
		printTimelineLoad(&models.TimelineInfo{LoadSpikes: []models.LoadSpike{
			{TimeStr: "10:00", Load1: 0.5, Load5: 0.4, Load15: 0.3}, // ok
			{TimeStr: "10:05", Load1: 5, Load5: 4, Load15: 3},       // warn
			{TimeStr: "10:10", Load1: 9, Load5: 8, Load15: 7},       // fail
		}}, output.ModePlain)
	})
	if !strings.Contains(out, "Load average") {
		t.Errorf("expected a Load average header, got: %q", out)
	}
	if !strings.Contains(out, "10:00") || !strings.Contains(out, "10:05") || !strings.Contains(out, "10:10") {
		t.Errorf("expected all three spikes rendered, got: %q", out)
	}
}

func TestPrintTimelineIncidents(t *testing.T) {
	if out := captureStdout(t, func() { printTimelineIncidents(&models.TimelineInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("0 incidents should print nothing, got: %q", out)
	}
	one := &models.TimelineInfo{Incidents: []models.TimelineIncident{{Level: "CRIT", StartStr: "10:00", Summary: "s"}}}
	if out := captureStdout(t, func() { printTimelineIncidents(one, output.ModePlain) }); out != "" {
		t.Errorf("1 incident should print nothing (list needs 2+), got: %q", out)
	}

	multi := &models.TimelineInfo{Incidents: []models.TimelineIncident{
		{Level: "CRIT", StartStr: "10:00", Summary: "kernel oops", EventCount: 1, Sources: 1, DurationSec: 0},
		{Level: "WARN", StartStr: "10:05", Summary: "disk pressure", EventCount: 3, Sources: 2, DurationSec: 45},
		{Level: "INFO", StartStr: "10:10", Summary: "restart", EventCount: 2, Sources: 1, DurationSec: 3700},
	}}
	out := captureStdout(t, func() { printTimelineIncidents(multi, output.ModePlain) })
	if !strings.Contains(out, "Incidents (3)") {
		t.Errorf("expected an incident count header, got: %q", out)
	}
	if !strings.Contains(out, "kernel oops") || !strings.Contains(out, "disk pressure") || !strings.Contains(out, "restart") {
		t.Errorf("expected all incident summaries rendered, got: %q", out)
	}
	if !strings.Contains(out, "2 units") {
		t.Errorf("expected multi-source incident to note unit count, got: %q", out)
	}
	if !strings.Contains(out, "over 1h1m") {
		t.Errorf("expected the >1h incident duration rendered, got: %q", out)
	}
}

func TestPrintTimelineEvents(t *testing.T) {
	base := time.Now().Truncate(time.Hour)
	events := []models.TimelineEvent{
		{TimestampUnix: base.Unix(), TimeStr: "10:00", Source: "journal", Level: "CRIT", Unit: "sshd.service", Message: "auth failure", Count: 3},
		{TimestampUnix: base.Add(48 * time.Hour).Unix(), TimeStr: "10:00", Source: "kernel", Level: "INFO", Unit: "kern", Message: "link up"},
		{TimestampUnix: base.Add(49 * time.Hour).Unix(), TimeStr: "11:00", Source: "journal", Level: "WARN", Unit: "docker.service", Message: "restart", Hint: &models.TimelineHint{
			Explain: "why", Inspect: "cmd1", Fix: "cmd2", Persist: "cmd3",
		}},
	}
	out := captureStdout(t, func() { printTimelineEvents(events, output.ModePlain) })
	if !strings.Contains(out, "jrnl") {
		t.Errorf("journal source should render as 'jrnl', got: %q", out)
	}
	if !strings.Contains(out, "×3") {
		t.Errorf("a repeat count should render '×N', got: %q", out)
	}
	if !strings.Contains(out, "why") || !strings.Contains(out, "cmd1") || !strings.Contains(out, "cmd2") || !strings.Contains(out, "cmd3") {
		t.Errorf("expected all 4 hint fields rendered, got: %q", out)
	}
	// Two distinct days must each get their own day-separator line.
	if strings.Count(out, "──") < 4 {
		t.Errorf("expected day separators for 2 distinct days, got: %q", out)
	}
}

// TestPrintTimelineEvents_StripsControlChars guards terminal escape
// injection: journal Unit/Message text is attacker-influenced (the
// collector's decodeJournalMessage comment notes raw non-UTF-8/binary bytes
// can appear), unlike other cmd/ print sites that already sanitize.
func TestPrintTimelineEvents_StripsControlChars(t *testing.T) {
	events := []models.TimelineEvent{
		{TimeStr: "10:00", Source: "journal", Level: "CRIT", Unit: "evil\x1b]0;pwned\x07.service", Message: "boom\x1b[2Jscreen-clear evil"},
	}
	out := captureStdout(t, func() { printTimelineEvents(events, output.ModePlain) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("printTimelineEvents output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printTimelineEvents output missing sanitized unit text:\n%s", out)
	}
	if !strings.Contains(out, "boom[2Jscreen-clear") {
		t.Errorf("printTimelineEvents output missing sanitized message text:\n%s", out)
	}
}

func TestPrintTimeline(t *testing.T) {
	clean := &models.TimelineInfo{WindowHours: 1}
	out := captureStdout(t, func() { printTimeline(clean, 1500*time.Millisecond, output.ModePlain) })
	if !strings.Contains(out, "Timeline clean") {
		t.Errorf("no events/crit/warn should render clean, got: %q", out)
	}
	if !strings.Contains(out, "No errors or warnings found") {
		t.Errorf("empty events should say so, got: %q", out)
	}

	unavailable := &models.TimelineInfo{WindowHours: 1, SourcesUnavailable: true}
	out = captureStdout(t, func() { printTimeline(unavailable, time.Second, output.ModePlain) })
	if !strings.Contains(out, "Timeline incomplete") {
		t.Errorf("unavailable sources should render incomplete, not clean, got: %q", out)
	}
	// The event-table block itself (printed well before the trailing summary
	// line, and easy to miss if output is skimmed/piped) must not show the same
	// green "No errors or warnings found" a genuinely clean window gets when
	// both sources failed to read — Events is empty for the wrong reason.
	if strings.Contains(out, "No errors or warnings found") {
		t.Errorf("unavailable sources must not render the clean-window message in the event table, got: %q", out)
	}
	if !strings.Contains(out, "Could not read journald or the kernel log") {
		t.Errorf("event table should disclose unreadable sources, got: %q", out)
	}

	issues := &models.TimelineInfo{
		WindowHours: 1, CritCount: 1, WarnCount: 2,
		Events: []models.TimelineEvent{{TimeStr: "10:00", Source: "journal", Level: "CRIT", Message: "boom"}},
	}
	out = captureStdout(t, func() { printTimeline(issues, time.Second, output.ModePlain) })
	if !strings.Contains(out, "1 CRIT") || !strings.Contains(out, "2 WARN") {
		t.Errorf("expected CRIT/WARN counts summarized, got: %q", out)
	}
	if !strings.Contains(out, "TIME") {
		t.Errorf("non-empty events should render the event table header, got: %q", out)
	}
}

// TestRunTimeline exercises runTimeline's real (read-only) collector wiring in
// --plain and --json mode. Same real-I/O precedent as cpu_report_test.go.
func TestRunTimeline(t *testing.T) {
	plainCmd := newBareTimelineCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runTimeline(plainCmd, nil); err != nil {
			t.Fatalf("runTimeline (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "Incident timeline") {
		t.Errorf("plain mode should render the timeline header, got: %q", plainOut)
	}

	jsonCmd := newBareTimelineCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runTimeline(jsonCmd, nil); err != nil {
			t.Fatalf("runTimeline (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, `"window_hours"`) {
		t.Errorf("json mode should emit the TimelineInfo JSON shape, got: %q", jsonOut)
	}
}
