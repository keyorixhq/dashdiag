package cmd

// history_run_test.go — covers runHistory (flag parsing, host resolution,
// empty-history message, json-vs-table dispatch) and printHistoryTable.
// buildHistoryRows/formatChanges already have coverage in history_test.go.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/store"
)

// newBareHistoryCmd builds a standalone *cobra.Command with the flags
// runHistory reads via cmd.Flags().Get*, mirroring newBareDiffCmd/
// newBareCaptureRawCmd elsewhere in this package.
func newBareHistoryCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.IntP("n", "n", 20, "")
	f.String("host", "", "")
	f.Bool("json", false, "")
	return c
}

// TestRunHistory_NoEntries covers the "no history yet" branch — not parallel:
// uses t.Setenv to redirect HOME (StorePath()'s basis).
func TestRunHistory_NoEntries(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	c := newBareHistoryCmd()
	_ = c.Flags().Set("host", "nobody-here")

	stderr := captureStderr(t, func() {
		if err := runHistory(c, nil); err != nil {
			t.Fatalf("runHistory: %v", err)
		}
	})
	if !strings.Contains(stderr, "no history yet") || !strings.Contains(stderr, "nobody-here") {
		t.Errorf("expected the no-history message naming the host, got: %q", stderr)
	}
}

// TestRunHistory_TableOutput seeds two entries and confirms the table path
// (printHistoryTable) renders the host, run count, and a status change.
// Not parallel: uses t.Setenv. Skipped as root — StorePath() returns the
// fixed system path as root, ignoring HOME, same as health_persist_test.go's
// precedent.
func TestRunHistory_TableOutput(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	path := filepath.Join(dir, ".dsd", "store.jsonl")
	ts := time.Now()
	seedStore(t, path, []store.Entry{
		{Hostname: "web01", Timestamp: ts, Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
		{Hostname: "web01", Timestamp: ts.Add(time.Hour), Verdict: "WARN", Checks: map[string]string{"cpu": "WARN"}},
	})

	c := newBareHistoryCmd()
	_ = c.Flags().Set("host", "web01")

	out := captureStdout(t, func() {
		if err := runHistory(c, nil); err != nil {
			t.Fatalf("runHistory: %v", err)
		}
	})
	if !strings.Contains(out, "web01") || !strings.Contains(out, "2 run(s)") {
		t.Errorf("expected the host and run count in the header, got:\n%s", out)
	}
	if !strings.Contains(out, "TIME") || !strings.Contains(out, "VERDICT") || !strings.Contains(out, "CHANGES") {
		t.Errorf("expected the table header columns, got:\n%s", out)
	}
	if !strings.Contains(out, "cpu OK→WARN") {
		t.Errorf("expected the second row's change summary, got:\n%s", out)
	}
}

// TestRunHistory_JSONOutput confirms --json emits valid, well-shaped JSON
// instead of the tabwriter table. Not parallel: uses t.Setenv. Skipped as
// root — see TestRunHistory_TableOutput.
func TestRunHistory_JSONOutput(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	path := filepath.Join(dir, ".dsd", "store.jsonl")
	seedStore(t, path, []store.Entry{
		{Hostname: "web01", Timestamp: time.Now(), Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
	})

	c := newBareHistoryCmd()
	_ = c.Flags().Set("host", "web01")
	_ = c.Flags().Set("json", "true")

	out := captureStdout(t, func() {
		if err := runHistory(c, nil); err != nil {
			t.Fatalf("runHistory: %v", err)
		}
	})
	if strings.Contains(out, "TIME\t") {
		t.Errorf("--json must not fall through to the tabwriter table, got:\n%s", out)
	}
	var rows []historyRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("--json output did not parse as []historyRow: %v\noutput:\n%s", err, out)
	}
	if len(rows) != 1 || rows[0].Verdict != "OK" {
		t.Errorf("unexpected decoded rows: %+v", rows)
	}
}

// TestRunHistory_DefaultsHostToLocalHostname covers the host-resolution
// branch: an empty --host falls back to os.Hostname(), so a store seeded
// under the REAL local hostname (not an arbitrary one) must be found.
// Not parallel: uses t.Setenv. Skipped as root — see TestRunHistory_TableOutput.
func TestRunHistory_DefaultsHostToLocalHostname(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	localHost, err := os.Hostname()
	if err != nil {
		t.Skip("os.Hostname() unavailable in this environment")
	}

	path := filepath.Join(dir, ".dsd", "store.jsonl")
	seedStore(t, path, []store.Entry{
		{Hostname: localHost, Timestamp: time.Now(), Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
	})

	c := newBareHistoryCmd() // --host left empty

	out := captureStdout(t, func() {
		if err := runHistory(c, nil); err != nil {
			t.Fatalf("runHistory: %v", err)
		}
	})
	if !strings.Contains(out, localHost) {
		t.Errorf("expected runHistory to default --host to os.Hostname() (%q), got:\n%s", localHost, out)
	}
}

// TestPrintHistoryTable_MultipleRows is a direct, non-store unit test of the
// tabwriter renderer itself.
func TestPrintHistoryTable_MultipleRows(t *testing.T) {
	rows := []historyRow{
		{Timestamp: "2026-08-20 10:00:00", Verdict: "OK"},
		{Timestamp: "2026-08-20 10:30:00", Verdict: "WARN", Changes: []store.CheckChange{{Name: "disk", Before: "OK", After: "WARN"}}},
	}
	out := captureStdout(t, func() { printHistoryTable(rows, "myhost") })
	if !strings.Contains(out, "myhost") || !strings.Contains(out, "2 run(s)") {
		t.Errorf("expected header naming the host and run count, got:\n%s", out)
	}
	if !strings.Contains(out, "disk OK→WARN") {
		t.Errorf("expected the second row's rendered change, got:\n%s", out)
	}
	if !strings.Contains(out, "—") {
		t.Errorf("expected the em-dash placeholder for the first (no-change) row, got:\n%s", out)
	}
}
