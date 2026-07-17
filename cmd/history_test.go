package cmd

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/store"
)

func TestFormatChanges_Empty(t *testing.T) {
	t.Parallel()
	if got := formatChanges(nil); got != "—" {
		t.Errorf("formatChanges(nil) = %q, want %q", got, "—")
	}
}

func TestFormatChanges_Single(t *testing.T) {
	t.Parallel()
	ch := []store.CheckChange{{Name: "mem", Before: "OK", After: "WARN"}}
	if got := formatChanges(ch); got != "mem OK→WARN" {
		t.Errorf("got %q", got)
	}
}

func TestFormatChanges_NewCheck(t *testing.T) {
	t.Parallel()
	ch := []store.CheckChange{{Name: "gpu", Before: "", After: "CRIT"}}
	if got := formatChanges(ch); got != "gpu new→CRIT" {
		t.Errorf("got %q", got)
	}
}

func TestFormatChanges_RemovedCheck(t *testing.T) {
	t.Parallel()
	ch := []store.CheckChange{{Name: "gpu", Before: "OK", After: ""}}
	if got := formatChanges(ch); got != "gpu OK→gone" {
		t.Errorf("got %q", got)
	}
}

func TestFormatChanges_Overflow(t *testing.T) {
	t.Parallel()
	ch := []store.CheckChange{
		{Name: "a", Before: "OK", After: "WARN"},
		{Name: "b", Before: "OK", After: "WARN"},
		{Name: "c", Before: "OK", After: "WARN"},
		{Name: "d", Before: "OK", After: "WARN"},
		{Name: "e", Before: "OK", After: "WARN"},
	}
	got := formatChanges(ch)
	// 4 shown inline, "+1 more" appended
	if got == "—" {
		t.Fatal("expected non-empty output")
	}
	last := got[len(got)-len("+1 more"):]
	if last != "+1 more" {
		t.Errorf("expected '+1 more' suffix, got %q", got)
	}
}

func TestBuildHistoryRows_DiffAccumulates(t *testing.T) {
	t.Parallel()
	ts := time.Now()
	entries := []store.Entry{
		{Timestamp: ts, Hostname: "h", Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
		{Timestamp: ts.Add(time.Hour), Hostname: "h", Verdict: "WARN", Checks: map[string]string{"cpu": "WARN"}},
		{Timestamp: ts.Add(2 * time.Hour), Hostname: "h", Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
	}
	rows := buildHistoryRows(entries)
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	// First row: no prior — no changes
	if len(rows[0].Changes) != 0 {
		t.Errorf("row 0: expected no changes, got %v", rows[0].Changes)
	}
	// Second row: cpu OK→WARN
	if len(rows[1].Changes) != 1 || rows[1].Changes[0].Name != "cpu" {
		t.Errorf("row 1: expected cpu change, got %v", rows[1].Changes)
	}
	// Third row: cpu WARN→OK
	if len(rows[2].Changes) != 1 || rows[2].Changes[0].After != "OK" {
		t.Errorf("row 2: expected cpu WARN→OK, got %v", rows[2].Changes)
	}
}
