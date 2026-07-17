package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func seedPruneStore(t *testing.T, path string, entries []Entry) {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	for _, e := range entries {
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestPrune_BelowLimit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	seedPruneStore(t, path, []Entry{
		{Hostname: "h", Verdict: "OK"},
		{Hostname: "h", Verdict: "WARN"},
	})

	if err := Prune(path, "h", 5); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	entries, _ := ReadAll(path, "h", 0)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries after no-op prune, got %d", len(entries))
	}
}

func TestPrune_ExactlyAtLimit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	seedPruneStore(t, path, []Entry{
		{Hostname: "h", Verdict: "OK"},
		{Hostname: "h", Verdict: "WARN"},
		{Hostname: "h", Verdict: "CRIT"},
	})

	if err := Prune(path, "h", 3); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	entries, _ := ReadAll(path, "h", 0)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries (no-op), got %d", len(entries))
	}
}

func TestPrune_TrimsOldest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	ts := time.Now()
	seedPruneStore(t, path, []Entry{
		{Hostname: "h", Timestamp: ts.Add(-3 * time.Hour), Verdict: "OK"},   // oldest → removed
		{Hostname: "h", Timestamp: ts.Add(-2 * time.Hour), Verdict: "WARN"}, // removed
		{Hostname: "h", Timestamp: ts.Add(-1 * time.Hour), Verdict: "CRIT"}, // kept
		{Hostname: "h", Timestamp: ts, Verdict: "OK"},                       // kept (newest)
	})

	if err := Prune(path, "h", 2); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	entries, err := ReadAll(path, "h", 0)
	if err != nil {
		t.Fatalf("ReadAll after prune: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after prune, got %d", len(entries))
	}
	// Oldest-first order preserved; CRIT then OK are the survivors.
	if entries[0].Verdict != "CRIT" || entries[1].Verdict != "OK" {
		t.Errorf("wrong entries survived: %v / %v", entries[0].Verdict, entries[1].Verdict)
	}
}

func TestPrune_PreservesOtherHosts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	seedPruneStore(t, path, []Entry{
		{Hostname: "h1", Verdict: "OK"},
		{Hostname: "h1", Verdict: "WARN"},
		{Hostname: "h1", Verdict: "CRIT"},
		{Hostname: "h2", Verdict: "OK"}, // must be preserved
	})

	if err := Prune(path, "h1", 1); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	h1, _ := ReadAll(path, "h1", 0)
	h2, _ := ReadAll(path, "h2", 0)
	if len(h1) != 1 {
		t.Errorf("h1: expected 1 entry after prune, got %d", len(h1))
	}
	if h1[0].Verdict != "CRIT" {
		t.Errorf("h1: expected CRIT (newest) to survive, got %q", h1[0].Verdict)
	}
	if len(h2) != 1 {
		t.Errorf("h2: expected 1 entry (untouched), got %d", len(h2))
	}
}

func TestPrune_MissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// File does not exist — ReadAll returns nil, nil → Prune is a no-op.
	if err := Prune(filepath.Join(dir, "nonexistent.jsonl"), "h", 10); err != nil {
		t.Errorf("Prune on missing file: %v", err)
	}
}

func TestPrune_ZeroMaxIsNoop(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	seedPruneStore(t, path, []Entry{
		{Hostname: "h", Verdict: "OK"},
		{Hostname: "h", Verdict: "WARN"},
	})
	if err := Prune(path, "h", 0); err != nil {
		t.Fatalf("Prune(0): %v", err)
	}
	entries, _ := ReadAll(path, "h", 0)
	if len(entries) != 2 {
		t.Errorf("Prune(0) should be a no-op, got %d entries", len(entries))
	}
}

func TestPrune_ResultIsReadable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	for i := range 10 {
		_ = i
		seedPruneStore(t, path, []Entry{{Hostname: "h", Verdict: "OK"}})
	}
	if err := Prune(path, "h", 3); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	// The pruned file must be openable as a JSONLStore and yield exactly 3 entries.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open after prune: %v", err)
	}
	defer func() { _ = s.Close() }() //nolint:errcheck
	hist, err := s.History(context.Background(), "h", 100)
	if err != nil {
		t.Fatalf("History after prune: %v", err)
	}
	if len(hist) != 3 {
		t.Errorf("expected 3 entries, got %d", len(hist))
	}
}
