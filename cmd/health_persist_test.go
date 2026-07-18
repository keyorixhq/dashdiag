package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/store"
)

// TestPersistHealthRun_OK covers the happy path of persistHealthRun:
// a writable HOME dir → store.Open succeeds → Append succeeds → Close succeeds.
// Not parallel: sets HOME via t.Setenv which affects process-global state.
func TestPersistHealthRun_OK(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	snap := &baseline.Snapshot{
		Hostname:  "testhostname",
		Timestamp: time.Now(),
		Version:   "v1.0.0",
		Checks: []baseline.CheckResult{
			{Name: "memory", Status: "OK"},
		},
	}
	insights := []models.Insight{{Level: "OK", Check: "memory"}}

	persistHealthRun(context.Background(), snap, insights)

	storePath := filepath.Join(dir, ".dsd", "store.jsonl")
	if _, err := os.Stat(storePath); err != nil {
		t.Errorf("store file should have been created at %s, got: %v", storePath, err)
	}
}

// TestPersistHealthRun_DriftSummary verifies that when a prior persisted run
// exists and check statuses changed, a "persist: N change(s)" line appears on
// stderr. Also covers the first-run path (no prior → no drift line).
func TestPersistHealthRun_DriftSummary(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	ctx := context.Background()

	snap1 := &baseline.Snapshot{
		Hostname:  "drifthost",
		Timestamp: time.Now(),
		Version:   "v1.0.0",
		Checks:    []baseline.CheckResult{{Name: "memory", Status: "OK"}},
	}

	// First run: no prior entry — no drift line.
	stderr1 := captureStderr(t, func() {
		persistHealthRun(ctx, snap1, nil)
	})
	if strings.Contains(stderr1, "persist:") {
		t.Errorf("first run should not emit a drift line, got %q", stderr1)
	}

	// Pre-seed the store with a prior entry that has memory=WARN.
	storePath := filepath.Join(dir, ".dsd", "store.jsonl")
	s, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("seeding store: %v", err)
	}
	_ = s.Append(ctx, store.Entry{
		Hostname:  "drifthost",
		Timestamp: time.Now().Add(-time.Hour),
		Verdict:   "WARN",
		Checks:    map[string]string{"memory": "WARN"},
	})
	_ = s.Close()

	// Second run with memory now OK — should see the drift summary.
	snap2 := &baseline.Snapshot{
		Hostname:  "drifthost",
		Timestamp: time.Now(),
		Version:   "v1.0.0",
		Checks:    []baseline.CheckResult{{Name: "memory", Status: "OK"}},
	}
	stderr2 := captureStderr(t, func() {
		persistHealthRun(ctx, snap2, nil)
	})
	if !strings.Contains(stderr2, "persist:") || !strings.Contains(stderr2, "memory") {
		t.Errorf("expected drift line mentioning 'memory', got %q", stderr2)
	}
}

// TestPersistHealthRun_StoreOpenError covers the store.Open failure branch:
// a regular file placed at the expected directory path causes MkdirAll to fail,
// so persistHealthRun must print to stderr and return without panicking.
func TestPersistHealthRun_StoreOpenError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	// Place a regular file where MkdirAll would need to create the .dsd directory.
	// This makes store.Open's MkdirAll call fail with ENOTDIR.
	blocker := filepath.Join(dir, ".dsd")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)

	snap := &baseline.Snapshot{Hostname: "h"}
	stderr := captureStderr(t, func() {
		persistHealthRun(context.Background(), snap, nil)
	})
	if !strings.Contains(stderr, "store:") {
		t.Errorf("expected 'store:' on stderr when Open fails, got %q", stderr)
	}
}
