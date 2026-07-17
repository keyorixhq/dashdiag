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
)

// TestPersistHealthRun_OK covers the happy path of persistHealthRun:
// a writable HOME dir → store.Open succeeds → Append succeeds → Close succeeds.
// Not parallel: sets HOME via t.Setenv which affects process-global state.
func TestPersistHealthRun_OK(t *testing.T) {
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

// TestPersistHealthRun_StoreOpenError covers the store.Open failure branch:
// a regular file placed at the expected directory path causes MkdirAll to fail,
// so persistHealthRun must print to stderr and return without panicking.
func TestPersistHealthRun_StoreOpenError(t *testing.T) {
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
