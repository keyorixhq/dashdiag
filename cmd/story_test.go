package cmd

// story_test.go covers runStory (cmd/story.go). LoadHistory reads
// ~/.dsd/baselines/<hostname>-<timestamp>.json, so HOME is redirected to a
// t.TempDir() and snapshot files are written matching the hostname LoadHistory
// resolves via the REAL os.Hostname() (same constraint documented in
// health_run_test.go). Not t.Parallel(): uses t.Setenv.
//
// The "not enough history yet" branch ends in os.Exit(1) — untestable in this
// harness (would abort the whole test binary) — so it is intentionally not
// exercised here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
)

func writeStorySnapshot(t *testing.T, dir, hostname string, ts time.Time, checks []baseline.CheckResult) {
	t.Helper()
	snap := baseline.Snapshot{Hostname: hostname, Timestamp: ts, Checks: checks}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	name := hostname + "-" + ts.Format("20060102-150405") + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatalf("writing snapshot: %v", err)
	}
}

func TestRunStory_InvalidArg(t *testing.T) {
	stderr := captureStderr(t, func() {
		err := runStory(storyCmd, []string{"not-a-number"})
		if err == nil {
			t.Error("expected an error for a non-integer snapshot count")
		}
	})
	if !strings.Contains(stderr, "must be an integer") {
		t.Errorf("expected a usage hint on stderr, got: %q", stderr)
	}
}

func TestRunStory_TooFewSnapshotsArg(t *testing.T) {
	// v < 2 must be rejected before ever touching history.
	stderr := captureStderr(t, func() {
		err := runStory(storyCmd, []string{"1"})
		if err == nil {
			t.Error("expected an error for a count below 2")
		}
	})
	if !strings.Contains(stderr, "must be an integer") {
		t.Errorf("expected a usage hint on stderr, got: %q", stderr)
	}
}

func TestRunStory_Success(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname: %v", err)
	}
	base := time.Now().Add(-2 * time.Hour)
	writeStorySnapshot(t, dir, hostname, base,
		[]baseline.CheckResult{{Name: "CPU", Status: "OK", Value: "5% used"}})
	writeStorySnapshot(t, dir, hostname, base.Add(time.Hour),
		[]baseline.CheckResult{{Name: "CPU", Status: "WARN", Value: "92% used"}})

	stdout := captureStdout(t, func() {
		if err := runStory(storyCmd, nil); err != nil {
			t.Fatalf("runStory: %v", err)
		}
	})
	if !strings.Contains(stdout, "snapshots") {
		t.Errorf("expected the narrated story on stdout, got: %q", stdout)
	}
}

func TestRunStory_SuccessWithExplicitCount(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname: %v", err)
	}
	base := time.Now().Add(-2 * time.Hour)
	writeStorySnapshot(t, dir, hostname, base,
		[]baseline.CheckResult{{Name: "Disk", Status: "OK"}})
	writeStorySnapshot(t, dir, hostname, base.Add(time.Hour),
		[]baseline.CheckResult{{Name: "Disk", Status: "OK"}})

	stdout := captureStdout(t, func() {
		if err := runStory(storyCmd, []string{"5"}); err != nil {
			t.Fatalf("runStory: %v", err)
		}
	})
	if stdout == "" {
		t.Error("expected non-empty story output")
	}
}
