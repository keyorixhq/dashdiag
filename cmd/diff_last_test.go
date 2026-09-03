package cmd

// diff_last_test.go — tests for `dsd diff --last` (store-based diff path).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/store"
)

func seedStore(t *testing.T, path string, entries []store.Entry) {
	t.Helper()
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("seedStore open: %v", err)
	}
	ctx := context.Background()
	for _, e := range entries {
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("seedStore append: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("seedStore close: %v", err)
	}
}

// TestRunDiffFromStore_TooFewEntries: one stored entry → error.
// Not parallel: uses t.Setenv.
func TestRunDiffFromStore_TooFewEntries(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	path := filepath.Join(dir, ".dsd", "store.jsonl")
	seedStore(t, path, []store.Entry{
		{Hostname: "myhost", Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
	})

	c := newBareDiffCmd()
	_ = c.Flags().Set("last", "true")
	_ = c.Flags().Set("host", "myhost")

	err := runDiffFromStore(c)
	if err == nil || !strings.Contains(err.Error(), "need at least 2") {
		t.Errorf("expected 'need at least 2' error, got: %v", err)
	}
}

// TestRunDiffFromStore_NoEntries: empty store → error.
// Not parallel: uses t.Setenv.
func TestRunDiffFromStore_NoEntries(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir) // StorePath() → dir/.dsd/store.jsonl (does not exist)

	c := newBareDiffCmd()
	_ = c.Flags().Set("last", "true")
	_ = c.Flags().Set("host", "nobody")

	err := runDiffFromStore(c)
	if err == nil || !strings.Contains(err.Error(), "need at least 2") {
		t.Errorf("expected 'need at least 2' error, got: %v", err)
	}
}

// TestRenderStoreDiff_NoChanges: identical check maps → "no check status changes".
// Not parallel: captureStdout swaps os.Stdout globally.
func TestRenderStoreDiff_NoChanges(t *testing.T) {
	ts := time.Now()
	prev := store.Entry{Timestamp: ts.Add(-time.Hour), Verdict: "OK", Checks: map[string]string{"cpu": "OK"}}
	cur := store.Entry{Timestamp: ts, Verdict: "OK", Checks: map[string]string{"cpu": "OK"}}
	changes := store.DiffChecks(prev, cur)

	out := captureStdout(t, func() {
		if err := renderStoreDiff(prev, cur, changes, false); err != nil {
			t.Fatalf("renderStoreDiff: %v", err)
		}
	})
	if !strings.Contains(out, "no check status changes") {
		t.Errorf("expected 'no check status changes', got: %q", out)
	}
}

// TestRenderStoreDiff_HumanChanges: changed check appears in tabwriter output.
// Not parallel: captureStdout swaps os.Stdout globally.
func TestRenderStoreDiff_HumanChanges(t *testing.T) {
	ts := time.Now()
	prev := store.Entry{Timestamp: ts.Add(-time.Hour), Verdict: "OK", Checks: map[string]string{"cpu": "OK", "memory": "OK"}}
	cur := store.Entry{Timestamp: ts, Verdict: "WARN", Checks: map[string]string{"cpu": "OK", "memory": "WARN"}}
	changes := store.DiffChecks(prev, cur)

	out := captureStdout(t, func() {
		if err := renderStoreDiff(prev, cur, changes, false); err != nil {
			t.Fatalf("renderStoreDiff: %v", err)
		}
	})
	if !strings.Contains(out, "memory") {
		t.Errorf("expected 'memory' in output, got: %q", out)
	}
	if !strings.Contains(out, "OK") || !strings.Contains(out, "WARN") {
		t.Errorf("expected status values in output, got: %q", out)
	}
}

// TestRenderStoreDiff_JSONOutput: --json emits valid storeDiffOutput JSON.
// Not parallel: captureStdout swaps os.Stdout globally.
func TestRenderStoreDiff_JSONOutput(t *testing.T) {
	ts := time.Now()
	prev := store.Entry{Timestamp: ts.Add(-time.Hour), Verdict: "OK", Checks: map[string]string{"disk": "OK"}}
	cur := store.Entry{Timestamp: ts, Verdict: "CRIT", Checks: map[string]string{"disk": "CRIT"}}
	changes := store.DiffChecks(prev, cur)

	out := captureStdout(t, func() {
		if err := renderStoreDiff(prev, cur, changes, true); err != nil {
			t.Fatalf("renderStoreDiff (json): %v", err)
		}
	})

	var result storeDiffOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %q", err, out)
	}
	if len(result.Changes) != 1 {
		t.Errorf("expected 1 change, got %d", len(result.Changes))
	}
	if result.Changes[0].Name != "disk" || result.Changes[0].Before != "OK" || result.Changes[0].After != "CRIT" {
		t.Errorf("unexpected change: %+v", result.Changes[0])
	}
}

// TestRenderStoreDiff_SeveritySort: CRIT check appears before WARN check in output.
// Not parallel: captureStdout swaps os.Stdout globally.
func TestRenderStoreDiff_SeveritySort(t *testing.T) {
	ts := time.Now()
	prev := store.Entry{
		Timestamp: ts.Add(-time.Hour),
		Verdict:   "OK",
		Checks:    map[string]string{"cpu": "OK", "disk": "OK", "memory": "OK"},
	}
	cur := store.Entry{
		Timestamp: ts,
		Verdict:   "CRIT",
		Checks:    map[string]string{"cpu": "WARN", "disk": "CRIT", "memory": "OK"},
	}
	changes := store.DiffChecks(prev, cur)

	out := captureStdout(t, func() {
		if err := renderStoreDiff(prev, cur, changes, false); err != nil {
			t.Fatalf("renderStoreDiff: %v", err)
		}
	})

	diskIdx := strings.Index(out, "disk")
	cpuIdx := strings.Index(out, "cpu")
	if diskIdx == -1 || cpuIdx == -1 {
		t.Fatalf("expected 'disk' and 'cpu' in output: %q", out)
	}
	// CRIT (disk) must appear before WARN (cpu) due to severity sort.
	if diskIdx > cpuIdx {
		t.Errorf("CRIT check 'disk' should appear before WARN check 'cpu'; got:\n%s", out)
	}
}

func TestStatusRank(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status string
		want   int
	}{
		{"CRIT", 4},
		{"WARN", 3},
		{"OK", 2},
		{"INFO", 1},
		{"", -1},
		{"PENDING", 0},
	}
	for _, tc := range cases {
		if got := statusRank(tc.status); got != tc.want {
			t.Errorf("statusRank(%q) = %d, want %d", tc.status, got, tc.want)
		}
	}
}

// TestRunDiffFromStore_Success_Human covers runDiffFromStore's success
// path end to end (ReadAll → DiffChecks → renderStoreDiff), previously only
// exercised at the renderStoreDiff layer directly. Not parallel: uses
// t.Setenv.
func TestRunDiffFromStore_Success_Human(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	path := filepath.Join(dir, ".dsd", "store.jsonl")
	ts := time.Now()
	seedStore(t, path, []store.Entry{
		{Hostname: "myhost", Timestamp: ts.Add(-time.Hour), Verdict: "OK", Checks: map[string]string{"cpu": "OK", "memory": "OK"}},
		{Hostname: "myhost", Timestamp: ts, Verdict: "WARN", Checks: map[string]string{"cpu": "OK", "memory": "WARN"}},
	})

	c := newBareDiffCmd()
	_ = c.Flags().Set("last", "true")
	_ = c.Flags().Set("host", "myhost")

	out := captureStdout(t, func() {
		if err := runDiffFromStore(c); err != nil {
			t.Fatalf("runDiffFromStore: %v", err)
		}
	})
	if !strings.Contains(out, "memory") {
		t.Errorf("expected the changed 'memory' check in output, got: %q", out)
	}
}

// TestRunDiffFromStore_Success_JSON covers runDiffFromStore's --json branch
// end to end.
func TestRunDiffFromStore_Success_JSON(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	path := filepath.Join(dir, ".dsd", "store.jsonl")
	ts := time.Now()
	seedStore(t, path, []store.Entry{
		{Hostname: "myhost", Timestamp: ts.Add(-time.Hour), Verdict: "OK", Checks: map[string]string{"disk": "OK"}},
		{Hostname: "myhost", Timestamp: ts, Verdict: "CRIT", Checks: map[string]string{"disk": "CRIT"}},
	})

	c := newBareDiffCmd()
	_ = c.Flags().Set("last", "true")
	_ = c.Flags().Set("host", "myhost")
	_ = c.Flags().Set("json", "true")

	out := captureStdout(t, func() {
		if err := runDiffFromStore(c); err != nil {
			t.Fatalf("runDiffFromStore (json): %v", err)
		}
	})
	var result storeDiffOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %q", err, out)
	}
	if len(result.Changes) != 1 || result.Changes[0].Name != "disk" {
		t.Errorf("unexpected changes: %+v", result.Changes)
	}
}

// TestRunDiffFromStore_EmptyHostResolvesLocal covers the host=="" branch,
// which falls back to os.Hostname() instead of the --host flag.
func TestRunDiffFromStore_EmptyHostResolvesLocal(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	local, err := os.Hostname()
	if err != nil {
		t.Skipf("os.Hostname unavailable in this environment: %v", err)
	}

	path := filepath.Join(dir, ".dsd", "store.jsonl")
	ts := time.Now()
	seedStore(t, path, []store.Entry{
		{Hostname: local, Timestamp: ts.Add(-time.Hour), Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
		{Hostname: local, Timestamp: ts, Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
	})

	c := newBareDiffCmd() // "host" left empty
	_ = c.Flags().Set("last", "true")

	out := captureStdout(t, func() {
		if err := runDiffFromStore(c); err != nil {
			t.Fatalf("runDiffFromStore (empty --host): %v", err)
		}
	})
	if !strings.Contains(out, "no check status changes") {
		t.Errorf("expected 'no check status changes', got: %q", out)
	}
}

// TestRunDiffFromStore_ReadAllError covers the store.ReadAll error branch:
// a directory sitting at the store path (instead of a regular file) opens
// successfully but fails on the first Read — same EISDIR trick used for
// internal/store's own ReadAll error-path test.
func TestRunDiffFromStore_ReadAllError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath() returns system path as root; test requires non-root")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	storeDir := filepath.Join(dir, ".dsd", "store.jsonl")
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatal(err)
	}

	c := newBareDiffCmd()
	_ = c.Flags().Set("last", "true")
	_ = c.Flags().Set("host", "myhost")

	err := runDiffFromStore(c)
	if err == nil || !strings.Contains(err.Error(), "reading store") {
		t.Errorf("expected a 'reading store' error, got: %v", err)
	}
}

func TestRunDiff_NoArgsNoLast(t *testing.T) {
	t.Parallel()
	c := newBareDiffCmd()
	err := runDiff(c, []string{})
	if err == nil || !strings.Contains(err.Error(), "--last") {
		t.Errorf("expected error mentioning --last, got: %v", err)
	}
}
