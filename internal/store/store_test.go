package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNullStore(t *testing.T) {
	t.Parallel()
	var s NullStore
	ctx := context.Background()
	e := Entry{Timestamp: time.Now(), Hostname: "h", Verdict: "OK"}

	if err := s.Append(ctx, e); err != nil {
		t.Fatalf("NullStore.Append: %v", err)
	}
	hist, err := s.History(ctx, "h", 10)
	if err != nil || len(hist) != 0 {
		t.Fatalf("NullStore.History: got (%v, %v), want (nil, nil)", hist, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("NullStore.Close: %v", err)
	}
}

func TestVerdictFromInsights(t *testing.T) {
	t.Parallel()
	cases := []struct {
		levels []string
		want   string
	}{
		{nil, "OK"},
		{[]string{"OK"}, "OK"},
		{[]string{"INFO", "OK"}, "OK"},
		{[]string{"WARN"}, "WARN"},
		{[]string{"OK", "WARN"}, "WARN"},
		{[]string{"WARN", "CRIT"}, "CRIT"},
		{[]string{"CRIT", "WARN"}, "CRIT"},
		{[]string{"INFO", "WARN", "CRIT"}, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.want+"_"+joinLevels(tc.levels), func(t *testing.T) {
			t.Parallel()
			if got := VerdictFromInsights(tc.levels); got != tc.want {
				t.Errorf("VerdictFromInsights(%v) = %q, want %q", tc.levels, got, tc.want)
			}
		})
	}
}

func joinLevels(ls []string) string {
	s := ""
	for _, l := range ls {
		s += l
	}
	return s
}

func TestJSONLStore_AppendAndHistory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	entries := []Entry{
		{Timestamp: time.Now(), Hostname: "host1", Version: "v1.0.0", Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
		{Timestamp: time.Now(), Hostname: "host1", Version: "v1.0.0", Verdict: "WARN", Checks: map[string]string{"cpu": "WARN"}},
		{Timestamp: time.Now(), Hostname: "host2", Version: "v1.0.0", Verdict: "CRIT", Checks: map[string]string{"disk": "CRIT"}},
		{Timestamp: time.Now(), Hostname: "host1", Version: "v1.0.1", Verdict: "OK", Checks: map[string]string{"cpu": "OK"}},
	}
	for i, e := range entries {
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	// History for host1 returns 3 entries (not host2's).
	hist, err := s.History(ctx, "host1", 100)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 3 {
		t.Fatalf("History host1: got %d entries, want 3", len(hist))
	}
	// Entries are oldest-first.
	if hist[0].Verdict != "OK" || hist[1].Verdict != "WARN" || hist[2].Verdict != "OK" {
		t.Errorf("unexpected order: %v", verdicts(hist))
	}

	// host2 has 1 entry.
	hist2, err := s.History(ctx, "host2", 100)
	if err != nil {
		t.Fatalf("History host2: %v", err)
	}
	if len(hist2) != 1 || hist2[0].Verdict != "CRIT" {
		t.Errorf("History host2: got %v", hist2)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestJSONLStore_HistoryLimit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	for i := range 5 {
		_ = i
		if err := s.Append(ctx, Entry{Hostname: "h", Verdict: "OK"}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := s.Append(ctx, Entry{Hostname: "h", Verdict: "WARN"}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Requesting last 2 returns the 2 most recent, oldest-first.
	hist, err := s.History(ctx, "h", 2)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("got %d entries, want 2", len(hist))
	}
	// The last appended entry (WARN) should be the most recent.
	if hist[1].Verdict != "WARN" {
		t.Errorf("expected WARN as last entry, got %q", hist[1].Verdict)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestJSONLStore_HistoryMissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")

	// Open creates the file, so for "missing file" test we open then remove.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Re-open to get a valid JSONLStore pointing to the now-missing path.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("Open (re-open): %v", err)
	}
	// Remove again — the file was re-created by Open.
	_ = os.Remove(path)

	ctx := context.Background()
	hist, err := s2.History(ctx, "h", 10)
	if err != nil || hist != nil {
		t.Errorf("History on missing file: got (%v, %v), want (nil, nil)", hist, err)
	}
	_ = s2.Close()
}

func TestJSONLStore_SkipsMalformedLines(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")

	// Write one good entry, one malformed line, then another good entry.
	good := `{"ts":"2026-01-01T00:00:00Z","host":"h","version":"v1","verdict":"OK","checks":{}}` + "\n"
	bad := "this is not json\n"
	if err := os.WriteFile(path, []byte(good+bad+good), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	hist, err := s.History(ctx, "h", 100)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 2 {
		t.Errorf("expected 2 valid entries, got %d", len(hist))
	}
	_ = s.Close()
}

func TestStorePath_NonRoot(t *testing.T) {
	t.Parallel()
	// Non-root: path should be under home dir.
	if os.Getuid() == 0 {
		t.Skip("running as root; cannot test non-root path")
	}
	p := StorePath()
	home, _ := os.UserHomeDir()
	if len(p) == 0 || p[:len(home)] != home {
		t.Errorf("StorePath %q does not start with home %q", p, home)
	}
}

func TestReadAll_AllHosts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	_ = s.Append(ctx, Entry{Hostname: "h1", Verdict: "OK"})
	_ = s.Append(ctx, Entry{Hostname: "h2", Verdict: "WARN"})
	_ = s.Append(ctx, Entry{Hostname: "h1", Verdict: "CRIT"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// hostname="" returns all entries across all hosts.
	all, err := ReadAll(path, "", 0)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("ReadAll all-hosts: got %d entries, want 3", len(all))
	}

	// hostname="h1" filters correctly.
	h1, err := ReadAll(path, "h1", 0)
	if err != nil {
		t.Fatalf("ReadAll h1: %v", err)
	}
	if len(h1) != 2 {
		t.Errorf("ReadAll h1: got %d entries, want 2", len(h1))
	}
}

// TestReadAll_TailWindowOrderedAfterManyWraps is a correctness check for the
// internal-store-01-05 fix: ReadAll(n>0) now keeps only a fixed-size window
// of the last n matches as it scans (instead of accumulating every match in
// the file before truncating at the end), to bound memory to O(n) rather
// than O(file size). This confirms the rewritten sliding-window logic still
// returns exactly the last n entries in the correct oldest-first order after
// far more than n entries have been scanned (multiple "wraps" of the
// window).
func TestReadAll_TailWindowOrderedAfterManyWraps(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	const total = 47
	for i := range total {
		if err := s.Append(ctx, Entry{Hostname: "h", Verdict: fmt.Sprintf("v%d", i)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	const n = 5
	got, err := ReadAll(path, "h", n)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != n {
		t.Fatalf("got %d entries, want %d", len(got), n)
	}
	for i := range n {
		want := fmt.Sprintf("v%d", total-n+i)
		if got[i].Verdict != want {
			t.Errorf("got[%d].Verdict = %q, want %q (oldest-first order of the last %d entries)", i, got[i].Verdict, want, n)
		}
	}
}

// TestReadAll_UnboundedReadCappedAtMaxEntries is the regression test for
// internal-store-01-05: ReadAll(path, "", 0) — the "return everything" mode
// used by Prune — accumulated every matching entry in the whole file with no
// limit before applying the (nonexistent, for n<=0) tail truncation. A store
// file with more than maxReadAllEntries matching lines must not have all of
// them loaded into memory.
func TestReadAll_UnboundedReadCappedAtMaxEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")

	// Write the fixture directly (not via s.Append) — 200k+ individual mutex-
	// guarded Append calls would make this test needlessly slow; the file
	// format is a plain one-JSON-object-per-line, so building it directly is
	// equivalent and fast.
	line := `{"host":"h","verdict":"OK"}` + "\n"
	var buf strings.Builder
	over := maxReadAllEntries + 10
	for range over {
		buf.WriteString(line)
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o644); err != nil {
		t.Fatalf("failed to write test fixture: %v", err)
	}

	got, err := ReadAll(path, "h", 0)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) > maxReadAllEntries {
		t.Errorf("ReadAll returned %d entries, want capped at %d", len(got), maxReadAllEntries)
	}
}

func TestReadAll_MissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	entries, err := ReadAll(filepath.Join(dir, "nonexistent.jsonl"), "h", 10)
	if err != nil || entries != nil {
		t.Errorf("ReadAll missing file: got (%v, %v), want (nil, nil)", entries, err)
	}
}

func verdicts(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Verdict
	}
	return out
}
