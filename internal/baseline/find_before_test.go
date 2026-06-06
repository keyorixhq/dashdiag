package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FindBaselineBeforeTime picks the most recent baseline whose mtime is before a
// cutoff (used by "since deploy" diffs). It selects by file mtime, so the test
// controls mtimes directly via os.Chtimes.
func TestFindBaselineBeforeTime(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	write := func(name, version string, mtime time.Time) {
		snap := Snapshot{Hostname: "h", Version: version, Timestamp: mtime}
		data, err := json.MarshalIndent(&snap, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	// The glob requires "<host>-2*.json"; the YYYYMMDD stamp starts with "2".
	write("h-20260101-000000.json", "old", now.Add(-72*time.Hour))
	write("h-20260201-000000.json", "mid", now.Add(-48*time.Hour))
	write("h-20260301-000000.json", "new", now.Add(-24*time.Hour))

	// Cutoff after all three → newest (-24h) wins.
	snap, err := FindBaselineBeforeTime(now.Add(-1*time.Hour), "h")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Version != "new" {
		t.Errorf("cutoff now-1h: got %q, want newest 'new'", snap.Version)
	}

	// Cutoff between mid and new (-36h) → "mid" is the newest still before it.
	snap, err = FindBaselineBeforeTime(now.Add(-36*time.Hour), "h")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Version != "mid" {
		t.Errorf("cutoff now-36h: got %q, want 'mid'", snap.Version)
	}

	// Cutoff before everything → error.
	if _, err := FindBaselineBeforeTime(now.Add(-100*time.Hour), "h"); err == nil {
		t.Error("cutoff before all baselines should error")
	}

	// Unknown host → no baselines found.
	if _, err := FindBaselineBeforeTime(now, "ghost"); err == nil {
		t.Error("unknown host should error")
	}
}
