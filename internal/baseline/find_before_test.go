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

// TestFindBaselineBeforeTime_HostnameTraversal guards against a hostname
// argument that contains path-traversal segments escaping baselineDir() via
// the Glob pattern (internal-baseline-01-07). hostname flows into
// FindBaselineBeforeTime unsanitized from cmd/ callers; without SafeHostname
// applied to it, filepath.Glob(filepath.Join(dir, hostname+"-2*.json")) can
// resolve to a path outside ~/.dsd/baselines/ and read an arbitrary
// attacker-planted snapshot from a sibling directory.
func TestFindBaselineBeforeTime_HostnameTraversal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	// A file OUTSIDE baselineDir(), in a sibling directory, that a traversal
	// hostname could reach.
	evilDir := filepath.Join(home, ".dsd", "evil")
	if err := os.MkdirAll(evilDir, 0o750); err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{Hostname: "evil", Version: "planted-outside-baselines", Timestamp: time.Now()}
	data, err := json.MarshalIndent(&snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	evilPath := filepath.Join(evilDir, "evilhost-20260101-000000.json")
	if err := os.WriteFile(evilPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// hostname reaches into the sibling "evil" dir via "../evil/evilhost".
	_, err = FindBaselineBeforeTime(time.Now(), "../evil/evilhost")
	if err == nil {
		t.Fatal("traversal hostname must not resolve to a file outside baselineDir(); FindBaselineBeforeTime should have errored with 'no baselines found'")
	}
}
