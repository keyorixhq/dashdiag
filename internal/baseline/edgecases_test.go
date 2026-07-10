package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// statusRank maps insight levels to a total order (worst wins in BuildSnapshot).
// Unknown/empty levels must rank below all real levels.
func TestStatusRank(t *testing.T) {
	cases := []struct {
		level string
		want  int
	}{
		{"CRIT", 3},
		{"WARN", 2},
		{"INFO", 1},
		{"OK", 0},
		{"", 0},
		{"bogus", 0},
	}
	for _, c := range cases {
		if got := statusRank(c.level); got != c.want {
			t.Errorf("statusRank(%q) = %d, want %d", c.level, got, c.want)
		}
	}
}

// LoadBaseline("-") reads a snapshot from stdin, used by piped `dsd diff`.
func TestLoadBaseline_Stdin(t *testing.T) {
	snap := &Snapshot{Hostname: "pipehost", Version: "vpipe", Timestamp: time.Now()}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })

	go func() {
		_, _ = w.Write(data)
		_ = w.Close()
	}()

	got, err := LoadBaseline("-")
	if err != nil {
		t.Fatalf("LoadBaseline(\"-\"): %v", err)
	}
	if got.Version != "vpipe" || got.Hostname != "pipehost" {
		t.Errorf("stdin round-trip mismatch: got %+v", got)
	}
}

// LoadBaseline("") resolves to the current host's -latest.json (the "last
// completed run" that `dsd health --diff` compares against).
func TestLoadBaseline_EmptyPathReadsLatest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	hostname, _ := os.Hostname()
	bdir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Hostname: hostname, Version: "vlatest", Timestamp: time.Now()}
	data, _ := json.MarshalIndent(snap, "", "  ")
	if err := os.WriteFile(filepath.Join(bdir, hostname+"-latest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := LoadBaseline("")
	if err != nil {
		t.Fatalf("LoadBaseline(\"\"): %v", err)
	}
	if got.Version != "vlatest" {
		t.Errorf("empty path should read -latest.json, got version %q", got.Version)
	}
}

// LoadBaseline surfaces read errors (missing file) and parse errors (bad JSON)
// distinctly rather than returning a zero snapshot.
func TestLoadBaseline_Errors(t *testing.T) {
	if _, err := LoadBaseline(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Error("missing file should error")
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(bad); err == nil {
		t.Error("corrupt JSON should error")
	}
}

// SaveBaseline and SaveGolden must surface a marshal failure rather than writing
// a partial file. A channel in Raw is unmarshalable by encoding/json.
func TestSave_MarshalError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	snap := &Snapshot{
		Hostname:  "h",
		Timestamp: time.Now(),
		Checks:    []CheckResult{{Name: "bad", Raw: make(chan int)}},
	}

	if err := SaveBaseline(snap); err == nil {
		t.Error("SaveBaseline should error on unmarshalable Raw")
	}
	if err := SaveGolden(snap, "prod"); err == nil {
		t.Error("SaveGolden should error on unmarshalable Raw")
	}
}

// LoadSecurityBaseline surfaces a parse error for corrupt on-disk JSON (distinct
// from the missing-file case, which returns nil,nil).
func TestLoadSecurityBaseline_Corrupt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".dsd")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "security-baseline.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecurityBaseline(); err == nil {
		t.Error("corrupt security baseline JSON should error")
	}
}

// extractSysctlRaw returns nil when the Sysctl check's Raw cannot be marshalled
// (defensive: a live struct carrying an unmarshalable field), so ComputeSysctlDrift
// yields no drift rather than panicking.
func TestExtractSysctlRaw_MarshalError(t *testing.T) {
	snap := &Snapshot{Checks: []CheckResult{{Name: "Sysctl", Raw: make(chan int)}}}
	if raw := extractSysctlRaw(snap); raw != nil {
		t.Errorf("unmarshalable Raw should yield nil, got %v", raw)
	}
	// And drift computed against it is nil, not a panic.
	if d := ComputeSysctlDrift(snap, snap); d != nil {
		t.Errorf("drift over unmarshalable Sysctl should be nil, got %v", d)
	}
}
