package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeSnap(hostname, version, checkName, status string) *Snapshot {
	return &Snapshot{
		Hostname:  hostname,
		Timestamp: time.Now().UTC().Truncate(time.Second),
		Version:   version,
		Checks:    []CheckResult{{Name: checkName, Status: status, Value: status + " value"}},
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	hostname, _ := os.Hostname()
	snap := makeSnap(hostname, "v1.2.3", "cpu", "OK")

	if err := SaveBaseline(snap); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	latestFile := filepath.Join(dir, ".dsd", "baselines", hostname+"-latest.json")
	loaded, err := LoadBaseline(latestFile)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	if loaded.Version != snap.Version {
		t.Errorf("Version: got %q, want %q", loaded.Version, snap.Version)
	}
	if loaded.Hostname != snap.Hostname {
		t.Errorf("Hostname: got %q, want %q", loaded.Hostname, snap.Hostname)
	}
	if len(loaded.Checks) != 1 || loaded.Checks[0].Status != "OK" {
		t.Errorf("Checks mismatch: got %+v", loaded.Checks)
	}
	if !loaded.Timestamp.Equal(snap.Timestamp) {
		t.Errorf("Timestamp: got %v, want %v", loaded.Timestamp, snap.Timestamp)
	}
}

func TestSaveBaseline_RotatesPrevious(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	hostname, _ := os.Hostname()
	snap1 := makeSnap(hostname, "v1.0.0", "mem", "OK")
	snap2 := makeSnap(hostname, "v1.1.0", "mem", "WARN")
	// Ensure unique timestamps so filenames don't collide
	snap2.Timestamp = snap1.Timestamp.Add(2 * time.Second)

	if err := SaveBaseline(snap1); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := SaveBaseline(snap2); err != nil {
		t.Fatalf("second save: %v", err)
	}

	// After two saves, prev must be snap1
	prevFile := filepath.Join(dir, ".dsd", "baselines", hostname+"-prev.json")
	loaded, err := LoadBaseline(prevFile)
	if err != nil {
		t.Fatalf("load prev: %v", err)
	}
	if loaded.Version != "v1.0.0" {
		t.Errorf("prev version: got %q, want v1.0.0", loaded.Version)
	}

	// Latest must be snap2
	latestFile := filepath.Join(dir, ".dsd", "baselines", hostname+"-latest.json")
	latest, err := LoadBaseline(latestFile)
	if err != nil {
		t.Fatalf("load latest: %v", err)
	}
	if latest.Version != "v1.1.0" {
		t.Errorf("latest version: got %q, want v1.1.0", latest.Version)
	}
}

func TestComputeDiff_OneChange(t *testing.T) {
	before := &Snapshot{Checks: []CheckResult{
		{Name: "memory", Status: "OK", Value: "50% used"},
	}}
	after := &Snapshot{Checks: []CheckResult{
		{Name: "memory", Status: "WARN", Value: "82% used"},
	}}

	diff := ComputeDiff(before, after)
	if len(diff) != 1 {
		t.Fatalf("expected 1 diff entry, got %d", len(diff))
	}
	d := diff[0]
	if !d.Changed {
		t.Error("expected Changed=true")
	}
	if d.Improved {
		t.Error("expected Improved=false for OK→WARN")
	}
	if d.StatusChange != "OK->WARN" {
		t.Errorf("StatusChange: got %q, want %q", d.StatusChange, "OK->WARN")
	}
	if d.Name != "memory" {
		t.Errorf("Name: got %q, want memory", d.Name)
	}
}

func TestComputeDiff_NoChange(t *testing.T) {
	snap := &Snapshot{Checks: []CheckResult{
		{Name: "cpu", Status: "OK", Value: "5% load"},
		{Name: "disk", Status: "OK", Value: "50% used"},
	}}

	diff := ComputeDiff(snap, snap)
	if len(diff) != 2 {
		t.Fatalf("expected 2 diff entries, got %d", len(diff))
	}
	for _, d := range diff {
		if d.Changed {
			t.Errorf("expected Changed=false for %q", d.Name)
		}
		if d.Improved {
			t.Errorf("expected Improved=false for %q", d.Name)
		}
	}
}

func TestComputeDiff_Improved(t *testing.T) {
	before := &Snapshot{Checks: []CheckResult{
		{Name: "swap", Status: "CRIT", Value: "90% used"},
	}}
	after := &Snapshot{Checks: []CheckResult{
		{Name: "swap", Status: "OK", Value: "5% used"},
	}}

	diff := ComputeDiff(before, after)
	if len(diff) != 1 {
		t.Fatalf("expected 1 diff entry, got %d", len(diff))
	}
	d := diff[0]
	if !d.Changed {
		t.Error("expected Changed=true")
	}
	if !d.Improved {
		t.Error("expected Improved=true for CRIT→OK")
	}
	if d.StatusChange != "CRIT->OK" {
		t.Errorf("StatusChange: got %q, want %q", d.StatusChange, "CRIT->OK")
	}
}

func TestComputeDiff_Ordering(t *testing.T) {
	before := &Snapshot{Checks: []CheckResult{
		{Name: "cpu", Status: "OK"},
		{Name: "mem", Status: "WARN"},
		{Name: "disk", Status: "OK"},
	}}
	after := &Snapshot{Checks: []CheckResult{
		{Name: "cpu", Status: "OK"},    // unchanged
		{Name: "mem", Status: "OK"},    // improved
		{Name: "disk", Status: "CRIT"}, // degraded
	}}

	diff := ComputeDiff(before, after)
	if len(diff) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(diff))
	}
	// degraded first
	if diff[0].Name != "disk" {
		t.Errorf("first entry should be degraded (disk), got %q", diff[0].Name)
	}
	// improved second
	if diff[1].Name != "mem" {
		t.Errorf("second entry should be improved (mem), got %q", diff[1].Name)
	}
	// unchanged last
	if diff[2].Name != "cpu" {
		t.Errorf("third entry should be unchanged (cpu), got %q", diff[2].Name)
	}
}

func TestComputeDiff_NewCheckInAfter(t *testing.T) {
	before := &Snapshot{Checks: []CheckResult{
		{Name: "cpu", Status: "OK"},
	}}
	after := &Snapshot{Checks: []CheckResult{
		{Name: "cpu", Status: "WARN"},
		{Name: "newcheck", Status: "OK"},
	}}

	diff := ComputeDiff(before, after)
	if len(diff) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(diff))
	}
	// cpu degraded → first
	if diff[0].Name != "cpu" || !diff[0].Changed || diff[0].Improved {
		t.Errorf("unexpected first entry: %+v", diff[0])
	}
}

// A new healthy check must NOT be reported as a (degraded) status change; a new
// problem check must be. Regression for the zero-value "->OK" misclassification.
func TestComputeDiff_NewCheckClassification(t *testing.T) {
	before := &Snapshot{Checks: []CheckResult{{Name: "cpu", Status: "OK"}}}
	after := &Snapshot{Checks: []CheckResult{
		{Name: "cpu", Status: "OK"},
		{Name: "newok", Status: "OK"},     // new + healthy → not a change
		{Name: "newwarn", Status: "WARN"}, // new + problem → degraded change
	}}
	byName := map[string]DiffEntry{}
	for _, d := range ComputeDiff(before, after) {
		byName[d.Name] = d
	}
	if d := byName["newok"]; d.Changed {
		t.Errorf("new healthy check must not be Changed, got %+v", d)
	}
	if d := byName["newwarn"]; !d.Changed || d.Improved {
		t.Errorf("new WARN check must be a degraded change, got %+v", d)
	}
}

// A WARN/CRIT check that vanishes from the current run must surface (not be
// silently dropped); a vanished OK check stays quiet.
func TestComputeDiff_DisappearedCheck(t *testing.T) {
	before := &Snapshot{Checks: []CheckResult{
		{Name: "nfs", Status: "CRIT"},
		{Name: "cpu", Status: "OK"},
	}}
	after := &Snapshot{Checks: []CheckResult{{Name: "cpu", Status: "OK"}}}

	var nfs *DiffEntry
	diff := ComputeDiff(before, after)
	for i := range diff {
		if diff[i].Name == "nfs" {
			nfs = &diff[i]
		}
	}
	if nfs == nil {
		t.Fatal("vanished CRIT check 'nfs' must be surfaced, not dropped")
	}
	if !nfs.Changed || nfs.After != "absent" {
		t.Errorf("vanished check entry = %+v, want Changed with After=absent", *nfs)
	}
}

func TestLoadBaseline_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadBaseline(filepath.Join(dir, "nonexistent.json"))
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestSaveBaseline_NoTmpFileLeft(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	hostname, _ := os.Hostname()
	snap := makeSnap(hostname, "v1.0", "cpu", "OK")
	if err := SaveBaseline(snap); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	baseDir := filepath.Join(dir, ".dsd", "baselines")
	entries, _ := os.ReadDir(baseDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file %q was not cleaned up after save", e.Name())
		}
	}
}
