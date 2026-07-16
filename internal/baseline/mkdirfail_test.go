package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Save* functions must surface a MkdirAll failure rather than silently
// succeeding or panicking. Force the failure by making HOME a path whose
// ".dsd" component is a regular file, so os.MkdirAll(dir, ...) fails with
// ENOTDIR when it tries to create the subdirectory under it.
func blockedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	blocker := filepath.Join(home, ".dsd")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("writing blocker file: %v", err)
	}
	return home
}

func TestSaveBaseline_MkdirAllFails(t *testing.T) {
	home := blockedHome(t)
	t.Setenv("HOME", home)

	hostname, _ := os.Hostname()
	snap := makeSnap(hostname, "v1", "cpu", "OK")
	if err := SaveBaseline(snap); err == nil {
		t.Error("SaveBaseline should error when the baseline dir cannot be created")
	}
}

func TestSaveGolden_MkdirAllFails(t *testing.T) {
	home := blockedHome(t)
	t.Setenv("HOME", home)

	snap := &Snapshot{Hostname: "h", Version: "v1", Timestamp: time.Now()}
	if err := SaveGolden(snap, "prod"); err == nil {
		t.Error("SaveGolden should error when the golden dir cannot be created")
	}
}

func TestSaveSecurityBaseline_MkdirAllFails(t *testing.T) {
	home := blockedHome(t)
	t.Setenv("HOME", home)

	b := &SecurityBaseline{Hostname: "h"}
	if err := SaveSecurityBaseline(b); err == nil {
		t.Error("SaveSecurityBaseline should error when the dsd dir cannot be created")
	}
}

// ListGolden must surface a non-NotExist ReadDir error (e.g. a path component
// that exists but is not a directory), distinct from the "no golden dir yet"
// case which returns nil, nil.
func TestListGolden_ReadDirError(t *testing.T) {
	home := blockedHome(t)
	t.Setenv("HOME", home)

	// goldenDir() = $HOME/.dsd/golden, and $HOME/.dsd is a regular file, so
	// os.ReadDir on it fails with ENOTDIR (not ENOENT).
	_, err := ListGolden()
	if err == nil {
		t.Error("ListGolden should surface a non-NotExist ReadDir error")
	}
}

// extractSysctlRaw must skip non-Sysctl checks and keep scanning for the real
// Sysctl entry, rather than stopping at the first check in the slice.
func TestExtractSysctlRaw_SkipsNonSysctlChecks(t *testing.T) {
	t.Parallel()
	snap := &Snapshot{Checks: []CheckResult{
		{Name: "CPU Load", Raw: models.CPUInfo{UsagePct: 5}},
		{Name: "Sysctl", Raw: models.SysctlInfo{VMSwappiness: 42}},
	}}
	raw := extractSysctlRaw(snap)
	if raw == nil {
		t.Fatal("expected non-nil raw map from the Sysctl check")
	}
	if got, ok := raw["vm_swappiness"].(float64); !ok || got != 42 {
		t.Errorf("vm_swappiness = %v, want 42", raw["vm_swappiness"])
	}
}

// A Sysctl check with a nil Raw must be skipped (continue), not returned as a
// nil map short-circuit — the scan should still be able to find a later
// non-nil Sysctl entry (defensive: shouldn't normally happen, but the loop
// condition explicitly guards Raw == nil).
func TestExtractSysctlRaw_NilRawSkipped(t *testing.T) {
	t.Parallel()
	snap := &Snapshot{Checks: []CheckResult{
		{Name: "Sysctl", Raw: nil},
	}}
	if raw := extractSysctlRaw(snap); raw != nil {
		t.Errorf("Sysctl check with nil Raw should yield nil, got %v", raw)
	}
}

// extractSysctlRaw must return nil when the Sysctl check's Raw marshals to
// valid JSON that is not a JSON object (e.g. a slice) — json.Marshal succeeds
// but the subsequent json.Unmarshal into map[string]any fails.
func TestExtractSysctlRaw_UnmarshalNotAnObject(t *testing.T) {
	snap := &Snapshot{Checks: []CheckResult{{Name: "Sysctl", Raw: []int{1, 2, 3}}}}
	if raw := extractSysctlRaw(snap); raw != nil {
		t.Errorf("non-object Raw should yield nil, got %v", raw)
	}
}

// ComputeSysctlDrift must skip a key whose value is not numeric in both
// snapshots (a JSON-decoded map can carry any JSON type), rather than
// panicking on the failed type assertion.
func TestComputeSysctlDrift_SkipsNonNumericField(t *testing.T) {
	golden := &Snapshot{Checks: []CheckResult{{Name: "Sysctl", Raw: map[string]any{
		"vm_swappiness": float64(10),
		"kernel_name":   "linux", // non-numeric, not in the skip set
	}}}}
	current := &Snapshot{Checks: []CheckResult{{Name: "Sysctl", Raw: map[string]any{
		"vm_swappiness": float64(60),
		"kernel_name":   "linux",
	}}}}

	drift := ComputeSysctlDrift(golden, current)
	if len(drift) != 1 || drift[0].Param != "vm_swappiness" {
		t.Fatalf("expected only vm_swappiness to drift (kernel_name skipped as non-numeric), got %+v", drift)
	}
}

// ComputeSysctlDrift must skip a key present in the golden snapshot but
// absent from the current one (the current system doesn't report that
// tunable), rather than treating a missing key as drift.
func TestComputeSysctlDrift_SkipsKeyMissingFromCurrent(t *testing.T) {
	golden := &Snapshot{Checks: []CheckResult{{Name: "Sysctl", Raw: map[string]any{
		"vm_swappiness":  float64(10),
		"only_in_golden": float64(99),
	}}}}
	current := &Snapshot{Checks: []CheckResult{{Name: "Sysctl", Raw: map[string]any{
		"vm_swappiness": float64(10),
	}}}}

	drift := ComputeSysctlDrift(golden, current)
	if len(drift) != 0 {
		t.Errorf("key missing from current should not be reported as drift, got %+v", drift)
	}
}

// Save* functions must surface an os.CreateTemp failure (e.g. the target
// directory exists but isn't writable) rather than silently succeeding.
// MkdirAll on an already-existing directory is a no-op regardless of the
// requested mode, so pre-creating the target read-only lets MkdirAll succeed
// and CreateTemp fail — reaching the "creating temp file" error branch.
func TestSaveBaseline_CreateTempFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) }) // let TempDir clean up
	if f, err := os.CreateTemp(dir, "rootcheck-*"); err == nil {
		f.Close()
		_ = os.Remove(f.Name())
		t.Skip("running as root; directory-permission restriction cannot be triggered")
	}

	hostname, _ := os.Hostname()
	snap := makeSnap(hostname, "v1", "cpu", "OK")
	if err := SaveBaseline(snap); err == nil {
		t.Error("SaveBaseline should error when the baseline dir is not writable")
	}
}

func TestSaveGolden_CreateTempFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dsd", "golden")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })
	if f, err := os.CreateTemp(dir, "rootcheck-*"); err == nil {
		f.Close()
		_ = os.Remove(f.Name())
		t.Skip("running as root; directory-permission restriction cannot be triggered")
	}

	snap := &Snapshot{Hostname: "h", Version: "v1", Timestamp: time.Now()}
	if err := SaveGolden(snap, "prod"); err == nil {
		t.Error("SaveGolden should error when the golden dir is not writable")
	}
}

func TestSaveSecurityBaseline_CreateTempFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dsd")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })
	if f, err := os.CreateTemp(dir, "rootcheck-*"); err == nil {
		f.Close()
		_ = os.Remove(f.Name())
		t.Skip("running as root; directory-permission restriction cannot be triggered")
	}

	b := &SecurityBaseline{Hostname: "h"}
	if err := SaveSecurityBaseline(b); err == nil {
		t.Error("SaveSecurityBaseline should error when the dsd dir is not writable")
	}
}

// SaveBaseline must surface an os.Rename failure when the timestamped
// snapshot's target path is already occupied by a directory (rename onto an
// existing directory fails), rather than silently succeeding.
func TestSaveBaseline_RenameToTsFileFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	hostname, _ := os.Hostname()
	snap := makeSnap(hostname, "v1", "cpu", "OK")

	bdir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Pre-create a directory at the exact path SaveBaseline will try to
	// rename its temp file onto.
	tsFile := filepath.Join(bdir, hostname+"-"+snap.Timestamp.Format("20060102-150405")+".json")
	if err := os.MkdirAll(tsFile, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := SaveBaseline(snap); err == nil {
		t.Error("SaveBaseline should error when the timestamped target path is a directory")
	}
}

// SaveBaseline must surface an os.Rename failure on its SECOND rename (the
// tmp2 -> "-latest.json" swap), distinctly from the first rename above. The
// timestamped rename must succeed so the function proceeds far enough to
// create, write and close tmp2 — only the final rename onto "latest" is
// blocked, by pre-occupying that exact path with a directory. This exercises
// the tmp2 CreateTemp/Write/Close success path that no other test reaches,
// since every other failure test returns before tmp2 is ever created.
func TestSaveBaseline_RenameToLatestFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	hostname, _ := os.Hostname()
	snap := makeSnap(hostname, "v1", "cpu", "OK")

	bdir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Pre-create a directory at the exact path SaveBaseline will try to
	// rename its "latest" temp file onto. The timestamped file's path is
	// left free, so that first rename succeeds.
	//
	// SaveBaseline itself rotates any pre-existing "latest" out to "-prev"
	// before attempting the final rename (line: os.Rename(latest, prevPath)).
	// That rotation would clear our directory obstruction out of the way, so
	// "-prev" must ALSO be pre-occupied by a directory: the rotation rename
	// then fails (its error is deliberately ignored by SaveBaseline), leaving
	// our directory at "latest" in place to block the final rename.
	latest := latestPath(hostname)
	if err := os.MkdirAll(latest, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prevPath(hostname), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := SaveBaseline(snap); err == nil {
		t.Error("SaveBaseline should error when the latest-file target path is a directory")
	}
	// The timestamped snapshot file must have been written despite the
	// later failure — confirms the first rename really did succeed and
	// the function proceeded into the tmp2 path rather than failing early.
	tsFile := filepath.Join(bdir, hostname+"-"+snap.Timestamp.Format("20060102-150405")+".json")
	if _, err := os.Stat(tsFile); err != nil {
		t.Errorf("expected timestamped snapshot file to exist, stat failed: %v", err)
	}
}

// SaveGolden must surface an os.Rename failure when the golden file's target
// path is already occupied by a directory.
func TestSaveGolden_RenameFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	gdir := filepath.Join(home, ".dsd", "golden")
	if err := os.MkdirAll(filepath.Join(gdir, "prod.json"), 0o750); err != nil {
		t.Fatal(err)
	}

	snap := &Snapshot{Hostname: "h", Version: "v1", Timestamp: time.Now()}
	if err := SaveGolden(snap, "prod"); err == nil {
		t.Error("SaveGolden should error when the target path is a directory")
	}
}

// SaveSecurityBaseline must surface an os.Rename failure when the baseline's
// target path is already occupied by a directory.
func TestSaveSecurityBaseline_RenameFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if err := os.MkdirAll(filepath.Join(home, ".dsd", "security-baseline.json"), 0o750); err != nil {
		t.Fatal(err)
	}

	b := &SecurityBaseline{Hostname: "h"}
	if err := SaveSecurityBaseline(b); err == nil {
		t.Error("SaveSecurityBaseline should error when the target path is a directory")
	}
}

// LoadSecurityBaseline must surface a non-NotExist read error (e.g. the
// baseline path exists but is a directory, not a file) distinctly from the
// missing-file case, which returns nil, nil.
func TestLoadSecurityBaseline_ReadError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".dsd")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// security-baseline.json is a directory, not a file: os.ReadFile fails
	// with EISDIR, not ENOENT.
	if err := os.MkdirAll(filepath.Join(dir, "security-baseline.json"), 0o750); err != nil {
		t.Fatal(err)
	}

	got, err := LoadSecurityBaseline()
	if err == nil {
		t.Errorf("expected a read error, got nil (result %+v)", got)
	}
}

// LoadHistory must skip an entry whose path cannot be read (not just one that
// parses as invalid JSON) — a directory matching the timestamp glob pattern
// triggers a ReadFile error rather than a JSON parse error.
func TestLoadHistory_SkipsUnreadableEntry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	hostname, _ := os.Hostname()
	bdir := filepath.Join(dir, ".dsd", "baselines")
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}

	// A directory matching the timestamped-snapshot glob pattern: os.ReadFile
	// on it fails (EISDIR), exercising the ReadFile-error skip branch.
	badDir := filepath.Join(bdir, hostname+"-20260101-000000.json")
	if err := os.MkdirAll(badDir, 0o750); err != nil {
		t.Fatal(err)
	}

	good := Snapshot{Hostname: hostname, Version: "good", Timestamp: time.Now()}
	data, err := json.MarshalIndent(&good, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bdir, hostname+"-20260201-000000.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	snaps, err := LoadHistory(10)
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(snaps) != 1 || snaps[0].Version != "good" {
		t.Errorf("want only the good snapshot, got %+v", versions(snaps))
	}
}

// FindBaselineBeforeTime must skip a candidate file that fails to load (e.g.
// corrupt JSON) rather than aborting, and still return the best valid match.
func TestFindBaselineBeforeTime_SkipsCorruptCandidate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	now := time.Now()

	// Corrupt candidate — newer mtime, would be picked first if not skipped.
	corrupt := filepath.Join(dir, "h-20260301-000000.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(corrupt, now.Add(-24*time.Hour), now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Valid, older candidate.
	valid := filepath.Join(dir, "h-20260201-000000.json")
	snap := Snapshot{Hostname: "h", Version: "valid", Timestamp: now}
	data, err := json.MarshalIndent(&snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(valid, now.Add(-48*time.Hour), now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}

	got, err := FindBaselineBeforeTime(now, "h")
	if err != nil {
		t.Fatalf("FindBaselineBeforeTime: %v", err)
	}
	if got.Version != "valid" {
		t.Errorf("expected the corrupt (newer) candidate to be skipped, got version %q", got.Version)
	}
}
