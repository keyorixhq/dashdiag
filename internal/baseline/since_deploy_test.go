package baseline

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/output"
)

// parseBootTime pulls the btime epoch out of /proc/stat-shaped content.
func TestParseBootTime(t *testing.T) {
	const stat = "cpu  1 2 3 4\n" +
		"intr 12345\n" +
		"btime 1700000000\n" +
		"processes 999\n"
	bt, ok := parseBootTime(strings.NewReader(stat))
	if !ok {
		t.Fatal("expected btime to parse")
	}
	if got := bt.Unix(); got != 1700000000 {
		t.Errorf("btime: got %d, want 1700000000", got)
	}
}

func TestParseBootTime_Missing(t *testing.T) {
	if _, ok := parseBootTime(strings.NewReader("cpu 1 2 3\nprocesses 5\n")); ok {
		t.Error("no btime line should return ok=false")
	}
}

func TestParseBootTime_Malformed(t *testing.T) {
	if _, ok := parseBootTime(strings.NewReader("btime notanumber\n")); ok {
		t.Error("non-numeric btime should return ok=false")
	}
}

// A reader that fails mid-scan (not a clean EOF) must surface as ok=false via
// scanner.Err(), not be treated the same as "no btime line found".
func TestParseBootTime_ScanError(t *testing.T) {
	if _, ok := parseBootTime(errReader{}); ok {
		t.Error("a reader that fails should return ok=false")
	}
}

// parseProcStart reads field 2 (comm) and field 22 (starttime, ticks) from a
// /proc/<pid>/stat record and offsets from boot (100 ticks/sec).
func TestParseProcStart(t *testing.T) {
	boot := time.Unix(1700000000, 0)
	// 22 fields; field[1]=(nginx), field[21]=starttime=500 ticks → boot+5s.
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "1234"
	fields[1] = "(nginx)"
	fields[21] = "500"
	rec := strings.Join(fields, " ")

	ts, name, ok := parseProcStart(strings.NewReader(rec), boot)
	if !ok {
		t.Fatal("expected valid record to parse")
	}
	if name != "nginx" {
		t.Errorf("name: got %q, want nginx", name)
	}
	if want := boot.Add(5 * time.Second); !ts.Equal(want) {
		t.Errorf("start time: got %v, want %v", ts, want)
	}
}

// errReader always fails on Read, exercising parseProcStart's io.ReadAll
// error branch.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated read failure")
}

func TestParseProcStart_ReadError(t *testing.T) {
	if _, _, ok := parseProcStart(errReader{}, time.Now()); ok {
		t.Error("a reader that fails should return ok=false")
	}
}

func TestParseProcStart_TooFewFields(t *testing.T) {
	if _, _, ok := parseProcStart(strings.NewReader("1 (x) S 0"), time.Now()); ok {
		t.Error("record with <22 fields should return ok=false")
	}
}

func TestParseProcStart_BadStartTicks(t *testing.T) {
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[1] = "(proc)"
	fields[21] = "xyz"
	if _, _, ok := parseProcStart(strings.NewReader(strings.Join(fields, " ")), time.Now()); ok {
		t.Error("non-numeric starttime should return ok=false")
	}
}

// getBootTime always returns a non-zero, past timestamp — either parsed from
// /proc/stat (Linux) or the 24h-ago fallback (no /proc, e.g. macOS).
func TestGetBootTime(t *testing.T) {
	bt := getBootTime()
	if bt.IsZero() {
		t.Fatal("getBootTime returned zero time")
	}
	if bt.After(time.Now()) {
		t.Errorf("boot time %v is in the future", bt)
	}
}

// newestProcStart must be self-consistent: it either returns a process started
// within maxAge, or an error — never a zero time with nil error.
func TestNewestProcStart(t *testing.T) {
	ts, name, err := newestProcStart(2 * time.Hour)
	if err != nil {
		if !ts.IsZero() || name != "" {
			t.Errorf("error path should return zero values, got (%v, %q)", ts, name)
		}
		return
	}
	if ts.IsZero() {
		t.Error("success path returned zero time with nil error")
	}
	if age := time.Since(ts); age > 2*time.Hour {
		t.Errorf("returned process older than maxAge: %v", age)
	}
}

// newestProcStart with maxAge=0 must reject every running process (every
// process has age > 0), exercising the age-filter skip branch and returning
// the "no recent process" error deterministically.
func TestNewestProcStart_ZeroMaxAgeRejectsAll(t *testing.T) {
	ts, name, err := newestProcStart(0)
	if err == nil {
		t.Fatalf("expected error with maxAge=0, got (%v, %q)", ts, name)
	}
	if !ts.IsZero() || name != "" {
		t.Errorf("error path should return zero values, got (%v, %q)", ts, name)
	}
}

// RunSinceDeployDiff degrades gracefully to a nil error (info message) when no
// pre-deploy baseline exists for the host.
func TestRunSinceDeployDiff_NoBaseline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := RunSinceDeployDiff(output.ModePlain); err != nil {
		t.Errorf("RunSinceDeployDiff should not error with no baseline, got %v", err)
	}
}

// RunSinceDeployDiff's success path (a deploy signal is found AND a baseline
// predates it) prints the "Changes since last deploy" header rather than one
// of the two info fallbacks. DetectLastDeployTime has no injection seam (it
// cascades through systemctl / /proc / git), so this test relies on the test
// process itself being a "recently started process" — true for every go test
// invocation — to make newestProcStart succeed, then plants a baseline file
// old enough to predate it.
func TestRunSinceDeployDiff_WithBaseline(t *testing.T) {
	deployTime, _, err := DetectLastDeployTime()
	if err != nil {
		t.Skip("no deploy signal available in this environment")
	}

	dir := t.TempDir()
	t.Setenv("HOME", dir)
	hostname, _ := os.Hostname()
	bdir := filepath.Join(dir, ".dsd", "baselines")
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{Hostname: hostname, Version: "pre-deploy"}
	data, err := json.MarshalIndent(&snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(bdir, hostname+"-20260101-000000.json")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// Backdate the baseline file so its mtime is well before the deploy signal.
	before := deployTime.Add(-1 * time.Hour)
	if err := os.Chtimes(p, before, before); err != nil {
		t.Fatal(err)
	}

	if err := RunSinceDeployDiff(output.ModePlain); err != nil {
		t.Errorf("RunSinceDeployDiff should not error on the success path, got %v", err)
	}
}

// LoadHistory returns the last n timestamped snapshots oldest-first, ignoring
// the -latest/-prev rolling files (which lack the numeric timestamp glob shape).
func TestLoadHistory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	hostname, _ := os.Hostname()
	bdir := filepath.Join(dir, ".dsd", "baselines")
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}

	write := func(fname, version string) {
		snap := Snapshot{Hostname: hostname, Version: version, Timestamp: time.Now()}
		data, err := json.MarshalIndent(&snap, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bdir, fname), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Three timestamped snapshots (filename sort == chronological) plus the
	// rolling symlink-style files that must be excluded.
	write(hostname+"-20260101-000000.json", "v1")
	write(hostname+"-20260201-000000.json", "v2")
	write(hostname+"-20260301-000000.json", "v3")
	write(hostname+"-latest.json", "latest")
	write(hostname+"-prev.json", "prev")

	// n larger than count → all three, oldest-first.
	snaps, err := LoadHistory(10)
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(snaps) != 3 {
		t.Fatalf("want 3 timestamped snaps (latest/prev excluded), got %d", len(snaps))
	}
	if snaps[0].Version != "v1" || snaps[2].Version != "v3" {
		t.Errorf("want oldest-first v1..v3, got %q..%q", snaps[0].Version, snaps[2].Version)
	}

	// n smaller than count → last n (most recent).
	snaps, err = LoadHistory(2)
	if err != nil {
		t.Fatalf("LoadHistory(2): %v", err)
	}
	if len(snaps) != 2 || snaps[0].Version != "v2" || snaps[1].Version != "v3" {
		t.Errorf("LoadHistory(2) want [v2 v3], got %+v", versions(snaps))
	}
}

// LoadHistory skips corrupt files rather than aborting the whole history.
func TestLoadHistory_SkipsCorrupt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	hostname, _ := os.Hostname()
	bdir := filepath.Join(dir, ".dsd", "baselines")
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}

	good := Snapshot{Hostname: hostname, Version: "good", Timestamp: time.Now()}
	data, _ := json.MarshalIndent(&good, "", "  ")
	if err := os.WriteFile(filepath.Join(bdir, hostname+"-20260101-000000.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bdir, hostname+"-20260201-000000.json"), []byte("{broken"), 0o644); err != nil {
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

// LoadHistory must surface a non-syntax filepath.Glob error rather than
// treating it as "no history": an unclosed "[" bracket-class in HOME makes
// the derived glob pattern malformed, forcing filepath.ErrBadPattern.
func TestLoadHistory_BadGlobPattern(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "bad[home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	snaps, err := LoadHistory(10)
	if err == nil {
		t.Errorf("LoadHistory should surface a bad glob pattern error, got snaps=%+v", snaps)
	}
}

func TestNewestProcStartFrom(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	boot := time.Now().Add(-1000 * time.Second)

	makeStatFile := func(pidDir, comm, ticks string) {
		t.Helper()
		if err := os.Mkdir(pidDir, 0o755); err != nil {
			t.Fatal(err)
		}
		fields := make([]string, 22)
		for i := range fields {
			fields[i] = "0"
		}
		fields[1] = "(" + comm + ")"
		fields[21] = ticks
		if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(strings.Join(fields, " ")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Process 100: started 500s after boot → 500s old, within maxAge
	makeStatFile(filepath.Join(dir, "100"), "older", "50000")
	// Process 200: started 900s after boot → 100s old, within maxAge and newer
	makeStatFile(filepath.Join(dir, "200"), "newer", "90000")
	// Process 300: malformed stat → parseProcStart returns ok=false → skipped
	if err := os.Mkdir(filepath.Join(dir, "300"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "300", "stat"), []byte("bad"), 0o644); err != nil {
		t.Fatal(err)
	}

	glob := filepath.Join(dir, "[0-9]*/stat")
	ts, name, err := newestProcStartFrom(glob, boot, 2*time.Hour)
	if err != nil {
		t.Fatalf("newestProcStartFrom: %v", err)
	}
	if name != "newer" {
		t.Errorf("name: got %q, want newer", name)
	}
	want := boot.Add(900 * time.Second)
	if diff := ts.Sub(want); diff < -time.Second || diff > time.Second {
		t.Errorf("start time: got %v, want ~%v", ts, want)
	}
}

func TestNewestProcStartFrom_MaxAgeRejectsOld(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Boot was 10000s ago; process started 500s after boot → 9500s old > 1h
	boot := time.Now().Add(-10000 * time.Second)
	if err := os.Mkdir(filepath.Join(dir, "100"), 0o755); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[1] = "(oldproc)"
	fields[21] = "50000"
	if err := os.WriteFile(filepath.Join(dir, "100", "stat"), []byte(strings.Join(fields, " ")), 0o644); err != nil {
		t.Fatal(err)
	}
	glob := filepath.Join(dir, "[0-9]*/stat")
	_, _, err := newestProcStartFrom(glob, boot, 1*time.Hour)
	if err == nil {
		t.Error("expected error when all processes are older than maxAge")
	}
}

func TestNewestProcStartFrom_BadGlob(t *testing.T) {
	t.Parallel()
	_, _, err := newestProcStartFrom("[invalid", time.Now(), time.Hour)
	if err == nil {
		t.Error("expected error for bad glob pattern")
	}
}

func TestNewestProcStartFrom_EmptyGlob(t *testing.T) {
	t.Parallel()
	_, _, err := newestProcStartFrom("/nonexistent/[0-9]*/stat", time.Now(), time.Hour)
	if err == nil {
		t.Error("expected 'no recent process' error when glob matches nothing")
	}
}

func TestGetBootTimeFrom(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "proc_stat")
	content := "cpu  1 2 3 4\nbtime 1700000000\nprocesses 999\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	bt := getBootTimeFrom(path)
	if bt.Unix() != 1700000000 {
		t.Errorf("getBootTimeFrom: got unix %d, want 1700000000", bt.Unix())
	}
}

func TestGetBootTimeFrom_Missing(t *testing.T) {
	t.Parallel()
	bt := getBootTimeFrom("/nonexistent/proc/stat")
	age := time.Since(bt)
	if age < 23*time.Hour || age > 25*time.Hour {
		t.Errorf("expected ~24h-ago fallback, got age %v", age)
	}
}

func TestGetBootTimeFrom_NoBtimeLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "proc_stat")
	if err := os.WriteFile(path, []byte("cpu  1 2 3 4\nprocesses 999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bt := getBootTimeFrom(path)
	age := time.Since(bt)
	if age < 23*time.Hour || age > 25*time.Hour {
		t.Errorf("expected ~24h-ago fallback when no btime line, got age %v", age)
	}
}

func versions(snaps []*Snapshot) []string {
	out := make([]string, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, s.Version)
	}
	return out
}
