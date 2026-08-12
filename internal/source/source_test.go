package source

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecordReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, []byte("AMD k10temp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")

	rec := NewRecorder(Live{})
	ctx := context.Background()

	if _, err := rec.ReadFile(present); err != nil {
		t.Fatalf("read present: %v", err)
	}
	if _, err := rec.ReadFile(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing should be ErrNotExist, got %v", err)
	}
	if _, err := rec.Run(ctx, "sh", "-c", "printf abc"); err != nil {
		t.Fatalf("run sh: %v", err)
	}
	if _, err := rec.Run(ctx, "false"); err != nil {
		t.Fatalf("run false should not be exec error: %v", err)
	}
	if _, err := rec.Run(ctx, "dsd-no-such-binary-zzz"); err == nil {
		t.Fatal("absent binary should return exec error")
	}

	rp := NewReplay(rec.Bundle())

	if got, _ := rp.ReadFile(present); string(got) != "AMD k10temp\n" {
		t.Fatalf("replay present = %q", got)
	}
	if _, err := rp.ReadFile(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replay missing should be ErrNotExist, got %v", err)
	}
	if _, err := rp.ReadFile(filepath.Join(dir, "never-touched")); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded read should be ErrNotRecorded, got %v", err)
	}
	if res, _ := rp.Run(ctx, "sh", "-c", "printf abc"); string(res.Stdout) != "abc" {
		t.Fatalf("replay sh stdout = %q", res.Stdout)
	}
	if res, _ := rp.Run(ctx, "false"); res.ExitCode != 1 {
		t.Fatalf("replay false exit = %d, want 1", res.ExitCode)
	}
	if _, err := rp.Run(ctx, "dsd-no-such-binary-zzz"); err == nil {
		t.Fatal("replay absent binary should return exec error")
	}
	if _, err := rp.Run(ctx, "uptime"); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded run should be ErrNotRecorded, got %v", err)
	}
}

func TestStatRecordReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, []byte("0123456789"), 0o640); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")

	rec := NewRecorder(Live{})
	fm, err := rec.Stat(present)
	if err != nil {
		t.Fatalf("stat present: %v", err)
	}
	if fm.Size != 10 || fm.IsDir {
		t.Fatalf("present meta = %+v, want size 10, not dir", fm)
	}
	if _, err := rec.Stat(subdir); err != nil {
		t.Fatalf("stat subdir: %v", err)
	}
	if _, err := rec.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing stat should be ErrNotExist, got %v", err)
	}

	// Replay must serve the recorded outcomes without touching the live FS.
	rp := NewReplay(rec.Bundle())
	got, err := rp.Stat(present)
	if err != nil {
		t.Fatalf("replay stat present: %v", err)
	}
	if got.Size != 10 || got.IsDir || got.ModTime != fm.ModTime {
		t.Fatalf("replay present meta = %+v, want %+v", got, fm)
	}
	if d, _ := rp.Stat(subdir); !d.IsDir {
		t.Fatalf("replay subdir IsDir = false, want true")
	}
	if _, err := rp.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replay missing should be ErrNotExist, got %v", err)
	}
	// A path never stat'd at capture must be a loud recording gap, NOT a
	// fall-through to the replaying machine's own filesystem.
	if _, err := rp.Stat(filepath.Join(dir, "never-touched")); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded stat should be ErrNotRecorded, got %v", err)
	}

	// And the records survive a Save/Load round-trip.
	out := t.TempDir()
	if err := rec.Bundle().Save(out); err != nil {
		t.Fatalf("save: %v", err)
	}
	b2, err := Load(out)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rp2 := NewReplay(b2)
	if got, _ := rp2.Stat(present); got.Size != 10 {
		t.Fatalf("loaded stat size = %d, want 10", got.Size)
	}
	if _, err := rp2.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loaded missing should be ErrNotExist, got %v", err)
	}
}

func TestStatfsRecordReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-mount")

	rec := NewRecorder(Live{})
	got, err := rec.Statfs(dir)
	if err != nil {
		t.Fatalf("statfs present dir: %v", err)
	}
	if got.Blocks == 0 || got.Bsize == 0 {
		t.Fatalf("statfs of a real dir returned zero blocks/bsize: %+v", got)
	}
	if _, err := rec.Statfs(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("statfs missing should be ErrNotExist, got %v", err)
	}

	// Replay must serve the recorded values, not stat the live FS.
	rp := NewReplay(rec.Bundle())
	rgot, err := rp.Statfs(dir)
	if err != nil {
		t.Fatalf("replay statfs: %v", err)
	}
	if rgot != got {
		t.Fatalf("replay statfs = %+v, want %+v", rgot, got)
	}
	if _, err := rp.Statfs(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replay missing should be ErrNotExist, got %v", err)
	}
	if _, err := rp.Statfs(filepath.Join(dir, "never-touched")); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded statfs should be ErrNotRecorded, got %v", err)
	}

	// Survives Save/Load.
	out := t.TempDir()
	if err := rec.Bundle().Save(out); err != nil {
		t.Fatalf("save: %v", err)
	}
	b2, err := Load(out)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if lgot, _ := NewReplay(b2).Statfs(dir); lgot != got {
		t.Fatalf("loaded statfs = %+v, want %+v", lgot, got)
	}
}

func TestCachedRecordReplayRoundTrip(t *testing.T) {
	produced := 0
	produce := func() ([]byte, error) {
		produced++
		return []byte(`{"rx":1,"tx":2}`), nil
	}

	rec := NewRecorder(Live{})
	got, err := rec.Cached("gopsutil/net/iocounters", produce)
	if err != nil || string(got) != `{"rx":1,"tx":2}` {
		t.Fatalf("record Cached = %q, %v", got, err)
	}
	if produced != 1 {
		t.Fatalf("produce called %d times during record, want 1", produced)
	}

	// Replay must return the recorded bytes WITHOUT invoking produce — that is the
	// whole point: no live probe runs on replay.
	rp := NewReplay(rec.Bundle())
	rgot, err := rp.Cached("gopsutil/net/iocounters", produce)
	if err != nil || string(rgot) != `{"rx":1,"tx":2}` {
		t.Fatalf("replay Cached = %q, %v", rgot, err)
	}
	if produced != 1 {
		t.Fatalf("produce was invoked on replay (count=%d) — replay is not hermetic", produced)
	}
	if _, err := rp.Cached("never-recorded", produce); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded Cached should be ErrNotRecorded, got %v", err)
	}

	// Survives Save/Load.
	out := t.TempDir()
	if err := rec.Bundle().Save(out); err != nil {
		t.Fatalf("save: %v", err)
	}
	b2, err := Load(out)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if lgot, _ := NewReplay(b2).Cached("gopsutil/net/iocounters", produce); string(lgot) != `{"rx":1,"tx":2}` {
		t.Fatalf("loaded Cached = %q", lgot)
	}
}

func TestSaveLoad(t *testing.T) {
	src := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(src, []byte("Tctl 45000\n"), 0o644)

	rec := NewRecorder(Live{})
	_, _ = rec.ReadFile(src)
	_, _ = rec.Run(context.Background(), "false")

	out := t.TempDir()
	if err := rec.Bundle().Save(out); err != nil {
		t.Fatalf("save: %v", err)
	}
	b2, err := Load(out)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rp := NewReplay(b2)
	if got, _ := rp.ReadFile(src); string(got) != "Tctl 45000\n" {
		t.Fatalf("loaded read = %q", got)
	}
	if res, _ := rp.Run(context.Background(), "false"); res.ExitCode != 1 {
		t.Fatalf("loaded exit = %d", res.ExitCode)
	}
}

func TestFromSnapshot(t *testing.T) {
	hwmon := "===== /sys/class/hwmon/hwmon0/name =====\nk10temp\n\n" +
		"===== /sys/class/hwmon/hwmon0/temp1_label =====\nTctl\n\n"
	tarball := writeTestTarball(t, map[string]string{
		"hwsnap-host-x/hwmon.txt":      hwmon,
		"hwsnap-host-x/os-release.txt": "ID=debian\n",
		"hwsnap-host-x/MANIFEST.txt":   "ignore me",
	})

	b, err := FromSnapshot(tarball)
	if err != nil {
		t.Fatalf("from snapshot: %v", err)
	}
	rp := NewReplay(b)

	got, err := rp.ReadFile("/sys/class/hwmon/hwmon0/name")
	if err != nil {
		t.Fatalf("read hwmon name: %v", err)
	}
	if strings.TrimSpace(string(got)) != "k10temp" {
		t.Fatalf("hwmon name = %q", got)
	}
	if got, _ := rp.ReadFile("/sys/class/hwmon/hwmon0/temp1_label"); strings.TrimSpace(string(got)) != "Tctl" {
		t.Fatalf("temp1_label = %q", got)
	}
	if got, _ := rp.ReadFile("/etc/os-release"); string(got) != "ID=debian\n" {
		t.Fatalf("os-release = %q", got)
	}
}

func writeTestTarball(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snap.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTarballRoundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(src, []byte("Tctl 50000\n"), 0o644)

	rec := NewRecorder(Live{})
	_, _ = rec.ReadFile(src)
	_, _ = rec.Run(context.Background(), "false")
	rec.Bundle().Manifest.Host = "amd-box"

	out := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := rec.Bundle().SaveTarball(out); err != nil {
		t.Fatalf("save tarball: %v", err)
	}
	b2, err := LoadTarball(out)
	if err != nil {
		t.Fatalf("load tarball: %v", err)
	}
	if b2.Manifest.Host != "amd-box" {
		t.Fatalf("manifest host = %q", b2.Manifest.Host)
	}
	rp := NewReplay(b2)
	if got, _ := rp.ReadFile(src); string(got) != "Tctl 50000\n" {
		t.Fatalf("tarball replay read = %q", got)
	}
	if res, _ := rp.Run(context.Background(), "false"); res.ExitCode != 1 {
		t.Fatalf("tarball replay exit = %d", res.ExitCode)
	}
}

// TestDirectBundleSeeding exercises PutFile/PutDir/PutGlob/PutStat — the direct
// fixture-seeding API (as opposed to NewRecorder(Live{}), which tees a real
// read). This lets a collector test build fake file/dir/glob/stat state without
// touching the real filesystem at all, which is what a plain unit test over
// production collector code (not an integration/replay-fidelity test) wants.
func TestDirectBundleSeeding(t *testing.T) {
	b := NewBundle()
	b.PutFile("/etc/fake", []byte("hello"))
	b.PutDir("/etc/fake.d", []string{"a.conf", "b.conf"})
	b.PutGlob("/etc/fake.d/*.conf", []string{"/etc/fake.d/a.conf", "/etc/fake.d/b.conf"})
	mtime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b.PutStat("/etc/fake", FileMeta{Size: 5, ModTime: mtime})

	rp := NewReplay(b)
	if got, err := rp.ReadFile("/etc/fake"); err != nil || string(got) != "hello" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
	if got, err := rp.ReadDir("/etc/fake.d"); err != nil || len(got) != 2 {
		t.Fatalf("ReadDir = %v, %v", got, err)
	}
	if got, err := rp.Glob("/etc/fake.d/*.conf"); err != nil || len(got) != 2 {
		t.Fatalf("Glob = %v, %v", got, err)
	}
	if got, err := rp.Stat("/etc/fake"); err != nil || !got.ModTime.Equal(mtime) {
		t.Fatalf("Stat = %+v, %v", got, err)
	}

	// An unseeded path must behave as "not recorded", never silently succeed.
	if _, err := rp.ReadFile("/etc/never-seeded"); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unseeded ReadFile should be ErrNotRecorded, got %v", err)
	}
}

func TestPutCmdAndPutCmdNotFound(t *testing.T) {
	b := NewBundle()
	b.PutCmd("btrfs", []string{"filesystem", "show"}, "Label: none  uuid: abc-123\n", 0)
	b.PutCmdNotFound("smartctl", []string{"-a", "/dev/sda"})

	rp := NewReplay(b)
	res, err := rp.Run(context.Background(), "btrfs", "filesystem", "show")
	if err != nil || string(res.Stdout) != "Label: none  uuid: abc-123\n" {
		t.Fatalf("Run(btrfs) = %+v, %v", res, err)
	}

	if _, err := rp.Run(context.Background(), "smartctl", "-a", "/dev/sda"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("Run(smartctl) should report ErrNotFound (tool not installed), got %v", err)
	}
}

// TestLiveGlobReadDir exercises Live.Glob and Live.ReadDir directly against a
// real temp dir — the thin os/filepath wrappers that Live delegates to.
func TestLiveGlobReadDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"b.conf", "a.conf", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	live := Live{}
	matches, err := live.Glob(filepath.Join(dir, "*.conf"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("Glob matches = %v, want 2 entries", matches)
	}

	names, err := live.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	want := []string{"a.conf", "b.conf", "c.txt"}
	if len(names) != len(want) {
		t.Fatalf("ReadDir = %v, want %v", names, want)
	}
	for i, n := range want {
		if names[i] != n {
			t.Fatalf("ReadDir[%d] = %q, want %q (should be sorted)", i, names[i], n)
		}
	}

	if _, err := live.ReadDir(filepath.Join(dir, "no-such-subdir")); err == nil {
		t.Fatal("ReadDir of missing dir should error")
	}
}

// TestLiveRunWithInjectedExec verifies Live.Run prefers l.Exec when set (the
// collector-injected locale-safe runner path) instead of falling back to
// defaultExec.
func TestLiveRunWithInjectedExec(t *testing.T) {
	t.Parallel()
	called := false
	live := Live{
		Exec: func(_ context.Context, name string, args ...string) (Result, error) {
			called = true
			return Result{Stdout: []byte("injected:" + name)}, nil
		},
	}
	res, err := live.Run(context.Background(), "uptime")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !called {
		t.Fatal("Live.Run did not use the injected Exec function")
	}
	if string(res.Stdout) != "injected:uptime" {
		t.Fatalf("Run stdout = %q, want injected result", res.Stdout)
	}
}

// TestDefaultExecCapsOutput covers read-bounding-02 / internal-source-01-04:
// defaultExec is the exec fallback Live.Run uses when no collector-injected
// Exec is set (used directly by this package's own tests, and defensively by
// any future caller of a bare source.Live{}). A subprocess that emits far
// more output than any real diagnostic tool would must not make dsd buffer
// unbounded memory just by writing to its own stdout.
func TestDefaultExecCapsOutput(t *testing.T) {
	t.Parallel()
	const wantCap = 64 * 1024 * 1024 // must match MaxCapturedOutput
	live := Live{}
	res, err := live.Run(context.Background(), "/bin/sh", "-c", "dd if=/dev/zero bs=1m count=100 2>/dev/null")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Stdout) > wantCap {
		t.Errorf("stdout not capped: got %d bytes, want <= %d", len(res.Stdout), wantCap)
	}
}

// TestRecorderGlobReadDir verifies Recorder tees Glob/ReadDir results into the
// bundle so a subsequent Replay can serve them without touching the live FS.
func TestRecorderGlobReadDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"one.conf", "two.conf"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pattern := filepath.Join(dir, "*.conf")

	rec := NewRecorder(Live{})
	matches, err := rec.Glob(pattern)
	if err != nil || len(matches) != 2 {
		t.Fatalf("record Glob = %v, %v", matches, err)
	}
	names, err := rec.ReadDir(dir)
	if err != nil || len(names) != 2 {
		t.Fatalf("record ReadDir = %v, %v", names, err)
	}

	rp := NewReplay(rec.Bundle())
	rmatches, err := rp.Glob(pattern)
	if err != nil || len(rmatches) != 2 {
		t.Fatalf("replay Glob = %v, %v", rmatches, err)
	}
	rnames, err := rp.ReadDir(dir)
	if err != nil || len(rnames) != 2 {
		t.Fatalf("replay ReadDir = %v, %v", rnames, err)
	}
	if _, err := rp.Glob(filepath.Join(dir, "never-globbed", "*.conf")); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded Glob should be ErrNotRecorded, got %v", err)
	}
	if _, err := rp.ReadDir(filepath.Join(dir, "never-read")); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded ReadDir should be ErrNotRecorded, got %v", err)
	}
}

// TestRecorderGlobReadDirErrorNotRecorded verifies a failed ReadDir at the
// inner Source is forwarded but NOT recorded into the bundle (mirroring
// ReadFile/Stat which always record — Glob/ReadDir only record on success
// since the bundle has no "not exist" encoding for them).
func TestRecorderGlobReadDirErrorNotRecorded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")

	rec := NewRecorder(Live{})
	if _, err := rec.ReadDir(missing); err == nil {
		t.Fatal("ReadDir of missing dir should error")
	}

	rp := NewReplay(rec.Bundle())
	if _, err := rp.ReadDir(missing); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("a failed ReadDir should not be recorded, replay should be ErrNotRecorded, got %v", err)
	}
}
