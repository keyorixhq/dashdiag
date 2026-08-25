package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// writeProcIOFixture writes /proc/<pid>/io and a matching /proc/<pid>/stat
// (constant fixtureStartTime, same helper cpu_test.go uses) so
// topProcessesByIOLinuxAt's starttime-based identity check — added to close
// the recycled-PID misattribution finding — sees the same process instance
// across repeated calls for the same pid within one test. Tests that need to
// simulate an actual PID recycling (different starttime) write /proc/<pid>/stat
// themselves via writeProcStatFixtureWithStart instead.
func writeProcIOFixture(t *testing.T, procRoot string, pid int, readBytes, writeBytes uint64) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := fmt.Sprintf(
		"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: %d\nwrite_bytes: %d\ncancelled_write_bytes: 0\n",
		readBytes, writeBytes)
	if err := os.WriteFile(filepath.Join(dir, "io"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile io: %v", err)
	}
	writeProcStatFixtureWithStart(t, procRoot, pid, "R", 1, 0, 0, fixtureStartTime)
}

func TestReadProcIO_HappyPath(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcIOFixture(t, procRoot, 42, 4096, 8192)

	r, w, err := readProcIO(procRoot, 42)
	if err != nil {
		t.Fatalf("readProcIO: %v", err)
	}
	if r != 4096 || w != 8192 {
		t.Errorf("readProcIO() = (%d, %d), want (4096, 8192)", r, w)
	}
}

// TestTopProcessesByIOLinux_Sorting exercises the real two-sample rate
// calculation against a fixture /proc tree, mutating it mid-flight to
// simulate I/O accruing during topProcessesByIOLinuxAt's 500ms sampling gap.
func TestTopProcessesByIOLinux_Sorting(t *testing.T) {
	procRoot := t.TempDir()
	const pid = 42
	writeProcIOFixture(t, procRoot, pid, 1000, 500)
	if err := os.WriteFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"), []byte("iohog\n"), 0644); err != nil {
		t.Fatalf("WriteFile comm: %v", err)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		// +5000 read bytes, +2500 write bytes over the 0.5s window:
		// readBps = 10000 B/s -> "9.8KB/s", writeBps = 5000 B/s -> "4.9KB/s"
		writeProcIOFixture(t, procRoot, pid, 6000, 3000)
	}()

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{strconv.Itoa(pid), "9.8KB/s", "4.9KB/s", "iohog"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

func TestTopProcessesByIOLinux_NoActivity(t *testing.T) {
	procRoot := t.TempDir()
	writeProcIOFixture(t, procRoot, 99, 1000, 500)

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected no rows when I/O counters don't change, got %+v", got.Rows)
	}
	if got.Note == "" {
		t.Error("expected a note explaining zero activity")
	}
}

// TestTopProcessesByIOLinux_NewPidMidWindowSkipped guards the "PID appeared
// mid-window" branch: a process present only in the second sample (s1) has no
// baseline in s0, so its rate cannot be computed and it must be skipped rather
// than treated as a huge (or negative) delta.
func TestTopProcessesByIOLinux_NewPidMidWindowSkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcIOFixture(t, procRoot, 1, 1000, 500) // present in both samples, no activity

	go func() {
		time.Sleep(50 * time.Millisecond)
		writeProcIOFixture(t, procRoot, 2, 100, 100) // new PID, appears only in s1
	}()

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	for _, row := range got.Rows {
		if row[0] == "2" {
			t.Errorf("PID 2 appeared only in the second sample and should be skipped, got row %+v", row)
		}
	}
}

// TestSampleAllProcIO_PermissionDeniedSetsPartial guards the false-OK-by-
// omission classification in sampleAllProcIO: a permission-denied /proc/<pid>/io
// read (owned by another user) must flip partial=true rather than silently
// vanishing from the sample, per the same rationale as the fdlimits/swap
// analogues in this package. A directory with mode 0000 triggers EACCES for a
// non-root reader; skip gracefully if the test happens to run as root (where
// permission bits don't apply).
func TestSampleAllProcIO_PermissionDeniedSetsPartial(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()
	const pid = 55
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	ioPath := filepath.Join(dir, "io")
	if err := os.WriteFile(ioPath, []byte("read_bytes: 0\nwrite_bytes: 0\n"), 0000); err != nil {
		t.Fatalf("WriteFile io: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ioPath, 0644) }) // TempDir cleanup needs read perms restored

	_, partial := sampleAllProcIO(context.Background(), procRoot)
	if !partial {
		t.Error("expected partial=true when /proc/<pid>/io is permission-denied")
	}
}

// TestTopProcessesByIOLinux_RecycledPIDSkipped guards the "counter went
// backwards" skip: if a PID's read/write bytes in the second sample are
// lower than in the first, the PID must have been recycled by a new process
// between samples and must be excluded rather than wrapping to a huge bogus
// rate.
func TestTopProcessesByIOLinux_RecycledPIDSkipped(t *testing.T) {
	procRoot := t.TempDir()
	const pid = 7
	writeProcIOFixture(t, procRoot, pid, 100000, 100000) // high baseline

	go func() {
		time.Sleep(100 * time.Millisecond)
		writeProcIOFixture(t, procRoot, pid, 10, 10) // recycled — much lower
	}()

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected the recycled pid to be skipped, got %+v", got.Rows)
	}
}

// TestTopProcessesByIOLinux_RecycledPIDHigherCounterDifferentStartTimeSkipped
// guards Finding internal-drilldown-01-09: the old "counter went backwards"
// check alone cannot catch a PID recycled between the two samples if the new
// process happens to report HIGHER byte counters than the old one's first
// sample — that case must now be caught by the starttime (stat field 22)
// identity mismatch, not silently misattributed to the wrong process.
func TestTopProcessesByIOLinux_RecycledPIDHigherCounterDifferentStartTimeSkipped(t *testing.T) {
	procRoot := t.TempDir()
	const pid = 8
	// First sample: original process, starttime=1000, low counters.
	writeProcIOFixture(t, procRoot, pid, 100, 100)
	writeProcStatFixtureWithStart(t, procRoot, pid, "R", 1, 0, 0, 1000)

	go func() {
		time.Sleep(100 * time.Millisecond)
		// Second sample: PID recycled by an unrelated process (different
		// starttime) that happens to report much HIGHER byte counters — the
		// exact scenario the plain monotonicity check misses.
		writeProcIOFixture(t, procRoot, pid, 999999, 999999)
		writeProcStatFixtureWithStart(t, procRoot, pid, "R", 1, 0, 0, 2000)
	}()

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	for _, row := range got.Rows {
		if row[0] == strconv.Itoa(pid) {
			t.Errorf("recycled pid %d with mismatched starttime must be excluded even with higher counters, got row %+v", pid, row)
		}
	}
}

// TestSampleAllProcIO_NonPermissionErrorSkippedWithoutPartial guards the
// "readProcIO failed for a reason OTHER than permission" branch: a process
// whose /proc/<pid>/io vanished mid-scan (ENOENT, a common /proc race) must
// be silently skipped without flipping partial=true — that flag is reserved
// for genuine permission gaps, per readProcIONonexistentPidIsNotPermissionError's
// rationale in io_test.go.
func TestSampleAllProcIO_NonPermissionErrorSkippedWithoutPartial(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	const pid = 77
	// Create the PID directory (so walkProcs picks it up) but no "io" file —
	// readProcIO's os.ReadFile fails with ENOENT, not EACCES.
	if err := os.MkdirAll(filepath.Join(procRoot, strconv.Itoa(pid)), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	samples, partial := sampleAllProcIO(context.Background(), procRoot)
	if partial {
		t.Error("expected partial=false when the io file is simply missing (not a permission error)")
	}
	if _, ok := samples[pid]; ok {
		t.Errorf("expected pid %d to be skipped, got %+v", pid, samples)
	}
}

// TestTopProcessesByIOLinuxAt_TruncatesToN guards the len(entries) > n cap:
// more I/O-active processes than requested must be truncated to the top n
// by total bytes/sec, not merely sorted.
func TestTopProcessesByIOLinuxAt_TruncatesToN(t *testing.T) {
	procRoot := t.TempDir()
	writeProcIOFixture(t, procRoot, 1, 1000, 0)
	writeProcIOFixture(t, procRoot, 2, 2000, 0)
	writeProcIOFixture(t, procRoot, 3, 3000, 0) // busiest

	go func() {
		time.Sleep(100 * time.Millisecond)
		writeProcIOFixture(t, procRoot, 1, 1100, 0) // +100
		writeProcIOFixture(t, procRoot, 2, 2300, 0) // +300
		writeProcIOFixture(t, procRoot, 3, 3900, 0) // +900
	}()

	got, err := topProcessesByIOLinuxAt(context.Background(), 2, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected n=2 to cap rows at 2, got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][0] != "3" {
		t.Errorf("expected pid 3 (busiest) first, got %+v", got.Rows)
	}
}

// TestTopProcessesByIOLinuxAt_PartialWithNoRowsGetsHonestNote guards the
// "partial && len(rows) == 0" Note branch: when every process is
// permission-denied (so no rows are produced) the caller must see an honest
// "run as root" caveat rather than the ambiguous "no active I/O" message,
// which would otherwise look like a clean bill of health. Skips under root
// (permission bits don't apply), matching the sibling permission tests in
// this package.
func TestTopProcessesByIOLinuxAt_PartialWithNoRowsGetsHonestNote(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()
	const pid = 88
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	ioPath := filepath.Join(dir, "io")
	if err := os.WriteFile(ioPath, []byte("read_bytes: 0\nwrite_bytes: 0\n"), 0000); err != nil {
		t.Fatalf("WriteFile io: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ioPath, 0644) })

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected no rows for a fully permission-denied sample, got %+v", got.Rows)
	}
	if got.Note == "" || !strings.Contains(got.Note, "permission denied") {
		t.Errorf("expected the permission-denied-specific note, got %q", got.Note)
	}
}

// TestTopProcessesByIOLinuxAt_PartialWithRowsGetsGenericNote guards the
// "partial" (rows non-empty) Note branch: when some processes are visible
// and I/O-active AND at least one other process is permission-denied, the
// caller must see the generic "some processes hidden" caveat alongside the
// real rows. Skips under root, matching the sibling permission tests.
func TestTopProcessesByIOLinuxAt_PartialWithRowsGetsGenericNote(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()
	const visiblePID = 89
	writeProcIOFixture(t, procRoot, visiblePID, 1000, 0)
	if err := os.WriteFile(filepath.Join(procRoot, strconv.Itoa(visiblePID), "comm"), []byte("visible\n"), 0644); err != nil {
		t.Fatalf("WriteFile comm: %v", err)
	}

	const hiddenPID = 90
	hiddenDir := filepath.Join(procRoot, strconv.Itoa(hiddenPID))
	if err := os.MkdirAll(hiddenDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	hiddenIOPath := filepath.Join(hiddenDir, "io")
	if err := os.WriteFile(hiddenIOPath, []byte("read_bytes: 0\nwrite_bytes: 0\n"), 0000); err != nil {
		t.Fatalf("WriteFile io: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(hiddenIOPath, 0644) })

	go func() {
		time.Sleep(100 * time.Millisecond)
		writeProcIOFixture(t, procRoot, visiblePID, 6000, 0) // +5000 bytes over 0.5s
	}()

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 visible row, got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Note != "some processes hidden — run as root for full visibility" {
		t.Errorf("expected the generic partial-visibility note, got %q", got.Note)
	}
}

// TestTopProcessesByIOLinuxAt_ContextCancelled guards the ctx.Done() branch
// hit between the two sampling passes: a context cancelled before the 500ms
// gap elapses must return ctx.Err(), not silently proceed to a second sample.
func TestTopProcessesByIOLinuxAt_ContextCancelled(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcIOFixture(t, procRoot, 1, 100, 100)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := topProcessesByIOLinuxAt(ctx, 5, procRoot)
	if err == nil {
		t.Error("expected an error from a pre-cancelled context")
	}
}

// TestProcStartTime_MissingStatFile covers procStartTime's os.ReadFile error
// branch: no /proc/<pid>/stat present at all (process already exited between
// listing and reading) must degrade to ("", false), not an error.
func TestProcStartTime_MissingStatFile(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	start, ok := procStartTime(procRoot, 999)
	if ok || start != "" {
		t.Errorf("procStartTime(missing pid) = (%q, %v), want (\"\", false)", start, ok)
	}
}

// TestProcStartTime_TooFewFields covers procStartTime's len(rest) < 20
// branch: a stat file whose post-comm fields are truncated before reaching
// field 22 (starttime) must degrade to ("", false), same as a missing file —
// this is the fallback the PID-recycling identity check (io.go:132-140)
// relies on when starttime can't be determined.
func TestProcStartTime_TooFewFields(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	dir := filepath.Join(procRoot, "42")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Only 10 fields after "(comm) state" — starttime is field 22, so this is
	// truncated well before it.
	truncated := "42 (fixtureproc) R 0 0 0 0 0 0 0 0 0\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(truncated), 0644); err != nil {
		t.Fatalf("WriteFile stat: %v", err)
	}
	start, ok := procStartTime(procRoot, 42)
	if ok || start != "" {
		t.Errorf("procStartTime(truncated stat) = (%q, %v), want (\"\", false)", start, ok)
	}
}
