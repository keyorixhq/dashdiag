//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// refNow is a fixed reference time used so age math is deterministic.
func refNow(t *testing.T) time.Time {
	t.Helper()
	return mustTime(t, "2026-06-03T12:00:00Z")
}

// mustTime parses an RFC3339 timestamp or fails the test.
func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	n, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

func TestParseJournalTopError(t *testing.T) {
	t.Parallel()
	now := refNow(t)

	// Live journalctl --output=short-iso uses RFC3339 with a colon in the
	// offset (e.g. "+00:00"). 3h before refNow; source has [pid] to strip.
	line := "2026-06-03T09:00:00+00:00 myhost kernel: Out of memory: Kill process 8823 (java)"
	e, ok := parseJournalTopError(line, now)
	if !ok {
		t.Fatal("expected ok")
	}
	if e.Source != "kernel" {
		t.Errorf("source = %q, want kernel", e.Source)
	}
	if e.Message != "Out of memory: Kill process 8823 (java)" {
		t.Errorf("message = %q", e.Message)
	}
	if e.AgeMin != 180 {
		t.Errorf("age = %d, want 180", e.AgeMin)
	}

	pidLine := "2026-06-03T11:30:00+00:00 myhost rsyslogd[263]: imklog: cannot open kernel log"
	e2, _ := parseJournalTopError(pidLine, now)
	if e2.Source != "rsyslogd" {
		t.Errorf("source = %q, want rsyslogd (pid stripped)", e2.Source)
	}
	if e2.AgeMin != 30 {
		t.Errorf("age = %d, want 30", e2.AgeMin)
	}

	// Regression for the -1 age bug: the exact live format must yield a real
	// age, not -1 (the old "-0700" layout failed on the colon offset).
	live := "2026-06-03T19:16:09+00:00 ubuntu24-lxc rsyslogd[263]: action suspended"
	liveNow := mustTime(t, "2026-06-03T19:46:09Z")
	el, ok := parseJournalTopError(live, liveNow)
	if !ok {
		t.Fatal("live line should parse")
	}
	if el.AgeMin != 30 {
		t.Errorf("live age = %d, want 30 (not -1)", el.AgeMin)
	}

	// A non-RFC3339 timestamp degrades gracefully to AgeMin = -1 (unknown).
	bad := "not-a-timestamp myhost kernel: something broke here"
	if eb, ok := parseJournalTopError(bad, now); !ok || eb.AgeMin != -1 {
		t.Errorf("bad timestamp: ok=%v age=%d, want ok=true age=-1", ok, eb.AgeMin)
	}

	if _, ok := parseJournalTopError("too short", now); ok {
		t.Error("short line should not parse")
	}
}

func TestParseSyslogTopError(t *testing.T) {
	t.Parallel()
	now := refNow(t)
	// Traditional syslog stamp with no year and a single-digit day (double space).
	line := "Jun  3 10:00:00 myhost nginx[1200]: connect() failed (111: Connection refused)"
	e, ok := parseSyslogTopError(line, now)
	if !ok {
		t.Fatal("expected ok")
	}
	if e.Source != "nginx" {
		t.Errorf("source = %q, want nginx", e.Source)
	}
	if e.AgeMin != 120 {
		t.Errorf("age = %d, want 120", e.AgeMin)
	}
}

// TestParseSyslogTopError_TooFewFields covers the "len(fields) < 6 -> false"
// branch: a syslog-shaped line missing the process/message tokens entirely.
func TestParseSyslogTopError_TooFewFields(t *testing.T) {
	t.Parallel()
	if _, ok := parseSyslogTopError("Jun  3 10:00:00 myhost", refNow(t)); ok {
		t.Error("expected ok=false for a line with fewer than 6 fields")
	}
}

// TestParseSyslogTopError_EmptyMessage covers the "msg == \"\" -> false"
// branch: sourceAndMessage returns an empty message when msgStart lands
// exactly at len(fields) (no message tokens remain).
func TestParseSyslogTopError_EmptyMessage(t *testing.T) {
	t.Parallel()
	// 6 fields total, so msgStart=5 == len(fields) -> sourceAndMessage returns "".
	if _, ok := parseSyslogTopError("Jun  3 10:00:00 myhost nginx[1200]:", refNow(t)); ok {
		t.Error("expected ok=false when no message tokens remain after the source field")
	}
}

// TestSourceAndMessage_MsgStartBeyondFields covers the "msgStart >=
// len(fields) -> (\"\", \"\")" guard directly.
func TestSourceAndMessage_MsgStartBeyondFields(t *testing.T) {
	t.Parallel()
	src, msg := sourceAndMessage([]string{"a", "b"}, 5)
	if src != "" || msg != "" {
		t.Errorf("sourceAndMessage with msgStart beyond len(fields) = (%q, %q), want (\"\", \"\")", src, msg)
	}
}

// TestSourceAndMessage_TruncatesLongMessage covers the topErrorMsgCap
// truncation branch: a message longer than the cap must be cut to exactly
// topErrorMsgCap runes.
func TestSourceAndMessage_TruncatesLongMessage(t *testing.T) {
	t.Parallel()
	longWord := strings.Repeat("x", topErrorMsgCap+50)
	_, msg := sourceAndMessage([]string{"host", "app:", longWord}, 2)
	if len(msg) != topErrorMsgCap {
		t.Errorf("len(msg) = %d, want %d (truncated)", len(msg), topErrorMsgCap)
	}
}

// TestSourceAndMessage_TruncatesLongSource covers the topErrorSourceCap
// truncation branch: a source token longer than the cap (e.g. via
// SYSLOG_IDENTIFIER/systemd-cat, which the caller does not otherwise bound)
// must be cut to exactly topErrorSourceCap runes.
func TestSourceAndMessage_TruncatesLongSource(t *testing.T) {
	t.Parallel()
	longSource := strings.Repeat("y", topErrorSourceCap+50) + ":"
	src, _ := sourceAndMessage([]string{"host", longSource, "msg"}, 2)
	if len(src) != topErrorSourceCap {
		t.Errorf("len(src) = %d, want %d (truncated)", len(src), topErrorSourceCap)
	}
}

// TestAgeMinutes_ClampsNegative covers the "m < 0 -> 0" clamp: a timestamp
// AFTER now (clock skew, or a future-dated log line) must not yield a
// negative age.
func TestAgeMinutes_ClampsNegative(t *testing.T) {
	t.Parallel()
	now := refNow(t)
	future := now.Add(10 * time.Minute)
	if got := ageMinutes(now, future); got != 0 {
		t.Errorf("ageMinutes with a future timestamp = %d, want 0 (clamped)", got)
	}
}

func TestTopErrorEntries_DedupNewestFirst(t *testing.T) {
	t.Parallel()
	// Oldest-first input (as journalctl emits); same message appears twice.
	entries := []models.TopError{
		{Message: "disk error", Source: "kernel", AgeMin: 300},
		{Message: "auth failure", Source: "sshd", AgeMin: 200},
		{Message: "disk error", Source: "kernel", AgeMin: 50}, // newer dup
	}
	out := topErrorEntries(entries, 5)
	if len(out) != 2 {
		t.Fatalf("expected 2 deduped entries, got %d", len(out))
	}
	// Newest-first: the 50-min "disk error" comes first.
	if out[0].Message != "disk error" || out[0].AgeMin != 50 {
		t.Errorf("entry[0] = %+v, want newest disk error (50m)", out[0])
	}
	if out[1].Message != "auth failure" {
		t.Errorf("entry[1] = %+v, want auth failure", out[1])
	}

	// Cap is respected.
	many := make([]models.TopError, 10)
	for i := range many {
		many[i] = models.TopError{Message: string(rune('a' + i)), AgeMin: i}
	}
	if got := topErrorEntries(many, 3); len(got) != 3 {
		t.Errorf("cap not applied: got %d", len(got))
	}
}

func TestScanVarLog_Fallback(t *testing.T) {
	t.Parallel()
	now := refNow(t)
	content := `Jun  3 09:00:00 host systemd[1]: Started normal thing.
Jun  3 10:00:00 host nginx[1200]: error: upstream timed out
Jun  3 10:05:00 host kernel: EXT4-fs error (sdb1): bad block bitmap
Jun  3 10:06:00 host postgres[900]: FATAL: could not open file
Jun  3 11:00:00 host CRON[55]: pam_unix session opened
`
	count, top, crit := scanVarLog(content, now)
	// Matches: nginx "error", kernel "error", postgres "FATAL"? FATAL has no keyword,
	// but line has no err/error/crit/alert/emerg -> not matched. So 2 matches.
	if count != 2 {
		t.Errorf("count = %d, want 2 (nginx error + kernel error)", count)
	}
	if len(top) == 0 {
		t.Error("expected legacy TopErrors populated")
	}
	if len(crit) != 2 {
		t.Fatalf("expected 2 structured entries, got %d", len(crit))
	}
	// Newest-first: kernel EXT4 error (10:05) before nginx (10:00).
	if crit[0].Source != "kernel" {
		t.Errorf("crit[0].Source = %q, want kernel (newest)", crit[0].Source)
	}
}

// TestCollectVarLogErrorsFrom_Fires confirms the /var/log fallback path runs
// when JournalVolatile=true and a log file exists: it must populate the error
// counts AND flip LogSource to the file used (FIX B — confirmable on AlmaLinux).
func TestCollectVarLogErrorsFrom_Fires(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "messages")
	content := "Jun  3 10:00:00 host nginx[1200]: error: upstream timed out\n" +
		"Jun  3 10:05:00 host kernel: EXT4-fs error (sdb1): bad block bitmap\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp log: %v", err)
	}

	info := &models.LogsInfo{JournalVolatile: true, LogSource: "journald"}
	collectVarLogErrorsFrom(info, []string{filepath.Join(dir, "syslog"), path})

	if info.LogSource != "messages" {
		t.Errorf("LogSource = %q, want messages (fallback must mark the source)", info.LogSource)
	}
	if info.ErrorCount != 2 {
		t.Errorf("ErrorCount = %d, want 2", info.ErrorCount)
	}
	if len(info.TopCritical) != 2 {
		t.Errorf("TopCritical = %d entries, want 2", len(info.TopCritical))
	}
}

// TestCollectVarLogErrorsFrom_CleanSystem confirms that on a fresh box (file
// present but no errors) the path still records it ran via LogSource, with
// ErrorCount=0 — matching the AlmaLinux 9 observation.
func TestCollectVarLogErrorsFrom_CleanSystem(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "messages")
	clean := "Jun  3 10:00:00 host systemd[1]: Started routine job.\n"
	if err := os.WriteFile(path, []byte(clean), 0o600); err != nil {
		t.Fatalf("write temp log: %v", err)
	}

	info := &models.LogsInfo{JournalVolatile: true, LogSource: "journald"}
	collectVarLogErrorsFrom(info, []string{path})

	if info.LogSource != "messages" {
		t.Errorf("LogSource = %q, want messages even with 0 errors", info.LogSource)
	}
	if info.ErrorCount != 0 {
		t.Errorf("ErrorCount = %d, want 0 on clean system", info.ErrorCount)
	}
}

// TestCollectVarLogErrorsFrom_NoFile confirms a no-op when no log file exists.
func TestCollectVarLogErrorsFrom_NoFile(t *testing.T) {
	t.Parallel()
	info := &models.LogsInfo{JournalVolatile: true, LogSource: "journald"}
	collectVarLogErrorsFrom(info, []string{filepath.Join(t.TempDir(), "absent")})
	if info.LogSource != "journald" {
		t.Errorf("LogSource = %q, want unchanged journald when no file", info.LogSource)
	}
}

// TestShouldReadVarLogFallback pins when the severity summary falls back to
// /var/log. The "pure syslog" case is the regression guard: on a no-journald host
// the journalctl scan reads nothing, so without the fallback Logs would report
// "0 errors" having consulted no log at all (a false-OK).
func TestShouldReadVarLogFallback(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		info models.LogsInfo
		want bool
	}{
		{"pure syslog, no errors → fall back (the fix)", models.LogsInfo{LogSource: "syslog"}, true},
		{"volatile journald, no errors → fall back", models.LogsInfo{JournalVolatile: true, LogSource: "journald"}, true},
		{"persistent journald, no errors → trust journal", models.LogsInfo{LogSource: "journald"}, false},
		{"journald+syslog, no errors → don't double-read", models.LogsInfo{LogSource: "journald+syslog"}, false},
		{"unknown source, no errors → nothing to read", models.LogsInfo{LogSource: "unknown"}, false},
		{"syslog but errors already found → don't double-count", models.LogsInfo{LogSource: "syslog", ErrorCount: 4}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldReadVarLogFallback(&tc.info); got != tc.want {
				t.Errorf("shouldReadVarLogFallback(%+v) = %v, want %v", tc.info, got, tc.want)
			}
		})
	}
}

func TestScanVarLog_TailCap(t *testing.T) {
	t.Parallel()
	now := refNow(t)
	// Build > varLogTailLines lines, only the last one is an error.
	b := make([]byte, 0, 40*(varLogTailLines+50)+50)
	for range varLogTailLines + 50 {
		b = append(b, []byte("Jun  3 10:00:00 host app[1]: routine ok\n")...)
	}
	b = append(b, []byte("Jun  3 11:59:00 host app[1]: fatal error happened\n")...)
	count, _, _ := scanVarLog(string(b), now)
	if count != 1 {
		t.Errorf("count = %d, want 1 (only tail scanned, 'ok' lines excluded)", count)
	}
}

func TestLineHasSeverity(t *testing.T) {
	t.Parallel()
	hits := []string{
		"nginx: ERROR connecting",
		"kernel CRITical failure",
		"pam alert raised",
		"syslog emerg shutdown",
		"stderr: something", // contains "err"
	}
	misses := []string{
		"systemd: Started service",
		"cron: session opened",
	}
	for _, l := range hits {
		if !lineHasSeverity(l) {
			t.Errorf("%q should match a severity keyword", l)
		}
	}
	for _, l := range misses {
		if lineHasSeverity(l) {
			t.Errorf("%q should NOT match", l)
		}
	}
}

func TestIsVMVirtType(t *testing.T) {
	for _, vm := range []string{"kvm", "qemu", "vmware", "microsoft", "amazon", "xen", "oracle", "bochs"} {
		if !isVMVirtType(vm) {
			t.Errorf("isVMVirtType(%q) = false, want true (VM)", vm)
		}
	}
	for _, notVM := range []string{"none", "", "lxc", "lxc-libvirt", "docker", "podman", "systemd-nspawn", "wsl", "openvz"} {
		if isVMVirtType(notVM) {
			t.Errorf("isVMVirtType(%q) = true, want false (bare metal / container)", notVM)
		}
	}
}

// TestCollect_KmsgParseDoesNotRaceWithLaterWrites is a regression test for the
// abandoned-goroutine race that used to exist in Collect(): kmsg parsing ran in
// a background goroutine that Collect only *waited* on for up to 600ms via
// select+time.After, without ever joining it. If the parse didn't finish in
// time, Collect proceeded anyway and kept writing the same *models.LogsInfo
// (info.KernelPanics += countPstorePanics(), immediately after the kmsg step)
// while the abandoned goroutine could still be writing to it — an
// unsynchronized concurrent read/write on the same field, only reliably caught
// under -race. kmsgParseFn is swapped for a stand-in that mimics parseKmsg's
// signature but deliberately outlasts any reasonable timeout window, so the
// hazard is exercised regardless of exactly how the call is wrapped.
func TestCollect_KmsgParseDoesNotRaceWithLaterWrites(t *testing.T) {
	// No t.Parallel(): swaps the package-global kmsgParseFn seam and source.
	withFixtureSource(t, func(_ *source.Bundle) {})
	prevFn := kmsgParseFn
	t.Cleanup(func() { kmsgParseFn = prevFn })

	started := make(chan struct{})
	kmsgParseFn = func(_ context.Context, info *models.LogsInfo, _ time.Duration) {
		close(started)
		// Deliberately ignores ctx cancellation to model a slow real kmsg parse
		// that outlives any select/timeout window wrapped around it, then
		// mutates the same field Collect writes immediately after this call
		// returns.
		time.Sleep(700 * time.Millisecond)
		info.KernelPanics++
	}

	c := NewLogsCollectorWithLookback(time.Hour)
	_, err := c.Collect(context.Background())

	// Whether or not Collect has already returned, the background parse must
	// have at least begun (so the old abandoned-goroutine shape doesn't instead
	// race on the kmsgParseFn seam itself) and had time to reach its own write
	// before this test — and t.Cleanup's restoration of kmsgParseFn — proceeds,
	// so the race detector actually observes both accesses to info.KernelPanics
	// instead of the process moving on first.
	<-started
	time.Sleep(400 * time.Millisecond)

	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
}

// crashLoopRecent gates the crash-loop insight to genuinely recent failures, so a
// unit given up on days ago (NRestarts is cumulative and never resets) stops being
// reported as a live crash loop. Inputs are formatted with systemd's wall-clock
// layout so they round-trip through the same parser.
func TestCrashLoopRecent(t *testing.T) {
	const layout = "Mon 2006-01-02 15:04:05 MST"
	now := time.Now().UTC()
	fmtTS := func(d time.Duration) string { return now.Add(d).Format(layout) }
	cases := []struct {
		name string
		ts   string
		want bool
	}{
		{"just now", fmtTS(-1 * time.Minute), true},
		{"stale (2h ago)", fmtTS(-2 * time.Hour), false},
		{"6 days ago (the live repro)", fmtTS(-6 * 24 * time.Hour), false},
		{"future ⇒ conservative report", fmtTS(2 * time.Hour), true},
		{"blank ⇒ conservative report", "", true},
		{"unparseable ⇒ conservative report", "not a timestamp", true},
	}
	for _, c := range cases {
		if got := crashLoopRecent(c.ts, crashLoopRecencyWindow, now); got != c.want {
			t.Errorf("%s: crashLoopRecent(%q) = %v, want %v", c.name, c.ts, got, c.want)
		}
	}
}

// TestCrashLoopRecent_HermeticUnderReplay guards the actual bug: now must come
// from the caller (NowViaSource under replay), not time.Now()/time.Since
// inside crashLoopRecent itself — otherwise a capture from days/months ago
// makes every failed unit's timestamp read as ancient relative to the
// replaying machine's real clock, silently hiding a crash loop that was live
// at capture time.
func TestCrashLoopRecent_HermeticUnderReplay(t *testing.T) {
	const layout = "Mon 2006-01-02 15:04:05 MST"
	captureTime := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	inactiveEnter := captureTime.Add(-5 * time.Minute).Format(layout)
	// The real wall clock is far in the future relative to captureTime — if
	// crashLoopRecent used time.Now()/time.Since internally instead of the
	// passed-in now, this would incorrectly read as stale.
	if !crashLoopRecent(inactiveEnter, crashLoopRecencyWindow, captureTime) {
		t.Error("a unit that crashed 5 minutes before capture time must read as recent when replayed against that same capture time, regardless of the real wall clock")
	}
}

// crashFileTooOld gates coredump/pstore-panic records to recent ones — pstore
// persists across reboots until manually cleared, so without the gate a months-old
// panic would CRIT forever and contradict the "last 30 days" crash-dump wording.
func TestCrashFileTooOld(t *testing.T) {
	now := mustTime(t, "2026-06-10T12:00:00Z")
	cases := []struct {
		name  string
		mtime time.Time
		want  bool
	}{
		{"today", now, false},
		{"10 days", now.Add(-10 * 24 * time.Hour), false},
		{"exactly 30 days", now.Add(-30 * 24 * time.Hour), false},
		{"31 days", now.Add(-31 * 24 * time.Hour), true},
		{"6 months", now.Add(-180 * 24 * time.Hour), true},
	}
	for _, c := range cases {
		if got := crashFileTooOld(c.mtime, now); got != c.want {
			t.Errorf("%s: crashFileTooOld = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCrashFileFromEntry is a regression guard: crashFileFromEntry must read the
// REAL on-disk mtime/size via statFile. Before the fix it used readDirEntries'
// fs.DirEntry.Info(), whose source-fake FileInfo always returns a zero ModTime —
// crashFileTooOld would then read every file as ~2000 years old, so CoreDumpCount
// and CrashFiles were permanently 0/empty on every host, every backend.
func TestCrashFileFromEntry(t *testing.T) {
	dir := t.TempDir()
	now := mustTime(t, "2026-06-10T12:00:00Z")

	recentPath := filepath.Join(dir, "core.1234")
	if err := os.WriteFile(recentPath, []byte("crashdata"), 0o644); err != nil {
		t.Fatal(err)
	}
	recentMTime := now.Add(-2 * 24 * time.Hour)
	if err := os.Chtimes(recentPath, recentMTime, recentMTime); err != nil {
		t.Fatal(err)
	}

	stalePath := filepath.Join(dir, "core.old")
	if err := os.WriteFile(stalePath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	staleMTime := now.Add(-90 * 24 * time.Hour)
	if err := os.Chtimes(stalePath, staleMTime, staleMTime); err != nil {
		t.Fatal(err)
	}

	cf, ok := crashFileFromEntry(recentPath, now)
	if !ok {
		t.Fatalf("recent crash file (mtime -2d) must be kept, got ok=false")
	}
	if cf.AgeDays != 2 {
		t.Errorf("AgeDays = %d, want 2", cf.AgeDays)
	}
	if cf.SizeMB <= 0 {
		t.Errorf("SizeMB = %v, want > 0 (real file size, not the always-zero fake FileInfo)", cf.SizeMB)
	}

	if _, ok := crashFileFromEntry(stalePath, now); ok {
		t.Errorf("90-day-old crash file must be dropped as stale, got ok=true")
	}

	if _, ok := crashFileFromEntry(filepath.Join(dir, "does-not-exist"), now); ok {
		t.Errorf("missing file must return ok=false")
	}
}

// TestHasCorruptArchived_ErrorWithoutFAILIsNotCorrupt is a regression guard:
// hasCorruptArchived used to treat ANY journalctl error (EACCES on a non-root
// run, the 5s timeout, journalctl missing) as corruption, because runCmd
// discards stdout/stderr on a non-zero exit — leaving `err != nil` as the only
// signal and making the "FAIL" check dead code. Only the verifier's own FAIL
// marker may report corruption.
func TestHasCorruptArchived_ErrorWithoutFAILIsNotCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "system.journal~"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		exec func(ctx context.Context, name string, args ...string) (source.Result, error)
		want bool
	}{
		{"EACCES (permission denied, no FAIL text)", func(_ context.Context, _ string, _ ...string) (source.Result, error) {
			return source.Result{Stderr: []byte("Permission denied"), ExitCode: 1}, &fakeCmdErr{}
		}, false},
		{"journalctl missing", func(_ context.Context, _ string, _ ...string) (source.Result, error) {
			return source.Result{}, &fakeCmdErr{}
		}, false},
		{"real corruption (FAIL in output)", func(_ context.Context, _ string, _ ...string) (source.Result, error) {
			return source.Result{Stdout: []byte("FAIL: /var/log/journal/x/system.journal~ (Bad message)\n"), ExitCode: 1}, &fakeCmdErr{}
		}, true},
		{"clean verify, exit 0", func(_ context.Context, _ string, _ ...string) (source.Result, error) {
			return source.Result{Stdout: []byte("PASS\n")}, nil
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := SetSource(source.Live{Exec: tc.exec})
			defer SetSource(prev)
			if got := hasCorruptArchived(dir); got != tc.want {
				t.Errorf("hasCorruptArchived() = %v, want %v", got, tc.want)
			}
		})
	}
}

// fakeCmdErr is a minimal non-nil error for injected exec results.
type fakeCmdErr struct{}

func (*fakeCmdErr) Error() string { return "exit status 1" }

// TestHasCorruptArchived_DirUnreadable covers the "readDirEntries errors ->
// false" branch: a directory that doesn't exist must not panic and must
// report no corruption (nothing to verify).
func TestHasCorruptArchived_DirUnreadable(t *testing.T) {
	t.Parallel()
	if got := hasCorruptArchived(filepath.Join(t.TempDir(), "does-not-exist")); got {
		t.Error("expected false for an unreadable/missing journal directory")
	}
}

// TestHasCorruptArchived_NonArchivedSuffixSkipped covers the "!strings.
// HasSuffix(.journal~) -> continue" branch: an active *.journal file (not yet
// archived) must never be handed to journalctl --verify at all.
func TestHasCorruptArchived_NonArchivedSuffixSkipped(t *testing.T) {
	// No t.Parallel(): this swaps the package-global source via SetSource, which
	// must not race a concurrent test reading it (see the swapRunCmd doc comment).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "system.journal"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := SetSource(source.Live{Exec: func(context.Context, string, ...string) (source.Result, error) {
		t.Fatal("journalctl --verify must not run against a non-archived (*.journal) file")
		return source.Result{}, nil
	}})
	defer SetSource(prev)
	if got := hasCorruptArchived(dir); got {
		t.Error("expected false when only an active *.journal file is present")
	}
}

// TestHasCorruptArchived_RecursesIntoSubdirs covers the "e.IsDir() ->
// recurse" branch: journald shards archives under one subdirectory per
// machine-ID, so a corrupt archive nested one level down must still surface.
func TestHasCorruptArchived_RecursesIntoSubdirs(t *testing.T) {
	// No t.Parallel(): this swaps the package-global source via SetSource, which
	// must not race a concurrent test reading it (see the swapRunCmd doc comment).
	dir := t.TempDir()
	sub := filepath.Join(dir, "abc123-machine-id")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "system.journal~"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := SetSource(source.Live{Exec: func(context.Context, string, ...string) (source.Result, error) {
		return source.Result{Stdout: []byte("FAIL: bad message\n"), ExitCode: 1}, &fakeCmdErr{}
	}})
	defer SetSource(prev)
	if got := hasCorruptArchived(dir); !got {
		t.Error("expected true: a corrupt archive nested under a machine-ID subdir must be found by recursion")
	}
}

// TestCollectCrashFiles_SkipsDirectoryEntries covers logs_linux.go:1006.17,1007.13 —
// a subdirectory inside a crash dump dir must be skipped, not treated as a crash file.
func TestCollectCrashFiles_SkipsDirectoryEntries(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/var/crash", []string{"subdir"})
		// seeding /var/crash/subdir as a readable dir causes probeIsDir to return true
		b.PutDir("/var/crash/subdir", []string{})
		// /var/lib/systemd/coredump not seeded → readDirEntries errors → continue (already covered)
	})
	info := &models.LogsInfo{}
	collectCrashFiles(info)
	if info.CoreDumpCount != 0 || len(info.CrashFiles) != 0 {
		t.Errorf("CoreDumpCount=%d CrashFiles=%v, want both zero (directory entries skipped)",
			info.CoreDumpCount, info.CrashFiles)
	}
}

// TestHasCorruptArchived_NonCorruptSubdirContinues covers logs_linux.go:534.4,534.12 —
// the `continue` after recursing into a subdirectory that contains no corrupt
// archives. The prior gapfill covered the "corrupt → return true" recursion path;
// this covers the "clean subdir → continue" path.
func TestHasCorruptArchived_NonCorruptSubdirContinues(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sub := filepath.Join(dir, "abc123-machine-id")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// sub has only an active *.journal file — no *.journal~ archives to verify.
	// hasCorruptArchived(sub) returns false → outer loop hits `continue` at line 534.
	if err := os.WriteFile(filepath.Join(sub, "active.journal"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := hasCorruptArchived(dir); got {
		t.Error("expected false: a clean (archive-free) subdirectory must not flag corruption")
	}
}

// TestCollectVarLogErrorsFrom_ReadFileError covers logs_linux.go:1111.16,1113.3 —
// the early return when readFile fails after statFile succeeds. The stat is seeded
// so path selection picks the candidate, but no file content is seeded so the
// replay source returns ErrNotRecorded and the function returns before writing info.
func TestCollectVarLogErrorsFrom_ReadFileError(t *testing.T) {
	// No t.Parallel(): withFixtureSource swaps the package-global source.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/log/syslog", source.FileMeta{Size: 100})
		// readFile for /var/log/syslog not seeded → replay returns ErrNotRecorded
	})
	info := &models.LogsInfo{}
	collectVarLogErrorsFrom(info, []string{"/var/log/syslog"})
	if info.LogSource != "" {
		t.Errorf("LogSource = %q, want empty: readFile error must cause early return", info.LogSource)
	}
}
