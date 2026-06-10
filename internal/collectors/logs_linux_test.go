//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
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

func TestScanVarLog_TailCap(t *testing.T) {
	t.Parallel()
	now := refNow(t)
	// Build > varLogTailLines lines, only the last one is an error.
	var b []byte
	for i := 0; i < varLogTailLines+50; i++ {
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

// crashLoopRecent gates the crash-loop insight to genuinely recent failures, so a
// unit given up on days ago (NRestarts is cumulative and never resets) stops being
// reported as a live crash loop. Inputs are formatted with systemd's wall-clock
// layout so they round-trip through the same parser.
func TestCrashLoopRecent(t *testing.T) {
	const layout = "Mon 2006-01-02 15:04:05 MST"
	fmtTS := func(d time.Duration) string { return time.Now().UTC().Add(d).Format(layout) }
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
		if got := crashLoopRecent(c.ts, crashLoopRecencyWindow); got != c.want {
			t.Errorf("%s: crashLoopRecent(%q) = %v, want %v", c.name, c.ts, got, c.want)
		}
	}
}
