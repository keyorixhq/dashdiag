//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseCrontabFileQuality pins the cron-quality scan against two false
// positives found on a real host: run-parts SCRIPTS in /etc/cron.daily/ etc. were
// mis-parsed as crontabs ("relative path" WARN), and Debian's empty
// /etc/cron.d/.placeholder got a "no MAILTO" WARN despite having no jobs.
func TestParseCrontabFileQuality(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// 1. A run-parts script (path under cron.daily) — shell content, NOT a crontab.
	//    Previously its `if [ -d … ] && [ -e … ]; then` line false-flagged a
	//    relative path. Must now be skipped entirely.
	script := write("etc/cron.daily/logrotate",
		"#!/bin/sh\n\ntest -x /usr/sbin/logrotate || exit 0\nif [ -d /var/lib/logrotate ] && [ -e /etc/logrotate.conf ]; then\n  /usr/sbin/logrotate /etc/logrotate.conf\nfi\n")
	if got := parseCrontabFile(script, script); got != nil {
		t.Errorf("run-parts script must yield no quality issues, got %+v", got)
	}

	// 2. Empty placeholder in /etc/cron.d — no jobs → no MAILTO false flag.
	ph := write("etc/cron.d/.placeholder", "# Debian places this here so the dir ships in the package\n")
	if got := parseCrontabFile(ph, ph); got != nil {
		t.Errorf("empty placeholder must yield no issues, got %+v", got)
	}

	// 3. A real /etc/cron.d job with no MAILTO and a relative command → both flags.
	real := write("etc/cron.d/myjob", "30 3 * * 0 root foo --run\n")
	got := parseCrontabFile(real, real)
	if got == nil || len(got) != 1 {
		t.Fatalf("real cron.d job = %+v, want one CronJob with issues", got)
	}
	joined := strings.Join(got[0].Issues, " | ")
	if !strings.Contains(joined, "MAILTO") || !strings.Contains(joined, "relative path") {
		t.Errorf("real job should flag MAILTO + relative path, got %q", joined)
	}

	// 4. A well-formed cron.d job (PATH + MAILTO + an absolute cmd that exists) → clean.
	clean := write("etc/cron.d/clean", "MAILTO=root\nPATH=/usr/bin:/bin\n0 2 * * * root /bin/sh -c true\n")
	if got := parseCrontabFile(clean, clean); got != nil {
		t.Errorf("well-formed cron.d job must be clean, got %+v", got)
	}
}

// TestAnyProcessNamedIn verifies the portable /proc/<pid>/comm scan that replaced
// `pgrep -x` (which busybox matches against argv[0] incl. path, missing a running
// /usr/sbin/crond on Alpine). Uses a fake /proc tree so it's host-independent.
func TestAnyProcessNamedIn(t *testing.T) {
	proc := t.TempDir()
	// pid 320: a busybox crond symlinked under /usr/sbin — comm is still "crond".
	writeComm(t, proc, "320", "crond")
	// pid 1: init; pid 7: a non-pid dir + a process named cron should not confuse.
	writeComm(t, proc, "1", "init")
	// a non-numeric entry (e.g. /proc/self) must be ignored.
	if err := os.MkdirAll(filepath.Join(proc, "self"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !anyProcessNamedIn(proc, "crond", "cron", "fcron") {
		t.Error("should find crond by comm (the busybox/Alpine regression)")
	}
	if !anyProcessNamedIn(proc, "init") {
		t.Error("should match an exact comm")
	}
	if anyProcessNamedIn(proc, "auditd", "sshd") {
		t.Error("must not match a process that isn't running")
	}
	// Exact match only — "cron" must not match a process whose comm is "crond".
	if anyProcessNamedIn(filtered(t, proc, "320"), "cron") {
		t.Error("comm match must be exact: 'cron' should not match comm 'crond'")
	}
}

func writeComm(t *testing.T, proc, pid, comm string) {
	t.Helper()
	dir := filepath.Join(proc, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// filtered returns a fresh /proc tree containing only the given pid (to isolate the
// exact-match assertion).
func filtered(t *testing.T, _ string, pid string) string {
	t.Helper()
	p := t.TempDir()
	writeComm(t, p, pid, "crond")
	return p
}

// TestDetectCronDaemonName covers the systemd-independent fallback: a cron daemon
// running on a non-systemd host (where systemctl is-active fails) must still be
// detected via the process check, instead of falsely reporting "no cron daemon".
func TestDetectCronDaemonName(t *testing.T) {
	never := func(string) bool { return false }
	only := func(want string) func(string) bool {
		return func(d string) bool { return d == want }
	}

	cases := []struct {
		name       string
		systemctl  func(string) bool
		process    func(string) bool
		wantName   string
		wantActive bool
	}{
		{"systemd host, crond active", only("crond"), never, "crond", true},
		{"systemd host, cron active", only("cron"), never, "cron", true},
		// The fix: non-systemd host (systemctl finds nothing) but the daemon is
		// running — detected via pgrep.
		{"non-systemd, busybox crond running", never, only("crond"), "crond", true},
		{"non-systemd, fcron running", never, only("fcron"), "fcron", true},
		// Genuinely no cron: neither signal fires.
		{"no cron anywhere", never, never, "", false},
		// systemctl wins when both agree (and is checked first).
		{"both signals", only("cron"), only("cron"), "cron", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, active := detectCronDaemonName(tc.systemctl, tc.process)
			if name != tc.wantName || active != tc.wantActive {
				t.Errorf("detectCronDaemonName = (%q, %v), want (%q, %v)", name, active, tc.wantName, tc.wantActive)
			}
		})
	}
}

// TestTruncateCron covers the boundary directly: exactly-at-limit must NOT
// truncate (the log/insight-message truncation for a long cron line/command,
// used at 120 chars in checkCronQuality — off-by-one here would either cut a
// message one char early or silently allow one char past the cap).
func TestTruncateCron(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"under limit — unchanged", "short", 120, "short"},
		{"exactly at limit — unchanged, no ellipsis", "12345", 5, "12345"},
		{"one over limit — truncated with ellipsis", "123456", 5, "12345…"},
		{"empty string — unchanged", "", 10, ""},
		{"n=0 on non-empty string — truncates to empty plus ellipsis", "abc", 0, "…"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := truncateCron(c.s, c.n); got != c.want {
				t.Errorf("truncateCron(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
			}
		})
	}
}
