//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

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
