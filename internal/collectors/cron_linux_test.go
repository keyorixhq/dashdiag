//go:build linux

package collectors

import "testing"

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
