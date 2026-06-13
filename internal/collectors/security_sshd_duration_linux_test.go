//go:build linux

package collectors

import "testing"

// TestParseSSHDurationRealSSHD pins parseSSHDuration against the AUTHORITATIVE
// normalization done by real `sshd -T` (debian:12 openssh-server): each input is
// the duration as written in sshd_config, want is the seconds sshd -T emits.
// Earlier this dropped the 'd' (day) and 'w' (week) units OpenSSH's time format
// supports — e.g. "1d12h" parsed as "112h" (403200s) instead of 129600s.
// Regenerate: printf 'LoginGraceTime %s\n' "$d" >c; sshd -T -f c | awk '/logingracetime/{print $2}'
func TestParseSSHDurationRealSSHD(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"30", 30},
		{"30s", 30},
		{"2m", 120},
		{"1h", 3600},
		{"1d", 86400},
		{"1w", 604800},
		{"1h30m", 5400},
		{"1d12h", 129600},
		{"90m", 5400},
		{"1w2d", 777600},
		{"0", 0},
		{"none", 0},
	}
	for _, c := range cases {
		if got := parseSSHDuration(c.in); got != c.want {
			t.Errorf("parseSSHDuration(%q) = %d, want %d (sshd -T)", c.in, got, c.want)
		}
	}
}
