//go:build linux

package collectors

import "testing"

// Batch 3 of the parser-fuzzing pass: duration/time and date→age parsers whose
// output feeds a threshold verdict. A duration/age must never come back NEGATIVE
// from integer overflow on the unit multiply (n*60 / n*3600 / ...), which would
// flip a `value <= N` / `value > N` threshold check.

// FuzzParseSystemdTime: "5min" → 300. Feeds journald SyncIntervalSec etc.
func FuzzParseSystemdTime(f *testing.F) {
	for _, s := range []string{"5min", "30s", "2h", "1m", "0", "", "200000000000000000min"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got := parseSystemdTime(s); got < 0 {
			t.Fatalf("parseSystemdTime(%q) = %d (negative — integer overflow on the unit multiply)", s, got)
		}
	})
}

// FuzzParseSSHDuration: "5m30s" → 330. Feeds SSH LoginGraceTime / ClientAlive
// thresholds; a negative from overflow would read as "well under the limit".
func FuzzParseSSHDuration(f *testing.F) {
	for _, s := range []string{"60", "5m", "2h30m", "none", "0", "", "200000000000000000w"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got := parseSSHDuration(s); got < 0 {
			t.Fatalf("parseSSHDuration(%q) = %d (negative — integer overflow on the unit multiply)", s, got)
		}
	})
}
