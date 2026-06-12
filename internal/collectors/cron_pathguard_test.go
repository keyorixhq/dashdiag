//go:build linux

package collectors

import "testing"

// TestIsStattableBinaryPath guards the cron G703 fix: only absolute, clean
// paths reach os.Stat; relative or traversing paths from crontab content are
// declined.
func TestIsStattableBinaryPath(t *testing.T) {
	stattable := []string{"/usr/bin/foo", "/bin/sh", "/opt/app/run"}
	for _, p := range stattable {
		if !isStattableBinaryPath(p) {
			t.Errorf("isStattableBinaryPath(%q) = false, want true", p)
		}
	}
	rejected := []string{
		"foo",                // relative
		"./foo",              // relative
		"/usr/../etc/passwd", // traversal
		"/a/../../b",         // traversal
		"/foo//bar",          // unclean
		"",                   // empty
		"../x",               // relative traversal
	}
	for _, p := range rejected {
		if isStattableBinaryPath(p) {
			t.Errorf("isStattableBinaryPath(%q) = true, want false", p)
		}
	}
}
