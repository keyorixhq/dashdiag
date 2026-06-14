//go:build linux

package collectors

import (
	"strings"
	"testing"
)

// TestIsSharedLibDeleted documents finding [29]: a deleted shared library's
// readlink target is "<path> (deleted)", so the classifier must strip that
// suffix and match on the base name — otherwise an unversioned ".so (deleted)"
// falls through to the generic file case and the restart-after-update warning
// is silently dropped.
func TestIsSharedLibDeleted(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", true},
		{"/usr/lib/libfoo.so", true},
		{"/usr/lib/libfoo.so.6 (deleted)", true},       // versioned, deleted
		{"/opt/app/plugin.so (deleted)", true},         // unversioned, deleted — the bug
		{"/usr/lib/libfoo.so (deleted)", true},         // unversioned, deleted
		{"/var/run/somesocket", false},                 // not a lib
		{"/home/user/notes.txt", false},                // not a lib
		{"/srv/.so-data/config.yaml (deleted)", false}, // dir contains ".so", base does not
	}
	for _, c := range cases {
		clean := strings.TrimSuffix(c.target, " (deleted)")
		if got := isSharedLib(clean); got != c.want {
			t.Errorf("isSharedLib(strip(%q)) = %v, want %v", c.target, got, c.want)
		}
	}
}
