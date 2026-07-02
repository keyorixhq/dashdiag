//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeMountinfoSource serves a fixed /proc/self/mountinfo body and falls back
// to Live for everything else.
type fakeMountinfoSource struct {
	source.Live
	mountinfo string
}

func (f fakeMountinfoSource) ReadFile(path string) ([]byte, error) {
	if path == "/proc/self/mountinfo" {
		return []byte(f.mountinfo), nil
	}
	return f.Live.ReadFile(path)
}

// TestFindMountPoint_LongestPrefixMatch is a regression guard for the switch
// from raw syscall.Stat device-number walking to /proc/self/mountinfo parsing:
// findMountPoint used to read the LIVE machine's device numbers directly, so
// under `dsd replay` it reported the replaying host's mount point, not the
// captured one. The new implementation must still resolve the deepest
// (longest-prefix) matching mount for a path.
func TestFindMountPoint_LongestPrefixMatch(t *testing.T) {
	const mountinfo = `25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
26 25 8:2 / /var rw,relatime shared:2 - ext4 /dev/sda2 rw
27 26 8:3 / /var/log rw,relatime shared:3 - ext4 /dev/sda3 rw
`
	prev := SetSource(fakeMountinfoSource{mountinfo: mountinfo})
	defer SetSource(prev)

	cases := []struct {
		path string
		want string
	}{
		{"/var/log/journal", "/var/log"}, // deepest match wins over /var and /
		{"/var/tmp", "/var"},             // /var/log is a sibling, not an ancestor
		{"/etc", "/"},                    // falls back to root
		{"/var/log", "/var/log"},         // exact match on the mount point itself
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := findMountPoint(tc.path); got != tc.want {
				t.Errorf("findMountPoint(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestFindMountPoint_UnreadableMountinfo confirms the honest fallback: if
// /proc/self/mountinfo can't be read, return path unchanged rather than panic
// or guess.
func TestFindMountPoint_UnreadableMountinfo(t *testing.T) {
	prev := SetSource(erroringReadFileSource{})
	defer SetSource(prev)
	if got := findMountPoint("/var/log"); got != "/var/log" {
		t.Errorf("got %q, want the original path unchanged on read failure", got)
	}
}

type erroringReadFileSource struct{ source.Live }

func (erroringReadFileSource) ReadFile(_ string) ([]byte, error) {
	return nil, &fakeCmdErr{}
}
