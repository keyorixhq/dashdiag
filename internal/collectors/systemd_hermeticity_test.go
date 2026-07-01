package collectors

import (
	"io/fs"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeStatSource lets a test control which paths "exist" from the active source's point
// of view, independent of the machine running the test. Only Stat is exercised by the
// systemd presence gate (via fileExists).
type fakeStatSource struct {
	source.Source
	present map[string]bool
}

func (f fakeStatSource) Stat(path string) (source.FileMeta, error) {
	if f.present[path] {
		return source.FileMeta{}, nil
	}
	return source.FileMeta{}, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
}

// TestSystemdPresentViaSourceIsHermetic guards the fix for the false-OK the migrate-certify
// live test surfaced: the Systemd presence gate must read the ACTIVE SOURCE (recorded on
// capture, replayed faithfully), not the live host. A live os.Stat probes the replaying
// machine, so replaying a systemd guest's bundle on a non-systemd host dropped the whole
// Systemd check — and any failed units with it — a false-PASS in dsd replay/diff/migrate.
func TestSystemdPresentViaSourceIsHermetic(t *testing.T) {
	cases := []struct {
		name    string
		present map[string]bool
		want    bool
	}{
		{"recorded systemd-present replays true", map[string]bool{"/run/systemd/private": true}, true},
		{"system dir fallback counts as present", map[string]bool{"/run/systemd/system": true}, true},
		{"recorded non-systemd replays false", map[string]bool{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := SetSource(fakeStatSource{present: c.present})
			defer SetSource(prev)
			if got := systemdPresentViaSource(); got != c.want {
				t.Errorf("systemdPresentViaSource() = %v, want %v — the gate must reflect the "+
					"captured source, not the live host", got, c.want)
			}
		})
	}
}
