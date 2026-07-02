package collectors

import (
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeLoadavgSource serves a fixed /proc/loadavg body and falls back to Live
// for everything else.
type fakeLoadavgSource struct {
	source.Live
	content string
}

func (f fakeLoadavgSource) ReadFile(path string) ([]byte, error) {
	if path == "/proc/loadavg" {
		return []byte(f.content), nil
	}
	return f.Live.ReadFile(path)
}

// TestReadTaskCount is a regression guard: kernel.pid_max governs the WHOLE
// task space (processes AND threads — every CLONE_THREAD thread gets its own
// slot under /proc/<pid>/task/<tid>), but countProcDirs() only counts
// top-level processes via /proc/[0-9]*. On a thread-heavy host (JVM/Go clone
// storm), that undercounts real PID-space usage, so genuine task exhaustion
// could read as a small, unconcerning percentage. readTaskCount must use
// /proc/loadavg's "running/total" field instead.
func TestReadTaskCount(t *testing.T) {
	t.Run("well-formed loadavg", func(t *testing.T) {
		prev := SetSource(fakeLoadavgSource{content: "0.52 0.43 0.32 3/412 8932\n"})
		defer SetSource(prev)
		if got := readTaskCount(); got != 412 {
			t.Errorf("got %d, want 412 (the total tasks field, not the process count)", got)
		}
	})

	t.Run("malformed loadavg falls back to process count", func(t *testing.T) {
		prev := SetSource(fakeLoadavgSource{content: "not loadavg data"})
		defer SetSource(prev)
		// Falls back to countProcDirs(); just confirm it doesn't panic and
		// returns a non-negative count (0 is valid on a host with no /proc glob
		// match, e.g. this test running on darwin).
		if got := readTaskCount(); got < 0 {
			t.Errorf("got %d, want >= 0", got)
		}
	})

	t.Run("unreadable loadavg falls back to process count", func(t *testing.T) {
		prev := SetSource(erroringLoadavgSource{})
		defer SetSource(prev)
		if got := readTaskCount(); got < 0 {
			t.Errorf("got %d, want >= 0", got)
		}
	})
}

type erroringLoadavgSource struct{ source.Live }

func (erroringLoadavgSource) ReadFile(string) ([]byte, error) {
	return nil, os.ErrPermission
}

func TestReadIntFile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		content string
		want    int
		wantErr bool
	}{
		{"integer value", "128\n", 128, false},
		{"integer no newline", "4096", 4096, false},
		{"zero", "0\n", 0, false},
		{"large value", "1048576\n", 1048576, false},
		{"empty file", "", 0, true},
		{"non-numeric", "abc\n", 0, true},
		{"float value", "1.5\n", 0, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, err := os.CreateTemp(t.TempDir(), "sysctl-*")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(tc.content); err != nil {
				t.Fatal(err)
			}
			f.Close()

			got, err := readIntFile(f.Name())
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}
