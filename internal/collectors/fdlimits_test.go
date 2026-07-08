package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestCollectLinux_ScanIsHermetic guards that the per-process FD scan replays from
// the captured bundle, not a live re-scan. The scan is ctx-budget-bounded and walks
// a live /proc, so under load two passes surface a different subset — a replay
// hermeticity regression (the FDLimits hot-process table flickered between two
// replays of one bundle on a busy CI runner). The fix routes the DERIVED scan
// result through Source.Cached. We prove it: seed a known scan during capture, then
// replay with a CANCELLED ctx — a live ctx-bounded scan would bail to empty, but the
// cached scan ignores ctx and returns the recorded value.
func TestCollectLinux_ScanIsHermetic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "file-nr")
	if err := os.WriteFile(p, []byte("100\t0\t1000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &FDLimitsCollector{fileNrPath: p}

	// Capture pass: record the file-nr read, then seed the cached scan key with a
	// known non-empty result (so the replay assertion is meaningful on any host).
	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	if _, err := c.collectLinux(context.Background()); err != nil {
		SetSource(prev)
		t.Fatalf("capture collectLinux: %v", err)
	}
	want := fdProcScan{
		Hot:               []models.FDProcessInfo{{PID: 4242, Name: "leaky", OpenFDs: 900, SoftLimit: 1000, UsedPct: 90}},
		DeletedOpenFiles:  3,
		DeletedOpenSizeGB: 1.5,
	}
	var discard fdProcScan
	if err := cachedJSON("fdlimits/proc-scan", func() (any, error) { return want, nil }, &discard); err != nil {
		SetSource(prev)
		t.Fatalf("seeding cached scan: %v", err)
	}
	SetSource(prev)

	// Replay pass with a cancelled ctx: cached scan must come back verbatim.
	rp := source.NewReplay(rec.Bundle())
	restore := SetSource(rp)
	defer SetSource(restore)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	info, err := c.collectLinux(ctx)
	if err != nil {
		t.Fatalf("replay collectLinux: %v", err)
	}
	if len(info.HotProcesses) != 1 || info.HotProcesses[0].PID != 4242 {
		t.Fatalf("replay did not return the recorded scan (live ctx-bounded scan leaked?): %+v", info.HotProcesses)
	}
	if info.DeletedOpenFiles != 3 || info.DeletedOpenSizeGB != 1.5 {
		t.Fatalf("deleted-file totals not from the cached scan: files=%d sizeGB=%v", info.DeletedOpenFiles, info.DeletedOpenSizeGB)
	}
	// System-wide usage still comes from the (recorded) file-nr read.
	if info.OpenCount != 100 || info.MaxCount != 1000 {
		t.Errorf("system-wide FD usage lost: open=%d max=%d, want 100/1000", info.OpenCount, info.MaxCount)
	}
}

// On a big/busy host the per-process FD scan can exceed the 1s budget. The fix
// makes collectLinux deadline-aware so it returns the already-computed
// system-wide FD usage (the primary signal) instead of letting the runner
// abandon the whole result. A cancelled context simulates the blown budget:
// the system-wide counts must survive, and the best-effort per-process scan is
// skipped.
func TestCollectLinux_DeadlineKeepsSystemWideInfo(t *testing.T) {
	p := filepath.Join(t.TempDir(), "file-nr")
	if err := os.WriteFile(p, []byte("100\t0\t1000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &FDLimitsCollector{fileNrPath: p}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // budget already blown — per-process loop must bail immediately

	info, err := c.collectLinux(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.OpenCount != 100 || info.MaxCount != 1000 {
		t.Errorf("system-wide FD usage lost under deadline: open=%d max=%d, want 100/1000",
			info.OpenCount, info.MaxCount)
	}
	if len(info.HotProcesses) != 0 || info.DeletedOpenFiles != 0 {
		t.Errorf("cancelled ctx should skip the per-process scan, got hot=%d deleted=%d",
			len(info.HotProcesses), info.DeletedOpenFiles)
	}
}

func TestParseFileNr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    string
		wantOpen uint64
		wantMax  uint64
		wantErr  bool
	}{
		{
			name:     "healthy",
			input:    "4821\t0\t1048576\n",
			wantOpen: 4821,
			wantMax:  1048576,
		},
		{
			name:     "space separated",
			input:    "4821  0  1048576\n",
			wantOpen: 4821,
			wantMax:  1048576,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "too few fields",
			input:   "4821 0\n",
			wantErr: true,
		},
		{
			name:    "non-numeric open",
			input:   "abc 0 1048576\n",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			open, max, err := parseFileNr(strings.NewReader(tc.input))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if open != tc.wantOpen {
				t.Errorf("open: got %d, want %d", open, tc.wantOpen)
			}
			if max != tc.wantMax {
				t.Errorf("max: got %d, want %d", max, tc.wantMax)
			}
		})
	}
}

func TestParseFileNr_Fixture(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/fdlimits/file_nr.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()
	open, max, err := parseFileNr(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if open != 4821 {
		t.Errorf("open: got %d, want 4821", open)
	}
	if max != 1048576 {
		t.Errorf("max: got %d, want 1048576", max)
	}
}

func TestParseSoftLimit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			name: "standard limits file",
			input: "Limit                     Soft Limit           Hard Limit           Units\n" +
				"Max open files            1024                 4096                 files\n",
			want: 1024,
		},
		{
			name: "unlimited soft limit",
			input: "Limit                     Soft Limit           Hard Limit           Units\n" +
				"Max open files            unlimited            unlimited            files\n",
			want: 2147483647,
		},
		{
			name:  "no Max open files line",
			input: "Limit                     Soft Limit           Hard Limit           Units\n",
			want:  -1,
		},
		{
			name:  "empty",
			input: "",
			want:  -1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseSoftLimit(strings.NewReader(tc.input))
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseSoftLimit_Fixture(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/fdlimits/limits.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()
	got := parseSoftLimit(f)
	if got != 1024 {
		t.Errorf("got %d, want 1024", got)
	}
}

func FuzzParseFileNr(f *testing.F) {
	f.Add("4821\t0\t1048576\n")
	f.Add("")
	f.Add("abc 0 1048576\n")
	f.Add("4821\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseFileNr(strings.NewReader(s)) //nolint:errcheck
	})
}
