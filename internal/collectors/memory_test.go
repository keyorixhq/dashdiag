package collectors

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// TestNewMemoryCollector_Identity pins the constructor and identity methods
// (Name/Timeout) — these touch no fixture source, so t.Parallel() is safe.
func TestNewMemoryCollector_Identity(t *testing.T) {
	t.Parallel()
	ctx := platform.ContainerContext{}
	c := NewMemoryCollector(ctx)
	if c == nil {
		t.Fatal("NewMemoryCollector returned nil")
	}
	if got, want := c.meminfoPath, "/proc/meminfo"; got != want {
		t.Errorf("meminfoPath = %q, want %q", got, want)
	}
	if got, want := c.Name(), "Memory"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	if got, want := c.Timeout(), 200*time.Millisecond; got != want {
		t.Errorf("Timeout() = %v, want %v", got, want)
	}
}

func TestParseMeminfo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    string
		wantKeys map[string]uint64
	}{
		{
			name: "typical linux meminfo",
			input: `MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    8192000 kB
Slab:             512000 kB
CommitLimit:    32768000 kB
Committed_AS:   10240000 kB
`,
			wantKeys: map[string]uint64{
				"MemTotal":     16384000,
				"MemFree":      2048000,
				"MemAvailable": 8192000,
				"Slab":         512000,
				"CommitLimit":  32768000,
				"Committed_AS": 10240000,
			},
		},
		{
			name:     "empty input",
			input:    "",
			wantKeys: map[string]uint64{},
		},
		{
			name:     "lines without colon are skipped",
			input:    "no colon here\nMemTotal: 1024 kB\n",
			wantKeys: map[string]uint64{"MemTotal": 1024},
		},
		{
			name:     "non-numeric values are skipped",
			input:    "BadKey: notanumber kB\nMemFree: 4096 kB\n",
			wantKeys: map[string]uint64{"MemFree": 4096},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := parseMeminfo(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for k, want := range tc.wantKeys {
				got, ok := result[k]
				if !ok {
					t.Errorf("key %q missing from result", k)
					continue
				}
				if got != want {
					t.Errorf("key %q: got %v, want %v", k, got, want)
				}
			}
		})
	}
}

func FuzzParseMeminfo(f *testing.F) {
	f.Add("MemTotal: 16384000 kB\nSlab: 512000 kB\n")
	f.Add("")
	f.Add("no colon here\n")
	f.Add("BadKey: notanumber kB\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseMeminfo(strings.NewReader(s)) //nolint:errcheck
	})
}

func TestMemoryCollector_Collect_TempFile(t *testing.T) {
	t.Parallel()

	content := `MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    8192000 kB
Slab:             512000 kB
CommitLimit:    32768000 kB
Committed_AS:   10240000 kB
`
	f, err := os.CreateTemp(t.TempDir(), "meminfo-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c := &MemoryCollector{
		meminfoPath:  f.Name(),
		ContainerCtx: platform.ContainerContext{},
	}

	out, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil result")
	}

	// Total/Free/UsedPct must be computed from the injected /proc/meminfo (read
	// through the active source), NOT from gopsutil reading the live host — that
	// bypass made `dsd replay` show the replaying machine's memory instead of the
	// bundle's (ADR-0003 replay fidelity). If someone reintroduces gopsutil for
	// these fields, the live host's real RAM lands here and these exact values
	// fail. kB→GB is /1024/1024; UsedPct = (Total-Available)/Total*100.
	result, ok := out.(*models.MemoryInfo)
	if !ok {
		t.Fatalf("expected *models.MemoryInfo, got %T", out)
	}
	const eps = 1e-9
	if want := 16384000.0 / (1024 * 1024); abs(result.TotalGB-want) > eps {
		t.Errorf("TotalGB: got %v, want %v (from injected meminfo, not gopsutil)", result.TotalGB, want)
	}
	if want := 8192000.0 / (1024 * 1024); abs(result.FreeGB-want) > eps {
		t.Errorf("FreeGB: got %v, want %v (from injected meminfo, not gopsutil)", result.FreeGB, want)
	}
	if want := 50.0; abs(result.UsedPct-want) > eps {
		t.Errorf("UsedPct: got %v, want %v (from injected meminfo, not gopsutil)", result.UsedPct, want)
	}
}

// TestMemoryCollector_Collect_TruncatedMeminfo guards against a false-CRIT:
// a /proc/meminfo read that parses MemTotal fine but is truncated before
// later keys (MemAvailable, Buffers, Cached, ...) — here forced via a single
// line exceeding bufio.Scanner's max token size, which makes scanner.Err()
// non-nil while the map already holds MemTotal from before the failure. If
// that scan error is discarded, the "MemTotal > 0" branch treats the
// partial map as complete: MemAvailable is absent, and the pre-3.14
// fallback (MemFree+Buffers+Cached+SReclaimable) sums to 0 from the
// unparsed keys, computing a false 100% UsedPct instead of reporting
// unmeasured.
func TestMemoryCollector_Collect_TruncatedMeminfo(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		// Non-Linux falls through to a genuine gopsutil live read regardless of
		// meminfoPath — the MeminfoUnreadable sentinel only applies on Linux.
		t.Skip("MeminfoUnreadable sentinel only applies on Linux")
	}

	content := "MemTotal:  8192000 kB\n" + strings.Repeat("x", 100000)
	f, err := os.CreateTemp(t.TempDir(), "meminfo-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c := &MemoryCollector{meminfoPath: f.Name(), ContainerCtx: platform.ContainerContext{}}
	out, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	result := out.(*models.MemoryInfo) //nolint:errcheck
	if !result.MeminfoUnreadable {
		t.Errorf("expected MeminfoUnreadable=true for a truncated read, got false (UsedPct=%v)", result.UsedPct)
	}
	if result.UsedPct == 100 {
		t.Error("truncated read must not report a false 100% UsedPct")
	}
}

// TestMemoryCollector_Collect_NoMemAvailable covers memory.go:75-79 — the
// pre-3.14 kernel fallback when MemAvailable is absent from /proc/meminfo.
// avail is approximated as MemFree + Buffers + Cached + SReclaimable.
func TestMemoryCollector_Collect_NoMemAvailable(t *testing.T) {
	t.Parallel()

	content := "MemTotal:  8192000 kB\nMemFree:   2048000 kB\nBuffers:    512000 kB\nCached:    1024000 kB\n"
	f, err := os.CreateTemp(t.TempDir(), "meminfo-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c := &MemoryCollector{meminfoPath: f.Name(), ContainerCtx: platform.ContainerContext{}}
	out, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	result := out.(*models.MemoryInfo) //nolint:errcheck
	// avail = MemFree + Buffers + Cached + SReclaimable = 2048000+512000+1024000+0 = 3584000 kB
	const eps = 0.01
	wantFree := 3584000.0 / (1024 * 1024)
	if abs(result.FreeGB-wantFree) > eps {
		t.Errorf("FreeGB = %v, want %v (MemAvailable-absent path: approximated from MemFree+Buffers+Cached+SReclaimable)", result.FreeGB, wantFree)
	}
	wantUsed := float64(8192000-3584000) / 8192000 * 100
	if abs(result.UsedPct-wantUsed) > eps {
		t.Errorf("UsedPct = %v, want %v", result.UsedPct, wantUsed)
	}
}
