//go:build linux

package readonly

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// Part 2 (extends DV1): drive collectors.{memory,swap,disk} through to the
// analysis verdict with a FUZZ-GENERATED procfs (huge / negative / truncated /
// million-line), injected through dsd's real source.Replay seam — the actual
// injection point on this codebase, since the Linux memory/swap/disk collectors
// read /proc through source.Source, not through gopsutil's HOST_PROC. Each input
// is bounded by resource oracles (no panic, read-only, bounded wall time,
// well-formed insight levels) and its allocation amplification is recorded as a
// lead.

var validInsightLevels = map[string]bool{
	"OK": true, "WARN": true, "CRIT": true, "INFO": true, "PENDING": true,
}

// collectUnderReplay runs one collector with the active source swapped to a
// Replay of the fuzzed procfs, returning the raw Result the analysis layer
// consumes. Restores the previous source.
func collectUnderReplay(ctx context.Context, c collectors.Collector, b *source.Bundle) runner.Result {
	prev := collectors.SetSource(source.NewReplay(b))
	defer collectors.SetSource(prev)
	start := time.Now()
	data, err := c.Collect(ctx)
	return runner.Result{Name: c.Name(), Data: data, Err: err, Duration: time.Since(start)}
}

// driveVerdict builds the fuzzed-procfs bundle, runs memory/swap/disk, and turns
// their output into the analysis verdict. Returns the insights.
func driveVerdict(t *testing.T, meminfo, swaps, vmstat, mounts []byte) []models.Insight {
	t.Helper()
	b := source.NewBundle()
	b.PutFile("/proc/meminfo", meminfo)
	b.PutFile("/proc/swaps", swaps)
	b.PutFile("/proc/vmstat", vmstat)
	b.PutFile("/proc/mounts", mounts)
	b.PutFile("/proc/sys/vm/overcommit_memory", []byte("0\n"))

	cc := platform.ContainerContext{}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var results []runner.Result
	results = append(results, collectUnderReplay(ctx, collectors.NewMemoryCollector(cc), b))
	results = append(results, collectUnderReplay(ctx, collectors.NewSwapCollector(cc), b))
	results = append(results, collectUnderReplay(ctx, collectors.NewDiskCollector(cc), b))

	thresh := analysis.DefaultThresholds(platform.CloudEnvironment(0))
	return analysis.ApplyThresholds(results, thresh, platform.CloudEnvironment(0), cc)
}

// exerciseVerdict runs one fuzzed procfs end-to-end under the resource + read-only
// oracles. Shared by the fuzz target and the seed test.
func exerciseVerdict(t *testing.T, meminfo, swaps, vmstat, mounts []byte) resource.Report {
	t.Helper()
	runMu.Lock()
	defer runMu.Unlock()

	// Read-only oracle: the collectors read the bundle, not disk — assert the
	// process writes nothing to a pinned temp tree during the run.
	root := t.TempDir()
	home := filepath.Join(root, "home")
	_ = os.MkdirAll(home, 0o755)
	restore := envOverride(map[string]string{"HOME": home, "TMPDIR": home})
	defer restore()
	before := resource.Fingerprint(t, root)

	inputLen := len(meminfo) + len(swaps) + len(vmstat) + len(mounts)
	var insights []models.Insight
	rep := resource.Measure(inputLen, func() {
		insights = driveVerdict(t, meminfo, swaps, vmstat, mounts)
	})

	resource.AssertUnchanged(t, root, before)

	// Verdict integrity: every insight the analysis layer produced must carry a
	// valid Level — a malformed/empty level means a fuzzed procfs drove the
	// verdict into an undefined state (DV1's property, re-asserted here).
	for _, in := range insights {
		if !validInsightLevels[in.Level] {
			t.Fatalf("VERDICT: fuzzed procfs produced insight with invalid Level %q (check=%q)", in.Level, in.Check)
		}
	}
	// Bounded work.
	if rep.Elapsed > resource.TimeBudget {
		t.Fatalf("VERDICT time over budget: input=%d B elapsed=%s", inputLen, rep.Elapsed)
	}
	return rep
}

// FuzzMemorySwapDiskVerdict fuzzes the procfs that feeds the memory/swap/disk
// verdict. Unlike the Part 1 targets this parses files only (no collector exec /
// dial / sampling), so it runs at high throughput.
func FuzzMemorySwapDiskVerdict(f *testing.F) {
	f.Add([]byte("MemTotal: 16384 kB\nMemAvailable: 8192 kB\n"), []byte("Filename\tType\tSize\tUsed\tPriority\n/dev/sda2\tpartition\t1048576\t0\t-2\n"), []byte("pgfault 1\npswpin 0\npswpout 0\n"), []byte("/dev/sda1 / ext4 rw 0 0\n"))
	f.Add([]byte("MemTotal: -1 kB\nMemAvailable: -99999 kB\n"), []byte("garbage"), []byte(""), []byte("//// ? ? ? ?\n"))
	f.Add([]byte("MemTotal: 99999999999999999999 kB\n"), []byte("Filename\tType\tSize\tUsed\tPriority\n"), []byte("pswpin 99999999999999999999\n"), []byte(""))
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})
	f.Add([]byte("MemTotal:\x00\x00\x00 kB\n\n\n"), []byte("\x00\x00\x00"), []byte("pswpin\t\t\t\n"), []byte("dev mnt fs opts 0 0\n"))

	f.Fuzz(func(t *testing.T, meminfo, swaps, vmstat, mounts []byte) {
		_ = exerciseVerdict(t, meminfo, swaps, vmstat, mounts)
	})
}

// TestMemorySwapDiskVerdictSeeds runs the stress fixtures deterministically,
// including a million-line meminfo, so the verdict path is watched working on
// every CI run (not only under fuzz).
func TestMemorySwapDiskVerdictSeeds(t *testing.T) {
	millionLine := make([]byte, 0, 1<<20)
	line := []byte("Bogus: 1 kB\n")
	for i := 0; i < 90000; i++ { // ~1e5 lines, ~1 MB (capped by maxSafeReadBytes anyway)
		millionLine = append(millionLine, line...)
	}
	cases := []struct {
		name                           string
		meminfo, swaps, vmstat, mounts []byte
	}{
		{"typical", []byte("MemTotal: 16384 kB\nMemAvailable: 8192 kB\nSlab: 100 kB\n"), []byte("Filename\tType\tSize\tUsed\tPriority\n/dev/sda2\tpartition\t1048576\t524288\t-2\n"), []byte("pswpin 5\npswpout 9\n"), []byte("/dev/sda1 / ext4 rw 0 0\n")},
		{"negative", []byte("MemTotal: -1 kB\nMemAvailable: -5 kB\n"), []byte("x"), []byte("pswpin -1\n"), []byte("")},
		{"huge-numbers", []byte("MemTotal: 99999999999999999999 kB\nMemAvailable: 1 kB\n"), []byte(""), []byte("pswpout 99999999999999999999\n"), []byte("")},
		{"truncated", []byte("MemTot"), []byte("Filename\tType"), []byte("pswp"), []byte("/dev/sd")},
		{"million-line", millionLine, millionLine, millionLine, millionLine},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := exerciseVerdict(t, c.meminfo, c.swaps, c.vmstat, c.mounts)
			t.Logf("%s: %s", c.name, rep.String())
		})
	}
}
