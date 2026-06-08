//go:build linux

package collectors

import (
	"fmt"
	"strings"
	"testing"
)

// High-core-count coverage for the per-core CPU path — the one surface the
// 2-vCPU AWS Graviton validation couldn't stress. Synthetic fixtures, so it runs
// in CI on any box (no real many-core host needed) and locks the behaviour
// against regression.

func TestParseProcStatCoresHighCoreCount(t *testing.T) {
	const cores = 96
	var b strings.Builder
	// Aggregate line (must be skipped) + auxiliary lines that share the "cpu"
	// prefix-adjacent space (intr/ctxt) to make sure only cpu0..cpuN are kept.
	b.WriteString("cpu  100 0 50 1000 0 0 0 0 0 0\n")
	for i := 0; i < cores; i++ {
		fmt.Fprintf(&b, "cpu%d 10 0 5 100 0 0 0 0 0 0\n", i)
	}
	b.WriteString("intr 12345\nctxt 67890\nprocs_running 4\nprocs_blocked 0\n")

	snaps, err := parseProcStatCores(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parseProcStatCores: %v", err)
	}
	if len(snaps) != cores {
		t.Fatalf("got %d cores, want %d (aggregate + non-cpu lines must be skipped)", len(snaps), cores)
	}
	// Spot-check a high-index core parsed correctly (no overflow / off-by-one).
	last := snaps[cores-1]
	if last.core != cores-1 || last.user != 10 || last.idle != 100 {
		t.Errorf("core %d parsed wrong: %+v", cores-1, last)
	}
}

func TestComputeCoreUsageHighCoreCount(t *testing.T) {
	const cores = 96
	mk := func(user, idle uint64) []coreSnapshot {
		s := make([]coreSnapshot, cores)
		for i := 0; i < cores; i++ {
			s[i] = coreSnapshot{core: i, user: user, idle: idle}
		}
		return s
	}
	// Per core: busy delta 50 (user 0→50), total delta 100 (also idle 0→50) → 50%.
	s1 := mk(0, 0)
	s2 := mk(50, 50)

	stats := computeCoreUsage(s1, s2)
	if len(stats) != cores {
		t.Fatalf("got %d core stats, want %d", len(stats), cores)
	}
	for i, st := range stats {
		if st.Core != i {
			t.Fatalf("stats not sorted by core: index %d has core %d", i, st.Core)
		}
		if st.UsagePct < 49.9 || st.UsagePct > 50.1 {
			t.Errorf("core %d usage = %.1f%%, want ~50%%", st.Core, st.UsagePct)
		}
	}
}
