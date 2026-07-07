//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestHealthDeep_CoreUsageHermetic guards replay FIDELITY of per-core CPU usage.
// The two /proc/stat snapshots share one source key, so they cannot be replayed
// independently — without caching the derived result, replay collapses both to the
// same snapshot and every core reads 0%. We seed a known per-core usage during
// capture and assert Collect reproduces it on replay (not 0%), including the
// derived max/min/imbalance.
func TestHealthDeep_CoreUsageHermetic(t *testing.T) {
	want := []models.CoreStat{{Core: 0, UsagePct: 75}, {Core: 1, UsagePct: 25}}
	blob, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	if _, err := rec.Cached("healthdeep/core-usage", func() ([]byte, error) { return blob, nil }); err != nil {
		SetSource(prev)
		t.Fatalf("seeding cached core usage: %v", err)
	}
	SetSource(prev)

	rp := source.NewReplay(rec.Bundle())
	restore := SetSource(rp)
	defer SetSource(restore)

	out, err := NewHealthDeepCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("replay Collect: %v", err)
	}
	info, ok := out.(*models.HealthDeepInfo)
	if !ok {
		t.Fatalf("unexpected result type %T", out)
	}
	if len(info.Cores) != 2 || info.Cores[0].UsagePct != 75 {
		t.Fatalf("replay did not return cached per-core usage (collapsed to 0%%?): %+v", info.Cores)
	}
	if info.MaxCorePct != 75 || info.MinCorePct != 25 || info.CoreImbalance != 50 {
		t.Fatalf("derived max/min/imbalance wrong: max=%v min=%v imb=%v", info.MaxCorePct, info.MinCorePct, info.CoreImbalance)
	}
}

// TestHealthDeep_TopIOHermetic guards replay fidelity of the top-IO-process
// sample the same way TestHealthDeep_CoreUsageHermetic does for per-core CPU:
// the two /proc/<pid>/io snapshots share source keys and cannot be replayed
// independently, so the derived top-N list must be cached and reproduced
// verbatim rather than collapsing to an empty list on replay.
func TestHealthDeep_TopIOHermetic(t *testing.T) {
	want := topIOSample{
		Procs:     []models.ProcessIOStat{{PID: 1204, Name: "postgres", ReadBps: 900, WriteBps: 100}},
		NeedsRoot: true,
	}
	blob, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	if _, err := rec.Cached("healthdeep/top-io", func() ([]byte, error) { return blob, nil }); err != nil {
		SetSource(prev)
		t.Fatalf("seeding cached top-io: %v", err)
	}
	SetSource(prev)

	rp := source.NewReplay(rec.Bundle())
	restore := SetSource(rp)
	defer SetSource(restore)

	out, err := NewHealthDeepCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("replay Collect: %v", err)
	}
	info, ok := out.(*models.HealthDeepInfo)
	if !ok {
		t.Fatalf("unexpected result type %T", out)
	}
	if len(info.TopIOProcs) != 1 || info.TopIOProcs[0].PID != 1204 || info.TopIOProcs[0].Name != "postgres" {
		t.Fatalf("replay did not return cached top-IO sample: %+v", info.TopIOProcs)
	}
	if !info.TopIOProcsNeedsRoot {
		t.Error("NeedsRoot caveat should replay verbatim, not silently drop")
	}
}

func TestComputeTopIORates(t *testing.T) {
	before := map[int]procIOCounters{
		1: {name: "postgres", readBytes: 1000, writeBytes: 0},
		2: {name: "idle", readBytes: 500, writeBytes: 500},
		3: {name: "recycled", readBytes: 9000, writeBytes: 0},
	}
	after := map[int]procIOCounters{
		1: {name: "postgres", readBytes: 1000 + 450, writeBytes: 50}, // 900 B/s read, 100 B/s write over 0.5s
		2: {name: "idle", readBytes: 500, writeBytes: 500},           // no movement — excluded (total == 0)
		3: {name: "recycled", readBytes: 100, writeBytes: 0},         // counters went backwards — recycled PID, excluded
		4: {name: "new", readBytes: 1000, writeBytes: 0},             // no "before" sample — excluded
	}

	got := computeTopIORates(before, after, 5)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 rate (idle/recycled/new excluded), got %+v", got)
	}
	if got[0].PID != 1 || got[0].Name != "postgres" {
		t.Fatalf("unexpected top process: %+v", got[0])
	}
	if got[0].ReadBps != 900 || got[0].WriteBps != 100 {
		t.Errorf("rate math wrong: %+v", got[0])
	}
}

func TestComputeTopIORates_TruncatesToN(t *testing.T) {
	before := map[int]procIOCounters{}
	after := map[int]procIOCounters{}
	for i := 1; i <= 10; i++ {
		before[i] = procIOCounters{name: fmt.Sprintf("p%d", i), readBytes: 0}
		after[i] = procIOCounters{name: fmt.Sprintf("p%d", i), readBytes: uint64(i * 1000)}
	}
	got := computeTopIORates(before, after, 3)
	if len(got) != 3 {
		t.Fatalf("expected truncation to 3, got %d", len(got))
	}
	if got[0].Name != "p10" {
		t.Errorf("expected the highest-rate process first, got %+v", got[0])
	}
}

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
