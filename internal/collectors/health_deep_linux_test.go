//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
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

// TestHealthDeep_CoreUsageHermetic_LaterCoreIsMax covers the cs.UsagePct >
// info.MaxCorePct branch inside Collect's max/min derivation loop: unlike
// TestHealthDeep_CoreUsageHermetic (where core 0 is already the max),  a
// LATER core reporting a higher usage than the first must update MaxCorePct.
func TestHealthDeep_CoreUsageHermetic_LaterCoreIsMax(t *testing.T) {
	want := []models.CoreStat{{Core: 0, UsagePct: 10}, {Core: 1, UsagePct: 90}}
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
	if info.MaxCorePct != 90 || info.MinCorePct != 10 || info.CoreImbalance != 80 {
		t.Fatalf("derived max/min/imbalance wrong: max=%v min=%v imb=%v, want 90/10/80", info.MaxCorePct, info.MinCorePct, info.CoreImbalance)
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

// TestHealthDeep_TopCPUHermetic guards replay fidelity of the top-CPU-process
// sample the same way TestHealthDeep_TopIOHermetic does for top-IO: the two
// /proc/<pid>/stat snapshots share source keys and cannot be replayed
// independently, so the derived top-N list must be cached and reproduced
// verbatim rather than collapsing to an empty list on replay.
func TestHealthDeep_TopCPUHermetic(t *testing.T) {
	want := []models.ProcessCPUStat{{PID: 8823, Name: "java", CPUPct: 42.1, CgroupScope: "container:abc123"}}
	blob, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	if _, err := rec.Cached("healthdeep/top-cpu", func() ([]byte, error) { return blob, nil }); err != nil {
		SetSource(prev)
		t.Fatalf("seeding cached top-cpu: %v", err)
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
	if len(info.TopCPUProcs) != 1 || info.TopCPUProcs[0].PID != 8823 || info.TopCPUProcs[0].CPUPct != 42.1 {
		t.Fatalf("replay did not return cached top-CPU sample: %+v", info.TopCPUProcs)
	}
}

// TestHealthDeep_CollectFullySeeded exercises Collect end-to-end with every
// static (non-two-sample) input populated, covering the branches the three
// Hermetic tests above (which each seed only ONE cached derived-sample key)
// leave untouched: the /proc/loadavg open-and-parse success path (including
// the max/min/imbalance derivation with >1 core), collectMemDetail,
// collectCgroupV2 (available + populated), and the cgroup-units sample gated
// on Cgroup.Available.
func TestHealthDeep_CollectFullySeeded(t *testing.T) {
	unitDir := cgroupRoot + "/system.slice/nginx.service"
	coreUsage, err := json.Marshal([]models.CoreStat{{Core: 0, UsagePct: 80}, {Core: 1, UsagePct: 20}})
	if err != nil {
		t.Fatal(err)
	}
	topIO, err := json.Marshal(topIOSample{})
	if err != nil {
		t.Fatal(err)
	}
	topCPU, err := json.Marshal([]models.ProcessCPUStat{})
	if err != nil {
		t.Fatal(err)
	}
	units, err := json.Marshal([]models.CgroupUnit{})
	if err != nil {
		t.Fatal(err)
	}

	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	for key, blob := range map[string][]byte{
		"healthdeep/core-usage":   coreUsage,
		"healthdeep/top-io":       topIO,
		"healthdeep/top-cpu":      topCPU,
		"healthdeep/cgroup-units": units,
	} {
		if _, err := rec.Cached(key, func() ([]byte, error) { return blob, nil }); err != nil {
			SetSource(prev)
			t.Fatalf("seeding cached %s: %v", key, err)
		}
	}
	SetSource(prev)

	b := rec.Bundle()
	b.PutFile("/proc/loadavg", []byte("1.50 1.20 0.90 2/456 12345\n"))
	b.PutFile("/proc/meminfo", []byte(
		"MemTotal:       16384000 kB\n"+
			"Cached:          2048000 kB\n"+
			"Buffers:          512000 kB\n"+
			"Dirty:              1024 kB\n"+
			"AnonPages:       4096000 kB\n",
	))
	b.PutFile(cgroupRoot+"/cgroup.controllers", []byte("cpu io memory\n"))
	b.PutStat(cgroupRoot+"/cgroup.controllers", source.FileMeta{})
	b.PutGlob(cgroupRoot+"/*.slice", []string{cgroupRoot + "/system.slice"})
	b.PutGlob(cgroupRoot+"/*.scope", []string{})
	b.PutFile(cgroupRoot+"/system.slice/cpu.stat", []byte("usage_usec 500000\nthrottled_usec 0\n"))
	b.PutFile(cgroupRoot+"/memory.events", []byte("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"))
	b.PutGlob(cgroupRoot+"/system.slice/*.service", []string{unitDir})
	b.PutGlob(cgroupRoot+"/system.slice/*.scope", []string{})
	b.PutGlob(cgroupRoot+"/machine.slice/*.scope", []string{})
	b.PutGlob(cgroupRoot+"/docker/*", []string{})
	b.PutGlob("/proc/[0-9]*", []string{})

	rp := source.NewReplay(b)
	restore := SetSource(rp)
	defer SetSource(restore)

	out, err := NewHealthDeepCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info, ok := out.(*models.HealthDeepInfo)
	if !ok {
		t.Fatalf("unexpected result type %T", out)
	}
	if info.LoadAvg1 != 1.50 {
		t.Errorf("LoadAvg1 = %v, want 1.50 (from /proc/loadavg)", info.LoadAvg1)
	}
	if info.NumCPU != 2 {
		t.Errorf("NumCPU = %d, want 2 (len(Cores))", info.NumCPU)
	}
	if info.MaxCorePct != 80 || info.MinCorePct != 20 || info.CoreImbalance != 60 {
		t.Errorf("max/min/imbalance = %v/%v/%v, want 80/20/60", info.MaxCorePct, info.MinCorePct, info.CoreImbalance)
	}
	if info.CachedMB != 2000 || info.BuffersMB != 500 {
		t.Errorf("mem detail not populated: CachedMB=%v BuffersMB=%v", info.CachedMB, info.BuffersMB)
	}
	if info.Cgroup == nil || !info.Cgroup.Available {
		t.Fatalf("expected a populated, available CgroupV2Info, got %+v", info.Cgroup)
	}
	if info.Cgroup.Units == nil {
		t.Error("expected cgroup Units to be populated (non-nil) once Cgroup.Available is true")
	}
}

// alwaysComputeCachedSource wraps a *source.Replay but makes Cached always
// invoke produce (like source.Live), instead of Replay's normal behaviour of
// serving only pre-seeded bytes and never calling produce. This is the only
// way to exercise the REAL sampleCoreUsage/sampleCgroupUnits/sampleTopIOProcs/
// sampleTopCPUProcs closures (as opposed to the Hermetic tests above, which
// deliberately seed the Cached key so the closures are bypassed entirely).
// Every other Source method still serves from the underlying fixture bundle.
type alwaysComputeCachedSource struct {
	*source.Replay
}

func (s alwaysComputeCachedSource) Cached(_ string, produce func() ([]byte, error)) ([]byte, error) {
	return produce()
}

// TestHealthDeep_CollectRunsRealSamplers drives Collect() with a source that
// actually invokes the four cachedJSON producer closures (sampleCoreUsage,
// sampleCgroupUnits, sampleTopIOProcs, sampleTopCPUProcs), rather than
// bypassing them via a pre-seeded Cached key as every other Collect test in
// this file does. All /proc/[0-9]* and cgroup-unit globs are seeded empty so
// the IO/CPU/cgroup-unit loops finish instantly; only the two-sample core
// usage path incurs its real ~500ms wait.
func TestHealthDeep_CollectRunsRealSamplers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real ~500ms sampling gap in short mode")
	}
	b := source.NewBundle()
	b.PutFile("/proc/stat", []byte("cpu  1000 0 500 8500 0 0 0 0\ncpu0 500 0 250 4250 0 0 0 0\n"))
	b.PutFile("/proc/loadavg", []byte("0.50 0.40 0.30 1/100 999\n"))
	b.PutFile("/proc/meminfo", []byte("MemTotal: 16384000 kB\n"))
	b.PutFile(cgroupRoot+"/cgroup.controllers", []byte("cpu io memory\n"))
	b.PutStat(cgroupRoot+"/cgroup.controllers", source.FileMeta{})
	b.PutGlob(cgroupRoot+"/*.slice", []string{})
	b.PutGlob(cgroupRoot+"/*.scope", []string{})
	b.PutGlob(cgroupRoot+"/system.slice/*.service", []string{})
	b.PutGlob(cgroupRoot+"/system.slice/*.scope", []string{})
	b.PutGlob(cgroupRoot+"/machine.slice/*.scope", []string{})
	b.PutGlob(cgroupRoot+"/docker/*", []string{})
	b.PutGlob("/proc/[0-9]*", []string{})

	prev := SetSource(alwaysComputeCachedSource{Replay: source.NewReplay(b)})
	defer SetSource(prev)

	out, err := NewHealthDeepCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info, ok := out.(*models.HealthDeepInfo)
	if !ok {
		t.Fatalf("unexpected result type %T", out)
	}
	if len(info.Cores) != 1 || info.Cores[0].Core != 0 {
		t.Errorf("Cores = %+v, want 1 real-sampled core", info.Cores)
	}
	if info.LoadAvg1 != 0.50 {
		t.Errorf("LoadAvg1 = %v, want 0.50", info.LoadAvg1)
	}
	if len(info.TopIOProcs) != 0 || len(info.TopCPUProcs) != 0 {
		t.Errorf("expected empty top-IO/top-CPU with no /proc/[0-9]* entries, got %+v / %+v", info.TopIOProcs, info.TopCPUProcs)
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

// TestParseProcStatCores_BareCPULineNoPanic guards a slice-bounds panic: a
// line that is exactly "cpu" (3 bytes, no trailing space/fields) used to hit
// line[:4] before the aggregate-line check confirmed the line was at least 4
// bytes long. Real /proc/stat always pads "cpu  <counters>", but a truncated
// or malformed read must degrade to skipping the line, never crash the
// collector.
func TestParseProcStatCores_BareCPULineNoPanic(t *testing.T) {
	t.Parallel()
	snaps, err := parseProcStatCores(strings.NewReader("cpu\ncpu0 10 0 5 100 0 0 0 0 0 0\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snaps) != 1 || snaps[0].core != 0 {
		t.Errorf("expected the bare \"cpu\" line skipped and cpu0 parsed, got %+v", snaps)
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
	for i := range cores {
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
		for i := range cores {
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

func TestComputeTopCPURates(t *testing.T) {
	before := map[int]procCPUCounters{
		1: {name: "postgres", ticks: 1000},
		2: {name: "idle", ticks: 500},
		3: {name: "recycled", ticks: 9000},
	}
	after := map[int]procCPUCounters{
		1: {name: "postgres", ticks: 1000 + 50}, // busy across the sample window
		2: {name: "idle", ticks: 500},           // no movement — excluded (pct == 0)
		3: {name: "recycled", ticks: 100},       // counters went backwards — recycled PID, excluded
		4: {name: "new", ticks: 1000},           // no "before" sample — excluded
	}

	got := computeTopCPURates(before, after, 100, 5) // sysDeltaTicks=100 for round numbers
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 rate (idle/recycled/new excluded), got %+v", got)
	}
	if got[0].PID != 1 || got[0].Name != "postgres" {
		t.Fatalf("unexpected top process: %+v", got[0])
	}
	wantPct := 50.0 / 100.0 * float64(runtime.NumCPU()) * 100
	if got[0].CPUPct != wantPct {
		t.Errorf("rate math wrong: got %.2f, want %.2f", got[0].CPUPct, wantPct)
	}
}

func TestComputeTopCPURates_TruncatesToN(t *testing.T) {
	before := map[int]procCPUCounters{}
	after := map[int]procCPUCounters{}
	for i := 1; i <= 10; i++ {
		before[i] = procCPUCounters{name: fmt.Sprintf("p%d", i), ticks: 0}
		after[i] = procCPUCounters{name: fmt.Sprintf("p%d", i), ticks: uint64(i * 1000)}
	}
	got := computeTopCPURates(before, after, 1000, 3)
	if len(got) != 3 {
		t.Fatalf("expected truncation to 3, got %d", len(got))
	}
	if got[0].Name != "p10" {
		t.Errorf("expected the highest-rate process first, got %+v", got[0])
	}
}

func TestComputeTopCPURates_ZeroSysDelta(t *testing.T) {
	// A zero system-wide tick delta (e.g. a sub-jiffy sampling window) must not
	// divide by zero — it should fall back to 1, not panic or return NaN/Inf.
	before := map[int]procCPUCounters{1: {name: "busy", ticks: 0}}
	after := map[int]procCPUCounters{1: {name: "busy", ticks: 5}}
	got := computeTopCPURates(before, after, 0, 5)
	if len(got) != 1 || math.IsNaN(got[0].CPUPct) || math.IsInf(got[0].CPUPct, 0) {
		t.Fatalf("expected a finite rate with zero sysDeltaTicks, got %+v", got)
	}
}

// TestParseProcStatUtimeStime guards against the comm-field trap documented on
// parseProcStatUtimeStime: a process name containing spaces/parens (e.g. Chrome's
// "(Web Content)") must not shift the utime/stime field indices.
func TestParseProcStatUtimeStime(t *testing.T) {
	// Real /proc/<pid>/stat line shape: pid (comm) state ppid ... utime stime ...
	// Field 14 = utime, field 15 = stime; fields 3-13 are filler here.
	line := "1234 (Web Content) S 1 1234 1234 0 -1 4194304 100 0 0 0 4200 1300 0 0 20 0 10 0"
	utime, stime, ok := parseProcStatUtimeStime(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if utime != 4200 || stime != 1300 {
		t.Errorf("got utime=%d stime=%d, want utime=4200 stime=1300", utime, stime)
	}
}

func TestParseProcStatUtimeStime_Malformed(t *testing.T) {
	if _, _, ok := parseProcStatUtimeStime("no parens here"); ok {
		t.Error("expected ok=false for a line with no comm parens")
	}
	if _, _, ok := parseProcStatUtimeStime("1234 (sh) S 1"); ok {
		t.Error("expected ok=false for a truncated stat line")
	}
}

// ── cgroup per-unit drill-down (Gap Spec §5, "per-cgroup resource summary") ──

func TestContainerIDLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, rawID, want string
	}{
		{"64-char id truncates to 12", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567", "container:abcdef012345"},
		{"trims .scope suffix before truncating", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.scope", "container:abcdef012345"},
		{"short id is not truncated", "short123", "container:short123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := containerIDLabel(tt.rawID); got != tt.want {
				t.Errorf("containerIDLabel(%q) = %q, want %q", tt.rawID, got, tt.want)
			}
		})
	}
}

func TestClassifyCgroupUnitDir(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, parentSlice, dirName string
		wantContainer              bool
		wantLabel                  string
	}{
		{"systemd service unit", "system.slice", "postgresql.service", false, "postgresql.service"},
		{"docker container under docker/ root (cgroupfs driver)", "docker", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567", true, "container:abcdef012345"},
		{"docker container as a scope (systemd driver)", "system.slice", "docker-abcdef0123456789abcdef0123456789abcdef0123456789abcdef01.scope", true, "container:abcdef012345"},
		{"podman container as a scope", "machine.slice", "libpod-abcdef0123456789abcdef0123456789abcdef0123456789abcdef01.scope", true, "container:abcdef012345"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			isContainer, label := classifyCgroupUnitDir(tt.parentSlice, tt.dirName)
			if isContainer != tt.wantContainer || label != tt.wantLabel {
				t.Errorf("classifyCgroupUnitDir(%q, %q) = (%v, %q), want (%v, %q)",
					tt.parentSlice, tt.dirName, isContainer, label, tt.wantContainer, tt.wantLabel)
			}
		})
	}
}

// TestCgroupUnitSignificant is the boundary table for the "significant
// usage" cutoff from Gap Spec §5 (>5% CPU or >500MB RAM) — at/below/above
// each mark, and independently for each of the two OR'd conditions.
func TestCgroupUnitSignificant(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		cpuPct, memMB float64
		want          bool
	}{
		{"both below bar", 5, 500, false},
		{"cpu just above bar", 5.1, 0, true},
		{"mem just above bar", 0, 500.1, true},
		{"cpu far above bar, mem irrelevant", 90, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := cgroupUnitSignificant(tt.cpuPct, tt.memMB); got != tt.want {
				t.Errorf("cgroupUnitSignificant(%v, %v) = %v, want %v", tt.cpuPct, tt.memMB, got, tt.want)
			}
		})
	}
}

// writeCgroupFixture writes a single cgroupfs-style pseudo-file under dir,
// mirroring the fixture pattern used elsewhere in this package (synthetic
// files, never real /sys/fs/cgroup — per the "never read real /proc/sys in
// tests" project rule).
func writeCgroupFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture %s: %v", name, err)
	}
}

func TestReadCgroupThrottledPct(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeCgroupFixture(t, dir, "cpu.stat", "usage_usec 1000000\nthrottled_usec 250000\nnr_periods 10\n")
	if got := readCgroupThrottledPct(dir); got != 25 {
		t.Errorf("readCgroupThrottledPct = %v, want 25", got)
	}

	emptyDir := t.TempDir()
	if got := readCgroupThrottledPct(emptyDir); got != 0 {
		t.Errorf("missing cpu.stat: readCgroupThrottledPct = %v, want 0", got)
	}
}

func TestReadCgroupCPUUsageUSec(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeCgroupFixture(t, dir, "cpu.stat", "usage_usec 4200000\nthrottled_usec 0\n")
	if got := readCgroupCPUUsageUSec(dir); got != 4200000 {
		t.Errorf("readCgroupCPUUsageUSec = %v, want 4200000", got)
	}
}

func TestReadCgroupCPULimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, content string
		want          bool
	}{
		{"unlimited", "max 100000\n", false},
		{"quota set", "50000 100000\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeCgroupFixture(t, dir, "cpu.max", tt.content)
			if got := readCgroupCPULimit(dir); got != tt.want {
				t.Errorf("readCgroupCPULimit(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}

func TestReadCgroupMem(t *testing.T) {
	t.Parallel()

	t.Run("unlimited", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeCgroupFixture(t, dir, "memory.current", "104857600\n") // 100MB
		writeCgroupFixture(t, dir, "memory.max", "max\n")
		current, limit, hasLimit := readCgroupMem(dir)
		if current != 100 || limit != -1 || hasLimit {
			t.Errorf("got current=%v limit=%v hasLimit=%v, want 100/-1/false", current, limit, hasLimit)
		}
	})

	t.Run("limited", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeCgroupFixture(t, dir, "memory.current", "524288000\n") // 500MB
		writeCgroupFixture(t, dir, "memory.max", "1048576000\n")    // 1000MB
		current, limit, hasLimit := readCgroupMem(dir)
		if current != 500 || limit != 1000 || !hasLimit {
			t.Errorf("got current=%v limit=%v hasLimit=%v, want 500/1000/true", current, limit, hasLimit)
		}
	})
}

// TestHealthDeep_CgroupUnitsGatedOnCgroupV2 guards the wiring in Collect():
// per-unit sampling only attaches when collectCgroupV2 itself found a
// mounted cgroup v2 hierarchy. Under replay without a cgroup.controllers
// fixture, Cgroup is nil — the cgroup-units cache attach must be skipped
// entirely, not attach an empty-but-present Units slice (that would read as
// "checked, nothing significant" instead of "cgroup v2 not available here").
func TestHealthDeep_CgroupUnitsGatedOnCgroupV2(t *testing.T) {
	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
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
	if info.Cgroup != nil {
		t.Fatalf("expected nil Cgroup under replay without a cgroup.controllers fixture, got %+v", info.Cgroup)
	}
}

// TestComputeCgroupUnits is the pure-function counterpart to
// TestComputeTopCPURates for the cgroup per-unit drill-down: given raw
// before/after usage_usec samples (no live /sys reads, no 500ms wait), it
// checks the CPU% delta math, the significant-usage filter, and sort order.
func TestComputeCgroupUnits(t *testing.T) {
	t.Parallel()
	samples := []cgroupRawSample{
		{dir: "/sys/fs/cgroup/system.slice/postgresql.service", usageBeforeUSec: 1_000_000, usageAfterUSec: 1_210_000},                                          // 210000/500000*100 = 42%
		{dir: "/sys/fs/cgroup/system.slice/idle.service", usageBeforeUSec: 500_000, usageAfterUSec: 505_000},                                                    // 1% CPU, no mem — excluded
		{dir: "/sys/fs/cgroup/docker/abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567", usageBeforeUSec: 0, usageAfterUSec: 0, memCurrentMB: 600}, // 0% CPU but >500MB mem — included
		{dir: "/sys/fs/cgroup/system.slice/recycled.service", usageBeforeUSec: 9000, usageAfterUSec: 100},                                                       // counters went backwards — clamped to 0, excluded (no mem either)
	}

	got := computeCgroupUnits(samples, 500000)
	if len(got) != 2 {
		t.Fatalf("expected 2 significant units (idle/recycled excluded), got %+v", got)
	}
	if got[0].Name != "postgresql.service" || got[0].CPUPct != 42 {
		t.Errorf("expected postgresql.service first at 42%%, got %+v", got[0])
	}
	if got[1].Name != "container:abcdef012345" || !got[1].IsContainer || got[1].MemCurrentMB != 600 {
		t.Errorf("expected the docker container second, got %+v", got[1])
	}
}

func TestComputeCgroupUnits_TruncatesToN(t *testing.T) {
	t.Parallel()
	samples := make([]cgroupRawSample, 0, 20)
	for i := 1; i <= 20; i++ {
		samples = append(samples, cgroupRawSample{
			dir:             fmt.Sprintf("/sys/fs/cgroup/system.slice/svc%d.service", i),
			usageBeforeUSec: 0,
			usageAfterUSec:  int64(i * 10000), // higher i → higher CPU%
		})
	}
	got := computeCgroupUnits(samples, 500000)
	if len(got) != 15 {
		t.Fatalf("expected truncation to 15, got %d", len(got))
	}
	if got[0].Name != "svc20.service" {
		t.Errorf("expected the highest-CPU unit first, got %+v", got[0])
	}
}

func TestComputeCgroupUnits_ZeroElapsedFallsBackToNominalWindow(t *testing.T) {
	t.Parallel()
	samples := []cgroupRawSample{
		{dir: "/sys/fs/cgroup/system.slice/x.service", usageBeforeUSec: 0, usageAfterUSec: 210_000},
	}
	got := computeCgroupUnits(samples, 0)
	if len(got) != 1 || math.IsNaN(got[0].CPUPct) || math.IsInf(got[0].CPUPct, 0) {
		t.Fatalf("expected a finite rate with elapsedUSec=0, got %+v", got)
	}
	if got[0].CPUPct != 42 {
		t.Errorf("expected fallback to the nominal 500ms window (42%%), got %.2f", got[0].CPUPct)
	}
}

// TestParseProcStatCores_NonNumericSuffix covers the strconv.Atoi error path
// in parseProcStatCores: a "cpuXYZ" line is skipped; "cpu0" is still parsed.
func TestParseProcStatCores_NonNumericSuffix(t *testing.T) {
	t.Parallel()
	input := "cpuXYZ 10 0 5 100 0 0 0 0 0 0\ncpu0 10 0 5 100 0 0 0 0 0 0\n"
	snaps, err := parseProcStatCores(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snaps) != 1 || snaps[0].core != 0 {
		t.Errorf("expected only cpu0 parsed (cpuXYZ skipped), got %+v", snaps)
	}
}

// TestComputeCoreUsage_CoreMissingInS1 covers the !ok branch in computeCoreUsage:
// a core present in s2 but absent in s1 is silently skipped.
func TestComputeCoreUsage_CoreMissingInS1(t *testing.T) {
	t.Parallel()
	s1 := []coreSnapshot{{core: 0, user: 10, idle: 90}}
	s2 := []coreSnapshot{
		{core: 0, user: 60, idle: 40},
		{core: 1, user: 50, idle: 50},
	}
	stats := computeCoreUsage(s1, s2)
	if len(stats) != 1 || stats[0].Core != 0 {
		t.Errorf("expected only core 0 (core 1 skipped), got %+v", stats)
	}
}

// TestCollectMemDetail_ReadError covers the early-return branch when
// /proc/meminfo is absent from the fixture bundle.
func TestCollectMemDetail_ReadError(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.HealthDeepInfo{}
	collectMemDetail(info)
	if info.CachedMB != 0 || info.BuffersMB != 0 || info.DirtyMB != 0 || info.AnonPagesMB != 0 {
		t.Errorf("expected no fields set after readFile error, got %+v", info)
	}
}

// TestTopMemoryProcs_EntryReadError covers the path where the /proc/<pid>/status
// read fails (pid directory exists in glob but status is not seeded).
func TestTopMemoryProcs_EntryReadError(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/999"})
	})
	procs, _ := topMemoryProcs(5)
	if len(procs) != 0 {
		t.Errorf("expected empty result when status read fails, got %v", procs)
	}
}

// TestTopMemoryProcs_ZeroRSS covers the skip-when-rssKB==0 branch.
func TestTopMemoryProcs_ZeroRSS(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/1001"})
		b.PutFile("/proc/1001/status", []byte("Name:\tidle\nVmRSS:\t0 kB\n"))
		b.PutFile("/proc/1001/comm", []byte("idle\n"))
		b.PutFile("/proc/1001/cgroup", []byte("0::/\n"))
	})
	procs, _ := topMemoryProcs(5)
	if len(procs) != 0 {
		t.Errorf("expected empty result when rssKB==0, got %v", procs)
	}
}

// TestTopMemoryProcs_ValidEntry covers the happy path and the totalKB→totalMB
// accumulator.
func TestTopMemoryProcs_ValidEntry(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/1002"})
		b.PutFile("/proc/1002/status", []byte("Name:\tworker\nVmRSS:\t4096 kB\n"))
		b.PutFile("/proc/1002/comm", []byte("worker\n"))
		b.PutFile("/proc/1002/cgroup", []byte("0::/system.slice/worker.service\n"))
	})
	procs, totalMB := topMemoryProcs(5)
	if len(procs) != 1 {
		t.Fatalf("expected 1 proc, got %d", len(procs))
	}
	if procs[0].Name != "worker" || procs[0].RSSMB != 4.0 {
		t.Errorf("unexpected: %+v", procs[0])
	}
	if totalMB != 4.0 {
		t.Errorf("expected totalMB=4.0, got %.2f", totalMB)
	}
}

// TestTopMemoryProcs_TruncatesToN covers the sort.Slice comparator and the
// truncation to n entries.
func TestTopMemoryProcs_TruncatesToN(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/2001", "/proc/2002"})
		b.PutFile("/proc/2001/status", []byte("Name:\tsmall\nVmRSS:\t1024 kB\n"))
		b.PutFile("/proc/2001/comm", []byte("small\n"))
		b.PutFile("/proc/2001/cgroup", []byte("0::/\n"))
		b.PutFile("/proc/2002/status", []byte("Name:\tbig\nVmRSS:\t8192 kB\n"))
		b.PutFile("/proc/2002/comm", []byte("big\n"))
		b.PutFile("/proc/2002/cgroup", []byte("0::/\n"))
	})
	procs, _ := topMemoryProcs(1)
	if len(procs) != 1 {
		t.Fatalf("expected truncation to 1, got %d", len(procs))
	}
	if procs[0].Name != "big" {
		t.Errorf("expected highest-RSS first, got %q", procs[0].Name)
	}
}

// TestCollectMemDetail_MalformedLine covers the len(fields)<2 branch inside
// collectMemDetail's parse closure: a "Cached:\n" line (key but no value) is
// skipped while following well-formed lines are still parsed.
func TestCollectMemDetail_MalformedLine(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/meminfo", []byte("Cached:\nBuffers:\t128 kB\nDirty:\t64 kB\nAnonPages:\t256 kB\n"))
	})
	info := &models.HealthDeepInfo{}
	collectMemDetail(info)
	if info.CachedMB != 0 {
		t.Errorf("expected CachedMB=0 for malformed line, got %.2f", info.CachedMB)
	}
	if info.BuffersMB == 0 {
		t.Error("expected BuffersMB non-zero for well-formed Buffers line")
	}
}

// fixedErrReader always returns an error (for scanner error coverage).
type fixedErrReader struct{}

func (fixedErrReader) Read([]byte) (int, error) { return 0, fmt.Errorf("injected read error") }

// TestParseProcStatCores_ScannerError covers the scanner.Err() != nil path.
func TestParseProcStatCores_ScannerError(t *testing.T) {
	t.Parallel()
	_, err := parseProcStatCores(fixedErrReader{})
	if err == nil {
		t.Error("expected error from parseProcStatCores when reader returns an error")
	}
}

// TestComputeCgroupUnits_MemUsedPct covers health_deep_linux.go:762.40,764.4 —
// the MemUsedPct calculation branch when hasMemLimit && memLimitMB > 0.
func TestComputeCgroupUnits_MemUsedPct(t *testing.T) {
	t.Parallel()
	samples := []cgroupRawSample{
		{
			dir:             "/sys/fs/cgroup/system.slice/memlimited.service",
			usageBeforeUSec: 0,
			usageAfterUSec:  250_000, // 50% CPU — above the 5% significance bar
			hasMemLimit:     true,
			memLimitMB:      1024,
			memCurrentMB:    512,
		},
	}
	got := computeCgroupUnits(samples, 500000)
	if len(got) != 1 {
		t.Fatalf("expected 1 unit, got %d: %+v", len(got), got)
	}
	if got[0].MemUsedPct != 50 {
		t.Errorf("MemUsedPct = %.1f, want 50 (512/1024*100)", got[0].MemUsedPct)
	}
}

// TestComputeCgroupUnits_SecondarySortOnMemory covers health_deep_linux.go:772.3,772.55
// — the secondary sort comparator that orders by MemCurrentMB when CPUPct is equal.
func TestComputeCgroupUnits_SecondarySortOnMemory(t *testing.T) {
	t.Parallel()
	// Both units have 0% CPU but >500MB RAM so they pass the significance filter.
	// The sort must place the higher-memory unit first.
	samples := []cgroupRawSample{
		{
			dir:          "/sys/fs/cgroup/system.slice/small.service",
			memCurrentMB: 600,
		},
		{
			dir:          "/sys/fs/cgroup/system.slice/large.service",
			memCurrentMB: 800,
		},
	}
	got := computeCgroupUnits(samples, 500000)
	if len(got) != 2 {
		t.Fatalf("expected 2 units, got %d: %+v", len(got), got)
	}
	if got[0].Name != "large.service" || got[0].MemCurrentMB != 800 {
		t.Errorf("expected large.service first (800MB > 600MB), got %+v", got[0])
	}
}
