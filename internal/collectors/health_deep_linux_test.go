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
