//go:build linux

package collectors

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeSequentialFileSource serves the Nth-call content for one specific path
// (1st ReadFile → seqs[0], 2nd → seqs[1], further calls repeat the last entry)
// and falls through to the wrapped Replay for every other path. A Bundle can
// only ever serve one static value per path, so the two-snapshot-500ms-apart
// samplers (sampleCoreUsage/sampleTopIOProcs/sampleTopCPUProcs/
// sampleCgroupUnits) need this to exercise a genuine non-zero before/after
// delta rather than always reading the same snapshot twice.
type fakeSequentialFileSource struct {
	*source.Replay
	path  string
	seqs  [][]byte
	calls int
}

func (f *fakeSequentialFileSource) ReadFile(path string) ([]byte, error) {
	if path == f.path {
		idx := f.calls
		if idx >= len(f.seqs) {
			idx = len(f.seqs) - 1
		}
		f.calls++
		return f.seqs[idx], nil
	}
	return f.Replay.ReadFile(path)
}

// fakePermissionDeniedFileSource reports fs.ErrPermission for one specific
// path — the Bundle API has no public seam for a ReadFile permission error.
type fakePermissionDeniedFileSource struct {
	*source.Replay
	deniedPath string
}

func (f fakePermissionDeniedFileSource) ReadFile(path string) ([]byte, error) {
	if path == f.deniedPath {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	return f.Replay.ReadFile(path)
}

// ── HealthDeepCollector identity ─────────────────────────────────────────────

func TestHealthDeepCollectorIdentity(t *testing.T) {
	c := NewHealthDeepCollector()
	if c.Name() != "CPUDeep" {
		t.Errorf("Name() = %q, want CPUDeep", c.Name())
	}
	if c.Timeout() != 8*time.Second {
		t.Errorf("Timeout() = %v, want 8s", c.Timeout())
	}
}

// ── readProcStatCores / procCommName ──────────────────────────────────────────

func TestReadProcStatCores(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/stat", []byte("cpu  100 0 50 850 0 0 0 0\ncpu0 100 0 50 850 0 0 0 0\n"))
	})
	snaps, err := readProcStatCores()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snaps) != 1 || snaps[0].core != 0 {
		t.Fatalf("expected 1 core snapshot for cpu0, got %+v", snaps)
	}
}

func TestReadProcStatCores_FileMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if _, err := readProcStatCores(); err == nil {
		t.Error("expected an error when /proc/stat is unreadable")
	}
}

func TestProcCommName(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/1234/comm", []byte("nginx\n"))
	})
	if got := procCommName(1234); got != "nginx" {
		t.Errorf("procCommName() = %q, want nginx", got)
	}
}

func TestProcCommName_Missing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := procCommName(9999); got != "?" {
		t.Errorf("procCommName() = %q, want ?", got)
	}
}

// ── sampleCoreUsage ───────────────────────────────────────────────────────────

func TestSampleCoreUsage_ReadError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	c := NewHealthDeepCollector()
	if got := c.sampleCoreUsage(context.Background()); got != nil {
		t.Errorf("expected nil on a read error, got %+v", got)
	}
}

func TestSampleCoreUsage_CtxCancelledDuringWait(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/stat", []byte("cpu  100 0 50 850 0 0 0 0\ncpu0 100 0 50 850 0 0 0 0\n"))
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewHealthDeepCollector()
	if got := c.sampleCoreUsage(ctx); got != nil {
		t.Errorf("expected nil for a pre-cancelled context, got %+v", got)
	}
}

func TestSampleCoreUsage_HappyPath(t *testing.T) {
	b := source.NewBundle()
	prev := SetSource(&fakeSequentialFileSource{
		Replay: source.NewReplay(b),
		path:   "/proc/stat",
		seqs: [][]byte{
			[]byte("cpu  100 0 50 850 0 0 0 0\ncpu0 100 0 50 850 0 0 0 0\n"),
			[]byte("cpu  200 0 100 900 0 0 0 0\ncpu0 200 0 100 900 0 0 0 0\n"),
		},
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewHealthDeepCollector()
	got := c.sampleCoreUsage(context.Background())
	if len(got) != 1 {
		t.Fatalf("expected 1 core stat, got %+v", got)
	}
	if got[0].UsagePct <= 0 {
		t.Errorf("expected a non-zero usage delta, got %v", got[0].UsagePct)
	}
}

// ── readAllProcIO ─────────────────────────────────────────────────────────────

func TestReadAllProcIO(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/100"})
		b.PutFile("/proc/100/io", []byte("read_bytes: 1024\nwrite_bytes: 2048\n"))
		b.PutFile("/proc/100/comm", []byte("myapp\n"))
	})
	counters, needsRoot := readAllProcIO()
	if needsRoot {
		t.Error("expected needsRoot=false")
	}
	c, ok := counters[100]
	if !ok {
		t.Fatal("expected an entry for pid 100")
	}
	if c.readBytes != 1024 || c.writeBytes != 2048 || c.name != "myapp" {
		t.Errorf("unexpected counters: %+v", c)
	}
}

func TestReadAllProcIO_PermissionDenied(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/proc/[0-9]*", []string{"/proc/100"})
	prev := SetSource(fakePermissionDeniedFileSource{
		Replay:     source.NewReplay(b),
		deniedPath: "/proc/100/io",
	})
	t.Cleanup(func() { SetSource(prev) })

	_, needsRoot := readAllProcIO()
	if !needsRoot {
		t.Error("expected needsRoot=true when a proc/<pid>/io read is denied")
	}
}

func TestReadAllProcIO_GlobFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	counters, needsRoot := readAllProcIO()
	if counters != nil || needsRoot {
		t.Errorf("expected nil/false when the glob itself fails, got %+v/%v", counters, needsRoot)
	}
}

// ── sampleTopIOProcs ──────────────────────────────────────────────────────────

func TestSampleTopIOProcs_CtxCancelled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/100"})
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewHealthDeepCollector()
	got := c.sampleTopIOProcs(ctx, 5)
	if len(got.Procs) != 0 || got.NeedsRoot {
		t.Errorf("expected an empty sample for a cancelled context, got %+v", got)
	}
}

func TestSampleTopIOProcs_HappyPath(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/proc/[0-9]*", []string{"/proc/100"})
	b.PutFile("/proc/100/comm", []byte("myapp\n"))
	b.PutFile("/proc/100/cgroup", []byte("0::/\n"))
	prev := SetSource(&fakeSequentialFileSource{
		Replay: source.NewReplay(b),
		path:   "/proc/100/io",
		seqs: [][]byte{
			[]byte("read_bytes: 1000\nwrite_bytes: 1000\n"),
			[]byte("read_bytes: 501000\nwrite_bytes: 501000\n"),
		},
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewHealthDeepCollector()
	got := c.sampleTopIOProcs(context.Background(), 5)
	if len(got.Procs) != 1 {
		t.Fatalf("expected 1 process in the sample, got %+v", got)
	}
	if got.Procs[0].PID != 100 || got.Procs[0].ReadBps <= 0 {
		t.Errorf("unexpected top-IO proc: %+v", got.Procs[0])
	}
}

// ── readAllProcCPU / systemTotalTicks ─────────────────────────────────────────

func TestReadAllProcCPU(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/100"})
		// utime is stat field 14, stime field 15 (1-indexed) — 13 fields after
		// the ")" close of the comm field.
		b.PutFile("/proc/100/stat", []byte("100 (myapp) S 1 100 100 0 -1 4194304 0 0 0 0 10 5 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"))
		b.PutFile("/proc/100/comm", []byte("myapp\n"))
		b.PutFile("/proc/stat", []byte("cpu  1000 0 500 8500 0 0 0 0\n"))
	})
	counters, sysTotal := readAllProcCPU()
	c, ok := counters[100]
	if !ok {
		t.Fatal("expected an entry for pid 100")
	}
	if c.ticks != 15 || c.name != "myapp" {
		t.Errorf("unexpected counters: %+v", c)
	}
	if sysTotal != 10000 {
		t.Errorf("systemTotalTicks (via readAllProcCPU) = %d, want 10000", sysTotal)
	}
}

func TestSystemTotalTicks(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/stat", []byte("cpu  1000 0 500 8500 0 0 0 0\ncpu0 500 0 250 4250 0 0 0 0\n"))
	})
	if got := systemTotalTicks(); got != 10000 {
		t.Errorf("systemTotalTicks() = %d, want 10000", got)
	}
}

func TestSystemTotalTicks_FileMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := systemTotalTicks(); got != 0 {
		t.Errorf("systemTotalTicks() = %d, want 0", got)
	}
}

// ── sampleTopCPUProcs ─────────────────────────────────────────────────────────

func TestSampleTopCPUProcs_CtxCancelled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/100"})
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewHealthDeepCollector()
	if got := c.sampleTopCPUProcs(ctx, 5); got != nil {
		t.Errorf("expected nil for a cancelled context, got %+v", got)
	}
}

func TestSampleTopCPUProcs_HappyPath(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/proc/[0-9]*", []string{"/proc/100"})
	b.PutFile("/proc/100/comm", []byte("myapp\n"))
	b.PutFile("/proc/100/cgroup", []byte("0::/\n"))
	prev := SetSource(&fakeSequentialProcSource{
		Replay: source.NewReplay(b),
		procStatSeqs: [][]byte{
			[]byte("100 (myapp) S 1 100 100 0 -1 4194304 0 0 0 0 10 5 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"),
			[]byte("100 (myapp) S 1 100 100 0 -1 4194304 0 0 0 0 60 30 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"),
		},
		sysStatSeqs: [][]byte{
			[]byte("cpu  1000 0 500 8500 0 0 0 0\n"),
			[]byte("cpu  1100 0 550 8850 0 0 0 0\n"), // +200 sys ticks
		},
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewHealthDeepCollector()
	got := c.sampleTopCPUProcs(context.Background(), 5)
	if len(got) != 1 {
		t.Fatalf("expected 1 process in the sample, got %+v", got)
	}
	if got[0].PID != 100 || got[0].CPUPct <= 0 {
		t.Errorf("unexpected top-CPU proc: %+v", got[0])
	}
}

// fakeSequentialProcSource serves distinct content for /proc/100/stat and
// /proc/stat on successive reads, needed because sampleTopCPUProcs reads BOTH
// per-process AND system-aggregate stat twice 500ms apart.
type fakeSequentialProcSource struct {
	*source.Replay
	procStatSeqs [][]byte
	procCalls    int
	sysStatSeqs  [][]byte
	sysCalls     int
}

func (f *fakeSequentialProcSource) ReadFile(path string) ([]byte, error) {
	switch path {
	case "/proc/100/stat":
		idx := f.procCalls
		if idx >= len(f.procStatSeqs) {
			idx = len(f.procStatSeqs) - 1
		}
		f.procCalls++
		return f.procStatSeqs[idx], nil
	case "/proc/stat":
		idx := f.sysCalls
		if idx >= len(f.sysStatSeqs) {
			idx = len(f.sysStatSeqs) - 1
		}
		f.sysCalls++
		return f.sysStatSeqs[idx], nil
	}
	return f.Replay.ReadFile(path)
}

// ── candidateCgroupUnitDirs ────────────────────────────────────────────────────

func TestCandidateCgroupUnitDirs(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob(cgroupRoot+"/system.slice/*.service", []string{cgroupRoot + "/system.slice/nginx.service"})
		b.PutGlob(cgroupRoot+"/system.slice/*.scope", []string{})
		b.PutGlob(cgroupRoot+"/machine.slice/*.scope", []string{cgroupRoot + "/machine.slice/libpod-abc.scope"})
		b.PutGlob(cgroupRoot+"/docker/*", []string{})
	})
	dirs := candidateCgroupUnitDirs()
	if len(dirs) != 2 {
		t.Fatalf("expected 2 candidate dirs, got %+v", dirs)
	}
}

func TestCandidateCgroupUnitDirs_None(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if dirs := candidateCgroupUnitDirs(); len(dirs) != 0 {
		t.Errorf("expected no candidate dirs, got %+v", dirs)
	}
}

// ── sampleCgroupUnits ──────────────────────────────────────────────────────────

func TestSampleCgroupUnits_NoCandidates(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	c := NewHealthDeepCollector()
	if got := c.sampleCgroupUnits(context.Background()); got != nil {
		t.Errorf("expected nil with no candidate dirs, got %+v", got)
	}
}

func TestSampleCgroupUnits_CtxCancelled(t *testing.T) {
	unitDir := cgroupRoot + "/system.slice/nginx.service"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob(cgroupRoot+"/system.slice/*.service", []string{unitDir})
		b.PutGlob(cgroupRoot+"/system.slice/*.scope", []string{})
		b.PutGlob(cgroupRoot+"/machine.slice/*.scope", []string{})
		b.PutGlob(cgroupRoot+"/docker/*", []string{})
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewHealthDeepCollector()
	if got := c.sampleCgroupUnits(ctx); got != nil {
		t.Errorf("expected nil for a cancelled context, got %+v", got)
	}
}

func TestSampleCgroupUnits_HappyPath(t *testing.T) {
	unitDir := cgroupRoot + "/system.slice/nginx.service"
	b := source.NewBundle()
	b.PutGlob(cgroupRoot+"/system.slice/*.service", []string{unitDir})
	b.PutGlob(cgroupRoot+"/system.slice/*.scope", []string{})
	b.PutGlob(cgroupRoot+"/machine.slice/*.scope", []string{})
	b.PutGlob(cgroupRoot+"/docker/*", []string{})
	b.PutFile(unitDir+"/cpu.max", []byte("max 100000\n"))
	b.PutFile(unitDir+"/memory.current", []byte("629145600\n")) // 600MB — over the 500MB significance bar
	b.PutFile(unitDir+"/memory.max", []byte("max\n"))
	prev := SetSource(&fakeSequentialFileSource{
		Replay: source.NewReplay(b),
		path:   unitDir + "/cpu.stat",
		seqs: [][]byte{
			[]byte("usage_usec 1000\nthrottled_usec 0\n"),
			[]byte("usage_usec 251000\nthrottled_usec 0\n"), // +250ms of usage inside a 500ms window
		},
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewHealthDeepCollector()
	got := c.sampleCgroupUnits(context.Background())
	if len(got) != 1 {
		t.Fatalf("expected 1 significant unit (memory over threshold), got %+v", got)
	}
	if got[0].Name != "nginx.service" {
		t.Errorf("Name = %q, want nginx.service", got[0].Name)
	}
	if got[0].MemCurrentMB <= 500 {
		t.Errorf("MemCurrentMB = %v, want > 500", got[0].MemCurrentMB)
	}
}

// ── readCgroupSlice ────────────────────────────────────────────────────────────

func TestReadCgroupSlice(t *testing.T) {
	dir := cgroupRoot + "/system.slice"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile(dir+"/cpu.stat", []byte("usage_usec 500000\nthrottled_usec 50000\n"))
		b.PutFile(dir+"/cpu.max", []byte("100000 100000\n"))
		b.PutFile(dir+"/memory.current", []byte("104857600\n")) // 100MB
		b.PutFile(dir+"/memory.max", []byte("209715200\n"))     // 200MB
		b.PutFile(dir+"/io.stat", []byte("253:0 rbytes=1048576 wbytes=2097152 rios=10 wios=20\n"))
	})
	s := readCgroupSlice(dir, "system.slice")
	if s.Name != "system.slice" {
		t.Errorf("Name = %q, want system.slice", s.Name)
	}
	if s.ThrottledPct != 10 {
		t.Errorf("ThrottledPct = %v, want 10", s.ThrottledPct)
	}
	if !s.HasCPULimit {
		t.Error("expected HasCPULimit=true")
	}
	if s.MemCurrentMB != 100 || s.MemLimitMB != 200 || !s.HasMemLimit {
		t.Errorf("mem fields = %v/%v/%v, want 100/200/true", s.MemCurrentMB, s.MemLimitMB, s.HasMemLimit)
	}
	if s.MemUsedPct != 50 {
		t.Errorf("MemUsedPct = %v, want 50", s.MemUsedPct)
	}
	if s.IOReadMBs != 1 || s.IOWriteMBs != 2 {
		t.Errorf("IO = %v/%v MB, want 1/2", s.IOReadMBs, s.IOWriteMBs)
	}
}

func TestReadCgroupSlice_NoLimitsNoIO(t *testing.T) {
	dir := cgroupRoot + "/user.slice"
	withFixtureSource(t, func(b *source.Bundle) {})
	s := readCgroupSlice(dir, "user.slice")
	if s.HasCPULimit || s.HasMemLimit {
		t.Errorf("expected no limits when files are unreadable, got %+v", s)
	}
	if s.MemLimitMB != -1 {
		t.Errorf("MemLimitMB = %v, want -1 (unreadable == unlimited sentinel)", s.MemLimitMB)
	}
}

// ── readCgroupOOMKills ─────────────────────────────────────────────────────────

func TestReadCgroupOOMKills(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile(cgroupRoot+"/memory.events", []byte("low 0\nhigh 0\nmax 0\noom 0\noom_kill 3\n"))
	})
	if got := readCgroupOOMKills(cgroupRoot + "/memory.events"); got != 3 {
		t.Errorf("readCgroupOOMKills() = %d, want 3", got)
	}
}

func TestReadCgroupOOMKills_FileMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := readCgroupOOMKills(cgroupRoot + "/memory.events"); got != 0 {
		t.Errorf("readCgroupOOMKills() = %d, want 0", got)
	}
}

// ── cgroupScope ────────────────────────────────────────────────────────────────

func TestCgroupScope(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/4242/cgroup", []byte("0::/system.slice/nginx.service\n"))
	})
	if got := cgroupScope(4242); got != "system:nginx.service" {
		t.Errorf("cgroupScope() = %q, want system:nginx.service", got)
	}
}

func TestCgroupScope_Missing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := cgroupScope(9999); got != "" {
		t.Errorf("cgroupScope() = %q, want empty when unreadable", got)
	}
}

// ── collectMemDetail ─────────────────────────────────────────────────────────

// TestCollectMemDetail guards the /proc/meminfo extended-field parse (kB→MB
// conversion) and the graceful no-op when the file is unreadable.
func TestCollectMemDetail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/meminfo", []byte(
			"MemTotal:       16384000 kB\n"+
				"Cached:          2048000 kB\n"+
				"Buffers:          512000 kB\n"+
				"Dirty:              1024 kB\n"+
				"AnonPages:       4096000 kB\n",
		))
	})
	info := &models.HealthDeepInfo{}
	collectMemDetail(info)
	if info.CachedMB != 2000 {
		t.Errorf("CachedMB = %v, want 2000", info.CachedMB)
	}
	if info.BuffersMB != 500 {
		t.Errorf("BuffersMB = %v, want 500", info.BuffersMB)
	}
	if info.DirtyMB != 1 {
		t.Errorf("DirtyMB = %v, want 1", info.DirtyMB)
	}
	if info.AnonPagesMB != 4000 {
		t.Errorf("AnonPagesMB = %v, want 4000", info.AnonPagesMB)
	}
}

func TestCollectMemDetail_FileMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.HealthDeepInfo{}
	collectMemDetail(info)
	if info.CachedMB != 0 || info.BuffersMB != 0 || info.DirtyMB != 0 || info.AnonPagesMB != 0 {
		t.Errorf("expected zero-value fields when /proc/meminfo is unreadable, got %+v", info)
	}
}

// ── collectCgroupV2 ──────────────────────────────────────────────────────────

// TestCollectCgroupV2 guards the top-level gate (cgroup v2 unmounted → nil)
// and the populated path: controllers, per-slice throttling surfaced into
// ThrottledSlices above the 5% bar, and OOM kill count from the root
// memory.events.
func TestCollectCgroupV2_NotMounted(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := collectCgroupV2(); got != nil {
		t.Errorf("expected nil when cgroup v2 is not mounted, got %+v", got)
	}
}

func TestCollectCgroupV2_Populated(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile(cgroupRoot+"/cgroup.controllers", []byte("cpu io memory\n"))
		b.PutStat(cgroupRoot+"/cgroup.controllers", source.FileMeta{})
		b.PutGlob(cgroupRoot+"/*.slice", []string{cgroupRoot + "/system.slice"})
		b.PutGlob(cgroupRoot+"/*.scope", []string{cgroupRoot + "/init.scope"})
		b.PutFile(cgroupRoot+"/system.slice/cpu.stat", []byte("usage_usec 500000\nthrottled_usec 100000\n"))
		b.PutFile(cgroupRoot+"/init.scope/cpu.stat", []byte("usage_usec 500000\nthrottled_usec 0\n"))
		b.PutFile(cgroupRoot+"/memory.events", []byte("low 0\nhigh 0\nmax 0\noom 0\noom_kill 2\n"))
	})
	got := collectCgroupV2()
	if got == nil || !got.Available {
		t.Fatalf("expected a populated CgroupV2Info, got %+v", got)
	}
	if len(got.Controllers) != 3 {
		t.Errorf("Controllers = %v, want 3 entries", got.Controllers)
	}
	if len(got.Slices) != 2 {
		t.Fatalf("expected 2 slices (system.slice + init.scope), got %+v", got.Slices)
	}
	if len(got.ThrottledSlices) != 1 || got.ThrottledSlices[0] != "system.slice" {
		t.Errorf("ThrottledSlices = %v, want [system.slice] (20%% throttled > 5%% bar)", got.ThrottledSlices)
	}
	if got.OOMKills != 2 {
		t.Errorf("OOMKills = %d, want 2", got.OOMKills)
	}
}

// ── parseCgroupPath ──────────────────────────────────────────────────────────

// TestParseCgroupPath guards the label derivation across every branch: root/
// init, docker, podman (libpod scope + pod), kubepods, system.slice service
// (with nested path stripped), user.slice, and the generic last-segment
// fallback.
func TestParseCgroupPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want string
	}{
		{"root", "/", "kernel"},
		{"empty", "", "kernel"},
		{"init scope", "/init.scope", "init"},
		{"docker container", "/docker/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a", "container:abcdef012345"},
		{"podman libpod scope", "/machine.slice/libpod-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a.scope", "container:abcdef012345"},
		{"podman pod", "/machine.slice/libpod_pod_something", "pod:podman"},
		{"kubepods with pod id", "/kubepods/besteffort/pod12345678-aaaa-bbbb-cccc-dddddddddddd/container1", "k8s-pod:12345678"},
		{"kubepods without pod segment", "/kubepods/besteffort", "k8s"},
		{"system slice nested", "/system.slice/k3s.service/some/nested/path", "system:k3s.service"},
		{"system slice flat", "/system.slice/nginx.service", "system:nginx.service"},
		{"user slice", "/user.slice/user-1000.slice/session-1.scope", "user:1000"},
		{"generic fallback", "/some/other/path", "path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseCgroupPath(tt.path); got != tt.want {
				t.Errorf("parseCgroupPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
