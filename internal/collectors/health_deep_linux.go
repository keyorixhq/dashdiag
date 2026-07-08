//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HealthDeepCollector extends dsd health with per-core CPU breakdown
// and top memory consumers. Requires two /proc/stat reads 500ms apart
// for accurate per-core usage.
type HealthDeepCollector struct{}

func NewHealthDeepCollector() *HealthDeepCollector { return &HealthDeepCollector{} }

func (c *HealthDeepCollector) Name() string           { return "CPUDeep" }
func (c *HealthDeepCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *HealthDeepCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.HealthDeepInfo{}

	// Per-core CPU usage needs two /proc/stat reads 500ms apart. Both reads hit the
	// same source key (/proc/stat), so under replay they collapse to a single snapshot
	// and every core reads 0%. Cache the DERIVED per-core usage instead: capture
	// computes it live (the two reads + 500ms wait) and records the result; replay
	// reproduces the captured percentages with no double-read and no wait. This keeps
	// CPUDeep faithful under `dsd replay`, not merely deterministic.
	var cores []models.CoreStat
	_ = cachedJSON("healthdeep/core-usage", func() (any, error) {
		return c.sampleCoreUsage(ctx), nil
	}, &cores)
	info.Cores = cores
	if len(info.Cores) > 0 {
		info.MaxCorePct = info.Cores[0].UsagePct
		info.MinCorePct = info.Cores[0].UsagePct
		for _, cs := range info.Cores {
			if cs.UsagePct > info.MaxCorePct {
				info.MaxCorePct = cs.UsagePct
			}
			if cs.UsagePct < info.MinCorePct {
				info.MinCorePct = cs.UsagePct
			}
		}
		info.CoreImbalance = info.MaxCorePct - info.MinCorePct
	}

	// Load average + core count to corroborate the per-core readings (which are
	// sampled during dsd's own deep collection and can read falsely high on a
	// small host). NumCPU comes from the /proc/stat per-core lines when present.
	info.NumCPU = len(info.Cores)
	if lf, lerr := openFile("/proc/loadavg"); lerr == nil {
		if l1, _, _, perr := parseLoadAvg(lf); perr == nil {
			info.LoadAvg1 = l1
		}
		_ = lf.Close()
	}

	// Top memory consumers from /proc/<pid>/status
	info.TopProcs, info.TotalProcsMB = topMemoryProcs(10)

	// Extended memory breakdown
	collectMemDetail(info)

	// cgroup v2 slice summary
	info.Cgroup = collectCgroupV2()

	// Per-unit (systemd service / container) drill-down — same replay-fidelity
	// concern as core usage, top-IO, and top-CPU above: two live cpu.stat reads
	// 500ms apart must be cached as the derived result.
	if info.Cgroup != nil && info.Cgroup.Available {
		var units []models.CgroupUnit
		_ = cachedJSON("healthdeep/cgroup-units", func() (any, error) {
			return c.sampleCgroupUnits(ctx), nil
		}, &units)
		info.Cgroup.Units = units
	}

	// Top I/O-consuming processes — same replay-fidelity concern as core usage
	// above: two live /proc/<pid>/io reads 500ms apart must be cached as the
	// derived result, not replayed as two independent reads.
	var topIO topIOSample
	_ = cachedJSON("healthdeep/top-io", func() (any, error) {
		return c.sampleTopIOProcs(ctx, 5), nil
	}, &topIO)
	info.TopIOProcs = topIO.Procs
	info.TopIOProcsNeedsRoot = topIO.NeedsRoot

	// Top CPU-consuming processes — same replay-fidelity concern as core usage
	// and top-IO above: two live /proc/<pid>/stat reads 500ms apart must be
	// cached as the derived result, not replayed as two independent reads.
	var topCPU []models.ProcessCPUStat
	_ = cachedJSON("healthdeep/top-cpu", func() (any, error) {
		return c.sampleTopCPUProcs(ctx, 10), nil
	}, &topCPU)
	info.TopCPUProcs = topCPU

	return info, nil
}

// sampleCoreUsage takes two /proc/stat snapshots 500ms apart and returns per-core
// usage percentages. It returns nil on a read error or if ctx is cancelled during
// the interval. The caller records the result via Source.Cached, so the
// two-snapshot delta replays faithfully instead of collapsing to 0% (both reads
// share the /proc/stat source key, so they cannot be replayed independently).
func (c *HealthDeepCollector) sampleCoreUsage(ctx context.Context) []models.CoreStat {
	snap1, err := readProcStatCores()
	if err != nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(500 * time.Millisecond):
	}
	snap2, err := readProcStatCores()
	if err != nil {
		return nil
	}
	return computeCoreUsage(snap1, snap2)
}

// coreSnapshot holds raw /proc/stat ticks for one core.
type coreSnapshot struct {
	core                                               int
	user, nice, sys, idle, iowait, irq, softirq, steal uint64
}

func (s coreSnapshot) total() uint64 {
	return s.user + s.nice + s.sys + s.idle + s.iowait + s.irq + s.softirq + s.steal
}

func (s coreSnapshot) busy() uint64 {
	return s.user + s.nice + s.sys + s.irq + s.softirq + s.steal
}

func readProcStatCores() ([]coreSnapshot, error) {
	f, err := openFile("/proc/stat") // #nosec G304 -- hardcoded path
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	return parseProcStatCores(f)
}

// parseProcStatCores parses the per-core ("cpu0".."cpuN") lines of /proc/stat,
// skipping the aggregate "cpu " line. Split out from readProcStatCores so the
// high-core-count path is unit-testable with a synthetic fixture.
func parseProcStatCores(r io.Reader) ([]coreSnapshot, error) {
	var snaps []coreSnapshot
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu") || line[:4] == "cpu " {
			continue // skip aggregate "cpu" line, keep cpu0..cpuN
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		coreNum, err := strconv.Atoi(fields[0][3:])
		if err != nil {
			continue
		}
		parse := func(i int) uint64 {
			n, _ := strconv.ParseUint(fields[i], 10, 64)
			return n
		}
		snaps = append(snaps, coreSnapshot{
			core:    coreNum,
			user:    parse(1),
			nice:    parse(2),
			sys:     parse(3),
			idle:    parse(4),
			iowait:  parse(5),
			irq:     parse(6),
			softirq: parse(7),
			steal:   parse(8),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning /proc/stat: %w", err)
	}
	return snaps, nil
}

func computeCoreUsage(s1, s2 []coreSnapshot) []models.CoreStat {
	m1 := make(map[int]coreSnapshot, len(s1))
	for _, s := range s1 {
		m1[s.core] = s
	}
	stats := make([]models.CoreStat, 0, len(s2))
	for _, b := range s2 {
		a, ok := m1[b.core]
		if !ok {
			continue
		}
		dtotal := b.total() - a.total()
		dbusy := b.busy() - a.busy()
		pct := 0.0
		if dtotal > 0 {
			pct = float64(dbusy) / float64(dtotal) * 100
		}
		stats = append(stats, models.CoreStat{Core: b.core, UsagePct: pct})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Core < stats[j].Core })
	return stats
}

// topMemoryProcs reads /proc/<pid>/status for RSS and returns top N by RSS.
func topMemoryProcs(n int) ([]models.ProcessMemStat, float64) {
	entries, err := glob("/proc/[0-9]*")
	if err != nil {
		return nil, 0
	}

	// Get total RAM for percentage calculation
	totalKB := uint64(0)
	if data, err := readFile("/proc/meminfo"); err == nil { // #nosec G304
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					totalKB, _ = strconv.ParseUint(fields[1], 10, 64)
				}
				break
			}
		}
	}

	var procs []models.ProcessMemStat
	totalRSSKB := uint64(0)

	for _, entry := range entries {
		statusPath := filepath.Join(entry, "status")
		data, err := readFile(filepath.Clean(statusPath)) // #nosec G304
		if err != nil {
			continue
		}

		var name string
		var rssKB uint64
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Name:") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			} else if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					rssKB, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			}
		}
		if rssKB == 0 || name == "" {
			continue
		}

		pid, _ := strconv.Atoi(filepath.Base(entry))
		pct := 0.0
		if totalKB > 0 {
			pct = float64(rssKB) / float64(totalKB) * 100
		}
		procs = append(procs, models.ProcessMemStat{
			PID:         pid,
			Name:        name,
			RSSMB:       float64(rssKB) / 1024,
			MemPct:      pct,
			CgroupScope: cgroupScope(pid),
		})
		totalRSSKB += rssKB
	}

	// Sort by RSS descending, take top N
	sort.Slice(procs, func(i, j int) bool { return procs[i].RSSMB > procs[j].RSSMB })
	if len(procs) > n {
		procs = procs[:n]
	}
	return procs, float64(totalRSSKB) / 1024
}

// topIOSample is the cached result of sampleTopIOProcs — the derived top-N
// list plus a partial-visibility flag, recorded as one unit so replay
// reproduces both the ranking and the caveat verbatim.
type topIOSample struct {
	Procs     []models.ProcessIOStat
	NeedsRoot bool
}

// procIOCounters holds the raw read_bytes/write_bytes counters for one PID.
type procIOCounters struct {
	name       string
	readBytes  uint64
	writeBytes uint64
}

// procCommName reads /proc/<pid>/comm for a process name, "?" on error.
func procCommName(pid int) string {
	data, err := readFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")) // #nosec G304
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}

// readAllProcIO reads /proc/<pid>/io for every process, returning the raw
// counters keyed by PID. needsRoot is true when at least one read was denied
// for lack of privilege — that process's I/O is invisible to this sample, so
// the ranking below may not reflect the true top consumer.
func readAllProcIO() (map[int]procIOCounters, bool) {
	entries, err := glob("/proc/[0-9]*")
	if err != nil {
		return nil, false
	}
	result := make(map[int]procIOCounters, len(entries))
	needsRoot := false
	for _, entry := range entries {
		pid, err := strconv.Atoi(filepath.Base(entry))
		if err != nil {
			continue
		}
		data, err := readFile(filepath.Join(entry, "io")) // #nosec G304
		if err != nil {
			if os.IsPermission(err) {
				needsRoot = true
			}
			continue
		}
		var readBytes, writeBytes uint64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch fields[0] {
			case "read_bytes:":
				readBytes, _ = strconv.ParseUint(fields[1], 10, 64)
			case "write_bytes:":
				writeBytes, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
		result[pid] = procIOCounters{name: procCommName(pid), readBytes: readBytes, writeBytes: writeBytes}
	}
	return result, needsRoot
}

// sampleTopIOProcs takes two /proc/<pid>/io snapshots 500ms apart and returns
// the top-n processes by combined read+write bytes/sec (Spec 5.3 — iowait
// culprit attribution: names the process behind a busy device, not just the
// device itself).
func (c *HealthDeepCollector) sampleTopIOProcs(ctx context.Context, n int) topIOSample {
	before, needsRoot1 := readAllProcIO()
	select {
	case <-ctx.Done():
		return topIOSample{}
	case <-time.After(500 * time.Millisecond):
	}
	after, needsRoot2 := readAllProcIO()

	procs := computeTopIORates(before, after, n)
	for i := range procs {
		procs[i].CgroupScope = cgroupScope(procs[i].PID)
	}
	return topIOSample{
		Procs:     procs,
		NeedsRoot: needsRoot1 || needsRoot2,
	}
}

// computeTopIORates turns two /proc/<pid>/io snapshots into the top-n
// processes by combined read+write bytes/sec. Split out from
// sampleTopIOProcs so the rate math is unit-testable without a live /proc.
func computeTopIORates(before, after map[int]procIOCounters, n int) []models.ProcessIOStat {
	type ioRate struct {
		pid      int
		name     string
		totalBps float64
		readBps  float64
		writeBps float64
	}
	rates := make([]ioRate, 0, len(after))
	for pid, a := range after {
		b, ok := before[pid]
		if !ok || a.readBytes < b.readBytes || a.writeBytes < b.writeBytes {
			// New or recycled PID within the window — skip (see the identical
			// guard in drilldown.topProcessesByIOLinux for why).
			continue
		}
		readBps := float64(a.readBytes-b.readBytes) / 0.5
		writeBps := float64(a.writeBytes-b.writeBytes) / 0.5
		total := readBps + writeBps
		if total > 0 {
			rates = append(rates, ioRate{pid: pid, name: a.name, totalBps: total, readBps: readBps, writeBps: writeBps})
		}
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i].totalBps > rates[j].totalBps })
	if len(rates) > n {
		rates = rates[:n]
	}

	procs := make([]models.ProcessIOStat, 0, len(rates))
	for _, r := range rates {
		procs = append(procs, models.ProcessIOStat{PID: r.pid, Name: r.name, ReadBps: r.readBps, WriteBps: r.writeBps})
	}
	return procs
}

// procCPUCounters holds the raw utime+stime tick counters for one PID.
type procCPUCounters struct {
	name  string
	ticks uint64 // utime + stime, in clock ticks
}

// readAllProcCPU reads /proc/<pid>/stat for every process, returning utime+stime
// tick counters keyed by PID, plus the system-wide aggregate tick total (the
// "cpu " line of /proc/stat) needed to normalize per-process ticks into a %.
func readAllProcCPU() (map[int]procCPUCounters, uint64) {
	entries, err := glob("/proc/[0-9]*")
	if err != nil {
		return nil, 0
	}
	result := make(map[int]procCPUCounters, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(filepath.Base(entry))
		if err != nil {
			continue
		}
		data, err := readFile(filepath.Join(entry, "stat")) // #nosec G304
		if err != nil {
			continue
		}
		utime, stime, ok := parseProcStatUtimeStime(string(data))
		if !ok {
			continue
		}
		result[pid] = procCPUCounters{name: procCommName(pid), ticks: utime + stime}
	}
	return result, systemTotalTicks()
}

// systemTotalTicks reads the aggregate "cpu " line of /proc/stat and sums its
// fields into one system-wide tick total, used to normalize per-process CPU
// ticks into a percentage.
func systemTotalTicks() uint64 {
	data, err := readFile("/proc/stat") // #nosec G304
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		var total uint64
		for _, f := range strings.Fields(line)[1:] {
			v, _ := strconv.ParseUint(f, 10, 64)
			total += v
		}
		return total
	}
	return 0
}

// parseProcStatUtimeStime extracts utime (field 14) and stime (field 15) from a
// /proc/<pid>/stat line. The comm field (2) is parenthesized and may itself
// contain spaces/parens un-escaped by the kernel (e.g. "(Web Content)"), so the
// fields after it are located from the LAST ')', not a naive whitespace split —
// same concern internal/drilldown/procstat.go documents for the same file.
func parseProcStatUtimeStime(stat string) (utime, stime uint64, ok bool) {
	closeIdx := strings.LastIndexByte(stat, ')')
	if closeIdx < 0 {
		return 0, 0, false
	}
	rest := strings.Fields(stat[closeIdx+1:])
	if len(rest) < 13 {
		return 0, 0, false
	}
	utime, _ = strconv.ParseUint(rest[11], 10, 64) // stat field 14
	stime, _ = strconv.ParseUint(rest[12], 10, 64) // stat field 15
	return utime, stime, true
}

// sampleTopCPUProcs takes two /proc/<pid>/stat snapshots 500ms apart and returns
// the top-n processes by CPU% — utime+stime delta over the system-wide tick
// delta, scaled by core count. Matches top/htop's per-process %CPU convention,
// which can exceed 100% for a multi-threaded process.
func (c *HealthDeepCollector) sampleTopCPUProcs(ctx context.Context, n int) []models.ProcessCPUStat {
	before, sysBefore := readAllProcCPU()
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(500 * time.Millisecond):
	}
	after, sysAfter := readAllProcCPU()

	procs := computeTopCPURates(before, after, sysAfter-sysBefore, n)
	for i := range procs {
		procs[i].CgroupScope = cgroupScope(procs[i].PID)
	}
	return procs
}

// computeTopCPURates turns two /proc/<pid>/stat snapshots into the top-n
// processes by CPU%. Split out from sampleTopCPUProcs so the rate math is
// unit-testable without a live /proc.
func computeTopCPURates(before, after map[int]procCPUCounters, sysDeltaTicks uint64, n int) []models.ProcessCPUStat {
	if sysDeltaTicks == 0 {
		sysDeltaTicks = 1
	}
	type cpuRate struct {
		pid  int
		name string
		pct  float64
	}
	rates := make([]cpuRate, 0, len(after))
	for pid, a := range after {
		b, ok := before[pid]
		if !ok || a.ticks < b.ticks {
			// New or recycled PID within the window — skip (same guard as
			// computeTopIORates above).
			continue
		}
		delta := float64(a.ticks - b.ticks)
		pct := delta / float64(sysDeltaTicks) * float64(runtime.NumCPU()) * 100
		if pct > 0.01 {
			rates = append(rates, cpuRate{pid: pid, name: a.name, pct: pct})
		}
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i].pct > rates[j].pct })
	if len(rates) > n {
		rates = rates[:n]
	}

	procs := make([]models.ProcessCPUStat, 0, len(rates))
	for _, r := range rates {
		procs = append(procs, models.ProcessCPUStat{PID: r.pid, Name: r.name, CPUPct: r.pct})
	}
	return procs
}

// collectMemDetail reads extended memory fields from /proc/meminfo.
func collectMemDetail(info *models.HealthDeepInfo) {
	data, err := readFile("/proc/meminfo") // #nosec G304
	if err != nil {
		return
	}
	parse := func(line string) float64 {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		return parseFloat(fields[1]) / 1024 // kB → MB
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "Cached:"):
			info.CachedMB = parse(line)
		case strings.HasPrefix(line, "Buffers:"):
			info.BuffersMB = parse(line)
		case strings.HasPrefix(line, "Dirty:"):
			info.DirtyMB = parse(line)
		case strings.HasPrefix(line, "AnonPages:"):
			info.AnonPagesMB = parse(line)
		}
	}
}

// ── cgroup v2 slice summary ───────────────────────────────────────────────────

const cgroupRoot = "/sys/fs/cgroup"

// collectCgroupV2 reads cgroup v2 top-level slices and surfaces
// CPU throttling, memory pressure, and I/O stats.
// Works on any kernel ≥ 4.15 with unified hierarchy mounted.
func collectCgroupV2() *models.CgroupV2Info {
	// Verify cgroup v2 is mounted (unified hierarchy)
	if !fileExists(cgroupRoot + "/cgroup.controllers") {
		return nil
	}

	cg := &models.CgroupV2Info{Available: true}

	// Controllers available at root
	if data, err := readFile(cgroupRoot + "/cgroup.controllers"); err == nil { // #nosec G304
		cg.Controllers = strings.Fields(strings.TrimSpace(string(data)))
	}

	// Slices: system.slice, user.slice, machine.slice, init.scope
	sliceDirs, _ := glob(cgroupRoot + "/*.slice")
	scopeDirs, _ := glob(cgroupRoot + "/*.scope")
	sliceDirs = append(sliceDirs, scopeDirs...)

	for _, dir := range sliceDirs {
		name := filepath.Base(dir)
		s := readCgroupSlice(dir, name)
		cg.Slices = append(cg.Slices, s)
		if s.ThrottledPct > 5 {
			cg.ThrottledSlices = append(cg.ThrottledSlices, name)
		}
	}

	// OOM kills from root memory.events
	cg.OOMKills = readCgroupOOMKills(cgroupRoot + "/memory.events")

	return cg
}

// candidateCgroupUnitDirs returns directories to inspect for the per-unit
// drill-down: systemd service units and container scopes under system.slice,
// container scopes under machine.slice (Docker/Podman via the systemd cgroup
// driver), and the flat docker/ root (Docker via the cgroupfs driver).
// The multi-level kubepods.slice QoS hierarchy (best-effort/burstable/
// guaranteed → pod → container) is intentionally out of scope here —
// `dsd k8s deep` already owns pod-level diagnosis.
func candidateCgroupUnitDirs() []string {
	var dirs []string
	for _, pattern := range []string{
		cgroupRoot + "/system.slice/*.service",
		cgroupRoot + "/system.slice/*.scope",
		cgroupRoot + "/machine.slice/*.scope",
		cgroupRoot + "/docker/*",
	} {
		if matches, err := glob(pattern); err == nil {
			dirs = append(dirs, matches...)
		}
	}
	return dirs
}

// classifyCgroupUnitDir turns a candidate unit directory's parent slice name
// and base directory name into an IsContainer flag and a display label —
// "<name>.service" as-is for systemd units, "container:<id12>" for Docker
// (both cgroup drivers) and Podman.
func classifyCgroupUnitDir(parentSlice, dirName string) (isContainer bool, label string) {
	switch {
	case parentSlice == "docker":
		return true, containerIDLabel(dirName)
	case strings.HasPrefix(dirName, "docker-"):
		return true, containerIDLabel(strings.TrimPrefix(dirName, "docker-"))
	case strings.HasPrefix(dirName, "libpod-"):
		return true, containerIDLabel(strings.TrimPrefix(dirName, "libpod-"))
	default:
		return false, dirName
	}
}

// cgroupUnitSignificant reports whether a unit crosses the "significant
// usage" bar from Gap Spec §5 — >5% CPU or >500MB RAM. This cap is decided
// here in the collector (not analysis), matching the existing top-N
// convention for TopProcs/TopCPUProcs/TopIOProcs: it bounds how many rows the
// per-unit summary carries, it is not a health verdict.
func cgroupUnitSignificant(cpuPct, memCurrentMB float64) bool {
	return cpuPct > 5 || memCurrentMB > 500
}

// cgroupRawSample holds one candidate unit directory's raw readings — the
// I/O boundary between the live sampler and the pure, unit-testable
// computeCgroupUnits below.
type cgroupRawSample struct {
	dir             string
	usageBeforeUSec int64
	usageAfterUSec  int64
	throttledPct    float64
	hasCPULimit     bool
	memCurrentMB    float64
	memLimitMB      float64
	hasMemLimit     bool
}

// sampleCgroupUnits takes two cpu.stat usage_usec snapshots ~500ms apart for
// each candidate unit directory and returns the significant units (see
// cgroupUnitSignificant), sorted by CPU% then memory descending and capped
// at 15 to bound /sys/fs/cgroup walk cost and output size.
func (c *HealthDeepCollector) sampleCgroupUnits(ctx context.Context) []models.CgroupUnit {
	dirs := candidateCgroupUnitDirs()
	if len(dirs) == 0 {
		return nil
	}

	before := make(map[string]int64, len(dirs))
	for _, dir := range dirs {
		before[dir] = readCgroupCPUUsageUSec(dir)
	}

	start := time.Now()
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(500 * time.Millisecond):
	}
	elapsedUSec := float64(time.Since(start).Microseconds())

	samples := make([]cgroupRawSample, 0, len(dirs))
	for _, dir := range dirs {
		memCurrentMB, memLimitMB, hasMemLimit := readCgroupMem(dir)
		samples = append(samples, cgroupRawSample{
			dir:             dir,
			usageBeforeUSec: before[dir],
			usageAfterUSec:  readCgroupCPUUsageUSec(dir),
			throttledPct:    readCgroupThrottledPct(dir),
			hasCPULimit:     readCgroupCPULimit(dir),
			memCurrentMB:    memCurrentMB,
			memLimitMB:      memLimitMB,
			hasMemLimit:     hasMemLimit,
		})
	}
	return computeCgroupUnits(samples, elapsedUSec)
}

// computeCgroupUnits turns raw per-directory samples into the significant-
// usage unit list: CPU% from the usage_usec delta over elapsedUSec, filtered
// by cgroupUnitSignificant, classified via classifyCgroupUnitDir, and sorted
// by CPU% then memory descending, capped at 15. Split out from
// sampleCgroupUnits so the math is unit-testable without live /sys reads or
// the 500ms sample wait — mirrors computeTopCPURates/computeTopIORates above.
func computeCgroupUnits(samples []cgroupRawSample, elapsedUSec float64) []models.CgroupUnit {
	if elapsedUSec <= 0 {
		elapsedUSec = 500000 // fall back to the nominal 500ms window, same guard as computeTopCPURates' sysDeltaTicks==0 case
	}

	var units []models.CgroupUnit
	for _, s := range samples {
		delta := max(s.usageAfterUSec-s.usageBeforeUSec, 0)
		cpuPct := float64(delta) / elapsedUSec * 100
		if !cgroupUnitSignificant(cpuPct, s.memCurrentMB) {
			continue
		}

		parentSlice := filepath.Base(filepath.Dir(s.dir))
		isContainer, label := classifyCgroupUnitDir(parentSlice, filepath.Base(s.dir))

		u := models.CgroupUnit{
			Name:         label,
			ParentSlice:  parentSlice,
			IsContainer:  isContainer,
			CPUPct:       cpuPct,
			ThrottledPct: s.throttledPct,
			MemCurrentMB: s.memCurrentMB,
			MemLimitMB:   s.memLimitMB,
			HasCPULimit:  s.hasCPULimit,
			HasMemLimit:  s.hasMemLimit,
		}
		if s.hasMemLimit && s.memLimitMB > 0 {
			u.MemUsedPct = s.memCurrentMB / s.memLimitMB * 100
		}
		units = append(units, u)
	}

	sort.Slice(units, func(i, j int) bool {
		if units[i].CPUPct != units[j].CPUPct {
			return units[i].CPUPct > units[j].CPUPct
		}
		return units[i].MemCurrentMB > units[j].MemCurrentMB
	})
	if len(units) > 15 {
		units = units[:15]
	}
	return units
}

// readCgroupThrottledPct reads cpu.stat and returns the lifetime throttled
// fraction (throttled_usec / usage_usec, 0-100). Returns 0 when the file is
// unreadable or usage_usec is 0.
func readCgroupThrottledPct(dir string) float64 {
	usageUSec, throttledUSec := readCgroupCPUStat(dir)
	if usageUSec == 0 {
		return 0
	}
	return float64(throttledUSec) / float64(usageUSec) * 100
}

// readCgroupCPUUsageUSec reads cpu.stat's usage_usec field alone — used for
// two-sample CPU% delta sampling of individual units (see sampleCgroupUnits).
func readCgroupCPUUsageUSec(dir string) int64 {
	usageUSec, _ := readCgroupCPUStat(dir)
	return usageUSec
}

// readCgroupCPUStat parses cpu.stat's usage_usec and throttled_usec fields,
// shared by readCgroupThrottledPct and readCgroupCPUUsageUSec.
func readCgroupCPUStat(dir string) (usageUSec, throttledUSec int64) {
	data, err := readFile(dir + "/cpu.stat") // #nosec G304
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "usage_usec":
			usageUSec = val
		case "throttled_usec":
			throttledUSec = val
		}
	}
	return usageUSec, throttledUSec
}

// readCgroupCPULimit reports whether cpu.max sets a quota — "max 100000"
// (the default) means unlimited.
func readCgroupCPULimit(dir string) bool {
	data, err := readFile(dir + "/cpu.max") // #nosec G304
	if err != nil {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	return len(fields) >= 1 && fields[0] != "max"
}

// readCgroupMem reads memory.current/memory.max, returning both in MB.
// limitMB is -1 when unlimited ("max") or unreadable.
func readCgroupMem(dir string) (currentMB, limitMB float64, hasLimit bool) {
	limitMB = -1
	if data, err := readFile(dir + "/memory.current"); err == nil { // #nosec G304
		if n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			currentMB = float64(n) / (1024 * 1024)
		}
	}
	if data, err := readFile(dir + "/memory.max"); err == nil { // #nosec G304
		val := strings.TrimSpace(string(data))
		if val != "max" {
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				limitMB = float64(n) / (1024 * 1024)
				hasLimit = true
			}
		}
	}
	return currentMB, limitMB, hasLimit
}

// readCgroupSlice reads metrics for one cgroup v2 slice directory.
func readCgroupSlice(dir, name string) models.CgroupSlice {
	s := models.CgroupSlice{Name: name}
	s.ThrottledPct = readCgroupThrottledPct(dir)
	s.HasCPULimit = readCgroupCPULimit(dir)
	s.MemCurrentMB, s.MemLimitMB, s.HasMemLimit = readCgroupMem(dir)
	if s.HasMemLimit && s.MemLimitMB > 0 {
		s.MemUsedPct = s.MemCurrentMB / s.MemLimitMB * 100
	}

	// I/O: io.stat — sum across all block devices
	if data, err := readFile(dir + "/io.stat"); err == nil { // #nosec G304
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			// Format: "253:0 rbytes=N wbytes=N rios=N wios=N ..."
			// Some lines may have only the device with no stats — skip them
			if len(fields) < 2 {
				continue
			}
			for _, f := range fields[1:] {
				kv := strings.SplitN(f, "=", 2)
				if len(kv) != 2 {
					continue
				}
				n, _ := strconv.ParseInt(kv[1], 10, 64)
				switch kv[0] {
				case "rbytes":
					s.IOReadMBs += float64(n) / (1024 * 1024)
				case "wbytes":
					s.IOWriteMBs += float64(n) / (1024 * 1024)
				}
			}
		}
	}

	return s
}

// readCgroupOOMKills reads the oom_kill counter from a memory.events file.
func readCgroupOOMKills(path string) int {
	data, err := readFile(path) // #nosec G304
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "oom_kill ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				n, _ := strconv.Atoi(fields[1])
				return n
			}
		}
	}
	return 0
}

// cgroupScope reads /proc/<pid>/cgroup and returns a human-readable scope label.
// Format: "system:<service>", "container:<id-prefix>", "user:<uid>", "kernel", "init", or "unknown".
func cgroupScope(pid int) string {
	return cgroupScopeIn("/proc", strconv.Itoa(pid))
}

// scopeIsContainer reports whether a parseCgroupPath scope label denotes a container
// (Docker/Podman/Kubernetes pod) as opposed to the host (kernel/init/system:/user:).
func scopeIsContainer(scope string) bool {
	return strings.HasPrefix(scope, "container") ||
		strings.HasPrefix(scope, "k8s") ||
		strings.HasPrefix(scope, "pod:")
}

// pidIsContainerizedIn reports whether <procDir>/<pid> belongs to a container rather
// than the host, by classifying its cgroup. Host service collectors (Nginx/Apache/
// HAProxy/BIND…) use it to ignore containerized processes that are visible in the host
// PID namespace: running a host-level check such as `nginx -t` against a service that
// actually lives in a container misreports (found on an Alpine Docker host, 2026-07-01
// — a container's nginx was flagged as a host nginx with a bogus "needs root" config
// message). Container health belongs to the Docker/k8s collector. An unreadable cgroup
// → false (treat as host; never hide a real host service because its cgroup was
// unreadable). procDir is parameterized so process-scan callers classify against the
// same /proc they enumerated (and tests against a fixture tree).
func pidIsContainerizedIn(procDir, pid string) bool {
	return scopeIsContainer(cgroupScopeIn(procDir, pid))
}

// cgroupScopeIn reads <procDir>/<pid>/cgroup and returns the human-readable scope.
func cgroupScopeIn(procDir, pid string) string {
	data, err := readFile(filepath.Join(procDir, pid, "cgroup")) // #nosec G304
	if err != nil {
		return ""
	}
	// cgroup v2: single line "0::/<path>"
	// cgroup v1: multiple lines "N:<subsystem>:<path>"
	// We want the v2 unified hierarchy path (line starting with "0::")
	cgPath := ""
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") {
			cgPath = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if cgPath == "" {
		// cgroup v1 fallback — use cpu subsystem path
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.Contains(line, ":cpu:") || strings.Contains(line, ":cpu,") {
				parts := strings.SplitN(line, ":", 3)
				if len(parts) == 3 {
					cgPath = parts[2]
					break
				}
			}
		}
	}
	return parseCgroupPath(cgPath)
}

// containerIDLabel trims a trailing ".scope" and truncates a container ID to
// its conventional 12-char display prefix (matching `docker ps`), returning
// a "container:<id>" scope label. Shared by parseCgroupPath's docker and
// libpod branches, and by classifyCgroupUnitDir.
func containerIDLabel(rawID string) string {
	id := strings.TrimSuffix(rawID, ".scope")
	if len(id) >= 12 {
		id = id[:12]
	}
	return "container:" + id
}

// parseCgroupPath converts a raw cgroup path to a human-readable scope label.
func parseCgroupPath(path string) string {
	path = strings.TrimSpace(path)
	switch {
	case path == "" || path == "/":
		return "kernel"
	case path == "/init.scope":
		return "init"
	case strings.Contains(path, "/docker/") || strings.Contains(path, "docker-"):
		// Extract container ID prefix: /docker/<64-char-id>
		parts := strings.Split(path, "/docker/")
		if len(parts) >= 2 {
			return containerIDLabel(parts[1])
		}
		return "container"
	case strings.Contains(path, "libpod-") || strings.Contains(path, "machine.slice"):
		// Podman: machine.slice/libpod-<id>.scope
		if idx := strings.Index(path, "libpod-"); idx >= 0 {
			return containerIDLabel(strings.TrimPrefix(path[idx:], "libpod-"))
		}
		if idx := strings.Index(path, "libpod_pod"); idx >= 0 {
			return "pod:podman"
		}
		return "container"
	case strings.Contains(path, "/kubepods/") || strings.Contains(path, "kubepods"):
		// Kubernetes pod
		parts := strings.Split(path, "/")
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.HasPrefix(parts[i], "pod") {
				podID := strings.TrimPrefix(parts[i], "pod")
				if len(podID) > 8 {
					return "k8s-pod:" + podID[:8]
				}
				return "k8s-pod:" + podID
			}
		}
		return "k8s"
	case strings.HasPrefix(path, "/system.slice/"):
		svc := strings.TrimPrefix(path, "/system.slice/")
		// Strip nested path: "k3s.service/..." → "k3s.service"
		if idx := strings.Index(svc, "/"); idx > 0 {
			svc = svc[:idx]
		}
		return "system:" + svc
	case strings.HasPrefix(path, "/user.slice/"):
		uid := path
		if idx := strings.Index(path, "user-"); idx >= 0 {
			rest := path[idx+5:]
			if dot := strings.Index(rest, "."); dot > 0 {
				uid = rest[:dot]
			}
		}
		return "user:" + uid
	default:
		// Generic: return last path segment
		parts := strings.Split(strings.TrimRight(path, "/"), "/")
		if len(parts) > 0 && parts[len(parts)-1] != "" {
			return parts[len(parts)-1]
		}
		return "unknown"
	}
}
