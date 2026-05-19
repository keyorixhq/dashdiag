//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
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
func (c *HealthDeepCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *HealthDeepCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.HealthDeepInfo{}

	// Per-core CPU: two reads 500ms apart
	snap1, err := readProcStatCores()
	if err == nil {
		select {
		case <-ctx.Done():
			return info, nil
		case <-time.After(500 * time.Millisecond):
		}
		snap2, err2 := readProcStatCores()
		if err2 == nil {
			info.Cores = computeCoreUsage(snap1, snap2)
			if len(info.Cores) > 0 {
				info.MaxCorePct = info.Cores[0].UsagePct
				info.MinCorePct = info.Cores[0].UsagePct
				for _, c := range info.Cores {
					if c.UsagePct > info.MaxCorePct {
						info.MaxCorePct = c.UsagePct
					}
					if c.UsagePct < info.MinCorePct {
						info.MinCorePct = c.UsagePct
					}
				}
				info.CoreImbalance = info.MaxCorePct - info.MinCorePct
			}
		}
	}

	// Top memory consumers from /proc/<pid>/status
	info.TopProcs, info.TotalProcsMB = topMemoryProcs(10)

	// Extended memory breakdown
	collectMemDetail(info)

	// cgroup v2 slice summary
	info.Cgroup = collectCgroupV2()

	return info, nil
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
	f, err := os.Open("/proc/stat") // #nosec G304 -- hardcoded path
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	var snaps []coreSnapshot
	scanner := bufio.NewScanner(f)
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
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, 0
	}

	// Get total RAM for percentage calculation
	totalKB := uint64(0)
	if data, err := os.ReadFile("/proc/meminfo"); err == nil { // #nosec G304
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
		data, err := os.ReadFile(filepath.Clean(statusPath)) // #nosec G304
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
			PID:    pid,
			Name:   name,
			RSSMB:  float64(rssKB) / 1024,
			MemPct: pct,
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

// collectMemDetail reads extended memory fields from /proc/meminfo.
func collectMemDetail(info *models.HealthDeepInfo) {
	data, err := os.ReadFile("/proc/meminfo") // #nosec G304
	if err != nil {
		return
	}
	parse := func(line string) float64 {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		n, _ := strconv.ParseFloat(fields[1], 64)
		return n / 1024 // kB → MB
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

// fmtMB formats MB values compactly.
func fmtMB(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fGB", mb/1024)
	}
	return fmt.Sprintf("%.0fMB", mb)
}

// ── cgroup v2 slice summary ───────────────────────────────────────────────────

const cgroupRoot = "/sys/fs/cgroup"

// collectCgroupV2 reads cgroup v2 top-level slices and surfaces
// CPU throttling, memory pressure, and I/O stats.
// Works on any kernel ≥ 4.15 with unified hierarchy mounted.
func collectCgroupV2() *models.CgroupV2Info {
	// Verify cgroup v2 is mounted (unified hierarchy)
	if _, err := os.Stat(cgroupRoot + "/cgroup.controllers"); err != nil {
		return nil
	}

	cg := &models.CgroupV2Info{Available: true}

	// Controllers available at root
	if data, err := os.ReadFile(cgroupRoot + "/cgroup.controllers"); err == nil { // #nosec G304
		cg.Controllers = strings.Fields(strings.TrimSpace(string(data)))
	}

	// Slices: system.slice, user.slice, machine.slice, init.scope
	sliceDirs, _ := filepath.Glob(cgroupRoot + "/*.slice")
	scopeDirs, _ := filepath.Glob(cgroupRoot + "/*.scope")
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

// readCgroupSlice reads metrics for one cgroup v2 slice directory.
func readCgroupSlice(dir, name string) models.CgroupSlice {
	s := models.CgroupSlice{Name: name, MemLimitMB: -1}

	// CPU: cpu.stat — throttled_usec / usage_usec
	if data, err := os.ReadFile(dir + "/cpu.stat"); err == nil { // #nosec G304
		var usageUSec, throttledUSec int64
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
		if usageUSec > 0 {
			s.ThrottledPct = float64(throttledUSec) / float64(usageUSec) * 100
		}
	}

	// CPU limit: cpu.max "quota period" — "max 100000" means no limit
	if data, err := os.ReadFile(dir + "/cpu.max"); err == nil { // #nosec G304
		fields := strings.Fields(strings.TrimSpace(string(data)))
		if len(fields) >= 1 && fields[0] != "max" {
			s.HasCPULimit = true
		}
	}

	// Memory: memory.current (bytes)
	if data, err := os.ReadFile(dir + "/memory.current"); err == nil { // #nosec G304
		if n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			s.MemCurrentMB = float64(n) / (1024 * 1024)
		}
	}

	// Memory limit: memory.max
	if data, err := os.ReadFile(dir + "/memory.max"); err == nil { // #nosec G304
		val := strings.TrimSpace(string(data))
		if val != "max" {
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				s.MemLimitMB = float64(n) / (1024 * 1024)
				s.HasMemLimit = true
				if s.MemLimitMB > 0 {
					s.MemUsedPct = s.MemCurrentMB / s.MemLimitMB * 100
				}
			}
		}
	}

	// I/O: io.stat — sum across all block devices
	if data, err := os.ReadFile(dir + "/io.stat"); err == nil { // #nosec G304
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
	data, err := os.ReadFile(path) // #nosec G304
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
