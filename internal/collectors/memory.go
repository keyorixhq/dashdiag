package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/mem"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

type MemoryCollector struct {
	meminfoPath  string
	ContainerCtx platform.ContainerContext
}

func NewMemoryCollector(ctx platform.ContainerContext) *MemoryCollector {
	return &MemoryCollector{
		meminfoPath:  "/proc/meminfo",
		ContainerCtx: ctx,
	}
}

func (c *MemoryCollector) Name() string           { return "Memory" }
func (c *MemoryCollector) Timeout() time.Duration { return 200 * time.Millisecond }

// parseMeminfo parses /proc/meminfo lines of the form "Key: value kB".
// Returns a map of key → value in kB.
func parseMeminfo(r io.Reader) (map[string]uint64, error) {
	result := make(map[string]uint64)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valStr := strings.TrimSpace(parts[1])
		valStr = strings.TrimSuffix(valStr, " kB")
		val, err := strconv.ParseUint(valStr, 10, 64)
		if err != nil {
			continue
		}
		result[key] = val
	}
	return result, scanner.Err()
}

func (c *MemoryCollector) Collect(ctx context.Context) (any, error) {
	info := &models.MemoryInfo{}

	// Primary source on Linux: /proc/meminfo via the active source, so
	// `dsd capture --raw` records it and `dsd replay` reproduces these numbers
	// instead of gopsutil re-reading the live host — which made Total/Free/UsedPct
	// reflect the replaying machine, not the bundle (ADR-0003 replay fidelity).
	// gopsutil's own Linux path just parses this same file; we read it through
	// Source for the identical math. Non-Linux (no /proc/meminfo) falls back to
	// gopsutil below.
	var m map[string]uint64
	if f, err := openFile(c.meminfoPath); err == nil {
		m, _ = parseMeminfo(f)
		_ = f.Close()
	}

	switch {
	case m["MemTotal"] > 0:
		total := m["MemTotal"]
		avail, ok := m["MemAvailable"]
		if !ok {
			// Pre-3.14 kernels lack MemAvailable; approximate it the way gopsutil
			// does so we stay self-contained (no live re-read on replay).
			avail = m["MemFree"] + m["Buffers"] + m["Cached"] + m["SReclaimable"]
		}
		info.TotalGB = float64(total) / (1024 * 1024)
		info.FreeGB = float64(avail) / (1024 * 1024)
		// Matches gopsutil v3: UsedPercent = (Total-Available)/Total * 100.
		info.UsedPct = float64(total-avail) / float64(total) * 100
	case runtime.GOOS != "linux":
		// Non-Linux (darwin): no /proc/meminfo, so the Source-routed read above
		// never applies here — a genuine live read is the only option.
		var vm mem.VirtualMemoryStat
		if err := cachedJSON("gopsutil/mem/virtual", func() (any, error) {
			return mem.VirtualMemoryWithContext(ctx)
		}, &vm); err != nil {
			return nil, fmt.Errorf("virtual memory: %w", err)
		}
		info.TotalGB = float64(vm.Total) / (1024 * 1024 * 1024)
		info.FreeGB = float64(vm.Available) / (1024 * 1024 * 1024)
		info.UsedPct = vm.UsedPercent
	default:
		// Linux, but /proc/meminfo couldn't be read or parsed through the active
		// Source — e.g. a replay bundle that never recorded it. Falling through to
		// a gopsutil live read here would silently report the REPLAYING machine's
		// own memory instead of the captured host's, breaking replay hermeticity
		// (internal-collectors-20-04). Report unmeasured instead of guessing.
		info.MeminfoUnreadable = true
	}

	// ECC memory errors — cheap sysfs read; zero on VMs/consumer HW and non-Linux.
	// Surfaced here so a failing DIMM is caught by routine `dsd health` rather than
	// only by the heavier `dsd hardware`.
	info.EDACAvailable, info.CorrectedErrors, info.UncorrectedErrors = readEDACCounts()

	// Memory hot-plug onlining — catches hot-added RAM the guest never onlined
	// (and so isn't using). Cheap sysfs read; zero on non-hotplug kernels / non-Linux.
	info.MemHotplugChecked, info.OfflineMemoryBlocks, info.OfflineMemoryMB, info.AutoOnlineBlocks = readMemHotplug()

	// Container memory limit overrides total. UsedPct/FreeGB above were derived
	// from host-wide /proc/meminfo, which no longer means anything once TotalGB is
	// the container's ceiling — recompute them against the container's own cgroup
	// usage counter when it's readable. Otherwise leave CgroupMemMeasured false so
	// checkMemory knows not to score host-wide usage against a container limit
	// (a container pinned at its limit on an idle host would read healthy, and a
	// busy host would falsely paint an idle container as under pressure).
	if c.ContainerCtx.InContainer && c.ContainerCtx.MemLimitMB > 0 {
		info.TotalGB = c.ContainerCtx.MemLimitMB / 1024
		if usedBytes, ok := cgroupMemoryUsageBytes(c.ContainerCtx); ok {
			usedGB := float64(usedBytes) / (1024 * 1024 * 1024)
			freeGB := info.TotalGB - usedGB
			if freeGB < 0 {
				freeGB = 0
			}
			info.FreeGB = freeGB
			info.UsedPct = usedGB / info.TotalGB * 100
			info.CgroupMemMeasured = true
		}
	}

	// Extended fields from the same /proc/meminfo map parsed above.
	if m == nil {
		if runtime.GOOS == "darwin" {
			info.SlabMB = -1
			info.CommitLimitMB = -1
		}
		return info, nil
	}
	info.SlabMB = float64(m["Slab"]) / 1024
	info.CommitLimitMB = float64(m["CommitLimit"]) / 1024
	info.CommittedAsMB = float64(m["Committed_AS"]) / 1024
	info.OverCommitted = info.CommitLimitMB > 0 && info.CommittedAsMB > info.CommitLimitMB
	// vm.overcommit_memory mode — CommitLimit is only enforced in mode 2, so the
	// over-commit CRIT must gate on it (see checkMemory). Absent (non-Linux) → 0.
	info.OvercommitMode, _ = readIntFile("/proc/sys/vm/overcommit_memory")

	return info, nil
}
