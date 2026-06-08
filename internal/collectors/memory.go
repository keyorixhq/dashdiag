package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
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

func (c *MemoryCollector) Collect(ctx context.Context) (interface{}, error) {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("virtual memory: %w", err)
	}

	info := &models.MemoryInfo{
		TotalGB: float64(vm.Total) / (1024 * 1024 * 1024),
		FreeGB:  float64(vm.Available) / (1024 * 1024 * 1024),
		UsedPct: vm.UsedPercent,
	}

	// ECC memory errors — cheap sysfs read; zero on VMs/consumer HW and non-Linux.
	// Surfaced here so a failing DIMM is caught by routine `dsd health` rather than
	// only by the heavier `dsd hardware`.
	info.EDACAvailable, info.CorrectedErrors, info.UncorrectedErrors = readEDACCounts()

	// Container memory limit overrides total
	if c.ContainerCtx.MemLimitMB > 0 {
		info.TotalGB = c.ContainerCtx.MemLimitMB / 1024
	}

	// Extended fields from /proc/meminfo
	f, err := os.Open(c.meminfoPath)
	if err != nil {
		if runtime.GOOS == "darwin" {
			info.SlabMB = -1
			info.CommitLimitMB = -1
			return info, nil
		}
		return info, nil
	}
	defer f.Close()

	m, err := parseMeminfo(f)
	if err != nil {
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
