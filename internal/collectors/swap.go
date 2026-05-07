package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/mem"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

type swapReaders struct {
	vmstatOpen func() (io.ReadCloser, error)
}

type SwapCollector struct {
	readers      swapReaders
	swapsPath    string
	ContainerCtx platform.ContainerContext
}

func NewSwapCollector(ctx platform.ContainerContext) *SwapCollector {
	return &SwapCollector{
		ContainerCtx: ctx,
		swapsPath:    "/proc/swaps",
		readers: swapReaders{
			vmstatOpen: func() (io.ReadCloser, error) { return os.Open("/proc/vmstat") },
		},
	}
}

func (c *SwapCollector) Name() string           { return "Swap" }
func (c *SwapCollector) Timeout() time.Duration { return 3 * time.Second }

// parseVMStat finds "pswpin N" and "pswpout N" lines in /proc/vmstat.
func parseVMStat(r io.Reader) (pswpin, pswpout uint64, err error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "pswpin":
			pswpin, err = strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("parsing pswpin: %w", err)
			}
		case "pswpout":
			pswpout, err = strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("parsing pswpout: %w", err)
			}
		}
	}
	return pswpin, pswpout, scanner.Err()
}

// parseSwaps parses /proc/swaps for total and used kB across all swap devices.
func parseSwaps(r io.Reader) (totalKB, usedKB uint64, err error) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		size, e1 := strconv.ParseUint(fields[2], 10, 64)
		used, e2 := strconv.ParseUint(fields[3], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		totalKB += size
		usedKB += used
	}
	return totalKB, usedKB, scanner.Err()
}

func (c *SwapCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}

	// Sample 1
	r1, err := c.readers.vmstatOpen()
	if err != nil {
		return nil, fmt.Errorf("opening vmstat: %w", err)
	}
	pin1, pout1, _ := parseVMStat(r1)
	r1.Close()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(time.Second):
	}

	// Sample 2
	r2, err := c.readers.vmstatOpen()
	if err != nil {
		return nil, fmt.Errorf("opening vmstat (2nd): %w", err)
	}
	pin2, pout2, _ := parseVMStat(r2)
	r2.Close()

	info := &models.SwapInfo{
		PagesInPerSec:  float64(pin2 - pin1),
		PagesOutPerSec: float64(pout2 - pout1),
	}
	if pin2 < pin1 {
		info.PagesInPerSec = 0
	}
	if pout2 < pout1 {
		info.PagesOutPerSec = 0
	}

	// /proc/swaps for totals
	sf, err := os.Open(c.swapsPath)
	if err == nil {
		totalKB, usedKB, _ := parseSwaps(sf)
		sf.Close()
		info.TotalGB = float64(totalKB) / (1024 * 1024)
		info.UsedGB = float64(usedKB) / (1024 * 1024)
		if totalKB > 0 {
			info.UsedPct = float64(usedKB) / float64(totalKB) * 100
		}
	}

	// Zram devices
	zrams, _ := filepath.Glob("/sys/block/zram*")
	info.ZramDevices = len(zrams)

	return info, nil
}

func (c *SwapCollector) collectDarwin(ctx context.Context) (*models.SwapInfo, error) {
	swap, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		return &models.SwapInfo{PagesInPerSec: -1, PagesOutPerSec: -1}, nil
	}
	return &models.SwapInfo{
		TotalGB:        float64(swap.Total) / (1024 * 1024 * 1024),
		UsedGB:         float64(swap.Used) / (1024 * 1024 * 1024),
		UsedPct:        swap.UsedPercent,
		PagesInPerSec:  -1,
		PagesOutPerSec: -1,
	}, nil
}
