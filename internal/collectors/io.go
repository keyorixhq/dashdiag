package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	gopsutildisk "github.com/shirou/gopsutil/v3/disk"

	"github.com/keyorixhq/dashdiag/internal/models"
)

var deviceRE = regexp.MustCompile(`^(sd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|xvd[a-z]+)$`)

type diskStatRaw struct {
	reads, writes             uint64
	readSectors, writeSectors uint64
	readTimeMs, writeTimeMs   uint64
	ioTimeMs                  uint64
}

type IOCollector struct {
	diskstatsPath string
}

func NewIOCollector() *IOCollector {
	return &IOCollector{diskstatsPath: "/proc/diskstats"}
}

func (c *IOCollector) Name() string           { return "IO" }
func (c *IOCollector) Timeout() time.Duration { return 4 * time.Second }

// parseDiskstats parses /proc/diskstats, returning only devices matching deviceRE.
// Fields (0-indexed): [2]=name [3]=reads [5]=readSectors [6]=readTimeMs
// [7]=writes [9]=writeSectors [10]=writeTimeMs [12]=ioTimeMs
func parseDiskstats(r io.Reader) (map[string]diskStatRaw, error) {
	result := make(map[string]diskStatRaw)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 13 {
			continue
		}
		name := fields[2]
		if !deviceRE.MatchString(name) {
			continue
		}
		parseU := func(i int) uint64 {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			return v
		}
		result[name] = diskStatRaw{
			reads:        parseU(3),
			readSectors:  parseU(5),
			readTimeMs:   parseU(6),
			writes:       parseU(7),
			writeSectors: parseU(9),
			writeTimeMs:  parseU(10),
			ioTimeMs:     parseU(12),
		}
	}
	return result, scanner.Err()
}

func readRotational(dev string) bool {
	data, err := os.ReadFile(filepath.Join("/sys/block", dev, "queue/rotational")) // #nosec G304 -- root is hardcoded to /sys/block; dev is from kernel diskstats, not user input
	if err != nil {
		return false // assume SSD on error
	}
	return strings.TrimSpace(string(data)) == "1"
}

func computeDelta(name string, before, after diskStatRaw) models.IODeviceInfo {
	var readSec, writeSec, ioMs uint64
	if after.readSectors >= before.readSectors {
		readSec = after.readSectors - before.readSectors
	}
	if after.writeSectors >= before.writeSectors {
		writeSec = after.writeSectors - before.writeSectors
	}
	if after.ioTimeMs >= before.ioTimeMs {
		ioMs = after.ioTimeMs - before.ioTimeMs
	}
	util := float64(ioMs) / 10.0
	if util > 100 {
		util = 100
	}
	var awaitMs float64
	ops := (after.reads + after.writes) - (before.reads + before.writes)
	if ops > 0 {
		totalTimeMs := (after.readTimeMs + after.writeTimeMs) - (before.readTimeMs + before.writeTimeMs)
		awaitMs = float64(totalTimeMs) / float64(ops)
	}
	return models.IODeviceInfo{
		Name:      name,
		IsSSD:     !readRotational(name),
		ReadMBps:  float64(readSec) * 512 / 1e6,
		WriteMBps: float64(writeSec) * 512 / 1e6,
		UtilPct:   util,
		AwaitMs:   awaitMs,
	}
}

func (c *IOCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}

	f1, err := os.Open(c.diskstatsPath)
	if err != nil {
		return nil, fmt.Errorf("opening diskstats: %w", err)
	}
	before, err := parseDiskstats(f1)
	_ = f1.Close()
	if err != nil {
		return nil, fmt.Errorf("parsing diskstats (1st): %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(1 * time.Second):
	}

	f2, err := os.Open(c.diskstatsPath)
	if err != nil {
		return nil, fmt.Errorf("opening diskstats (2nd): %w", err)
	}
	after, err := parseDiskstats(f2)
	_ = f2.Close()
	if err != nil {
		return nil, fmt.Errorf("parsing diskstats (2nd): %w", err)
	}

	result := &models.IOInfo{Devices: make([]models.IODeviceInfo, 0, len(after))}
	for name, afterStat := range after {
		result.Devices = append(result.Devices, computeDelta(name, before[name], afterStat))
	}
	return result, nil
}

func (c *IOCollector) collectDarwin(ctx context.Context) (*models.IOInfo, error) {
	counters, err := gopsutildisk.IOCountersWithContext(ctx)
	if err != nil {
		return &models.IOInfo{}, nil
	}
	result := &models.IOInfo{Devices: make([]models.IODeviceInfo, 0, len(counters))}
	for name, cnt := range counters {
		result.Devices = append(result.Devices, models.IODeviceInfo{
			Name:  name,
			IsSSD: true,
			// gopsutil returns cumulative bytes; rates unavailable without two-sample
			ReadMBps:  float64(cnt.ReadBytes) / 1e6,
			WriteMBps: float64(cnt.WriteBytes) / 1e6,
		})
	}
	return result, nil
}
