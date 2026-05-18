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

// driveType returns "nvme", "ssd", or "hdd" by reading sysfs.
func driveType(dev string) string {
	if strings.HasPrefix(dev, "nvme") {
		return "nvme"
	}
	if readRotational(dev) {
		return "hdd"
	}
	return "ssd"
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
	dt := driveType(name)
	return models.IODeviceInfo{
		Name:      name,
		IsSSD:     dt != "hdd",
		DriveType: dt,
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
	// iostat -d -c 2 -w 1: two samples, 1-second interval, disk-only.
	// First row = since-boot average (skip). Second row = last-second rate.
	// Format: KB/t  tps  MB/s  (per device, space-separated)
	out, err := runCmd(ctx, "iostat", "-d", "-c", "2", "-w", "1")
	if err != nil || out == "" {
		return &models.IOInfo{}, nil
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	// lines[0] = device headers (disk0  disk1 ...)
	// lines[1] = column headers (KB/t  tps  MB/s ...)
	// lines[2] = first sample (since boot)
	// lines[3] = second sample (last second) ← we want this
	if len(lines) < 4 {
		return &models.IOInfo{}, nil
	}

	// Parse device names from header line
	devNames := strings.Fields(lines[0])
	// Parse second-sample values
	values := strings.Fields(lines[3])
	// Each device has 3 columns: KB/t, tps, MB/s
	result := &models.IOInfo{Devices: make([]models.IODeviceInfo, 0, len(devNames))}
	for i, name := range devNames {
		base := i * 3
		if base+2 >= len(values) {
			break
		}
		mbps := parseFloat(values[base+2])
		result.Devices = append(result.Devices, models.IODeviceInfo{
			Name:     name,
			IsSSD:    true,
			ReadMBps: mbps, // iostat total MB/s (read+write combined)
		})
	}
	return result, nil
}

func parseFloat(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
