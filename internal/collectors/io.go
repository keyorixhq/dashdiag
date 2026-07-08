package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
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
	data, err := readFile(filepath.Join("/sys/block", dev, "queue/rotational")) // #nosec G304 -- root is hardcoded to /sys/block; dev is from kernel diskstats, not user input
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

func (c *IOCollector) Collect(ctx context.Context) (any, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}

	f1, err := openFile(c.diskstatsPath)
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

	f2, err := openFile(c.diskstatsPath)
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
		beforeStat, seen := before[name]
		if !seen {
			// Device appeared only in the 2nd sample (hotplugged/renamed within the 1s
			// window). A zero-value `before` makes every delta equal the full
			// since-boot counters → util clamps to 100% and the rates balloon → a false
			// "disk at 100% utilization" WARN. Skip it: only score a device both
			// samples observed (it'll be scored normally on the next run).
			continue
		}
		result.Devices = append(result.Devices, computeDelta(name, beforeStat, afterStat))
	}
	// Map iteration is randomized — sort for deterministic, diffable output
	// (TRIAGE §I; this was the intermittent device reorder the replay guard caught).
	sort.Slice(result.Devices, func(i, j int) bool { return result.Devices[i].Name < result.Devices[j].Name })
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

// parseFloat reads a numeric field where a bad value should just read as 0
// (an iostat MB/s field, a size, a count). See parseFiniteFloat for the
// underlying guard and callers that need to distinguish "no value" from a
// genuine 0 (they should use parseFiniteFloat directly and keep their own
// default instead of overwriting it with 0).
func parseFloat(s string) float64 {
	v, _ := parseFiniteFloat(s)
	return v
}

// parseFiniteFloat parses s, returning ok=false for a parse error OR a
// NaN/Inf/negative result. strconv.ParseFloat treats "NaN"/"Inf"/"+Inf"/
// "-Inf" as successful parses (not errors) — reject those plus a negative
// value, same bug class as the NVMe temp/GPU clock NaN/Inf fixes (#372/#373):
// a garbled value must never silently become a display/verdict-corrupting
// NaN or Inf, and must never silently overwrite a caller's sensible default.
func parseFiniteFloat(s string) (float64, bool) {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, false
	}
	return v, true
}
