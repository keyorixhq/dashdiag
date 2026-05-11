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

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

type cpuReaders struct {
	loadAvgOpen func() (io.ReadCloser, error)
	statOpen    func() (io.ReadCloser, error)
}

type CPUCollector struct {
	readers      cpuReaders
	ContainerCtx platform.ContainerContext
}

func NewCPUCollector(ctx platform.ContainerContext) *CPUCollector {
	return &CPUCollector{
		ContainerCtx: ctx,
		readers: cpuReaders{
			loadAvgOpen: func() (io.ReadCloser, error) { return os.Open("/proc/loadavg") },
			statOpen:    func() (io.ReadCloser, error) { return os.Open("/proc/stat") },
		},
	}
}

func (c *CPUCollector) Name() string           { return "CPU" }
func (c *CPUCollector) Timeout() time.Duration { return 2 * time.Second }

// parseLoadAvg parses /proc/loadavg format: "0.52 0.43 0.32 3/412 8932"
func parseLoadAvg(r io.Reader) (load1, load5, load15 float64, err error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return 0, 0, 0, fmt.Errorf("empty loadavg")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("unexpected loadavg: need 3 fields, got %d", len(fields))
	}
	if load1, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return 0, 0, 0, fmt.Errorf("parsing load1: %w", err)
	}
	if load5, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return 0, 0, 0, fmt.Errorf("parsing load5: %w", err)
	}
	if load15, err = strconv.ParseFloat(fields[2], 64); err != nil {
		return 0, 0, 0, fmt.Errorf("parsing load15: %w", err)
	}
	return load1, load5, load15, nil
}

// parseCPUStat parses the first "cpu " line from /proc/stat.
// Returns idle (field[3]) and total (sum of all fields).
func parseCPUStat(r io.Reader) (idle, total uint64, err error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0, 0, fmt.Errorf("unexpected cpu stat line: %q", line)
		}
		for i, f := range fields[1:] {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("parsing cpu field %d: %w", i, err)
			}
			total += v
			if i == 3 {
				idle = v
			}
		}
		return idle, total, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return 0, 0, fmt.Errorf("no cpu line in stat")
}

func (c *CPUCollector) Collect(ctx context.Context) (interface{}, error) {
	numCPU := runtime.NumCPU()
	if c.ContainerCtx.CPULimitCores > 0 {
		if n := int(c.ContainerCtx.CPULimitCores); n >= 1 {
			numCPU = n
		}
	}

	// Load average
	var load1, load5, load15 float64
	r, err := c.readers.loadAvgOpen()
	if err == nil {
		load1, load5, load15, err = parseLoadAvg(r)
		_ = r.Close()
	}
	if err != nil && runtime.GOOS == "darwin" {
		load1, load5, load15, err = loadAvgDarwin(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("load average: %w", err)
	}

	// Two-sample /proc/stat for CPU usage
	var usagePct float64
	r1, err1 := c.readers.statOpen()
	if err1 == nil {
		idle1, total1, parseErr := parseCPUStat(r1)
		_ = r1.Close()

		if parseErr == nil {
			select {
			case <-ctx.Done():
				return partialCPUInfo(load1, load5, load15, numCPU), nil
			case <-time.After(500 * time.Millisecond):
			}

			r2, err2 := c.readers.statOpen()
			if err2 == nil {
				idle2, total2, _ := parseCPUStat(r2)
				_ = r2.Close()
				if total2 > total1 && idle2 >= idle1 {
					usagePct = (1 - float64(idle2-idle1)/float64(total2-total1)) * 100
				}
			}
		}
	}

	return &models.CPUInfo{
		LoadAvg1:  load1,
		LoadAvg5:  load5,
		LoadAvg15: load15,
		NumCPU:    numCPU,
		UsagePct:  usagePct,
		LoadPct:   load1 / float64(numCPU) * 100,
	}, nil
}

func partialCPUInfo(load1, load5, load15 float64, numCPU int) *models.CPUInfo {
	return &models.CPUInfo{
		LoadAvg1:  load1,
		LoadAvg5:  load5,
		LoadAvg15: load15,
		NumCPU:    numCPU,
		LoadPct:   load1 / float64(numCPU) * 100,
	}
}

// loadAvgDarwin reads load averages on macOS via sysctl.
// Output format: "{ 0.52 0.43 0.32 }"
// On non-English locales the decimal separator may be a comma: "{ 2,12 0,43 0,32 }"
// runCmd sets LC_ALL=C as primary fix; comma replacement is belt-and-suspenders.
func loadAvgDarwin(ctx context.Context) (float64, float64, float64, error) {
	out, err := runCmd(ctx, "sysctl", "-n", "vm.loadavg")
	if err != nil {
		return 0, 0, 0, fmt.Errorf("sysctl vm.loadavg: %w", err)
	}
	s := strings.TrimSpace(out)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	s = strings.ReplaceAll(s, ",", ".") // normalize locale decimal separator
	return parseLoadAvg(strings.NewReader(strings.TrimSpace(s)))
}
