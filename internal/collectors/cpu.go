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

func (c *CPUCollector) Name() string { return "CPU Load" }
func (c *CPUCollector) Timeout() time.Duration {
	if runtime.GOOS == "darwin" {
		return 4 * time.Second // top -l 2 -s 1 needs ~1.5s to complete
	}
	return 2 * time.Second
}

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

// cpuStatSample holds raw counters from one /proc/stat read.
// Aggregate "cpu " field indices (0-based after the "cpu" label):
//
//	0=user 1=nice 2=system 3=idle 4=iowait 5=irq 6=softirq 7=steal 8=guest 9=guest_nice
//
// ctxt/procsRunning/procsBlocked come from their own single-value lines further
// down the file (ctxt is a since-boot counter; the procs_* are instantaneous).
type cpuStatSample struct {
	idle         uint64
	total        uint64
	steal        uint64
	iowait       uint64
	ctxt         uint64
	procsRunning uint64
	procsBlocked uint64
}

// parseCPUStatFull parses /proc/stat and returns all counters needed for
// accurate CPU usage, steal, and iowait rates, plus run-queue depth
// (procs_running), blocked-task count (procs_blocked), and the context-switch
// counter (ctxt). Scans the whole file since those auxiliary lines follow the
// per-CPU lines after the "cpu " aggregate.
func parseCPUStatFull(r io.Reader) (cpuStatSample, error) {
	var s cpuStatSample
	foundCPU := false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "cpu "):
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return cpuStatSample{}, fmt.Errorf("unexpected cpu stat line: %q", line)
			}
			for i, f := range fields[1:] {
				v, err := strconv.ParseUint(f, 10, 64)
				if err != nil {
					return cpuStatSample{}, fmt.Errorf("parsing cpu field %d: %w", i, err)
				}
				s.total += v
				switch i {
				case 3:
					s.idle = v
				case 4:
					s.iowait = v
				case 7:
					s.steal = v
				}
			}
			foundCPU = true
		case strings.HasPrefix(line, "ctxt "):
			s.ctxt = parseStatUint(line)
		case strings.HasPrefix(line, "procs_running "):
			s.procsRunning = parseStatUint(line)
		case strings.HasPrefix(line, "procs_blocked "):
			s.procsBlocked = parseStatUint(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return cpuStatSample{}, err
	}
	if !foundCPU {
		return cpuStatSample{}, fmt.Errorf("no cpu line in stat")
	}
	return s, nil
}

// parseStatUint extracts the integer value from a "key value" /proc/stat line
// such as "ctxt 123456" or "procs_running 2". Returns 0 if unparseable —
// these auxiliary counters are best-effort and must never fail the collector.
func parseStatUint(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// parseCPUStat is a compatibility shim used by cpu_test.go.
// New code should use parseCPUStatFull directly.
func parseCPUStat(r io.Reader) (idle, total uint64, err error) {
	s, parseErr := parseCPUStatFull(r)
	return s.idle, s.total, parseErr
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

	// Two-sample /proc/stat for CPU usage percentage plus steal and iowait rates.
	// Steal is the percentage of time the hypervisor stole CPU from this VM.
	// IOwait is the percentage of time the CPU was idle waiting for I/O completion.
	var usagePct, stealPct, iowaitPct, ctxSwitchRate float64
	var runQueue, procsBlocked int
	r1, err1 := c.readers.statOpen()
	if err1 == nil {
		s1, parseErr := parseCPUStatFull(r1)
		_ = r1.Close()
		t1 := time.Now()

		if parseErr == nil {
			select {
			case <-ctx.Done():
				return partialCPUInfo(load1, load5, load15, numCPU), nil
			case <-time.After(500 * time.Millisecond):
			}

			r2, err2 := c.readers.statOpen()
			if err2 == nil {
				s2, _ := parseCPUStatFull(r2)
				_ = r2.Close()
				delta := float64(s2.total - s1.total)
				if delta > 0 {
					idleDelta := float64(s2.idle - s1.idle)
					usagePct = (1 - idleDelta/delta) * 100
					if s2.steal >= s1.steal {
						stealPct = float64(s2.steal-s1.steal) / delta * 100
					}
					if s2.iowait >= s1.iowait {
						iowaitPct = float64(s2.iowait-s1.iowait) / delta * 100
					}
				}
				// Run-queue depth and blocked count are instantaneous — use the
				// most recent (second) sample.
				runQueue = int(s2.procsRunning)
				procsBlocked = int(s2.procsBlocked)
				// Context-switch rate over the actual elapsed sampling window.
				if elapsed := time.Since(t1).Seconds(); elapsed > 0 && s2.ctxt >= s1.ctxt {
					ctxSwitchRate = float64(s2.ctxt-s1.ctxt) / elapsed
				}
			}
		}
	}

	// On macOS /proc/stat is not available — read CPU usage from top instead.
	// 'top -l 2 -s 1 -n 0' takes two 1-second samples and reports the delta,
	// which matches what Activity Monitor shows.
	if runtime.GOOS == "darwin" && usagePct == 0 {
		if u := cpuUsageDarwin(ctx); u > 0 {
			usagePct = u
		}
	}

	return &models.CPUInfo{
		LoadAvg1:          load1,
		LoadAvg5:          load5,
		LoadAvg15:         load15,
		NumCPU:            numCPU,
		UsagePct:          usagePct,
		LoadPct:           load1 / float64(numCPU) * 100,
		StealPct:          stealPct,
		IOwaitPct:         iowaitPct,
		RunQueue:          runQueue,
		ProcsBlocked:      procsBlocked,
		ContextSwitchRate: ctxSwitchRate,
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

// cpuUsageDarwin reads real CPU utilisation on macOS via top.
// Uses two samples separated by 1 second so the delta matches what Activity Monitor shows.
// Parses: "CPU usage: 8.97% user, 4.77% sys, 86.25% idle"
func cpuUsageDarwin(ctx context.Context) float64 {
	// -l 2: two log samples, -s 1: 1-second interval, -n 0: no process rows
	out, err := runCmd(ctx, "top", "-l", "2", "-s", "1", "-n", "0")
	if err != nil || out == "" {
		return 0
	}
	// Take the last "CPU usage:" line (from the second sample)
	var lastLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "CPU usage:") {
			lastLine = line
		}
	}
	if lastLine == "" {
		return 0
	}
	// Parse user% + sys% from "CPU usage: 8.97% user, 4.77% sys, 86.25% idle"
	var user, sys float64
	for _, part := range strings.Split(lastLine, ",") {
		part = strings.TrimSpace(part)
		fields := strings.Fields(part)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseFloat(strings.TrimSuffix(fields[0], "%"), 64)
		if err != nil {
			continue
		}
		switch fields[1] {
		case "user":
			user = val
		case "sys":
			sys = val
		}
	}
	if user+sys > 0 {
		return user + sys
	}
	return 0
}
