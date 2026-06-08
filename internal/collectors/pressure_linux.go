//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// PressureCollector reads PSI (Pressure Stall Information) from cgroup v2.
// Requires Linux 4.20+ with CONFIG_PSI=y. No root required.
type PressureCollector struct{}

func NewPressureCollector() *PressureCollector      { return &PressureCollector{} }
func (c *PressureCollector) Name() string           { return "Pressure" }
func (c *PressureCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *PressureCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.PressureInfo{}

	base := "/proc/pressure"
	if _, err := os.Stat(base); os.IsNotExist(err) {
		base = "/sys/fs/cgroup"
		if _, err := os.Stat(base + "/memory.pressure"); os.IsNotExist(err) {
			return info, nil
		}
	}

	info.Available = true

	// len()>0 guards are required: readPSIFile returns (nil, nil) when the file
	// exists but no line parses (malformed/truncated), so a bare [0] would panic.
	if m, err := readPSIFile(fmt.Sprintf("%s/memory", base)); err == nil && len(m) > 0 {
		info.MemorySome = m[0]
		if len(m) > 1 {
			info.MemoryFull = m[1]
		}
	}
	if cpu, err := readPSIFile(fmt.Sprintf("%s/cpu", base)); err == nil && len(cpu) > 0 {
		info.CPUSome = cpu[0]
	}
	if io, err := readPSIFile(fmt.Sprintf("%s/io", base)); err == nil && len(io) > 0 {
		info.IOSome = io[0]
		if len(io) > 1 {
			info.IOFull = io[1]
		}
	}

	return info, nil
}

// IsPSIAvailable returns true when PSI files are readable.
func IsPSIAvailable() bool {
	if _, err := os.Stat("/proc/pressure/memory"); err == nil {
		return true
	}
	if _, err := os.Stat("/sys/fs/cgroup/memory.pressure"); err == nil {
		return true
	}
	return false
}

func readPSIFile(path string) ([]models.PSILine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return readPSIString(string(data))
}

// readPSIString parses PSI content from a string — exported for tests.
func readPSIString(content string) ([]models.PSILine, error) {
	var lines []models.PSILine
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		var psi models.PSILine
		for _, f := range fields[1:] {
			kv := strings.SplitN(f, "=", 2)
			if len(kv) != 2 {
				continue
			}
			v, err := strconv.ParseFloat(kv[1], 64)
			if err != nil {
				continue
			}
			switch kv[0] {
			case "avg10":
				psi.Avg10 = v
			case "avg60":
				psi.Avg60 = v
			case "avg300":
				psi.Avg300 = v
			}
		}
		lines = append(lines, psi)
	}
	return lines, nil
}
