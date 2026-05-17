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

	// /proc/pressure/* (since Linux 5.2, always readable without root)
	base := "/proc/pressure"
	if _, err := os.Stat(base); os.IsNotExist(err) {
		// Older kernels: try cgroup v2 root
		base = "/sys/fs/cgroup"
		if _, err := os.Stat(base + "/memory.pressure"); os.IsNotExist(err) {
			return info, nil // PSI not available on this kernel
		}
	}

	info.Available = true

	if m, err := readPSIFile(fmt.Sprintf("%s/memory", base)); err == nil {
		info.MemorySome = m[0]
		if len(m) > 1 {
			info.MemoryFull = m[1]
		}
	}
	if c, err := readPSIFile(fmt.Sprintf("%s/cpu", base)); err == nil {
		info.CPUSome = c[0]
	}
	if io, err := readPSIFile(fmt.Sprintf("%s/io", base)); err == nil {
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

// readPSIFile parses a PSI pressure file.
// Format per line: "some avg10=X avg60=X avg300=X total=N"
//
//	"full avg10=X avg60=X avg300=X total=N"
func readPSIFile(path string) ([]models.PSILine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []models.PSILine
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
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
