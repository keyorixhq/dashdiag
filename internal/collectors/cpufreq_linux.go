//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// CPUFreqCollector reads CPU frequency scaling from /sys/devices/system/cpu/.
// No root required.
type CPUFreqCollector struct{}

func NewCPUFreqCollector() *CPUFreqCollector       { return &CPUFreqCollector{} }
func (c *CPUFreqCollector) Name() string           { return "CPUFreq" }
func (c *CPUFreqCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *CPUFreqCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.CPUFreqInfo{}

	// Read cpu0 as representative — governor is typically system-wide
	base := "/sys/devices/system/cpu/cpu0/cpufreq"
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return info, nil // cpufreq not available (VM, container, or old kernel)
	}

	info.Governor = strings.TrimSpace(readSysfsStr(base + "/scaling_governor"))

	// Frequencies are in kHz — convert to MHz
	if v := readSysfsKHz(base + "/scaling_cur_freq"); v > 0 {
		info.CurrentMHz = v / 1000
	}
	if v := readSysfsKHz(base + "/cpuinfo_max_freq"); v > 0 {
		info.MaxMHz = v / 1000
	}
	if v := readSysfsKHz(base + "/cpuinfo_min_freq"); v > 0 {
		info.MinMHz = v / 1000
	}

	// CPU count from present list
	if cpus, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*"); len(cpus) > 0 {
		info.CPUCount = len(cpus)
	}

	// Throttle percentage: how far below max we are
	if info.MaxMHz > 0 && info.CurrentMHz > 0 {
		info.ThrottledPct = float64(info.MaxMHz-info.CurrentMHz) / float64(info.MaxMHz) * 100
		if info.ThrottledPct < 0 {
			info.ThrottledPct = 0
		}
	}

	return info, nil
}

// IsCPUFreqAvailable returns true when cpufreq sysfs is present.
func IsCPUFreqAvailable() bool {
	_, err := os.Stat("/sys/devices/system/cpu/cpu0/cpufreq")
	return err == nil
}

func readSysfsKHz(path string) int {
	s := strings.TrimSpace(readSysfsStr(path))
	n, _ := strconv.Atoi(s)
	return n
}

// parseCPUFreqGovernor extracts governor from scaling_governor content (for tests).
func parseCPUFreqGovernor(content string) string {
	return strings.TrimSpace(content)
}

// parseCPUFreqKHz parses a kHz value from sysfs content (for tests).
func parseCPUFreqKHz(content string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(content))
	return n
}
