//go:build linux

package collectors

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HugePagesCollector reads huge page config from /proc/meminfo and THP sysfs.
// No root required — all paths are world-readable.
type HugePagesCollector struct{}

func NewHugePagesCollector() *HugePagesCollector     { return &HugePagesCollector{} }
func (c *HugePagesCollector) Name() string           { return "HugePages" }
func (c *HugePagesCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *HugePagesCollector) Collect(_ context.Context) (interface{}, error) {
	data, err := readFile("/proc/meminfo")
	if err != nil {
		return &models.HugePagesInfo{Available: true}, nil
	}
	info := parseHugePagesMeminfo(string(data))
	info.Available = true

	// Transparent huge pages — /sys/kernel/mm/transparent_hugepage/enabled
	thpData, err := readFile("/sys/kernel/mm/transparent_hugepage/enabled")
	if err == nil {
		thpStr := strings.TrimSpace(string(thpData))
		// Format: "always [madvise] never" — bracketed value is active
		if strings.Contains(thpStr, "[always]") {
			info.THPEnabled = true
			info.THPMode = "always"
		} else if strings.Contains(thpStr, "[madvise]") {
			info.THPEnabled = true
			info.THPMode = "madvise"
		} else {
			info.THPMode = "never"
		}
	}

	return &info, nil
}

// IsHugePagesConfigured returns true when static huge pages are reserved.
func IsHugePagesConfigured() bool {
	data, err := readFile("/proc/meminfo")
	if err != nil {
		return false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "HugePages_Total:") {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 {
				n, _ := strconv.Atoi(fields[1])
				return n > 0
			}
		}
	}
	return false
}

func parseHugePagesMeminfo(content string) models.HugePagesInfo {
	info := models.HugePagesInfo{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		val, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		switch key {
		case "HugePages_Total":
			info.Configured = val
		case "HugePages_Free":
			info.Free = val
		case "Hugepagesize":
			info.PageSizeKB = val
		}
	}
	info.Used = info.Configured - info.Free
	if info.Configured > 0 && info.PageSizeKB > 0 {
		info.ReservedGB = float64(info.Configured) * float64(info.PageSizeKB) / (1024 * 1024)
	}
	return info
}
