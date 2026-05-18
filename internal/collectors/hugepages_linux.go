//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os"
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
	info := &models.HugePagesInfo{Available: true}

	// Read /proc/meminfo for huge page stats
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return info, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
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
			info.PageSizeKB = val // value is in kB
		}
	}

	info.Used = info.Configured - info.Free
	if info.Configured > 0 && info.PageSizeKB > 0 {
		info.ReservedGB = float64(info.Configured) * float64(info.PageSizeKB) / (1024 * 1024)
	}

	// Transparent huge pages — /sys/kernel/mm/transparent_hugepage/enabled
	thpData, err := os.ReadFile("/sys/kernel/mm/transparent_hugepage/enabled")
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

	return info, nil
}

// IsHugePagesConfigured returns true when static huge pages are reserved.
func IsHugePagesConfigured() bool {
	data, err := os.ReadFile("/proc/meminfo")
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
