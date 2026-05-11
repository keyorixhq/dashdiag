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

// NVMeCollector reads NVMe SMART health via `nvme smart-log`.
// nvme-cli is an acceptable wrapper — raw SMART ioctl requires CGO.
type NVMeCollector struct{}

func NewNVMeCollector() *NVMeCollector { return &NVMeCollector{} }

func (c *NVMeCollector) Name() string           { return "NVMe" }
func (c *NVMeCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *NVMeCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.NVMeInfo{}

	// Find all NVMe controllers
	controllers, _ := filepath.Glob("/sys/class/nvme/nvme*")
	for _, ctrl := range controllers {
		// Skip namespace entries (nvme0n1 etc) — only controllers
		base := filepath.Base(ctrl)
		if strings.Contains(base, "n") && len(base) > 5 {
			continue
		}

		dev := &models.NVMeDevice{
			Name:  "/dev/" + base,
			Model: strings.TrimSpace(readFileStr(filepath.Join(ctrl, "model"))),
			State: strings.TrimSpace(readFileStr(filepath.Join(ctrl, "state"))),
		}

		// Read SMART log via nvme-cli
		out, err := runCmd(ctx, "nvme", "smart-log", dev.Name, "--output-format=normal")
		if err != nil {
			// nvme-cli not installed — store basic info only
			info.Devices = append(info.Devices, *dev)
			continue
		}

		parseNVMeSmartLog(out, dev)

		// Detect mount points from /proc/mounts
		dev.MountPoints, dev.HasLinux = nvmeMountPoints(base)

		info.Devices = append(info.Devices, *dev)
	}

	return info, nil
}

// parseNVMeSmartLog parses `nvme smart-log` output into NVMeDevice fields.
func parseNVMeSmartLog(out string, dev *models.NVMeDevice) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "critical_warning":
			dev.CriticalWarning = parseInt(val)
		case "temperature":
			// Format: "111 °F (317 K)" — extract Kelvin and convert
			dev.TempC = parseNVMeTemp(val)
		case "available_spare":
			dev.AvailableSparePct = parseInt(strings.TrimSuffix(val, "%"))
		case "available_spare_threshold":
			dev.SpareThresholdPct = parseInt(strings.TrimSuffix(val, "%"))
		case "percentage_used":
			dev.PercentageUsed = parseInt(strings.TrimSuffix(val, "%"))
		case "media_errors":
			dev.MediaErrors = parseInt64(val)
		case "unsafe_shutdowns":
			dev.UnsafeShutdowns = parseInt64(val)
		case "power_on_hours":
			dev.PowerOnHours = parseInt64(val)
		case "power_cycles":
			dev.PowerCycles = parseInt64(val)
		}
	}
}

// parseNVMeTemp extracts temperature in Celsius from nvme smart-log output.
// Format: "111 °F (317 K)" — Kelvin is most reliable.
func parseNVMeTemp(s string) float64 {
	// Try to find Kelvin value in parentheses
	open := strings.LastIndex(s, "(")
	close := strings.LastIndex(s, " K)")
	if open >= 0 && close > open {
		kelvinStr := strings.TrimSpace(s[open+1 : close])
		if k, err := strconv.ParseFloat(kelvinStr, 64); err == nil && k > 0 {
			return k - 273.15
		}
	}
	// Fallback: parse Celsius directly if available
	fields := strings.Fields(s)
	if len(fields) > 0 {
		if c, err := strconv.ParseFloat(fields[0], 64); err == nil {
			return c
		}
	}
	return 0
}

// nvmeMountPoints reads /proc/mounts and returns all mount points for partitions
// of the given NVMe controller (e.g. "nvme0" → checks nvme0n1p1, nvme0n1p2 etc).
// Also returns true if any mounted filesystem is a Linux fs (xfs, ext4, btrfs etc).
func nvmeMountPoints(ctrlBase string) ([]string, bool) {
	// ctrlBase is like "/sys/class/nvme/nvme0" → device prefix is "nvme0"
	devPrefix := filepath.Base(ctrlBase) // "nvme0"

	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, false
	}

	linuxFS := map[string]bool{
		"xfs": true, "ext4": true, "ext3": true, "ext2": true,
		"btrfs": true, "f2fs": true, "jfs": true, "reiserfs": true,
	}

	var mounts []string
	hasLinux := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		dev := filepath.Base(fields[0]) // e.g. "nvme0n1p3"
		mountPoint := fields[1]
		fsType := fields[2]

		// Match any partition of this controller (nvme0n1p*, nvme0n2p* etc)
		if !strings.HasPrefix(dev, devPrefix) {
			continue
		}
		if mountPoint == "none" || mountPoint == "swap" {
			continue
		}
		mounts = append(mounts, mountPoint)
		if linuxFS[fsType] {
			hasLinux = true
		}
	}
	return mounts, hasLinux
}

func readFileStr(path string) string {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- path from sysfs glob
	if err != nil {
		return ""
	}
	return string(data)
}

func parseInt(s string) int {
	// Handle values like "60783741 (31.12 TB)"
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.Atoi(fields[0])
	return v
}

func parseInt64(s string) int64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseInt(fields[0], 10, 64)
	return v
}
