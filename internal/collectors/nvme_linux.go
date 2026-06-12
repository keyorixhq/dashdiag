//go:build linux

package collectors

import (
	"context"
	"encoding/json"
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

func (c *NVMeCollector) Name() string           { return "Drives" }
func (c *NVMeCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *NVMeCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.NVMeInfo{}

	// Find all NVMe controllers
	controllers, _ := filepath.Glob("/sys/class/nvme/nvme*")
	for _, ctrl := range controllers {
		// Only controllers (nvme0, nvme10, …) — skip namespaces (nvme0n1) and
		// multipath instances (nvme0c0n1).
		base := filepath.Base(ctrl)
		if !isNVMeController(base) {
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
		dev.SmartRead = true // smart-log read + parsed — health fields are real

		// Detect mount points from /proc/mounts
		dev.MountPoints, dev.HasLinux = nvmeMountPoints(base)

		info.Devices = append(info.Devices, *dev)
	}

	// Also detect SATA/SAS drives via smartctl
	collectSATADrives(ctx, info)

	if len(info.Devices) == 0 && len(info.SATADevices) == 0 {
		// No NVMe controllers and no SMART-capable SATA/SAS drives — typical of
		// cloud/KVM guests on virtio disks. Nothing to report; gate off rather
		// than emit a phantom "NVMe ✅ OK" row.
		return nil, nil
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
			dev.CriticalWarning = parseBitmask(val)
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

// parseBitmask parses an nvme `critical_warning` value. `nvme smart-log
// --output-format=normal` prints this field as %#x (verified in nvme-cli 2.13),
// so a NON-ZERO warning arrives hex-encoded ("0x4") while zero prints plain "0".
// strconv.Atoi chokes on the "0x" form and returned 0 — silently clearing a real
// warning (spare-exhausted / reliability-degraded / read-only / backup-failed
// bits) so a failing drive read as healthy at heuristics.go's `CriticalWarning >
// 0`. Base 0 auto-detects 0x; decimal still parses. Negative/garbled → 0.
func parseBitmask(s string) int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseInt(fields[0], 0, 64)
	if err != nil || v < 0 {
		return 0
	}
	return int(v)
}

// parseInt / parseInt64 read a SMART numeric attribute. They reject negative or
// garbled values (→ 0): a negative count would slip under the `> 0` / `>= N`
// failure thresholds in analysis/heuristics.go as a false-OK (mirrors the
// smartctl path's guard; same bug class as PR #200).
func parseInt(s string) int {
	// Handle values like "60783741 (31.12 TB)"
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.Atoi(fields[0])
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func parseInt64(s string) int64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// collectSATADrives detects SATA/SAS drives via smartctl --scan and reads SMART data.
// Gracefully skips if smartctl is not installed.
func collectSATADrives(ctx context.Context, info *models.NVMeInfo) {
	out, err := runCmd(ctx, "smartctl", "--scan-open", "--json=c")
	if err != nil || out == "" {
		return // smartctl not installed or no drives
	}

	var scan struct {
		Devices []struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Protocol string `json:"protocol"`
		} `json:"devices"`
	}
	if err := jsonUnmarshal([]byte(out), &scan); err != nil {
		return
	}

	for _, d := range scan.Devices {
		// Skip NVMe — already handled above
		proto := strings.ToLower(d.Protocol)
		if strings.Contains(proto, "nvme") {
			continue
		}

		dev := models.SATADevice{Name: d.Name}
		switch {
		case strings.Contains(proto, "ata") || strings.Contains(proto, "sata"):
			dev.Type = "sata"
		case strings.Contains(proto, "scsi") || strings.Contains(proto, "sas"):
			dev.Type = "sas"
		default:
			dev.Type = proto
		}

		// Read SMART data
		smartOut, err := runCmd(ctx, "smartctl", "--json=c", "-a", d.Name)
		if err != nil && smartOut == "" {
			dev.Error = "smartctl failed"
			info.SATADevices = append(info.SATADevices, dev)
			continue
		}

		var smart struct {
			ModelName   string `json:"model_name"`
			SmartStatus struct {
				Passed bool `json:"passed"`
			} `json:"smart_status"`
			Temperature struct {
				Current int `json:"current"`
			} `json:"temperature"`
			PowerOnTime struct {
				Hours int64 `json:"hours"`
			} `json:"power_on_time"`
			ATAAttributes *struct {
				Table []struct {
					ID  int `json:"id"`
					Raw struct {
						Value int64 `json:"value"`
					} `json:"raw"`
				} `json:"table"`
			} `json:"ata_smart_attributes,omitempty"`
		}
		if err := jsonUnmarshal([]byte(smartOut), &smart); err == nil {
			dev.Model = smart.ModelName
			dev.SmartOK = smart.SmartStatus.Passed
			dev.TempC = smart.Temperature.Current
			dev.PowerOnHours = smart.PowerOnTime.Hours
			if smart.ATAAttributes != nil {
				for _, attr := range smart.ATAAttributes.Table {
					switch attr.ID {
					case 5:
						dev.ReallocatedSectors = int(attr.Raw.Value)
					case 197:
						dev.PendingSectors = int(attr.Raw.Value)
					case 198:
						dev.UncorrectableErrors = int(attr.Raw.Value)
					}
				}
			}
		}
		info.SATADevices = append(info.SATADevices, dev)
	}
}

// jsonUnmarshal is a thin wrapper so we don't import encoding/json twice.
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
