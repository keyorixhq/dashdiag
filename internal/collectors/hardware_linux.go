//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HardwareCollector reads physical hardware health:
// drive SMART via smartctl, CPU/drive thermals via hwmon, EDAC memory errors.
type HardwareCollector struct{}

func NewHardwareCollector() *HardwareCollector { return &HardwareCollector{} }

func (c *HardwareCollector) Name() string           { return "Hardware" }
func (c *HardwareCollector) Timeout() time.Duration { return 15 * time.Second }

func (c *HardwareCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.HardwareInfo{}
	collectSMARTDrives(ctx, info)
	collectHwmonThermals(info)
	collectEDAC(info)
	return info, nil
}

// ── SMART ─────────────────────────────────────────────────────────────────────

// smartctlScan is the JSON output of `smartctl --scan-open --json`.
type smartctlScan struct {
	Devices []struct {
		Name     string `json:"name"`
		InfoName string `json:"info_name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"devices"`
}

// smartctlDevice is the subset of fields we parse from `smartctl -a --json`.
type smartctlDevice struct {
	ModelName string `json:"model_name"`
	Device    struct {
		Type     string `json:"type"` // nvme, sat, scsi
		Protocol string `json:"protocol"`
	} `json:"device"`
	SmartStatus struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime struct {
		Hours int64 `json:"hours"`
	} `json:"power_on_time"`
	PowerCycleCount int64 `json:"power_cycle_count"`

	// NVMe-specific
	NVMeLog *struct {
		PercentageUsed  int   `json:"percentage_used"`
		MediaErrors     int64 `json:"media_errors"`
		UnsafeShutdowns int64 `json:"unsafe_shutdowns"`
	} `json:"nvme_smart_health_information_log,omitempty"`

	// SATA/SAS — ATA SMART attributes table
	ATASMARTAttributes *struct {
		Table []struct {
			ID    int    `json:"id"`
			Name  string `json:"name"`
			Value int    `json:"value"` // normalised 0-100
			Raw   struct {
				Value int64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes,omitempty"`
}

func collectSMARTDrives(ctx context.Context, info *models.HardwareInfo) {
	// Check smartctl is available
	scanOut, err := runCmd(ctx, "smartctl", "--scan-open", "--json=c")
	if err != nil {
		// smartctl not installed — record on first drive slot so the heuristic
		// can emit an INFO hint rather than silently skipping
		info.Drives = append(info.Drives, models.HardwareDrive{
			SmartctlAvailable: false,
			Error:             "smartctl not installed — install smartmontools for drive health",
		})
		return
	}

	var scan smartctlScan
	if err := json.Unmarshal([]byte(scanOut), &scan); err != nil || len(scan.Devices) == 0 {
		return
	}

	for _, dev := range scan.Devices {
		drive := collectOneDrive(ctx, dev.Name)
		info.Drives = append(info.Drives, drive)
	}
}

func collectOneDrive(ctx context.Context, devPath string) models.HardwareDrive {
	drive := models.HardwareDrive{
		Device:            devPath,
		SmartctlAvailable: true,
	}

	out, err := runCmd(ctx, "smartctl", "--json=c", "-a", devPath)
	if err != nil && out == "" {
		drive.Error = fmt.Sprintf("smartctl failed: %v", err)
		return drive
	}

	var d smartctlDevice
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		drive.Error = fmt.Sprintf("smartctl JSON parse error: %v", err)
		return drive
	}

	drive.Model = d.ModelName
	drive.SmartOK = d.SmartStatus.Passed
	drive.TempC = d.Temperature.Current
	drive.PowerOnH = d.PowerOnTime.Hours

	// Drive type from protocol
	proto := strings.ToLower(d.Device.Protocol)
	switch {
	case strings.Contains(proto, "nvme"):
		drive.Type = "nvme"
	case strings.Contains(proto, "ata") || strings.Contains(proto, "sata"):
		drive.Type = "sata"
	case strings.Contains(proto, "scsi") || strings.Contains(proto, "sas"):
		drive.Type = "sas"
	default:
		drive.Type = d.Device.Protocol
	}

	// NVMe-specific fields
	if d.NVMeLog != nil {
		drive.WearPct = d.NVMeLog.PercentageUsed
		drive.MediaErrors = d.NVMeLog.MediaErrors
		drive.UnsafeShutdowns = d.NVMeLog.UnsafeShutdowns
	}

	// SATA/SAS — parse critical ATA SMART attributes
	if d.ATASMARTAttributes != nil {
		for _, attr := range d.ATASMARTAttributes.Table {
			switch attr.ID {
			case 5: // Reallocated Sectors Count
				drive.ReallocatedSectors = int(attr.Raw.Value)
			case 173, 177: // SSD Wear Leveling / Wear Range Delta
				// Some SSDs use attr 173 or 177 for wear %
				if drive.WearPct == 0 && attr.Raw.Value > 0 {
					drive.WearPct = int(attr.Raw.Value)
				}
			case 190, 194: // Airflow/HDD Temperature (some drives use 190 vs 194)
				if drive.TempC == 0 {
					drive.TempC = int(attr.Raw.Value & 0xFF)
				}
			case 197: // Current Pending Sector Count
				drive.PendingSectors = int(attr.Raw.Value)
			case 198: // Offline Uncorrectable Sector Count
				drive.UncorrectableErrors = int(attr.Raw.Value)
			case 231, 233: // SSD Life Left / Media Wearout Indicator
				if drive.WearPct == 0 {
					drive.WearPct = 100 - attr.Value // normalised value = remaining life
				}
			}
		}
	}

	return drive
}

// ── HWMON THERMALS ────────────────────────────────────────────────────────────

func collectHwmonThermals(info *models.HardwareInfo) {
	hwmonRoot := "/sys/class/hwmon"
	entries, err := os.ReadDir(hwmonRoot)
	if err != nil {
		return
	}

	for _, e := range entries {
		dir := filepath.Join(hwmonRoot, e.Name())
		nameBytes, err := os.ReadFile(filepath.Join(dir, "name")) // #nosec G304
		if err != nil {
			continue
		}
		sensorName := strings.TrimSpace(string(nameBytes))

		// Only collect CPU and drive thermal sensors
		switch sensorName {
		case "k10temp", "coretemp", "nvme", "drivetemp":
			// read all tempN_input files
		default:
			continue
		}

		temps, _ := filepath.Glob(filepath.Join(dir, "temp*_input"))
		for _, tf := range temps {
			val, err := os.ReadFile(tf) // #nosec G304
			if err != nil {
				continue
			}
			milli, err := strconv.Atoi(strings.TrimSpace(string(val)))
			if err != nil {
				continue
			}
			tempC := milli / 1000

			// Get label if available
			base := strings.TrimSuffix(filepath.Base(tf), "_input")
			labelFile := filepath.Join(dir, base+"_label")
			label := base
			if lb, err := os.ReadFile(labelFile); err == nil { // #nosec G304
				label = strings.TrimSpace(string(lb))
			}

			info.Thermals = append(info.Thermals, models.HardwareThermal{
				Sensor: sensorName,
				Label:  label,
				TempC:  tempC,
			})
		}
	}
}

// ── EDAC MEMORY ERRORS ───────────────────────────────────────────────────────

func collectEDAC(info *models.HardwareInfo) {
	edacRoot := "/sys/devices/system/edac/mc"
	entries, err := os.ReadDir(edacRoot)
	if err != nil {
		// EDAC not available — common on consumer hardware
		info.Memory.EDACAvailable = false
		return
	}

	info.Memory.EDACAvailable = true
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "mc") {
			continue
		}
		mcDir := filepath.Join(edacRoot, e.Name())

		if b, err := os.ReadFile(filepath.Join(mcDir, "ue_count")); err == nil { // #nosec G304
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
				info.Memory.UncorrectedErrors += n
			}
		}
		if b, err := os.ReadFile(filepath.Join(mcDir, "ce_count")); err == nil { // #nosec G304
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
				info.Memory.CorrectedErrors += n
			}
		}
	}
}
