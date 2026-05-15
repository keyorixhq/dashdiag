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
	collectSystem(info)
	collectCPU(info)
	collectRAM(ctx, info)
	collectSMARTDrives(ctx, info)
	collectHwmonThermals(info)
	collectEDAC(info)
	collectNICs(ctx, info)
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
		errStr := err.Error()
		if strings.Contains(errStr, "exit status 2") || strings.Contains(errStr, "exit status 1") {
			drive.Error = "needs root — run: sudo dsd hardware"
		} else {
			drive.Error = fmt.Sprintf("smartctl failed: %v", err)
		}
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

// ── CPU ───────────────────────────────────────────────────────────────────────

// armImplementerName maps ARM CPU implementer codes to vendor names.
func armImplementerName(code string) string {
	switch strings.ToLower(code) {
	case "0x41":
		return "ARM"
	case "0x42":
		return "Broadcom"
	case "0x43":
		return "Cavium"
	case "0x44":
		return "DEC"
	case "0x48":
		return "HiSilicon"
	case "0x49":
		return "Infineon"
	case "0x4d":
		return "Motorola/Freescale"
	case "0x4e":
		return "NVIDIA"
	case "0x50":
		return "APM"
	case "0x51":
		return "Qualcomm"
	case "0x53":
		return "Samsung"
	case "0x56":
		return "Marvell"
	case "0x61":
		return "Apple"
	case "0x66":
		return "Faraday"
	case "0x69":
		return "Intel"
	case "0x70":
		return "Phytium"
	case "0xc0":
		return "Ampere"
	default:
		return code
	}
}

func collectCPU(info *models.HardwareInfo) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return
	}

	var model, hardware, implementer string
	var threads, cores int
	var freq float64
	coresSet := false

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		switch key {
		case "model name": // x86
			if model == "" {
				model = val
			}
			threads++ // one entry per logical CPU on x86
		case "processor": // ARM: one entry per logical CPU
			threads++
		case "cpu cores": // x86
			if !coresSet {
				if n, err := strconv.Atoi(val); err == nil {
					cores = n
					coresSet = true
				}
			}
		case "cpu MHz": // x86
			if freq == 0 {
				if f, err := strconv.ParseFloat(val, 64); err == nil {
					freq = f
				}
			}
		case "Hardware": // ARM bare-metal: "Raspberry Pi 4 Model B Rev 1.4"
			hardware = val
		case "CPU implementer": // ARM
			if implementer == "" {
				implementer = val
			}
		}
	}

	// ARM: prefer Hardware field, then device tree, then vendor+arch description
	if model == "" {
		model = hardware
	}
	if model == "" {
		for _, path := range []string{
			"/sys/firmware/devicetree/base/model",
			"/proc/device-tree/model",
		} {
			if b, err := os.ReadFile(path); err == nil { // #nosec G304
				model = strings.TrimRight(string(b), "\x00\n")
				break
			}
		}
	}
	if model == "" && implementer != "" {
		vendor := armImplementerName(implementer)
		model = fmt.Sprintf("%s ARM (aarch64)", vendor)
	}

	info.CPU = models.HardwareCPU{
		Model:   model,
		Cores:   cores,
		Threads: threads,
		FreqMHz: freq,
	}

	// Max boost frequency from cpufreq sysfs (kHz → MHz)
	if b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"); err == nil { // #nosec G304
		if n, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
			info.CPU.MaxFreqMHz = n / 1000
		}
	}
	// Current frequency from cpufreq if not in /proc/cpuinfo (common on ARM)
	if info.CPU.FreqMHz == 0 {
		if b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"); err == nil { // #nosec G304
			if n, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
				info.CPU.FreqMHz = n / 1000
			}
		}
	}

	// Load average from /proc/loadavg — used for idle thermal check in render
	if b, err := os.ReadFile("/proc/loadavg"); err == nil { // #nosec G304
		fields := strings.Fields(string(b))
		if len(fields) >= 1 {
			if load1, err := strconv.ParseFloat(fields[0], 64); err == nil && threads > 0 {
				info.CPU.LoadPct = load1 / float64(threads) * 100
			}
		}
	}
}

// ── SYSTEM IDENTITY ───────────────────────────────────────────────────────────

func collectSystem(info *models.HardwareInfo) {
	readDMI := func(f string) string {
		b, err := os.ReadFile(f) // #nosec G304
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	info.System = models.HardwareSystem{
		Vendor: readDMI("/sys/class/dmi/id/sys_vendor"),
		Model:  readDMI("/sys/class/dmi/id/product_name"),
		Board:  readDMI("/sys/class/dmi/id/board_name"),
	}
}

// ── RAM SLOTS (dmidecode) ─────────────────────────────────────────────────────

func collectRAM(ctx context.Context, info *models.HardwareInfo) {
	out, err := runCmd(ctx, "dmidecode", "-t", "memory")
	if err != nil {
		return
	}

	var slots []models.MemorySlot
	var current models.MemorySlot
	inSlot := false

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Memory Device") {
			if inSlot && current.SizeGB > 0 {
				slots = append(slots, current)
			}
			current = models.MemorySlot{}
			inSlot = true
			continue
		}
		if !inSlot {
			continue
		}
		if strings.HasPrefix(line, "Size:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Size:"))
			if strings.Contains(val, "GB") {
				if n, err := strconv.ParseFloat(strings.Fields(val)[0], 64); err == nil {
					current.SizeGB = n
				}
			} else if strings.Contains(val, "MB") {
				if n, err := strconv.ParseFloat(strings.Fields(val)[0], 64); err == nil {
					current.SizeGB = n / 1024
				}
			}
		}
		if strings.HasPrefix(line, "Locator:") && !strings.HasPrefix(line, "Bank") {
			current.Locator = strings.TrimSpace(strings.TrimPrefix(line, "Locator:"))
		}
		if strings.HasPrefix(line, "Type:") && !strings.Contains(line, "Error") {
			current.Type = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
		}
		if strings.HasPrefix(line, "Speed:") && !strings.Contains(line, "Configured") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Speed:"))
			if strings.Contains(val, "MT/s") {
				if n, err := strconv.Atoi(strings.Fields(val)[0]); err == nil {
					current.SpeedMT = n
				}
			}
		}
	}
	if inSlot && current.SizeGB > 0 {
		slots = append(slots, current)
	}

	var total float64
	for _, s := range slots {
		total += s.SizeGB
	}
	info.Memory.TotalGB = total
	info.Memory.Slots = slots
}

// ── NETWORK INTERFACES ────────────────────────────────────────────────────────

func collectNICs(ctx context.Context, info *models.HardwareInfo) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return
	}

	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		// Skip virtual/tunnel interfaces
		switch {
		case strings.HasPrefix(name, "veth"),
			strings.HasPrefix(name, "docker"),
			strings.HasPrefix(name, "br-"),
			strings.HasPrefix(name, "vxlan"),
			strings.HasPrefix(name, "cali"),
			strings.HasPrefix(name, "flannel"),
			strings.HasPrefix(name, "cni"),
			strings.HasPrefix(name, "virbr"),
			strings.HasPrefix(name, "tunl"),
			strings.HasPrefix(name, "tun"):
			continue
		}

		nic := models.HardwareNIC{Name: name}

		netDir := "/sys/class/net/" + name
		if b, err := os.ReadFile(netDir + "/address"); err == nil { // #nosec G304
			nic.MAC = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(netDir + "/operstate"); err == nil { // #nosec G304
			nic.State = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(netDir + "/speed"); err == nil { // #nosec G304
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
				nic.SpeedMbps = n
			}
		}
		// Driver from symlink
		if link, err := os.Readlink(netDir + "/device/driver"); err == nil {
			nic.Driver = filepath.Base(link)
		}
		// RX/TX errors from sysfs stats
		if b, err := os.ReadFile(netDir + "/statistics/rx_errors"); err == nil { // #nosec G304
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
				nic.RxErrors = n
			}
		}
		if b, err := os.ReadFile(netDir + "/statistics/tx_errors"); err == nil { // #nosec G304
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
				nic.TxErrors = n
			}
		}

		info.NICs = append(info.NICs, nic)
	}
}
