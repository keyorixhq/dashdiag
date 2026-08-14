//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
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
	SmartStatus *struct {
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
	if err := json.Unmarshal([]byte(scanOut), &scan); err != nil {
		// internal-collectors-14-02: smartctl ran and produced output, but it
		// wasn't valid JSON (a version mismatch, truncated output, a wrapper
		// script mangling stdout). Distinct from "smartctl not installed"
		// above and from a genuine zero-devices scan below — a parse failure
		// must not silently read as "no drives to check".
		info.Drives = append(info.Drives, models.HardwareDrive{
			Device:            "(scan)",
			SmartctlAvailable: true,
			Error:             "smartctl --scan-open produced unparseable JSON output",
		})
		return
	}
	if len(scan.Devices) == 0 {
		return
	}

	for _, dev := range scan.Devices {
		// dev.Name is echoed back verbatim from `smartctl --scan-open`'s own
		// JSON and passed as the trailing argv element to the second
		// smartctl call below (collectOneDrive). A name beginning with "-"
		// would be parsed by smartctl as an option rather than a device
		// path — skip rather than let it be silently reinterpreted.
		if strings.HasPrefix(dev.Name, "-") {
			continue
		}
		drive := collectOneDrive(ctx, dev.Name)
		info.Drives = append(info.Drives, drive)
	}
}

func collectOneDrive(ctx context.Context, devPath string) models.HardwareDrive {
	drive := models.HardwareDrive{
		Device:            devPath,
		SmartctlAvailable: true,
	}

	// smartctl signals real findings via a non-zero exit while still writing
	// full JSON to stdout (bit2=SMART overall-health FAILED, bit3=prefail
	// attrs below threshold, bit6=error log has errors, etc — see man
	// smartctl EXIT STATUS). runCmd would discard that stdout on any
	// non-zero exit, permanently downgrading the single most important case
	// — an actually-failing drive — to a vague WARN with no diagnostic
	// content (never reaching the !d.SmartOK CRIT branch in
	// heuristics_hardware.go). Use runCmdOutput, which keeps stdout
	// regardless of exit code, the same helper already used for rpm/dnf.
	out, err := runCmdOutput(ctx, "smartctl", "--json=c", "-a", devPath)
	if err != nil && out == "" {
		errStr := err.Error()
		// runCmd/runCmdOutput's cmdError formats as "<name> exited <code>"
		// (collector.go), never Go's raw ExitError "exit status <code>" —
		// match the actual format so this branch is reachable.
		if strings.Contains(errStr, "exited 2") || strings.Contains(errStr, "exited 1") {
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
	if d.SmartStatus != nil { // verdict present → trust it; absent → SmartRead stays false
		drive.SmartRead = true
		drive.SmartOK = d.SmartStatus.Passed
	}
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

	// SATA/SAS — parse critical ATA SMART attributes. Absent on a real SAS/SCSI
	// drive (grown-defect-list data lives in different log pages this collector
	// doesn't parse) — BadSectorsRead records whether this table was actually
	// there, so a caller can't mistake the zero-value counters below for a
	// clean bad-sector verdict on hardware that was never measured.
	if d.ATASMARTAttributes != nil {
		drive.BadSectorsRead = true
		for _, attr := range d.ATASMARTAttributes.Table {
			switch attr.ID {
			case 5: // Reallocated Sectors Count
				drive.ReallocatedSectors = int(attr.Raw.Value)
			case 173, 177: // SSD Wear Leveling / Wear Range Delta
				// Normalised value (0-100) = remaining life percentage.
				// Raw value = erase cycle count — varies wildly by vendor, NOT a percentage.
				// Use: wear% = 100 - normalised. Only set if normalised is meaningful (<= 100).
				if drive.WearPct == 0 && attr.Value > 0 && attr.Value <= 100 {
					drive.WearPct = 100 - attr.Value
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
				// Normalised value (0-100) = remaining life. Guard against
				// non-normalised firmware values exactly as the 173/177 branch
				// does — without it, 100-Value yields garbage (the 173 raw on the
				// Apple SM128C was 3491877946276; same risk class here). See §J.
				if drive.WearPct == 0 && attr.Value > 0 && attr.Value <= 100 { // NOSONAR — same guard as 173/177: different SMART IDs, identical normalisation logic by design (see §J)
					drive.WearPct = 100 - attr.Value
				}
			}
		}
	}

	return drive
}

// ── HWMON THERMALS ────────────────────────────────────────────────────────────

func collectHwmonThermals(info *models.HardwareInfo) {
	hwmonRoot := "/sys/class/hwmon"
	entries, err := readDirNames(hwmonRoot)
	if err != nil {
		return
	}

	for _, e := range entries {
		dir := filepath.Join(hwmonRoot, e)
		nameBytes, err := readFile(filepath.Join(dir, "name")) // #nosec G304
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

		temps, _ := glob(filepath.Join(dir, "temp*_input"))
		for _, tf := range temps {
			val, err := readFile(tf) // #nosec G304
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
			if lb, err := readFile(labelFile); err == nil { // #nosec G304
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
	// Shared sysfs reader (also used by the fast health Memory collector) so the
	// two EDAC paths can't drift apart.
	avail, ce, ue, unreadable := readEDACCounts()
	info.Memory.EDACAvailable = avail
	info.Memory.CorrectedErrors += ce
	info.Memory.UncorrectedErrors += ue
	info.Memory.EDACCountersUnreadable = unreadable
}

// ── CPU ───────────────────────────────────────────────────────────────────────

// armImplementerName maps ARM CPU implementer codes to vendor names.

func collectCPU(info *models.HardwareInfo) {
	data, err := readFile("/proc/cpuinfo")
	if err != nil {
		return
	}

	cpu := parseProcCPUInfo(string(data))
	threads := cpu.threads
	model := cpu.model

	// ARM: device-tree model fallback (filesystem-backed, kept out of the parser).
	// Reached only when /proc/cpuinfo had no model name, Hardware, or implementer —
	// parseProcCPUInfo resolves the vendor/core string when an implementer is present.
	if model == "" {
		for _, path := range []string{
			"/sys/firmware/devicetree/base/model",
			"/proc/device-tree/model",
		} {
			if b, err := readFile(path); err == nil { // #nosec G304
				model = strings.TrimRight(string(b), "\x00\n")
				break
			}
		}
	}

	info.CPU = models.HardwareCPU{
		Model:   model,
		Cores:   cpu.cores,
		Threads: threads,
		FreqMHz: cpu.freqMHz,
	}

	// Max boost frequency from cpufreq sysfs (kHz → MHz)
	if b, err := readFile("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"); err == nil { // #nosec G304
		if n, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
			info.CPU.MaxFreqMHz = n / 1000
		}
	}
	// Current frequency from cpufreq if not in /proc/cpuinfo (common on ARM)
	if info.CPU.FreqMHz == 0 {
		if b, err := readFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"); err == nil { // #nosec G304
			if n, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
				info.CPU.FreqMHz = n / 1000
			}
		}
	}

	// Load average from /proc/loadavg — used for idle thermal check in render
	if b, err := readFile("/proc/loadavg"); err == nil { // #nosec G304
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
		b, err := readFile(f) // #nosec G304
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

func collectNICs(_ context.Context, info *models.HardwareInfo) {
	entries, err := readDirNames("/sys/class/net")
	if err != nil {
		return
	}

	for _, e := range entries {
		name := e
		if name == "lo" {
			continue
		}
		// Skip virtual/tunnel interfaces
		switch {
		case name == "bonding_masters": // sysfs control file, not an interface
			continue
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
		if b, err := readFile(netDir + "/address"); err == nil { // #nosec G304
			nic.MAC = strings.TrimSpace(string(b))
		}
		if b, err := readFile(netDir + "/operstate"); err == nil { // #nosec G304
			nic.State = strings.TrimSpace(string(b))
		}
		// tap/tun/veth and some virtual NICs leave operstate "unknown" even when the
		// link is up — they don't implement it. Fall back to carrier: carrier==1 means
		// the link is up. Without this, every virtualization host (PVE/libvirt/Docker)
		// false-WARNs on its tap/veth interfaces (found live on pve01: tap101i0
		// operstate=unknown, carrier=1).
		if nic.State == "unknown" {
			if b, err := readFile(netDir + "/carrier"); err == nil && strings.TrimSpace(string(b)) == "1" { // #nosec G304
				nic.State = "up"
			}
		}
		if b, err := readFile(netDir + "/speed"); err == nil { // #nosec G304
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
				nic.SpeedMbps = n
			}
		}
		// Driver from symlink
		if link, err := readLink(netDir + "/device/driver"); err == nil {
			nic.Driver = filepath.Base(link)
		}
		// RX/TX errors from sysfs stats
		if b, err := readFile(netDir + "/statistics/rx_errors"); err == nil { // #nosec G304
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
				nic.RxErrors = n
			}
		}
		if b, err := readFile(netDir + "/statistics/tx_errors"); err == nil { // #nosec G304
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
				nic.TxErrors = n
			}
		}

		info.NICs = append(info.NICs, nic)
	}
}
