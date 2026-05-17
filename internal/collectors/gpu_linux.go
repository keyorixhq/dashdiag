//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// GPUCollector reads GPU health.
// NVIDIA: via nvidia-smi (no stable kernel interface for VRAM/power/Xid).
// AMD:    via /sys/class/drm/card*/device/ sysfs (stable, no commands needed).
// Intel:  sysfs only — basic detection, limited metrics.
type GPUCollector struct{}

func NewGPUCollector() *GPUCollector { return &GPUCollector{} }

func (c *GPUCollector) Name() string           { return "GPU" }
func (c *GPUCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *GPUCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.GPUInfo{}

	// NVIDIA — nvidia-smi (opt-in via --gpu flag)
	smiCtx, smiCancel := context.WithTimeout(ctx, 5*time.Second)
	defer smiCancel()

	out, err := runCmd(smiCtx, "nvidia-smi",
		"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version",
		"--format=csv,noheader,nounits")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			dev, driverVer, err := parseNvidiaSMILine(line)
			if err != nil {
				continue
			}
			if driverVer != "" && info.DriverVersion == "" {
				info.DriverVersion = driverVer
			}
			if dev.UtilPct >= 50 || dev.TempC >= 70 {
				dev.Processes = collectGPUProcesses(smiCtx)
			}
			info.Devices = append(info.Devices, dev)
		}
	}

	// AMD — sysfs (always available, no commands needed)
	// Works on RDNA, RDNA2, RDNA3, Van Gogh (Steam Deck APU), Polaris, Vega
	amdDevices := collectAMDGPUs()
	info.Devices = append(info.Devices, amdDevices...)

	return info, nil
}

// collectGPUProcesses returns processes using the GPU via nvidia-smi.
func collectGPUProcesses(ctx context.Context) []models.GPUProcess {
	out, err := runCmd(ctx, "nvidia-smi",
		"--query-compute-apps=pid,used_memory,name",
		"--format=csv,noheader,nounits")
	if err != nil {
		return nil
	}

	var procs []models.GPUProcess
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, ",", 3)
		if len(fields) < 3 {
			continue
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(fields[0]))
		memStr := strings.TrimSpace(fields[1])
		// memory field may be "6823 MiB" or just "6823"
		memFields := strings.Fields(memStr)
		mem, _ := strconv.Atoi(memFields[0])
		name := strings.TrimSpace(fields[2])
		procs = append(procs, models.GPUProcess{
			PID:      pid,
			Name:     name,
			MemUseMB: mem,
		})
	}
	return procs
}

func parseNvidiaSMILine(line string) (models.GPUDevice, string, error) {
	fields := strings.Split(line, ",")
	if len(fields) < 8 {
		return models.GPUDevice{}, "", fmt.Errorf("unexpected fields: %d", len(fields))
	}
	trim := func(s string) string { return strings.TrimSpace(s) }

	idx, _ := strconv.Atoi(trim(fields[0]))
	name := trim(fields[1])
	temp, _ := strconv.Atoi(trim(fields[2]))
	util, _ := strconv.Atoi(trim(fields[3]))
	memUsed, _ := strconv.Atoi(trim(fields[4]))
	memTotal, _ := strconv.Atoi(trim(fields[5]))
	powerStr := trim(fields[6])
	var power float64
	if powerStr != "[N/A]" {
		power, _ = strconv.ParseFloat(powerStr, 64)
	}
	driverVer := trim(fields[7])

	memPct := 0.0
	if memTotal > 0 {
		memPct = float64(memUsed) / float64(memTotal) * 100
	}

	return models.GPUDevice{
		Index:      idx,
		Name:       name,
		TempC:      temp,
		UtilPct:    util,
		MemUsedMB:  memUsed,
		MemTotalMB: memTotal,
		MemUsedPct: memPct,
		PowerDrawW: power,
	}, driverVer, nil
}

// collectAMDGPUs reads AMD GPU health from /sys/class/drm/card*/device/.
// Pure sysfs — no commands, no root required, works on all AMD iGPU and dGPU.
// Paths are stable across kernel versions since DRM/KMS introduction.
//
// Metrics read per card:
//   - vendor: must be 0x1002 (AMD) to filter out Intel/NVIDIA DRM cards
//   - name: from hwmon/hwmon*/name or uevent MODEL
//   - temp: hwmon/hwmon*/temp1_input (millidegrees → °C)
//   - util: gpu_busy_percent (0-100%)
//   - VRAM: mem_info_vram_used + mem_info_vram_total (bytes)
//   - power: hwmon/hwmon*/power1_average (microwatts → W)
func collectAMDGPUs() []models.GPUDevice {
	cards, err := filepath.Glob("/sys/class/drm/card[0-9]")
	if err != nil || len(cards) == 0 {
		return nil
	}

	var devices []models.GPUDevice
	for idx, card := range cards {
		devPath := card + "/device"

		// Only process AMD cards (vendor ID 0x1002)
		vendor := readSysfsStr(devPath + "/vendor")
		if !strings.EqualFold(strings.TrimSpace(vendor), "0x1002") {
			continue
		}

		dev := models.GPUDevice{
			Index: idx,
			Name:  amdGPUName(devPath),
		}

		// Temperature — hwmon/hwmon*/temp1_input in millidegrees
		if tempStr := readSysfsFirstGlob(devPath + "/hwmon/hwmon*/temp1_input"); tempStr != "" {
			if milli, err := strconv.ParseInt(strings.TrimSpace(tempStr), 10, 64); err == nil {
				dev.TempC = int(milli / 1000)
			}
		}

		// GPU utilisation %
		if utilStr := readSysfsStr(devPath + "/gpu_busy_percent"); utilStr != "" {
			util, _ := strconv.Atoi(strings.TrimSpace(utilStr))
			dev.UtilPct = util
		}

		// VRAM
		if usedStr := readSysfsStr(devPath + "/mem_info_vram_used"); usedStr != "" {
			if used, err := strconv.ParseInt(strings.TrimSpace(usedStr), 10, 64); err == nil {
				dev.MemUsedMB = int(used / (1024 * 1024))
			}
		}
		if totalStr := readSysfsStr(devPath + "/mem_info_vram_total"); totalStr != "" {
			if total, err := strconv.ParseInt(strings.TrimSpace(totalStr), 10, 64); err == nil {
				dev.MemTotalMB = int(total / (1024 * 1024))
			}
		}
		if dev.MemTotalMB > 0 {
			dev.MemUsedPct = float64(dev.MemUsedMB) / float64(dev.MemTotalMB) * 100
		}

		// Power draw — hwmon/hwmon*/power1_average in microwatts
		if powerStr := readSysfsFirstGlob(devPath + "/hwmon/hwmon*/power1_average"); powerStr != "" {
			if uw, err := strconv.ParseInt(strings.TrimSpace(powerStr), 10, 64); err == nil {
				dev.PowerDrawW = float64(uw) / 1_000_000
			}
		}

		devices = append(devices, dev)
	}
	return devices
}

// amdGPUName returns a human-readable name for an AMD GPU.
// Tries hwmon name first, falls back to uevent MODEL, then device ID.
func amdGPUName(devPath string) string {
	// hwmon name (e.g. "amdgpu")
	name := readSysfsFirstGlob(devPath + "/hwmon/hwmon*/name")
	if name != "" && name != "amdgpu" {
		return strings.TrimSpace(name)
	}
	// uevent — may contain MODEL or PCI_ID
	uevent := readSysfsStr(devPath + "/uevent")
	for _, line := range strings.Split(uevent, "\n") {
		if strings.HasPrefix(line, "PCI_ID=") {
			// Format: "PCI_ID=1002:687F" → show as "AMD GPU (687F)"
			parts := strings.SplitN(strings.TrimPrefix(line, "PCI_ID="), ":", 2)
			if len(parts) == 2 {
				return "AMD GPU (" + parts[1] + ")"
			}
		}
	}
	return "AMD GPU"
}

// readSysfsStr reads a sysfs file and returns its content as a string.
// Returns "" on any error.
func readSysfsStr(path string) string {
	b, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return ""
	}
	return string(b)
}

// readSysfsFirstGlob returns the content of the first file matching a glob pattern.
func readSysfsFirstGlob(pattern string) string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	return readSysfsStr(matches[0])
}
