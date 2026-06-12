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
type GPUCollector struct {
	// Deep enables deep-only sysfs reads (e.g. power_dpm_force_performance_level).
	Deep bool
}

func NewGPUCollector() *GPUCollector { return &GPUCollector{} }

func (c *GPUCollector) Name() string           { return "GPU" }
func (c *GPUCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *GPUCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.GPUInfo{}

	// Start the 1-second AMD busy sampler early so its sleep overlaps with the
	// nvidia-smi call and the rest of collection — it never blocks the caller.
	amdCards := amdCardPaths()
	busyCh := make(chan []busySample, 1)
	if len(amdCards) > 0 {
		go sampleAMDBusy(amdCards, busyCh)
	}

	// NVIDIA — nvidia-smi (opt-in via --gpu flag)
	smiCtx, smiCancel := context.WithTimeout(ctx, 5*time.Second)
	defer smiCancel()

	nvidiaPresent := hasNvidiaCard()
	out, err := runCmd(smiCtx, "nvidia-smi",
		"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit",
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
			dev.Vendor = "nvidia"
			dev.DRMDriver = "nvidia"
			if driverVer != "" && info.DriverVersion == "" {
				info.DriverVersion = driverVer
			}
			if dev.UtilPct >= 50 || dev.TempC >= 70 {
				dev.Processes = collectGPUProcesses(smiCtx)
			}
			info.Devices = append(info.Devices, dev)
		}
	} else if nvidiaPresent {
		// NVIDIA GPU detected but nvidia-smi unavailable.
		// Determine why: nouveau (open-source, no power/memory metrics) vs truly no driver.
		nvidiaCards := detectNvidiaWithoutSMI()
		info.NoDriver = append(info.NoDriver, nvidiaCards...)
		if len(info.NoDriver) > 0 {
			info.Status = "nvidia-no-driver"
			info.StatusReason = fmt.Sprintf(
				"%d NVIDIA GPU(s) found without proprietary driver — nvidia-smi unavailable",
				len(info.NoDriver))
		}
	}

	// Mesa version is system-wide — detect once and apply to AMD/Intel devices.
	mesa := detectMesaVersion(ctx)

	// AMD — sysfs (always available, no commands needed)
	// Works on RDNA, RDNA2, RDNA3, Van Gogh (Steam Deck APU), Polaris, Vega
	amdDevices := collectAMDGPUs(amdCards, c.Deep)

	// Apply the 1-second busy sample (keyed by position — amdDevices is built
	// from amdCards in the same order).
	if len(amdCards) > 0 {
		select {
		case samples := <-busyCh:
			for i := range amdDevices {
				if i >= len(samples) {
					break
				}
				if samples[i].gpuBusy >= 0 {
					amdDevices[i].UtilPct = samples[i].gpuBusy
				}
				if samples[i].memBusy >= 0 {
					amdDevices[i].MemBusyPct = samples[i].memBusy
				}
			}
		case <-ctx.Done():
		}
	}
	for i := range amdDevices {
		if mesa != "" {
			amdDevices[i].MesaVersion = mesa
		}
	}
	info.Devices = append(info.Devices, amdDevices...)

	// Intel — sysfs (i915/xe): temperature + power only
	intelDevices := collectIntelGPUs()
	for i := range intelDevices {
		if mesa != "" {
			intelDevices[i].MesaVersion = mesa
		}
	}
	info.Devices = append(info.Devices, intelDevices...)

	return info, nil
}

// busySample holds a one-second-instantaneous GPU/memory busy reading.
// A negative value means the corresponding sysfs file was absent/unreadable.
type busySample struct {
	gpuBusy int
	memBusy int
}

// sampleAMDBusy sleeps 1 second, then reads gpu_busy_percent and mem_busy_percent
// for each AMD card. The post-sleep read is the instantaneous value that matches
// what htop/MangoHud show (not a long-window average). Results are ordered to
// match the input cards slice.
func sampleAMDBusy(cards []string, ch chan<- []busySample) {
	time.Sleep(1 * time.Second)
	out := make([]busySample, len(cards))
	for i, card := range cards {
		devPath := card + "/device"
		s := busySample{gpuBusy: -1, memBusy: -1}
		if v := readSysfsStr(devPath + "/gpu_busy_percent"); v != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				s.gpuBusy = n
			}
		}
		if v := readSysfsStr(devPath + "/mem_busy_percent"); v != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				s.memBusy = n
			}
		}
		out[i] = s
	}
	ch <- out
}

// collectGPUProcesses returns processes using the GPU via nvidia-smi.
func collectGPUProcesses(ctx context.Context) []models.GPUProcess {
	out, err := runCmd(ctx, "nvidia-smi",
		"--query-compute-apps=pid,used_memory,name",
		"--format=csv,noheader,nounits")
	if err != nil {
		return nil
	}
	return parseGPUProcesses(out)
}

// parseGPUProcesses parses `nvidia-smi --query-compute-apps=pid,used_memory,name
// --format=csv,noheader,nounits` output.
func parseGPUProcesses(out string) []models.GPUProcess {
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
		// memory field may be "6823 MiB", just "6823", or empty/"[N/A]" on
		// MIG / vGPU / no-accounting GPUs — guard against an empty slice.
		memFields := strings.Fields(memStr)
		mem := 0
		if len(memFields) > 0 {
			mem, _ = strconv.Atoi(memFields[0])
		}
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

	// power.limit is appended only on newer nvidia-smi; parse when present.
	var powerLimit float64
	if len(fields) >= 9 {
		if ls := trim(fields[8]); ls != "" && ls != "[N/A]" {
			powerLimit, _ = strconv.ParseFloat(ls, 64)
		}
	}

	memPct := 0.0
	if memTotal > 0 {
		memPct = float64(memUsed) / float64(memTotal) * 100
	}

	dev := models.GPUDevice{
		Index:       idx,
		Name:        name,
		TempC:       temp,
		UtilPct:     util,
		MemUsedMB:   memUsed,
		MemTotalMB:  memTotal,
		MemUsedPct:  memPct,
		VRAMUsedGB:  float64(memUsed) / 1024,
		VRAMTotalGB: float64(memTotal) / 1024,
		VRAMUsedPct: memPct,
		PowerDrawW:  power,
		TDPCurrentW: power,
		TDPLimitW:   powerLimit,
	}
	if powerLimit > 0 && power >= 0.95*powerLimit {
		dev.Throttling = true
	}
	return dev, driverVer, nil
}

// hasNvidiaCard returns true when an NVIDIA GPU is present in the system
// via /sys/class/drm sysfs — works even without the proprietary driver loaded.
func hasNvidiaCard() bool {
	cards, _ := filepath.Glob("/sys/class/drm/card[0-9]")
	for _, card := range cards {
		vendor := strings.TrimSpace(readSysfsStr(card + "/device/vendor"))
		if strings.EqualFold(vendor, "0x10de") {
			return true
		}
	}
	return false
}

// amdCardPaths returns the /sys/class/drm/cardN paths whose vendor ID is AMD
// (0x1002). The order is the glob order and is reused to align the async busy
// sample with the collected devices.
func amdCardPaths() []string {
	cards, err := filepath.Glob("/sys/class/drm/card[0-9]")
	if err != nil {
		return nil
	}
	var out []string
	for _, card := range cards {
		vendor := strings.TrimSpace(readSysfsStr(card + "/device/vendor"))
		if strings.EqualFold(vendor, "0x1002") {
			out = append(out, card)
		}
	}
	return out
}

// collectAMDGPUs reads AMD GPU health from /sys/class/drm/card*/device/.
// Pure sysfs — no commands, no root required, works on all AMD iGPU and dGPU.
// Paths are stable across kernel versions since DRM/KMS introduction.
//
// Metrics read per card:
//   - name: from hwmon/hwmon*/name or uevent MODEL
//   - temp: hwmon/hwmon*/temp{1,2,3}_input — edge / junction / memory (millidegrees → °C)
//   - clock: pp_dpm_sclk (current marked with '*', plus max level)
//   - VRAM: mem_info_vram_used + mem_info_vram_total (bytes)
//   - TDP: hwmon/hwmon*/power1_cap{,_max} + power1_input (microwatts → W)
//   - driver: device/driver symlink basename (amdgpu)
//   - (deep) power_dpm_force_performance_level
//
// gpu_busy_percent / mem_busy_percent are sampled separately (see sampleAMDBusy).
func collectAMDGPUs(cards []string, deep bool) []models.GPUDevice {
	devices := make([]models.GPUDevice, 0, len(cards))
	for _, card := range cards {
		devPath := card + "/device"

		dev := models.GPUDevice{
			Index:     cardIndex(card),
			Name:      amdGPUName(devPath),
			Vendor:    "amd",
			DRMDriver: drmDriver(devPath),
		}

		// Temperatures — millidegrees → °C. temp1=edge, temp2=junction, temp3=memory.
		dev.TempC = readSysfsMilliC(devPath + "/hwmon/hwmon*/temp1_input")
		dev.TempJunctionC = readSysfsMilliC(devPath + "/hwmon/hwmon*/temp2_input")
		dev.TempMemC = readSysfsMilliC(devPath + "/hwmon/hwmon*/temp3_input")

		// GPU utilisation % — base read; overridden by the 1s instantaneous sample.
		if utilStr := readSysfsStr(devPath + "/gpu_busy_percent"); utilStr != "" {
			dev.UtilPct, _ = strconv.Atoi(strings.TrimSpace(utilStr))
		}

		// GPU core clock — current (marked '*') and max from pp_dpm_sclk.
		dev.ClockMHz, dev.ClockMaxMHz = parseDPMSclk(readSysfsStr(devPath + "/pp_dpm_sclk"))

		// VRAM — bytes → MB (legacy) and GB (display).
		usedBytes := readSysfsInt64(devPath + "/mem_info_vram_used")
		totalBytes := readSysfsInt64(devPath + "/mem_info_vram_total")
		dev.MemUsedMB = int(usedBytes / (1024 * 1024))
		dev.MemTotalMB = int(totalBytes / (1024 * 1024))
		dev.VRAMUsedGB = float64(usedBytes) / (1024 * 1024 * 1024)
		dev.VRAMTotalGB = float64(totalBytes) / (1024 * 1024 * 1024)
		if dev.MemTotalMB > 0 {
			dev.MemUsedPct = float64(dev.MemUsedMB) / float64(dev.MemTotalMB) * 100
			dev.VRAMUsedPct = dev.MemUsedPct
		}
		// APU: small VRAM carveout + a GTT (shared system memory) pool present.
		if dev.VRAMTotalGB < 2.0 && readSysfsStr(devPath+"/mem_info_gtt_total") != "" {
			dev.IsAPU = true
		}

		// TDP — power1_cap (limit), power1_cap_max (hw max), power1_input (current).
		dev.TDPLimitW = readSysfsMicroW(devPath + "/hwmon/hwmon*/power1_cap")
		dev.TDPMaxW = readSysfsMicroW(devPath + "/hwmon/hwmon*/power1_cap_max")
		dev.TDPCurrentW = readSysfsMicroW(devPath + "/hwmon/hwmon*/power1_input")
		switch {
		case dev.TDPCurrentW > 0:
			dev.PowerDrawW = dev.TDPCurrentW
		default:
			// Fall back to power1_average if no instantaneous input is exposed.
			dev.PowerDrawW = readSysfsMicroW(devPath + "/hwmon/hwmon*/power1_average")
		}
		if dev.TDPLimitW > 0 && dev.TDPCurrentW >= 0.95*dev.TDPLimitW {
			dev.Throttling = true
		}

		if deep {
			dev.PowerDPMLevel = strings.TrimSpace(readSysfsStr(devPath + "/power_dpm_force_performance_level"))
		}

		devices = append(devices, dev)
	}
	return devices
}

// collectIntelGPUs reads the limited data Intel i915/xe exposes without root:
// hwmon temperature and, where present, power1_input. Clock and VRAM require
// debugfs + root and are skipped.
func collectIntelGPUs() []models.GPUDevice {
	cards, err := filepath.Glob("/sys/class/drm/card[0-9]")
	if err != nil {
		return nil
	}
	var devices []models.GPUDevice
	for _, card := range cards {
		devPath := card + "/device"
		vendor := strings.TrimSpace(readSysfsStr(devPath + "/vendor"))
		if !strings.EqualFold(vendor, "0x8086") {
			continue
		}
		dev := models.GPUDevice{
			Index:     cardIndex(card),
			Name:      intelGPUName(devPath),
			Vendor:    "intel",
			DRMDriver: drmDriver(devPath),
		}
		dev.TempC = readSysfsMilliC(devPath + "/hwmon/hwmon*/temp1_input")
		dev.PowerDrawW = readSysfsMicroW(devPath + "/hwmon/hwmon*/power1_input")
		devices = append(devices, dev)
	}
	return devices
}

// parseDPMSclk parses an amdgpu pp_dpm_sclk table. Lines look like
// "0: 200Mhz" / "2: 1600Mhz *"; the '*' marks the active level. Returns the
// current clock (the active line) and the maximum clock across all levels.
func parseDPMSclk(data string) (cur, max int) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		active := strings.HasSuffix(line, "*")
		mhz := 0
		for _, tok := range strings.Fields(line) {
			low := strings.ToLower(tok)
			if strings.HasSuffix(low, "mhz") {
				if v, err := strconv.Atoi(strings.TrimSuffix(low, "mhz")); err == nil {
					mhz = v
				}
			}
		}
		if mhz > max {
			max = mhz
		}
		if active {
			cur = mhz
		}
	}
	return cur, max
}

// detectMesaVersion parses `glxinfo -B` for the Mesa version in the OpenGL
// version string. It only runs when a display is available (glxinfo needs one)
// and is bounded to 2s. Returns "" on any failure.
func detectMesaVersion(ctx context.Context) string {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return ""
	}
	gctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := runCmd(gctx, "glxinfo", "-B")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "OpenGL version string") {
			continue
		}
		idx := strings.Index(line, "Mesa")
		if idx < 0 {
			continue
		}
		fields := strings.Fields(line[idx:])
		if len(fields) >= 2 {
			return fields[1] // "Mesa 24.3.1" → "24.3.1"
		}
	}
	return ""
}

// drmDriver returns the kernel driver bound to a DRM device (e.g. "amdgpu",
// "i915", "nouveau") from the device/driver symlink. Empty if none is bound.
func drmDriver(devPath string) string {
	link, err := os.Readlink(devPath + "/driver")
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

// cardIndex extracts the integer index from a "/sys/class/drm/cardN" path.
func cardIndex(card string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(card), "card"))
	return n
}

// intelGPUName returns a human-readable name for an Intel GPU.
func intelGPUName(devPath string) string {
	uevent := readSysfsStr(devPath + "/uevent")
	for _, line := range strings.Split(uevent, "\n") {
		if strings.HasPrefix(line, "PCI_ID=") {
			parts := strings.SplitN(strings.TrimPrefix(line, "PCI_ID="), ":", 2)
			if len(parts) == 2 {
				return "Intel GPU (" + parts[1] + ")"
			}
		}
	}
	return "Intel GPU"
}

// readSysfsInt64 reads a sysfs file holding a single integer as int64 — used
// for byte counts (VRAM) that can exceed 32-bit range.
func readSysfsInt64(path string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(readSysfsStr(path)), 10, 64)
	return n
}

// readSysfsMilliC reads a millidegree-Celsius sysfs file (first glob match) and
// returns whole °C. Returns 0 if absent/unreadable.
func readSysfsMilliC(pattern string) int {
	s := readSysfsFirstGlob(pattern)
	if s == "" {
		return 0
	}
	milli, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return int(milli / 1000)
}

// readSysfsMicroW reads a microwatt sysfs file (first glob match) and returns
// watts. Returns 0 if absent/unreadable.
func readSysfsMicroW(pattern string) float64 {
	s := readSysfsFirstGlob(pattern)
	if s == "" {
		return 0
	}
	uw, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return float64(uw) / 1_000_000
}

// detectNvidiaWithoutSMI finds NVIDIA GPUs whose driver is not the
// proprietary nvidia module (i.e. nvidia-smi won't work).
// Returns entries for: nouveau-bound, no-driver-at-all, or vfio-bound.
func detectNvidiaWithoutSMI() []models.GPUDetected {
	cards, _ := filepath.Glob("/sys/class/drm/card[0-9]")
	var found []models.GPUDetected
	for _, card := range cards {
		devPath := card + "/device"
		v := strings.TrimSpace(readSysfsStr(devPath + "/vendor"))
		if !strings.EqualFold(v, "0x10de") {
			continue
		}
		uevent := readSysfsStr(devPath + "/uevent")
		// Check bound driver from uevent DRIVER= field
		driverName := ""
		for _, line := range strings.Split(uevent, "\n") {
			if strings.HasPrefix(line, "DRIVER=") {
				driverName = strings.TrimPrefix(line, "DRIVER=")
				driverName = strings.TrimSpace(driverName)
				break
			}
		}
		// Skip if proprietary nvidia driver is bound (shouldn't happen — smi would work)
		if driverName == "nvidia" {
			continue
		}

		name := "NVIDIA GPU"
		pciAddr := ""
		for _, line := range strings.Split(uevent, "\n") {
			switch {
			case strings.HasPrefix(line, "PCI_ID="):
				parts := strings.SplitN(strings.TrimPrefix(line, "PCI_ID="), ":", 2)
				if len(parts) == 2 {
					name = "NVIDIA GPU (" + parts[1] + ")"
				}
			case strings.HasPrefix(line, "PCI_SLOT_NAME="):
				pciAddr = strings.TrimPrefix(line, "PCI_SLOT_NAME=")
			}
		}

		// Annotate with actual driver name so user knows what's bound
		if driverName != "" && driverName != "nvidia" {
			name += " [" + driverName + "]"
		}

		found = append(found, models.GPUDetected{
			Name:    name,
			Vendor:  "nvidia",
			PCIAddr: strings.TrimSpace(pciAddr),
		})
	}
	return found
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
