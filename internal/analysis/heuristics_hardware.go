package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
)

func checkBattery(b models.BatteryInfo) []models.Insight {
	if !b.Present {
		return nil // desktop or no battery
	}
	var out []models.Insight

	// Battery wear
	if b.HealthPct > 0 {
		if b.HealthPct < 60 {
			out = append(out, insight("CRIT", "Battery",
				fmt.Sprintf("battery health at %.0f%% — replacement recommended", b.HealthPct),
				[]string{"to inspect: cat /sys/class/power_supply/BAT0/energy_full_design"},
			))
		} else if b.HealthPct < 80 {
			out = append(out, insight("WARN", "Battery",
				fmt.Sprintf("battery health at %.0f%% (%.0f cycle(s)) — degraded", b.HealthPct, float64(b.CycleCounts)),
				[]string{"to inspect: cat /sys/class/power_supply/BAT0/energy_full"},
			))
		}
	}

	// Low charge while discharging
	if b.Status == "Discharging" && b.CapacityPct <= 10 {
		out = append(out, insight("CRIT", "Battery",
			fmt.Sprintf("battery at %d%% and discharging — connect power", b.CapacityPct),
			nil,
		))
	} else if b.Status == "Discharging" && b.CapacityPct <= 20 {
		out = append(out, insight("WARN", "Battery",
			fmt.Sprintf("battery at %d%% and discharging", b.CapacityPct),
			nil,
		))
	}

	return out
}

func checkThermal(t models.ThermalInfo, thresh Thresholds) []models.Insight {
	if t.CPUTempC == 0 || t.Source == "" {
		return nil // no thermal data available on this platform
	}
	// A faulted/virtual hwmon sensor can report an impossible value (the VMware
	// vNVMe 11758°C class, or a negative k10temp offset). readHwmonTemps does a bare
	// ParseFloat with no bounds, so reject implausible readings as unverified rather
	// than firing a false "thermal throttling active" CRIT — same gate the dsd
	// hardware display path and every drive-temp verdict already apply.
	if !TempPlausible(t.CPUTempC, TempCeilSilicon) {
		return []models.Insight{insight("WARN", "CPU Thermal",
			fmt.Sprintf("implausible CPU temperature %g°C (source: %s) — sensor likely faulted; reading rejected, health unverified", t.CPUTempC, t.Source),
			[]string{
				"to inspect: cat /sys/class/hwmon/hwmon*/temp*_input",
				"to inspect: sensors  (compare against a second source)",
			},
		)}
	}
	hints := []string{
		"to inspect: cat /sys/class/hwmon/hwmon*/temp*_input",
		"to inspect: check cooling and airflow",
	}
	if t.CPUTempC >= 95 {
		return []models.Insight{insight("CRIT", "CPU Thermal",
			fmt.Sprintf("CPU temperature %g°C — thermal throttling active", t.CPUTempC),
			hints,
		)}
	}
	if t.CPUTempC >= 85 {
		return []models.Insight{insight("WARN", "CPU Thermal",
			fmt.Sprintf("CPU temperature %g°C — elevated (source: %s)", t.CPUTempC, t.Source),
			hints,
		)}
	}
	// Load-aware idle thermal check:
	// High temp at low CPU load suggests poor cooling (dried paste, blocked vents)
	// rather than normal workload heat. Only warn if we actually have load data.
	// Threshold: ≥75°C when CPU is under 20% load. The floor was raised from 60°C
	// because 60–74°C at idle is normal for a large class of real hardware —
	// mini-PCs/NUCs, laptops, and high-TDP desktop chips (Ryzen, etc.) routinely
	// idle there with healthy cooling. Only ≥75°C at idle is genuinely suspect.
	if thresh.CPULoadPct > 0 && t.CPUTempC >= 75 && thresh.CPULoadPct < 20 {
		return []models.Insight{insight("WARN", "CPU Thermal",
			fmt.Sprintf("CPU temperature %g°C at %.0f%% load — elevated for low CPU activity, possible cooling issue",
				t.CPUTempC, thresh.CPULoadPct),
			[]string{
				"to inspect: cat /sys/class/hwmon/hwmon*/temp*_input",
				"to inspect: check for dust buildup and blocked vents",
				"to inspect: consider reseating thermal paste on older hardware",
			},
		)}
	}
	return nil
}

// isSteamOSHost reports whether the host is SteamOS / a Steam Deck by reading
// /etc/os-release. This is a cheap probe (single file read) suited to the analysis
// path; the full platform.Profile is not threaded through here. Routed through the
// active source so capture/replay reproduces it instead of reading the replaying
// machine's /etc/os-release (which would mis-detect SteamOS on replay).
func isSteamOSHost() bool {
	data, err := collectors.ReadFileViaSource("/etc/os-release")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		val = strings.ToLower(strings.Trim(val, `"'`))
		if key == "ID" && val == "steamos" {
			return true
		}
		if key == "VARIANT_ID" && val == "steamdeck" {
			return true
		}
	}
	return false
}

// hostIsOstree reports whether the host boots an ostree-managed immutable root —
// Fedora CoreOS, Silverblue, Kinoite, IoT, or RHEL CoreOS — where /usr is
// read-only and packages are layered via `rpm-ostree install <pkg>` + reboot,
// not live `dnf install`. Detected from /etc/os-release (routed through the
// active source for replay fidelity, same as isSteamOSHost): the immutable
// variants carry a VARIANT_ID of coreos/silverblue/kinoite/iot/sericea/onyx, or
// ID fedora-coreos / rhcos. Plain Fedora (VARIANT_ID=workstation/server/cloud)
// is mutable and must NOT match — it uses dnf. (Found on Fedora CoreOS, where
// the open-vm-tools/rsyslog fix hints said `dnf install`, which cannot persist
// on the read-only /usr, 2026-06-29.)
func hostIsOstree() bool {
	data, err := collectors.ReadFileViaSource("/etc/os-release")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		val = strings.ToLower(strings.Trim(val, `"'`))
		switch key {
		case "ID":
			if val == "fedora-coreos" || val == "rhcos" {
				return true
			}
		case "VARIANT_ID":
			switch val {
			case "coreos", "silverblue", "kinoite", "iot", "sericea", "onyx":
				return true
			}
		}
	}
	return false
}

func checkGPU(gpu models.GPUInfo) []models.Insight {
	if len(gpu.Devices) == 0 && gpu.Status == "" {
		return nil // no GPU or driver not loaded — skip silently
	}
	var out []models.Insight

	// NVIDIA detected but driver/nvidia-smi not available
	if gpu.Status == "nvidia-no-driver" {
		out = append(out, insight("INFO", "GPU",
			"NVIDIA GPU detected — install driver for GPU health monitoring",
			[]string{
				"to fix (Debian/Ubuntu): apt-get install nvidia-driver",
				"to fix (RHEL/Fedora):   dnf install akmod-nvidia  (RPM Fusion required)",
				"to inspect: lspci | grep -i nvidia",
				"note: reboot required after driver install",
			},
		))
	}

	steamOS := isSteamOSHost()
	for _, dev := range gpu.Devices {
		prefix := dev.Name
		if len(gpu.Devices) > 1 {
			prefix = fmt.Sprintf("GPU%d (%s)", dev.Index, dev.Name)
		}
		out = append(out, checkGPUDevice(dev, prefix, steamOS)...)
	}
	return out
}

// GPUDeviceHasMetrics reports whether any readable health metric was obtained for
// the device. An older Intel iGPU with no hwmon exposes none — temp/util/mem/
// power/clock all stay 0 — and must not be summarized as healthy. Shared by
// checkGPUDevice (dsd health) and the `dsd gpu` summary so the two cannot drift.
func GPUDeviceHasMetrics(d models.GPUDevice) bool {
	return d.TempC > 0 || d.TempJunctionC > 0 || d.PowerDrawW > 0 ||
		d.UtilPct > 0 || d.MemTotalMB > 0 || d.ClockMHz > 0 || d.TDPLimitW > 0
}

// GPUTempPlausible reports whether a GPU temperature (°C) is physically possible.
// hwmon temp*_input is read raw — readSysfsMilliC does a bare ParseInt/1000 with
// no bounds check — so a virtual GPU, a faulted sensor, or a garbage/sentinel
// sysfs value can surface as thousands of degrees and fire a false "thermal
// throttling likely" CRIT. Real GPU silicon throttles and then hard-shuts-down
// well below 150°C, so a reading outside the silicon range is garbage, not an
// overheat — surface it as unverified, do NOT score it as a CRIT. (0 is handled
// earlier by GPUDeviceHasMetrics, so it never reaches here.) Thin typed wrapper
// over the shared TempPlausible (see temp.go).
func GPUTempPlausible(c int) bool {
	return TempPlausible(float64(c), TempCeilSilicon)
}

// checkGPUDevice returns the health insights for a single GPU device.
func checkGPUDevice(dev models.GPUDevice, prefix string, steamOS bool) []models.Insight {
	var out []models.Insight
	// nvidia-smi listed the GPU but its core metrics came back [N/A]/ERR! — the
	// card has fallen off the bus or faulted. Its temp/util/mem are bogus zeros,
	// so emit the fault and skip the per-metric checks (which would read healthy).
	if dev.Unreadable {
		return append(out, insight("CRIT", "GPU",
			fmt.Sprintf("%s metrics unreadable — nvidia-smi reported [N/A] for temperature and memory (GPU likely fallen off the bus / hardware fault)", prefix),
			[]string{
				"to inspect: nvidia-smi",
				"to inspect: dmesg | grep -iE 'NVRM|Xid|fell off the bus'",
				"a reboot may clear a transient bus fault; persistent [N/A] points to failing hardware",
			},
		))
	}
	// The device was detected but exposed ZERO health metrics (e.g. an older Intel
	// iGPU with no hwmon temperature). The per-metric checks below all read 0 and
	// would silently pass — so we'd claim a healthy GPU we never measured (false-OK).
	// Say so instead. `dsd gpu` already does this; this keeps `dsd health --gpu`
	// consistent. (Real AMD/NVIDIA GPUs populate temp+VRAM, so they're unaffected.)
	if !GPUDeviceHasMetrics(dev) {
		return append(out, insight("INFO", "GPU",
			fmt.Sprintf("%s detected but exposed no health metrics — temperature/utilization not available, health NOT verified", prefix),
			[]string{"to inspect: ls /sys/class/drm/card*/device/hwmon/hwmon*/"},
		))
	}
	// Reject a physically-impossible edge temperature before it can fire a CRIT
	// (§L/§Q raw-tool implausible-value class — garbage hwmon reads as thousands
	// of degrees). Surface it as unverified rather than a false thermal alarm.
	if !GPUTempPlausible(dev.TempC) {
		out = append(out, insight("WARN", "GPU",
			fmt.Sprintf("%s reported an implausible temperature (%d°C) — thermal health unverified, reading rejected", prefix, dev.TempC),
			[]string{"to inspect: cat /sys/class/drm/card*/device/hwmon/hwmon*/temp1_input", "note: out-of-range value (faulted/virtual sensor) — ignored to avoid a false thermal-throttling alarm"},
		))
	} else if dev.TempC >= 90 {
		out = append(out, insight("CRIT", "GPU",
			fmt.Sprintf("%s temperature %d°C — thermal throttling likely", prefix, dev.TempC),
			[]string{"to inspect: nvidia-smi", "to inspect: check cooling and airflow"},
		))
	} else if dev.TempC >= 80 {
		out = append(out, insight("WARN", "GPU",
			fmt.Sprintf("%s temperature %d°C — elevated", prefix, dev.TempC),
			[]string{"to inspect: nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader"},
		))
	}
	// Junction (hotspot/die) temperature — runs hotter than edge; its own thresholds.
	// Same plausibility gate as the edge sensor.
	if !GPUTempPlausible(dev.TempJunctionC) {
		out = append(out, insight("WARN", "GPU",
			fmt.Sprintf("%s reported an implausible junction temperature (%d°C) — thermal health unverified, reading rejected", prefix, dev.TempJunctionC),
			[]string{"to inspect: cat /sys/class/drm/card*/device/hwmon/hwmon*/temp2_input", "note: out-of-range value (faulted/virtual sensor) — ignored to avoid a false thermal alarm"},
		))
	} else if dev.TempJunctionC >= 100 {
		out = append(out, insight("CRIT", "GPU",
			fmt.Sprintf("%s junction temperature %d°C — emergency thermal threshold", prefix, dev.TempJunctionC),
			[]string{"to inspect: cat /sys/class/drm/card*/device/hwmon/hwmon*/temp2_input", "shut down and check cooling immediately"},
		))
	} else if dev.TempJunctionC >= 90 {
		out = append(out, insight("WARN", "GPU",
			fmt.Sprintf("%s junction temperature %d°C — approaching thermal limit", prefix, dev.TempJunctionC),
			[]string{"to inspect: check thermal paste and fan curve if sustained"},
		))
	}
	// TDP throttling — GPU pinned at its power cap.
	if dev.Throttling {
		hint := "to inspect: raise the power cap or improve cooling if more performance is needed"
		if steamOS {
			hint = "to fix: on Steam Deck, increase the TDP limit in Performance settings when plugged in"
		}
		out = append(out, insight("WARN", "GPU",
			fmt.Sprintf("%s TDP throttling — at power limit (%.1fW / %.1fW)", prefix, dev.TDPCurrentW, dev.TDPLimitW),
			[]string{hint},
		))
	}
	// VRAM pressure (GB-based field, complements the MB-based check below).
	// Skip APUs: their "VRAM" is a small shared-RAM carveout that fills to 90%+
	// under any GPU load by design — a high % there is normal, not pressure.
	// Genuine memory exhaustion on an APU surfaces via system-RAM checks.
	if dev.VRAMUsedPct >= 90 && !dev.IsAPU {
		out = append(out, insight("WARN", "GPU",
			fmt.Sprintf("%s VRAM at %.0f%% — high memory pressure", prefix, dev.VRAMUsedPct),
			[]string{"to inspect: reduce texture/resolution settings or close GPU-heavy apps"},
		))
	}
	// DPM stuck low (deep-only field) — performance capped after failed power
	// management. Gated on UtilPct: many power profiles (laptop battery-saver,
	// tuned, an idle desktop) legitimately park DPM at "low" while idle — that's
	// correct behavior, not a fault. Only a genuine workload (UtilPct >= 50, the
	// same load-evidence bar used by the sustained-compute-load INFO below)
	// pinned at "low" indicates the GPU failed to ramp up under demand.
	if dev.PowerDPMLevel == "low" && dev.UtilPct >= 50 {
		out = append(out, insight("WARN", "GPU",
			fmt.Sprintf("%s stuck in low-power DPM mode under load (%d%% util) — performance capped", prefix, dev.UtilPct),
			[]string{"to fix: echo auto > /sys/class/drm/card*/device/power_dpm_force_performance_level"},
		))
	}
	if l := levelPct(dev.MemUsedPct, 85, 95); l != "" && !dev.IsAPU {
		out = append(out, insight(l, "GPU",
			fmt.Sprintf("%s VRAM usage at %.0f%% (%d/%d MB)", prefix, dev.MemUsedPct, dev.MemUsedMB, dev.MemTotalMB),
			[]string{"to inspect: nvidia-smi --query-gpu=memory.used,memory.total --format=csv"},
		))
	}
	// Sustained compute load — INFO signal for correlation engine.
	// Not a fault on its own, but provides context when combined with
	// thermal or memory pressure signals.
	if dev.UtilPct >= 80 && dev.PowerDrawW >= 80 {
		out = append(out, insight("INFO", "GPU",
			fmt.Sprintf("%s sustained compute load — util %d%%, %.0fW", prefix, dev.UtilPct, dev.PowerDrawW),
			nil,
		))
	}
	return out
}
