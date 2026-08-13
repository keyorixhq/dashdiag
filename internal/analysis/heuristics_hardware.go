package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	hwCatHardware    = "Hardware"
	hwCatIPMI        = "IPMI"
	hwDriveTypeNVMe  = "nvme"
	hwCatBattery     = "Battery"
	hwCatCPUFreq     = "CPUFreq"
	hwSevLow         = "low"
	inspectIPMISel   = "to inspect: ipmitool sel list | tail -20"
	inspectHwmonTemp = "to inspect: cat /sys/class/hwmon/hwmon*/temp*_input"
)

func checkBattery(b models.BatteryInfo) []models.Insight {
	if !b.Present {
		return nil // desktop or no battery
	}
	var out []models.Insight

	// Battery wear
	if b.HealthPct > 0 {
		if b.HealthPct < 60 {
			out = append(out, insight("CRIT", hwCatBattery,
				fmt.Sprintf("battery health at %.0f%% — replacement recommended", b.HealthPct),
				[]string{"to inspect: cat /sys/class/power_supply/BAT0/energy_full_design"},
			))
		} else if b.HealthPct < 80 {
			out = append(out, insight("WARN", hwCatBattery,
				fmt.Sprintf("battery health at %.0f%% (%.0f cycle(s)) — degraded", b.HealthPct, float64(b.CycleCounts)),
				[]string{"to inspect: cat /sys/class/power_supply/BAT0/energy_full"},
			))
		}
	}

	// Low charge while discharging
	if b.Status == "Discharging" && b.CapacityPct <= 10 {
		out = append(out, insight("CRIT", hwCatBattery,
			fmt.Sprintf("battery at %d%% and discharging — connect power", b.CapacityPct),
			nil,
		))
	} else if b.Status == "Discharging" && b.CapacityPct <= 20 {
		out = append(out, insight("WARN", hwCatBattery,
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
		return []models.Insight{unverifiedInsight("WARN", corrCatCPUThermal,
			fmt.Sprintf("implausible CPU temperature %g°C (source: %s) — sensor likely faulted; reading rejected, health unverified", t.CPUTempC, t.Source),
			[]string{
				inspectHwmonTemp,
				"to inspect: sensors  (compare against a second source)",
			},
		)}
	}
	hints := []string{
		inspectHwmonTemp,
		"to inspect: check cooling and airflow",
	}
	if t.CPUTempC >= 95 {
		return []models.Insight{insight("CRIT", corrCatCPUThermal,
			fmt.Sprintf("CPU temperature %g°C — thermal throttling active", t.CPUTempC),
			hints,
		)}
	}
	if t.CPUTempC >= 85 {
		return []models.Insight{insight("WARN", corrCatCPUThermal,
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
		return []models.Insight{insight("WARN", corrCatCPUThermal,
			fmt.Sprintf("CPU temperature %g°C at %.0f%% load — elevated for low CPU activity, possible cooling issue",
				t.CPUTempC, thresh.CPULoadPct),
			[]string{
				inspectHwmonTemp,
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
	for line := range strings.SplitSeq(string(data), "\n") {
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
	for line := range strings.SplitSeq(string(data), "\n") {
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
		out = append(out, insight("INFO", corrCatGPU,
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

// UtilPctPlausible reports whether a GPU utilization reading (%) is physically
// possible. gpu_busy_percent is read raw via a bare Atoi with no bounds check,
// so a garbled/faulted sysfs read can surface outside [0,100] and feed the
// DPM-stuck-low / sustained-load checks below with bogus "under load" evidence.
// Reject rather than trust it — same plausibility-gate pattern as GPUTempPlausible.
func UtilPctPlausible(pct int) bool {
	return pct >= 0 && pct <= 100
}

// checkGPUDevice returns the health insights for a single GPU device.
func checkGPUDevice(dev models.GPUDevice, prefix string, steamOS bool) []models.Insight {
	var out []models.Insight
	// nvidia-smi listed the GPU but its core metrics came back [N/A]/ERR! — the
	// card has fallen off the bus or faulted. Its temp/util/mem are bogus zeros,
	// so emit the fault and skip the per-metric checks (which would read healthy).
	if dev.Unreadable {
		return append(out, insight("CRIT", corrCatGPU,
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
		return append(out, unverifiedInsight("INFO", corrCatGPU,
			fmt.Sprintf("%s detected but exposed no health metrics — temperature/utilization not available, health NOT verified", prefix),
			[]string{"to inspect: ls /sys/class/drm/card*/device/hwmon/hwmon*/"},
		))
	}
	// Reject a physically-impossible edge temperature before it can fire a CRIT
	// (§L/§Q raw-tool implausible-value class — garbage hwmon reads as thousands
	// of degrees). Surface it as unverified rather than a false thermal alarm.
	if !GPUTempPlausible(dev.TempC) {
		out = append(out, unverifiedInsight("WARN", corrCatGPU,
			fmt.Sprintf("%s reported an implausible temperature (%d°C) — thermal health unverified, reading rejected", prefix, dev.TempC),
			[]string{"to inspect: cat /sys/class/drm/card*/device/hwmon/hwmon*/temp1_input", "note: out-of-range value (faulted/virtual sensor) — ignored to avoid a false thermal-throttling alarm"},
		))
	} else if dev.TempC >= 90 {
		out = append(out, insight("CRIT", corrCatGPU,
			fmt.Sprintf("%s temperature %d°C — thermal throttling likely", prefix, dev.TempC),
			[]string{"to inspect: nvidia-smi", "to inspect: check cooling and airflow"},
		))
	} else if dev.TempC >= 80 {
		out = append(out, insight("WARN", corrCatGPU,
			fmt.Sprintf("%s temperature %d°C — elevated", prefix, dev.TempC),
			[]string{"to inspect: nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader"},
		))
	}
	// Junction (hotspot/die) temperature — runs hotter than edge; its own thresholds.
	// Same plausibility gate as the edge sensor.
	if !GPUTempPlausible(dev.TempJunctionC) {
		out = append(out, unverifiedInsight("WARN", corrCatGPU,
			fmt.Sprintf("%s reported an implausible junction temperature (%d°C) — thermal health unverified, reading rejected", prefix, dev.TempJunctionC),
			[]string{"to inspect: cat /sys/class/drm/card*/device/hwmon/hwmon*/temp2_input", "note: out-of-range value (faulted/virtual sensor) — ignored to avoid a false thermal alarm"},
		))
	} else if dev.TempJunctionC >= 100 {
		out = append(out, insight("CRIT", corrCatGPU,
			fmt.Sprintf("%s junction temperature %d°C — emergency thermal threshold", prefix, dev.TempJunctionC),
			[]string{"to inspect: cat /sys/class/drm/card*/device/hwmon/hwmon*/temp2_input", "shut down and check cooling immediately"},
		))
	} else if dev.TempJunctionC >= 90 {
		out = append(out, insight("WARN", corrCatGPU,
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
		out = append(out, insight("WARN", corrCatGPU,
			fmt.Sprintf("%s TDP throttling — at power limit (%.1fW / %.1fW)", prefix, dev.TDPCurrentW, dev.TDPLimitW),
			[]string{hint},
		))
	}
	// VRAM pressure (GB-based field, complements the MB-based check below).
	// Skip APUs: their "VRAM" is a small shared-RAM carveout that fills to 90%+
	// under any GPU load by design — a high % there is normal, not pressure.
	// Genuine memory exhaustion on an APU surfaces via system-RAM checks.
	if dev.VRAMUsedPct >= 90 && !dev.IsAPU {
		out = append(out, insight("WARN", corrCatGPU,
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
	if dev.PowerDPMLevel == hwSevLow && UtilPctPlausible(dev.UtilPct) && dev.UtilPct >= 50 {
		out = append(out, insight("WARN", corrCatGPU,
			fmt.Sprintf("%s stuck in low-power DPM mode under load (%d%% util) — performance capped", prefix, dev.UtilPct),
			[]string{"to fix: echo auto > /sys/class/drm/card*/device/power_dpm_force_performance_level"},
		))
	}
	if l := levelPct(dev.MemUsedPct, 85, 95); l != "" && !dev.IsAPU {
		out = append(out, insight(l, corrCatGPU,
			fmt.Sprintf("%s VRAM usage at %.0f%% (%d/%d MB)", prefix, dev.MemUsedPct, dev.MemUsedMB, dev.MemTotalMB),
			[]string{"to inspect: nvidia-smi --query-gpu=memory.used,memory.total --format=csv"},
		))
	}
	// Sustained compute load — INFO signal for correlation engine.
	// Not a fault on its own, but provides context when combined with
	// thermal or memory pressure signals.
	if UtilPctPlausible(dev.UtilPct) && dev.UtilPct >= 80 && dev.PowerDrawW >= 80 {
		out = append(out, insight("INFO", corrCatGPU,
			fmt.Sprintf("%s sustained compute load — util %d%%, %.0fW", prefix, dev.UtilPct, dev.PowerDrawW),
			nil,
		))
	}
	return out
}

// checkHardware evaluates physical hardware health from SMART, hwmon, and EDAC.
func checkHardware(h models.HardwareInfo) []models.Insight { //nolint:cyclop,funlen // NOSONAR — flat independent hardware checks — splitting would harm readability
	var out []models.Insight

	// ── Drive health ──────────────────────────────────────────────────────────
	for _, d := range h.Drives {
		if !d.SmartctlAvailable {
			out = append(out, insight("INFO", hwCatHardware,
				"smartctl not installed — drive health unavailable",
				[]string{"to fix: install smartmontools (apt/dnf/zypper install smartmontools)"},
			))
			continue // skip this drive only — EDAC/ECC checks below are independent of smartctl
		}
		if d.Error != "" {
			out = append(out, insight("WARN", hwCatHardware,
				fmt.Sprintf("%s: %s", d.Device, d.Error),
				nil,
			))
			continue
		}

		prefix := d.Device
		if d.Model != "" {
			prefix = fmt.Sprintf("%s (%s)", d.Device, d.Model)
		}

		// SMART overall. Only a drive that actually reported a verdict can FAIL it;
		// a detected-but-unread drive (controller/USB bridge/virtual disk emits
		// JSON with no smart_status) must not be called failing — that was a false
		// CRIT ("back up immediately") on healthy drives.
		switch {
		case !d.SmartRead:
			out = append(out, insight("INFO", hwCatHardware,
				fmt.Sprintf("%s — SMART health not reported (behind a RAID/HBA controller or USB bridge, or a virtual disk)", prefix),
				[]string{inspectSmartCtlPrefix + d.Device + "  (try -d sat / -d cciss,N)"},
			))
		case !d.SmartOK:
			out = append(out, insight("CRIT", hwCatHardware,
				fmt.Sprintf("%s — SMART FAILED: drive may fail imminently, back up immediately", prefix),
				[]string{
					inspectSmartCtlPrefix + d.Device,
					"to run self-test: smartctl -t short " + d.Device,
				},
			))
		}

		// Drive temperature
		switch {
		case d.Type == hwDriveTypeNVMe && d.TempC >= 80:
			out = append(out, insight("CRIT", hwCatHardware,
				fmt.Sprintf("%s temperature %d°C — NVMe critical thermal threshold", prefix, d.TempC),
				[]string{inspectSmartCtlPrefix + d.Device},
			))
		case d.Type == hwDriveTypeNVMe && d.TempC >= 70:
			out = append(out, insight("WARN", hwCatHardware,
				fmt.Sprintf("%s temperature %d°C — NVMe running hot", prefix, d.TempC),
				[]string{inspectSmartCtlPrefix + d.Device},
			))
		case d.Type != hwDriveTypeNVMe && d.TempC >= 60:
			out = append(out, insight("CRIT", hwCatHardware,
				fmt.Sprintf("%s temperature %d°C — HDD critical thermal threshold", prefix, d.TempC),
				[]string{inspectSmartCtlPrefix + d.Device},
			))
		case d.Type != hwDriveTypeNVMe && d.TempC >= 50:
			out = append(out, insight("WARN", hwCatHardware,
				fmt.Sprintf("%s temperature %d°C — HDD running hot", prefix, d.TempC),
				[]string{inspectSmartCtlPrefix + d.Device},
			))
		}

		// Wear / endurance
		switch {
		case d.WearPct >= 95:
			out = append(out, insight("CRIT", hwCatHardware,
				fmt.Sprintf("%s wear at %d%% — drive near end of rated life, replace soon", prefix, d.WearPct),
				[]string{"to plan: schedule drive replacement"},
			))
		case d.WearPct >= 80:
			out = append(out, insight("WARN", hwCatHardware,
				fmt.Sprintf("%s wear at %d%% — approaching end of rated endurance", prefix, d.WearPct),
				[]string{"to plan: schedule drive replacement"},
			))
		}

		// SATA bad sectors
		if d.ReallocatedSectors > 0 {
			level := "WARN"
			if d.ReallocatedSectors >= 10 {
				level = "CRIT"
			}
			out = append(out, insight(level, hwCatHardware,
				fmt.Sprintf("%s: %d reallocated sector(s) — drive remapping failed reads", prefix, d.ReallocatedSectors),
				[]string{
					inspectSmartCtlPrefix + d.Device,
					"to test: smartctl -t long " + d.Device,
				},
			))
		}
		if d.PendingSectors > 0 {
			level := "WARN"
			if d.PendingSectors >= 5 {
				level = "CRIT"
			}
			out = append(out, insight(level, hwCatHardware,
				fmt.Sprintf("%s: %d pending sector(s) — unreadable sectors awaiting remap", prefix, d.PendingSectors),
				[]string{inspectSmartCtlPrefix + d.Device},
			))
		}
		if d.UncorrectableErrors > 0 {
			out = append(out, insight("CRIT", hwCatHardware,
				fmt.Sprintf("%s: %d offline uncorrectable sector(s) — data loss risk", prefix, d.UncorrectableErrors),
				[]string{
					inspectSmartCtlPrefix + d.Device,
					"to rescue: back up immediately",
				},
			))
		}

		// NVMe media errors
		if d.MediaErrors > 0 {
			level := "WARN"
			if d.MediaErrors >= 10 {
				level = "CRIT"
			}
			out = append(out, insight(level, hwCatHardware,
				fmt.Sprintf("%s: %d media error(s) — NVMe data integrity events", prefix, d.MediaErrors),
				[]string{inspectSmartCtlPrefix + d.Device},
			))
		}

		// Healthy drive — emit OK so it shows in output
		healthy := len(out) == 0 || func() bool {
			for _, i := range out {
				if i.Check == hwCatHardware && strings.HasPrefix(i.Message, prefix) {
					return false
				}
			}
			return true
		}()
		if healthy {
			msg := fmt.Sprintf("%s — SMART OK", prefix)
			if d.TempC > 0 {
				msg += fmt.Sprintf(", %d°C", d.TempC)
			}
			if d.PowerOnH > 0 {
				msg += fmt.Sprintf(", %d h", d.PowerOnH)
			}
			if d.WearPct > 0 {
				msg += fmt.Sprintf(", %d%% worn", d.WearPct)
			}
			out = append(out, insight("OK", hwCatHardware, msg, nil))
		}
	}

	// ── EDAC memory ───────────────────────────────────────────────────────────
	if h.Memory.EDACAvailable {
		// Never suppress a genuine CRIT/WARN from whatever counters WERE read
		// successfully — a real detected error on one controller must still
		// surface even if another controller's read failed.
		out = append(out, eccInsights(h.Memory.CorrectedErrors, h.Memory.UncorrectedErrors, hwCatHardware)...)
		if h.Memory.EDACCountersUnreadable {
			out = append(out, unverifiedInsight("INFO", hwCatHardware,
				"ECC error counters could not be fully read — the corrected/uncorrected counts above may be incomplete",
				[]string{"to inspect: edac-util -s 4"}))
		}
	}

	return out
}

func checkIPMI(ipmi models.IPMIInfo) []models.Insight {
	// In-band IPMI reads the 0600 root:root BMC device — a non-root sensor-read
	// failure is expected, not a real IPMI problem. Report it honestly rather
	// than the WARN below, which would otherwise fire on every non-root
	// `dsd health` run on a physical server, healthy BMC or not.
	if ipmi.NeedsRoot {
		return []models.Insight{unverifiedInsight("INFO", hwCatIPMI,
			"IPMI hardware detected but sensor read requires root — re-run as root to verify sensor health",
			[]string{"to inspect: sudo ipmitool sdr"})}
	}
	// IPMI hardware is present (the collector is gated on /dev/ipmi*) but the
	// sensor read failed — surface it rather than stay silent. The collector sets
	// Status="error" with Available=false here; returning nil on !Available alone
	// hid a BMC/sensor read failure on a server that has IPMI.
	if ipmi.Status == "error" {
		reason := ipmi.StatusReason
		if reason == "" {
			reason = "IPMI sensor read failed"
		}
		return []models.Insight{unverifiedInsight("WARN", hwCatIPMI, reason,
			[]string{
				"to inspect: ipmitool sdr",
				inspectIPMISel,
				"note: check BMC access — kernel module ipmi_devintf and /dev/ipmi0 permissions",
			})}
	}
	if !ipmi.Available {
		return nil
	}
	var out []models.Insight
	if ipmi.PSUFailed > 0 {
		out = append(out, insight("CRIT", hwCatIPMI,
			fmt.Sprintf("%d PSU(s) in fault state — risk of host going offline", ipmi.PSUFailed),
			[]string{
				"to inspect: ipmitool sdr type 'Power Supply'",
				inspectIPMISel,
				"note: replace failed PSU before removing redundant one",
			},
		))
	}
	if ipmi.FanFailed > 0 {
		out = append(out, insight("WARN", hwCatIPMI,
			fmt.Sprintf("%d fan(s) in fault state — thermal risk", ipmi.FanFailed),
			[]string{
				"to inspect: ipmitool sdr type Fan",
				inspectIPMISel,
			},
		))
	}
	if ipmi.TempCritical > 0 {
		out = append(out, insight("CRIT", hwCatIPMI,
			fmt.Sprintf("%d temperature sensor(s) in critical state", ipmi.TempCritical),
			[]string{
				"to inspect: ipmitool sdr type Temperature",
				"to inspect: check airflow and fan operation",
			},
		))
	}
	return out
}

func checkNUMA(n models.NUMAInfo) []models.Insight {
	if !n.Available {
		return nil
	}
	if n.Imbalanced {
		return []models.Insight{insight("WARN", "NUMA",
			fmt.Sprintf("%d NUMA nodes with unbalanced memory — may cause performance issues", n.NodeCount),
			[]string{
				"to inspect: numactl --hardware",
				"to inspect: numastat -m",
				"note: consider NUMA-aware memory allocation for latency-sensitive workloads",
			})}
	}
	return nil
}

func checkCPUFreq(f models.CPUFreqInfo, thresh Thresholds) []models.Insight {
	if f.Governor == "" {
		return nil // cpufreq not available
	}
	var out []models.Insight

	// The 'powersave' WARN's premise — "capped at min frequency" — only holds for
	// the LEGACY drivers (acpi-cpufreq, cppc_cpufreq, cpufreq-dt). intel_pstate and
	// amd-pstate (active mode) expose only performance/powersave governors, and
	// their 'powersave' is DYNAMIC (scales to load via EPP) — the modern default,
	// not performance-limited. So:
	//   - pstate driver  → no finding (healthy default; WARNing it false-alarms on
	//     essentially every modern Intel/AMD bare-metal server)
	//   - battery device → INFO (laptop / Steam Deck — powersave is deliberate)
	//   - legacy driver on a server → WARN (genuinely capped at min freq)
	if f.Governor == "powersave" {
		switch {
		case isDynamicPstateDriver(f.ScalingDriver):
			// silent — dynamic powersave is the recommended default, not a problem
		case f.HasBattery:
			out = append(out, insight("INFO", hwCatCPUFreq,
				fmt.Sprintf("CPU governor is 'powersave' (%d MHz, max %d MHz) — expected on a battery device for power saving",
					f.CurrentMHz, f.MaxMHz),
				[]string{"on AC and want full speed: cpupower frequency-set -g performance (or 'schedutil')"},
			))
		default:
			out = append(out, insight("WARN", hwCatCPUFreq,
				fmt.Sprintf("CPU governor is 'powersave' — CPU running at %d MHz (max %d MHz), performance limited",
					f.CurrentMHz, f.MaxMHz),
				[]string{
					"to inspect: cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",
					"to fix: cpupower frequency-set -g performance",
					"to fix (manual): echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",
					"to persist: add to /etc/rc.local or use tuned profile 'throughput-performance'",
					"note: 'schedutil' or 'ondemand' are also acceptable for variable workloads",
				},
			))
		}
	}

	// Heavy throttling — current frequency well below max despite not being powersave.
	// ThrottledPct = (max - current)/max from a single instantaneous read, so an IDLE
	// box on a dynamic governor (schedutil/ondemand) parks cores at min freq and reads
	// 70-80% "throttled" while being perfectly healthy. Only flag when the CPU is
	// actually under load (>=20%, same idle cutoff as the thermal check) — there, a
	// frequency stuck well below max is a genuine thermal/power-throttle signal.
	// thresh.CPULoadPct==0 means load is unknown → don't fire (can't tell idle apart).
	if f.Governor != "powersave" && f.ThrottledPct >= 40 && f.MaxMHz > 0 && thresh.CPULoadPct >= 20 {
		out = append(out, insight("WARN", hwCatCPUFreq,
			fmt.Sprintf("CPU running at %d MHz (%d%% below max %d MHz) — possible thermal or power throttle",
				f.CurrentMHz, int(f.ThrottledPct), f.MaxMHz),
			[]string{
				"to inspect: cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
				"to inspect: sensors  (check CPU temperature)",
				"to inspect: dmesg | grep -i 'throttl\\|thermal\\|power limit'",
				"to inspect: turbostat --quiet --show Busy%,Avg_MHz,Bzy_MHz,PkgWatt 2>/dev/null | head -5",
			},
		))
	}

	return out
}

// isDynamicPstateDriver reports whether the cpufreq scaling driver is intel_pstate
// or amd-pstate (active mode), where the 'powersave' governor is a dynamic,
// load-scaling EPP mode (the modern default) — NOT the min-frequency cap that the
// legacy acpi-cpufreq/cppc_cpufreq drivers impose. Used so the powersave WARN
// doesn't false-fire on essentially every modern Intel/AMD bare-metal server.
func isDynamicPstateDriver(driver string) bool {
	d := strings.ToLower(strings.TrimSpace(driver))
	return d == "intel_pstate" ||
		strings.HasPrefix(d, "amd-pstate") ||
		strings.HasPrefix(d, "amd_pstate")
}
