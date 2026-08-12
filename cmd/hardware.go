package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

var hardwareCmd = &cobra.Command{
	Use:   "hardware",
	Short: "Physical hardware health — drives, thermals, memory",
	Long: `Check physical hardware health via SMART (smartctl), hwmon thermals, and EDAC.

Covers:
  - Drive health: SMART status, wear %, temperature, bad sectors (NVMe + SATA/SAS)
  - CPU and drive temperatures via /sys/class/hwmon
  - EDAC memory error counters (where available)

Requires smartmontools for drive SMART checks (graceful degradation if missing).
Root recommended for full SMART access on all drive types.

Examples:
  dsd hardware             hardware health check
  dsd hardware --plain     plain text output
  dsd hardware --json      machine-readable output`,
	RunE: runHardware,
}

func init() {
	rootCmd.AddCommand(hardwareCmd)
}

func runHardware(cmd *cobra.Command, _ []string) error {
	hwInfo := func(r []runner.Result) *models.HardwareInfo {
		if info := resultData[*models.HardwareInfo](r); info != nil {
			return info
		}
		return &models.HardwareInfo{}
	}
	return runDiagnostic(cmd, diagnostic{
		label:   "Hardware health",
		timeout: 15 * time.Second,
		cols:    []runner.Collector{collectors.NewHardwareCollector()},
		jsonValue: func(r []runner.Result) (any, error) {
			return hwInfo(r), nil
		},
		render: func(r []runner.Result, mode output.OutputMode, elapsed time.Duration) error {
			printHardwareReport(hwInfo(r), mode, elapsed)
			return nil
		},
	})
}

// printHardwareReport is the flat dispatcher for `dsd hardware`'s report.
// Each print*Section below covers one independent theme and writes straight
// to stdout with no shared buffer — split out of a single ~205-line function
// (was `//nolint:cyclop,funlen`) the same way printSecurityReport was split.
func printHardwareReport(info *models.HardwareInfo, mode output.OutputMode, elapsed time.Duration) {
	sep := render.StyleDim.Render("────────────────────────────────────────────────────────")

	printHardwareSystemSection(info)
	printHardwareCPUSection(info)
	printHardwareMemorySection(info, mode)
	printHardwareDrivesSection(info, mode)
	printHardwareThermalsSection(info, mode)
	printHardwareNetworkSection(info, mode)

	fmt.Println(sep)
	fmt.Println(render.StyleDim.Render(fmt.Sprintf("done in %.1fs", elapsed.Seconds())))
	_ = os.Stdout.Sync()
}

// printHardwareSystemSection prints the System section (vendor/model).
func printHardwareSystemSection(info *models.HardwareInfo) {
	// ── System ────────────────────────────────────────────────────────────────
	if info.System.Vendor != "" || info.System.Model != "" {
		fmt.Println(render.StyleBold.Render("System"))
		if info.System.Vendor != "" {
			fmt.Printf("  %-14s %s\n", "Vendor:", info.System.Vendor)
		}
		if info.System.Model != "" {
			fmt.Printf("  %-14s %s\n", "Model:", info.System.Model)
		}
		fmt.Println()
	}
}

// printHardwareCPUSection prints the CPU section (model, topology, frequency).
func printHardwareCPUSection(info *models.HardwareInfo) {
	// ── CPU ───────────────────────────────────────────────────────────────────
	if info.CPU.Model != "" || info.CPU.Threads > 0 {
		fmt.Println(render.StyleBold.Render("CPU"))
		if info.CPU.Model != "" {
			fmt.Printf("  %-14s %s\n", "Model:", info.CPU.Model)
		} else {
			fmt.Printf("  %-14s %s\n", "Model:", render.StyleDim.Render("unknown"))
		}
		if info.CPU.Threads > 0 {
			if info.CPU.Cores > 0 {
				fmt.Printf("  %-14s %d cores / %d threads\n", "Topology:", info.CPU.Cores, info.CPU.Threads)
			} else {
				fmt.Printf("  %-14s %d threads\n", "Topology:", info.CPU.Threads)
			}
		}
		if info.CPU.FreqMHz > 0 {
			freqStr := fmt.Sprintf("%.0f MHz", info.CPU.FreqMHz)
			if info.CPU.MaxFreqMHz > 0 {
				freqStr += fmt.Sprintf(" (max %.0f MHz)", info.CPU.MaxFreqMHz)
			}
			fmt.Printf("  %-14s %s\n", "Frequency:", freqStr)
		}
		fmt.Println()
	}
}

// printHardwareMemorySection prints the Memory section (RAM slots, EDAC/ECC).
func printHardwareMemorySection(info *models.HardwareInfo, mode output.OutputMode) {
	// ── Memory ────────────────────────────────────────────────────────────────
	fmt.Println(render.StyleBold.Render("Memory"))
	if info.Memory.TotalGB > 0 {
		fmt.Printf("  %-14s %.0f GB total\n", "RAM:", info.Memory.TotalGB)
		for _, s := range info.Memory.Slots {
			fmt.Printf("  %-14s %s — %.0f GB %s @ %d MT/s\n",
				"", s.Locator, s.SizeGB, s.Type, s.SpeedMT)
		}
	}
	if !info.Memory.EDACAvailable {
		fmt.Printf("  %-14s %s  EDAC not available\n", "ECC errors:", output.StatusIcon("info", mode))
	} else {
		ueLevel := "ok"
		if info.Memory.UncorrectedErrors > 0 {
			ueLevel = "fail"
		}
		ceLevel := "ok"
		if info.Memory.CorrectedErrors > 100 {
			ceLevel = "warn"
		}
		fmt.Printf("  %-14s %s  %d uncorrected\n", "ECC (UE):", output.StatusIcon(ueLevel, mode), info.Memory.UncorrectedErrors)
		fmt.Printf("  %-14s %s  %d corrected\n", "ECC (CE):", output.StatusIcon(ceLevel, mode), info.Memory.CorrectedErrors)
	}
	fmt.Println()
}

// printHardwareDrivesSection prints the per-drive SMART/thermal/wear/error
// section.
func printHardwareDrivesSection(info *models.HardwareInfo, mode output.OutputMode) {
	// ── Drives ────────────────────────────────────────────────────────────────
	if len(info.Drives) == 0 {
		fmt.Printf("%-12s %s  no drives detected\n", "Drives", output.StatusIcon("info", mode))
	}

	for _, d := range info.Drives {
		if !d.SmartctlAvailable {
			fmt.Printf("%-12s %s  %s\n", "Drives", output.StatusIcon("info", mode), d.Error)
			continue
		}

		prefix := d.Device
		if d.Model != "" {
			prefix = fmt.Sprintf("%s — %s", d.Device, d.Model)
		}
		fmt.Println(render.StyleBold.Render(prefix))

		// SMART status — only show if no error (error means permission denied or tool missing)
		if d.Error == "" {
			smartIcon := output.StatusIcon("ok", mode)
			smartMsg := "PASSED"
			if !d.SmartOK {
				smartIcon = output.StatusIcon("fail", mode)
				smartMsg = "FAILED — back up immediately"
			}
			fmt.Printf("  %-14s %s  %s\n", "SMART:", smartIcon, smartMsg)
		} else {
			fmt.Printf("  %-14s %s  %s\n", "SMART:", output.StatusIcon("info", mode), d.Error)
		}

		// Temperature
		if d.TempC > 0 {
			if level, plausible := driveThermalLevel(d.TempC, d.Type == "nvme"); !plausible {
				fmt.Printf("  %-14s %s  implausible (%d°C) — SMART sensor unreliable, rejected\n",
					"Temperature:", output.StatusIcon("info", mode), d.TempC)
			} else {
				fmt.Printf("  %-14s %s  %d°C\n", "Temperature:", output.StatusIcon(level, mode), d.TempC)
			}
		}

		// Power-on hours
		if d.PowerOnH > 0 {
			fmt.Printf("  %-14s %s  %d h (%d days)\n", "Power-on:", output.StatusIcon("ok", mode), d.PowerOnH, d.PowerOnH/24)
		}

		// Wear
		if d.WearPct > 0 {
			wearLevel := "ok"
			if d.WearPct >= 95 {
				wearLevel = "fail"
			} else if d.WearPct >= 80 {
				wearLevel = "warn"
			}
			fmt.Printf("  %-14s %s  %d%% used\n", "Wear:", output.StatusIcon(wearLevel, mode), d.WearPct)
		}

		// SATA bad sectors. cmd-06-02: the counters below come exclusively from
		// smartctl's ATA SMART attribute table — a real SAS/SCSI drive (or
		// degraded smartctl output) never populates it, so BadSectorsRead=false
		// must render as "couldn't verify", never a green zero-count OK.
		if d.Type != "nvme" {
			if !d.BadSectorsRead {
				fmt.Printf("  %-14s %s  could not verify — no ATA attribute data (SAS drive, or smartctl output incomplete)\n",
					"Bad sectors:", output.StatusIcon("info", mode))
			} else {
				bsLevel := "ok"
				bsMsg := "none"
				if d.ReallocatedSectors > 0 || d.PendingSectors > 0 || d.UncorrectableErrors > 0 {
					bsLevel = "warn"
					if d.ReallocatedSectors >= 10 || d.PendingSectors >= 5 || d.UncorrectableErrors > 0 {
						bsLevel = "fail"
					}
					bsMsg = fmt.Sprintf("reallocated:%d  pending:%d  uncorrectable:%d",
						d.ReallocatedSectors, d.PendingSectors, d.UncorrectableErrors)
				}
				fmt.Printf("  %-14s %s  %s\n", "Bad sectors:", output.StatusIcon(bsLevel, mode), bsMsg)
			}
		}

		// NVMe error counters
		if d.Type == "nvme" {
			errLevel := "ok"
			if d.MediaErrors >= 10 {
				errLevel = "fail"
			} else if d.MediaErrors > 0 {
				errLevel = "warn"
			}
			fmt.Printf("  %-14s %s  media errors: %d  unsafe shutdowns: %d\n",
				"NVMe errors:", output.StatusIcon(errLevel, mode), d.MediaErrors, d.UnsafeShutdowns)
		}

		fmt.Println()
	}
}

// printHardwareThermalsSection prints the CPU Thermals section.
func printHardwareThermalsSection(info *models.HardwareInfo, mode output.OutputMode) {
	// ── CPU Thermals ──────────────────────────────────────────────────────────
	if len(info.Thermals) > 0 {
		fmt.Println(render.StyleBold.Render("CPU Thermals"))
		for _, t := range info.Thermals {
			// A sensor reporting the 0-Kelvin sentinel (-273°C) or otherwise out of a
			// plausible range isn't measuring — common on virtual/cloud hwmon (e.g.
			// AWS EBS NVMe "Composite" returns 0 K). Don't render it as a healthy
			// "✅ -273°C" (a green check on an impossible reading); show it as
			// unreported. Shared plausibility logic (see analysis/temp.go).
			if !analysis.TempPlausible(float64(t.TempC), analysis.TempCeilSilicon) {
				fmt.Printf("  %-14s %s  not reported  (%s)\n",
					t.Label+":", output.StatusIcon("info", mode), t.Sensor)
				continue
			}
			level, note := coreThermalLevel(t.TempC, info.CPU.LoadPct)
			fmt.Printf("  %-14s %s  %d°C%s  (%s)\n",
				t.Label+":", output.StatusIcon(level, mode), t.TempC, note, t.Sensor)
		}
		fmt.Println()
	}
}

// printHardwareNetworkSection prints the Network interfaces section.
func printHardwareNetworkSection(info *models.HardwareInfo, mode output.OutputMode) {
	// ── Network interfaces ────────────────────────────────────────────────────
	if len(info.NICs) > 0 {
		fmt.Println(render.StyleBold.Render("Network"))
		for _, n := range info.NICs {
			stateLevel := "ok"
			if n.State != "up" {
				stateLevel = "warn"
			}
			errLevel := "ok"
			if n.RxErrors > 0 || n.TxErrors > 0 {
				errLevel = "warn"
			}
			speed := ""
			if n.SpeedMbps > 0 {
				speed = fmt.Sprintf(" @ %d Mbps", n.SpeedMbps)
			}
			driver := ""
			if n.Driver != "" {
				driver = fmt.Sprintf(" [%s]", n.Driver)
			}
			fmt.Printf("  %-14s %s  %s%s%s  MAC: %s\n",
				n.Name+":", output.StatusIcon(stateLevel, mode),
				n.State, speed, driver, n.MAC)
			if n.RxErrors > 0 || n.TxErrors > 0 {
				fmt.Printf("  %-14s %s  rx_errors:%d  tx_errors:%d\n",
					"errors:", output.StatusIcon(errLevel, mode), n.RxErrors, n.TxErrors)
			}
		}
		fmt.Println()
	}
}

// coreThermalLevel grades a per-core CPU temperature for `dsd hardware`. Above the
// hard ceilings it's throttling/elevated regardless of load. The "warm at low load"
// rung catches a cooling fault (dried paste, blocked vents, dead fan) where the CPU
// runs hot while nearly idle — but only at/above 75°C: 50-70°C at idle is normal for
// a desktop/SFF chip, so the old 60°C threshold false-WARNed on healthy metal (found
// live on an i7-6700 idling at 61°C). 75°C sits above normal idle yet below the 85°C
// "elevated" rung, so it fires only when a near-idle core is genuinely hot.
func coreThermalLevel(tempC int, loadPct float64) (level, note string) {
	switch {
	case tempC >= 95:
		return "fail", " — throttling"
	case tempC >= 85:
		return "warn", " — elevated"
	case tempC >= 75 && loadPct < 20:
		return "warn", fmt.Sprintf(" — high at %.0f%% load", loadPct)
	}
	return "ok", ""
}

// driveThermalLevel grades a drive temperature for `dsd hardware`. It first
// rejects implausible SMART readings — a VMware virtual NVMe reporting 11759°C
// (found live on real vNVMe) is garbage, not a measurement — returning
// plausible=false so the caller shows "rejected" rather than a thermal CRIT.
// This mirrors how `dsd health`'s Drives check rejects the same data (§L); without
// it the standalone command false-CRITs on a reading health correctly discards,
// and the divergence only surfaces with root + smartctl (invisible unprivileged).
// NVMe and SATA/SAS use different thresholds (see the inline note history).
func driveThermalLevel(tempC int, isNVMe bool) (level string, plausible bool) {
	if !analysis.TempPlausible(float64(tempC), analysis.TempCeilNVMe) {
		return "info", false
	}
	if isNVMe {
		switch {
		case tempC >= 80:
			return "fail", true
		case tempC >= 70:
			return "warn", true
		}
		return "ok", true
	}
	switch {
	case tempC >= 60:
		return "fail", true
	case tempC >= 55:
		return "warn", true
	}
	return "ok", true
}
