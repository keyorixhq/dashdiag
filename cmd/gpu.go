package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(gpuCmd)
	gpuCmd.Flags().Bool("deep", false, "deep mode: DPM performance level + extra sysfs reads")
}

var gpuCmd = &cobra.Command{
	Use:   "gpu",
	Short: "GPU health — temperature, VRAM, clocks, TDP, utilization",
	RunE:  runGPU,
}

func runGPU(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	deep, _ := cmd.Flags().GetBool("deep")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	col := collectors.NewGPUCollector()
	col.Deep = deep

	p := output.NewCommandProgress("GPU health", 6*time.Second, mode, 1)
	if mode != output.ModeJSON {
		p.Start()
		defer p.Done()
	}

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		if mode != output.ModeJSON {
			p.Step(r.Name)
		}
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.GPUInfo)
	if !ok || info == nil {
		return result.Err
	}
	recordResultSeverity([]runner.Result{result})

	if mode == output.ModeJSON {
		// Print [] for an empty GPU list — no GPU is not an error.
		if len(info.Devices) == 0 && len(info.NoDriver) == 0 {
			fmt.Println("[]")
			return nil
		}
		return outputJSON(os.Stdout, info)
	}

	printGPUReport(info, elapsed, mode)
	return nil
}

func printGPUReport(info *models.GPUInfo, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	fmt.Println("\n🎮 GPU")

	if len(info.Devices) == 0 && len(info.NoDriver) == 0 {
		fmt.Printf("\nGPU   %s no GPU detected (virtual machine or no sysfs data)\n", asciiOr("info", "ℹ️ ", mode))
		return
	}

	steamOS := platform.Detect().IsSteamOS

	for _, dev := range info.Devices {
		printGPUDevice(dev, info.DriverVersion, mode)
	}
	printGPUNoDriver(info.NoDriver, mode)

	hints := gpuHints(info, steamOS, mode)
	if len(hints) > 0 {
		fmt.Println()
		fmt.Println(sep)
		for _, h := range hints {
			fmt.Println(h)
		}
	}

	fmt.Println()
	fmt.Println(sep)
	fmt.Println(gpuSummaryLine(info, timing, mode))
}

func printGPUDevice(dev models.GPUDevice, driverVersion string, mode output.OutputMode) {
	printGPUHeader(dev, driverVersion, mode)
	printGPUTemps(dev, mode)
	printGPUPerformance(dev, mode)
}

// printGPUHeader renders the device identity line:
// "[Name]  Driver: amdgpu  Mesa 24.3.1".
func printGPUHeader(dev models.GPUDevice, driverVersion string, _ output.OutputMode) {
	var parts []string
	driver := dev.DRMDriver
	if driver == "" && dev.Vendor == "nvidia" {
		driver = "nvidia"
	}
	if driver != "" {
		parts = append(parts, "Driver: "+driver)
	}
	if dev.Vendor == "nvidia" && driverVersion != "" {
		parts = append(parts, driverVersion)
	}
	if dev.MesaVersion != "" {
		parts = append(parts, "Mesa "+dev.MesaVersion)
	}
	suffix := ""
	if len(parts) > 0 {
		suffix = "  " + strings.Join(parts, "  ")
	}
	fmt.Printf("\n[%s]%s\n", dev.Name, suffix)
}

// printGPUTemps renders the Temperature section. Intel (and any device with no
// junction/memory sensors) gets a single compact temperature line.
func printGPUTemps(dev models.GPUDevice, mode output.OutputMode) {
	if dev.TempC == 0 && dev.TempJunctionC == 0 && dev.TempMemC == 0 {
		return
	}
	fmt.Println("\n  Temperature")
	if dev.TempJunctionC == 0 && dev.TempMemC == 0 {
		fmt.Printf("    %s %d°C\n", tempIcon(dev.TempC, 80, 90, mode), dev.TempC)
		return
	}
	if dev.TempC > 0 {
		fmt.Printf("    %s Edge:      %d°C\n", tempIcon(dev.TempC, 80, 90, mode), dev.TempC)
	}
	if dev.TempJunctionC > 0 {
		note := ""
		if dev.TempJunctionC >= 90 {
			note = "  (approaching thermal limit — 90°C threshold)"
		}
		fmt.Printf("    %s Junction:  %d°C%s\n", tempIcon(dev.TempJunctionC, 90, 100, mode), dev.TempJunctionC, note)
	}
	if dev.TempMemC > 0 {
		fmt.Printf("    %s Memory:    %d°C\n", tempIcon(dev.TempMemC, 95, 105, mode), dev.TempMemC)
	}
}

// printGPUPerformance renders the Performance section: clocks, TDP, VRAM, util.
func printGPUPerformance(dev models.GPUDevice, mode output.OutputMode) {
	lines := make([]string, 0, 5)

	if dev.ClockMaxMHz > 0 {
		pct := 0
		if dev.ClockMaxMHz > 0 {
			pct = dev.ClockMHz * 100 / dev.ClockMaxMHz
		}
		lines = append(lines, fmt.Sprintf("    %s Clock:       %d / %d MHz  (%d%%)", asciiOr("ok", "✅", mode), dev.ClockMHz, dev.ClockMaxMHz, pct))
	}

	if dev.TDPLimitW > 0 {
		icon := asciiOr("ok", "✅", mode)
		tail := ""
		if dev.Throttling {
			icon = asciiOr("warn", "⚠️ ", mode)
			tail = " ← throttling"
		}
		lines = append(lines, fmt.Sprintf("    %s TDP:         %.1f / %.1f W limit  (current: %.1fW)%s",
			icon, dev.TDPLimitW, dev.TDPLimitW, dev.TDPCurrentW, tail))
	}

	if dev.VRAMTotalGB > 0 {
		apu := ""
		if dev.IsAPU {
			apu = "  [shared APU memory]"
		}
		lines = append(lines, fmt.Sprintf("    %s VRAM:        %.1f / %.1f GB  (%.0f%%)%s",
			vramIcon(dev.VRAMUsedPct, mode), dev.VRAMUsedGB, dev.VRAMTotalGB, dev.VRAMUsedPct, apu))
	} else if dev.MemTotalMB > 0 {
		lines = append(lines, fmt.Sprintf("    %s VRAM:        %d / %d MB  (%.0f%%)",
			vramIcon(dev.MemUsedPct, mode), dev.MemUsedMB, dev.MemTotalMB, dev.MemUsedPct))
	}

	if dev.UtilPct > 0 {
		icon := asciiOr("ok", "✅", mode)
		if dev.UtilPct >= 95 {
			icon = asciiOr("warn", "⚠️ ", mode)
		}
		lines = append(lines, fmt.Sprintf("    %s Utilization: %d%%", icon, dev.UtilPct))
	}

	if dev.PowerDPMLevel != "" {
		icon := asciiOr("ok", "✅", mode)
		if dev.PowerDPMLevel == "low" {
			icon = asciiOr("warn", "⚠️ ", mode)
		}
		lines = append(lines, fmt.Sprintf("    %s DPM level:   %s", icon, dev.PowerDPMLevel))
	}

	if dev.XidErrors > 0 {
		lines = append(lines, fmt.Sprintf("    %s Xid errors:  %d hardware fault(s)", asciiOr("fail", "❌", mode), dev.XidErrors))
	}

	if len(lines) == 0 {
		return
	}
	fmt.Println("\n  Performance")
	for _, l := range lines {
		fmt.Println(l)
	}

	if len(dev.Processes) > 0 {
		fmt.Printf("\n  Processes\n")
		for _, p := range dev.Processes {
			fmt.Printf("    %-8d %-8s %s\n", p.PID, fmt.Sprintf("%dMB", p.MemUseMB), p.Name)
		}
	}
}

// gpuHints builds the actionable hint lines shown under the separator.
func gpuHints(info *models.GPUInfo, steamOS bool, mode output.OutputMode) []string {
	var hints []string
	for _, dev := range info.Devices {
		if dev.TempJunctionC >= 100 {
			hints = append(hints,
				fmt.Sprintf("%s Junction temperature %d°C — emergency thermal threshold (100°C)", asciiOr("fail", "❌", mode), dev.TempJunctionC),
				"   → Shut down and inspect cooling immediately")
		} else if dev.TempJunctionC >= 90 {
			hints = append(hints,
				fmt.Sprintf("%s Junction temperature %d°C — approaching 90°C threshold", asciiOr("warn", "⚠️ ", mode), dev.TempJunctionC),
				"   → Check thermal paste and fan curve if sustained")
		}
		if dev.Throttling {
			hints = append(hints,
				fmt.Sprintf("%s TDP throttling — GPU at power limit (%.1fW / %.1fW)", asciiOr("warn", "⚠️ ", mode), dev.TDPCurrentW, dev.TDPLimitW))
			if steamOS {
				hints = append(hints, "   → On Steam Deck: increase TDP limit in Performance settings when plugged in")
			} else {
				hints = append(hints, "   → Raise the power cap or improve cooling if more performance is needed")
			}
		}
		if dev.VRAMUsedPct >= 90 {
			hints = append(hints,
				fmt.Sprintf("%s VRAM at %.0f%% — high memory pressure", asciiOr("warn", "⚠️ ", mode), dev.VRAMUsedPct),
				"   → Reduce texture/resolution settings or close GPU-heavy apps")
		}
		if dev.PowerDPMLevel == "low" {
			hints = append(hints,
				fmt.Sprintf("%s GPU stuck in low-power DPM mode — performance capped", asciiOr("warn", "⚠️ ", mode)),
				"   → echo auto > /sys/class/drm/card*/device/power_dpm_force_performance_level")
		}
	}
	return hints
}

func printGPUNoDriver(noDriver []models.GPUDetected, mode output.OutputMode) {
	if len(noDriver) == 0 {
		return
	}
	fmt.Println()
	for _, nd := range noDriver {
		pci := ""
		if nd.PCIAddr != "" {
			pci = " @ " + nd.PCIAddr
		}
		fmt.Printf("GPU — %s%s\n", nd.Name, pci)
		fmt.Printf("  %s  proprietary driver not loaded — power/VRAM metrics unavailable\n", asciiOr("warn", "⚠️ ", mode))
		switch nd.Vendor {
		case "nvidia":
			nixos := isNixOS(cvedata.DetectDistroID())
			if strings.Contains(nd.Name, "nouveau") {
				fmt.Printf("  → nouveau is bound; for full metrics install: nvidia proprietary driver\n")
				if nixos {
					fmt.Printf("  → NixOS: set services.xserver.videoDrivers = [ \"nvidia\" ]; in configuration.nix, then nixos-rebuild switch\n")
				} else {
					fmt.Printf("  → RHEL/Fedora: dnf install akmod-nvidia (RPM Fusion required)\n")
				}
			} else if nixos {
				fmt.Printf("  → NixOS: set services.xserver.videoDrivers = [ \"nvidia\" ]; in configuration.nix, then nixos-rebuild switch\n")
			} else {
				fmt.Printf("  → install: dnf install akmod-nvidia  (Fedora/RHEL via RPM Fusion)\n")
				fmt.Printf("  → install: apt-get install nvidia-driver  (Debian/Ubuntu)\n")
			}
		case "amd":
			fmt.Printf("  → install: modprobe amdgpu  or check kernel parameters\n")
		}
	}
}

func gpuSummaryLine(info *models.GPUInfo, timing string, mode output.OutputMode) string {
	crits, warns := 0, 0
	for _, dev := range info.Devices {
		switch {
		case dev.TempC >= 90 || dev.TempJunctionC >= 100 || dev.MemUsedPct >= 95 || dev.XidErrors > 0:
			crits++
		case dev.TempC >= 80 || dev.TempJunctionC >= 90 || dev.Throttling ||
			dev.MemUsedPct >= 85 || dev.VRAMUsedPct >= 90 || dev.UtilPct >= 95 || dev.PowerDPMLevel == "low":
			warns++
		}
	}
	n := len(info.NoDriver)
	switch {
	case crits > 0:
		return render.StyleCrit.Render(fmt.Sprintf("%s %d GPU issue(s) found%s", asciiOr("fail", "❌", mode), crits, timing))
	case warns > 0:
		return render.StyleWarn.Render(fmt.Sprintf("%s GPU elevated%s", asciiOr("warn", "⚠️ ", mode), timing))
	case n > 0 && len(info.Devices) == 0:
		return render.StyleWarn.Render(fmt.Sprintf("%s %d GPU(s) detected, no driver loaded%s", asciiOr("warn", "⚠️ ", mode), n, timing))
	case n > 0:
		return render.StyleWarn.Render(fmt.Sprintf("%s active GPU healthy — %d GPU(s) without driver%s", asciiOr("ok", "✅", mode), n, timing))
	default:
		return render.StyleOK.Render(fmt.Sprintf("%s GPU healthy. Checks passed%s", asciiOr("ok", "✅", mode), timing))
	}
}

// tempIcon returns the status icon for a temperature against warn/crit thresholds.
func tempIcon(temp, warn, crit int, mode output.OutputMode) string {
	switch {
	case temp >= crit:
		return asciiOr("fail", "❌", mode)
	case temp >= warn:
		return asciiOr("warn", "⚠️ ", mode)
	default:
		return asciiOr("ok", "✅", mode)
	}
}

// vramIcon returns the status icon for a VRAM usage percentage.
func vramIcon(pct float64, mode output.OutputMode) string {
	switch {
	case pct >= 95:
		return asciiOr("fail", "❌", mode)
	case pct >= 85:
		return asciiOr("warn", "⚠️ ", mode)
	default:
		return asciiOr("ok", "✅", mode)
	}
}
