package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(gpuCmd)
}

var gpuCmd = &cobra.Command{
	Use:   "gpu",
	Short: "GPU health — temperature, VRAM, utilization, power draw",
	RunE:  runGPU,
}

func runGPU(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")

	p := output.NewCommandProgress("GPU health", 5*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewGPUCollector()}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.GPUInfo)
	if !ok || info == nil {
		return result.Err
	}

	printGPUReport(info, mode, elapsed)
	return nil
}

func printGPUReport(info *models.GPUInfo, mode output.OutputMode, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if len(info.Devices) == 0 && len(info.NoDriver) == 0 {
		fmt.Println("\nNo GPU detected or driver not loaded.")
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleInfo.Render("ℹ️  No GPU data available"))
		return
	}

	for _, dev := range info.Devices {
		printGPUDevice(dev, info.DriverVersion)
	}
	printGPUNoDriver(info.NoDriver)

	fmt.Println()
	fmt.Println(sep)
	fmt.Println(gpuSummaryLine(info, timing))
}

func printGPUDevice(dev models.GPUDevice, driverVersion string) {
	vendor := ""
	if dev.Vendor != "" {
		vendor = " [" + dev.Vendor + "]"
	}
	fmt.Printf("\nGPU %d — %s%s\n", dev.Index, dev.Name, vendor)
	if driverVersion != "" && dev.Vendor == "nvidia" {
		fmt.Printf("  Driver:        %s\n", driverVersion)
	}
	tempIcon := "✅"
	if dev.TempC >= 90 {
		tempIcon = "❌"
	} else if dev.TempC >= 80 {
		tempIcon = "⚠️ "
	}
	fmt.Printf("  Temperature:   %s %d°C\n", tempIcon, dev.TempC)
	utilIcon := "✅"
	if dev.UtilPct >= 95 {
		utilIcon = "⚠️ "
	}
	fmt.Printf("  Utilization:   %s %d%%\n", utilIcon, dev.UtilPct)
	vramIcon := "✅"
	if dev.MemUsedPct >= 95 {
		vramIcon = "❌"
	} else if dev.MemUsedPct >= 85 {
		vramIcon = "⚠️ "
	}
	if dev.MemTotalMB > 0 {
		fmt.Printf("  VRAM:          %s %d MB / %d MB (%.0f%%)\n",
			vramIcon, dev.MemUsedMB, dev.MemTotalMB, dev.MemUsedPct)
	}
	if dev.PowerDrawW > 0 {
		fmt.Printf("  Power draw:    ✅  %.1fW\n", dev.PowerDrawW)
	}
	if dev.XidErrors == 0 {
		fmt.Printf("  Xid errors:    ✅  none (last 1h)\n")
	} else {
		fmt.Printf("  Xid errors:    ❌  %d hardware fault(s) detected\n", dev.XidErrors)
		fmt.Printf("                     → dmesg | grep 'NVRM: Xid'\n")
	}
	if len(dev.Processes) > 0 {
		fmt.Printf("  Processes:\n")
		fmt.Printf("    %-8s %-10s %s\n", "PID", "VRAM", "NAME")
		for _, p := range dev.Processes {
			fmt.Printf("    %-8d %-10s %s\n", p.PID, fmt.Sprintf("%dMB", p.MemUseMB), p.Name)
		}
	}
}

func printGPUNoDriver(noDriver []models.GPUDetected) {
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
		fmt.Printf("  ⚠️   proprietary driver not loaded — power/VRAM metrics unavailable\n")
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

func gpuSummaryLine(info *models.GPUInfo, timing string) string {
	crits, warns := 0, 0
	for _, dev := range info.Devices {
		if dev.TempC >= 90 || dev.MemUsedPct >= 95 || dev.XidErrors > 0 {
			crits++
		} else if dev.TempC >= 80 || dev.MemUsedPct >= 85 || dev.UtilPct >= 95 {
			warns++
		}
	}
	n := len(info.NoDriver)
	switch {
	case crits > 0:
		return render.StyleCrit.Render(fmt.Sprintf("❌ %d GPU issue(s) found%s", crits, timing))
	case warns > 0:
		return render.StyleWarn.Render(fmt.Sprintf("⚠️  GPU elevated%s", timing))
	case n > 0 && len(info.Devices) == 0:
		return render.StyleWarn.Render(fmt.Sprintf("⚠️  %d GPU(s) detected, no driver loaded%s", n, timing))
	case n > 0:
		return render.StyleWarn.Render(fmt.Sprintf("✅ active GPU healthy — %d GPU(s) without driver%s", n, timing))
	default:
		return render.StyleOK.Render(fmt.Sprintf("✅ GPU healthy. Checks passed%s", timing))
	}
}
