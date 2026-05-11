package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
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

	if len(info.Devices) == 0 {
		fmt.Println("\nNo NVIDIA GPU detected or driver not loaded.")
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleInfo.Render("ℹ️  No GPU data available"))
		return
	}

	for _, dev := range info.Devices {
		fmt.Printf("\nGPU %d — %s\n", dev.Index, dev.Name)
		if info.DriverVersion != "" {
			fmt.Printf("  Driver:        %s\n", info.DriverVersion)
		}

		// Temperature with color indication
		tempIcon := "✅"
		if dev.TempC >= 90 {
			tempIcon = "❌"
		} else if dev.TempC >= 80 {
			tempIcon = "⚠️ "
		}
		fmt.Printf("  Temperature:   %s %d°C\n", tempIcon, dev.TempC)

		// Utilization
		utilIcon := "✅"
		if dev.UtilPct >= 95 {
			utilIcon = "⚠️ "
		}
		fmt.Printf("  Utilization:   %s %d%%\n", utilIcon, dev.UtilPct)

		// VRAM
		vramIcon := "✅"
		if dev.MemUsedPct >= 95 {
			vramIcon = "❌"
		} else if dev.MemUsedPct >= 85 {
			vramIcon = "⚠️ "
		}
		fmt.Printf("  VRAM:          %s %d MB / %d MB (%.0f%%)\n",
			vramIcon, dev.MemUsedMB, dev.MemTotalMB, dev.MemUsedPct)

		// Power draw
		if dev.PowerDrawW > 0 {
			fmt.Printf("  Power draw:    ✅  %.1fW\n", dev.PowerDrawW)
		}

		// Xid errors
		if dev.XidErrors == 0 {
			fmt.Printf("  Xid errors:    ✅  none (last 1h)\n")
		} else {
			fmt.Printf("  Xid errors:    ❌  %d hardware fault(s) detected\n", dev.XidErrors)
			fmt.Printf("                     → dmesg | grep 'NVRM: Xid'\n")
		}

		// GPU processes — shown when GPU is busy
		if len(dev.Processes) > 0 {
			fmt.Printf("  Processes:\n")
			fmt.Printf("    %-8s %-10s %s\n", "PID", "VRAM", "NAME")
			for _, p := range dev.Processes {
				fmt.Printf("    %-8d %-10s %s\n",
					p.PID, fmt.Sprintf("%dMB", p.MemUseMB), p.Name)
			}
		}
	}

	fmt.Println()
	fmt.Println(sep)

	// Summary
	crits, warns := 0, 0
	for _, dev := range info.Devices {
		if dev.TempC >= 90 || dev.MemUsedPct >= 95 || dev.XidErrors > 0 {
			crits++
		} else if dev.TempC >= 80 || dev.MemUsedPct >= 85 || dev.UtilPct >= 95 {
			warns++
		}
	}
	switch {
	case crits > 0:
		fmt.Println(render.StyleCrit.Render(fmt.Sprintf("❌ %d GPU issue(s) found%s", crits, timing)))
	case warns > 0:
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  GPU elevated%s", timing)))
	default:
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ GPU healthy. Checks passed%s", timing)))
	}
}
