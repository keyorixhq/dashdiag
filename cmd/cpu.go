package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/drilldown"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

func init() {
	cpuCmd.Flags().Bool("plain", false, "plain text output (no colour, machine-friendly)")
	rootCmd.AddCommand(cpuCmd)
}

var cpuCmd = &cobra.Command{
	Use:   "cpu",
	Short: "CPU health — load, frequency, temperature, top processes (~3s)",
	Long:  "CPU health snapshot: load averages, usage %, iowait, steal, frequency scaling, thermal, top consumers.",
	RunE:  runCPU,
}

func runCPU(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	isJSON, _ := cmd.Flags().GetBool("json")
	mode := output.DetectMode(plain, false, "")

	ctrCtx := platform.DetectContainerContext()
	start := time.Now()

	cpuRaw, _ := collectors.NewCPUCollector(ctrCtx).Collect(ctx)
	freqRaw, _ := collectors.NewCPUFreqCollector().Collect(ctx)
	thermalRaw, _ := collectors.NewThermalCollector().Collect(ctx)
	hwRaw, _ := collectors.NewHardwareCollector().Collect(ctx)
	elapsed := time.Since(start)

	if isJSON {
		type cpuReport struct {
			CPU     interface{} `json:"cpu"`
			Freq    interface{} `json:"freq"`
			Thermal interface{} `json:"thermal"`
		}
		return outputJSON(os.Stdout, cpuReport{cpuRaw, freqRaw, thermalRaw})
	}

	var cpu *models.CPUInfo
	switch v := cpuRaw.(type) {
	case *models.CPUInfo:
		cpu = v
	case models.CPUInfo:
		cpu = &v
	}
	var freq *models.CPUFreqInfo
	switch v := freqRaw.(type) {
	case *models.CPUFreqInfo:
		freq = v
	case models.CPUFreqInfo:
		freq = &v
	}
	var thermal *models.ThermalInfo
	switch v := thermalRaw.(type) {
	case *models.ThermalInfo:
		thermal = v
	case models.ThermalInfo:
		thermal = &v
	}
	var hw *models.HardwareInfo
	switch v := hwRaw.(type) {
	case *models.HardwareInfo:
		hw = v
	case models.HardwareInfo:
		hw = &v
	}

	printCPUReport(ctx, cpu, freq, thermal, hw, mode, elapsed)
	return nil
}

func printCPUReport(ctx context.Context, cpu *models.CPUInfo, freq *models.CPUFreqInfo, thermal *models.ThermalInfo, hw *models.HardwareInfo, _ output.OutputMode, elapsed time.Duration) { //nolint:funlen // flat display renderer — each section is independent
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	numCPU := 1
	if cpu != nil && cpu.NumCPU > 0 {
		numCPU = cpu.NumCPU
	}

	// Identity
	fmt.Println()
	if hw != nil && hw.CPU.Model != "" {
		fmt.Printf("CPU  %s\n", hw.CPU.Model)
		if hw.CPU.Cores > 0 {
			threadStr := ""
			if hw.CPU.Threads > hw.CPU.Cores {
				threadStr = fmt.Sprintf("  %d threads (hyperthreading)", hw.CPU.Threads)
			}
			fmt.Printf("     %d cores%s\n", hw.CPU.Cores, threadStr)
		}
	} else {
		fmt.Printf("CPU  %d logical CPUs\n", numCPU)
	}

	// Load & Usage
	fmt.Println("\nLoad")
	if cpu != nil {
		load1Pct := cpu.LoadAvg1 / float64(numCPU) * 100
		fmt.Printf("  %s  Usage:            %4.1f%%\n", cpuIcon(cpu.UsagePct, 70, 90), cpu.UsagePct)
		fmt.Printf("  %s  Load avg 1m:      %.2f  (%d%% of capacity)\n", cpuIcon(load1Pct, 70, 90), cpu.LoadAvg1, int(load1Pct))
		fmt.Printf("       Load avg 5m:      %.2f\n", cpu.LoadAvg5)
		fmt.Printf("       Load avg 15m:     %.2f\n", cpu.LoadAvg15)
		if cpu.IOwaitPct > 0.5 {
			fmt.Printf("  %s  IOWait:           %4.1f%%\n", cpuIcon(cpu.IOwaitPct, 10, 25), cpu.IOwaitPct)
		}
		if cpu.StealPct > 0.1 {
			fmt.Printf("  %s  Steal:            %4.1f%%  <- hypervisor over-provisioned?\n", cpuIcon(cpu.StealPct, 5, 15), cpu.StealPct)
		}
	}

	// Frequency
	if freq != nil {
		fmt.Println("\nFrequency")
		fmt.Printf("       Governor:         %s\n", freq.Governor)
		fmt.Printf("       Current:          %d MHz\n", freq.CurrentMHz)
		if freq.MaxMHz > 0 {
			fmt.Printf("       Max (boost):      %d MHz\n", freq.MaxMHz)
		}
		if freq.ThrottledPct > 5 {
			fmt.Printf("  %s  Throttled:        %.1f%%\n", cpuIcon(freq.ThrottledPct, 20, 50), freq.ThrottledPct)
		} else {
			fmt.Printf("  ✅  Throttled:        %.1f%%\n", freq.ThrottledPct)
		}
	}

	// Thermal
	if thermal != nil && thermal.Available {
		fmt.Println("\nThermal")
		fmt.Printf("  %s  CPU temp:         %.1f°C\n", cpuIcon(thermal.CPUTempC, 80, 95), thermal.CPUTempC)
		if len(thermal.CoreTemps) > 1 {
			for name, temp := range thermal.CoreTemps {
				fmt.Printf("  %s    %-18s  %.1f°C\n", cpuIcon(temp, 80, 95), name, temp)
			}
		}
	}

	// Top CPU processes — live 1s sample via drilldown
	fmt.Println("\nTop processes by CPU")
	if d, err := drilldown.TopProcessesByCPU(ctx, 10); err == nil && d != nil {
		if len(d.Rows) == 0 {
			fmt.Println("  (all processes idle)")
		} else {
			fmt.Printf("  %-7s %-6s %s\n", "PID", "CPU%", "COMMAND")
			for _, row := range d.Rows {
				if len(row) >= 3 {
					fmt.Printf("  %-7s %-6s %s\n", row[0], row[1], row[2])
				}
			}
		}
	}

	fmt.Println()
	fmt.Println(sep)
	issues := 0
	if cpu != nil {
		if cpu.UsagePct > 90 || cpu.LoadAvg1/float64(numCPU)*100 > 90 {
			issues++
		}
		if cpu.StealPct > 10 {
			issues++
		}
	}
	if thermal != nil && thermal.CPUTempC > 95 {
		issues++
	}
	if issues == 0 {
		fmt.Printf("✅ CPU healthy. Checks passed%s\n", timing)
	} else {
		fmt.Printf("⚠️  %d CPU concern(s) found%s\n", issues, timing)
	}
}

func cpuIcon(val, warn, crit float64) string {
	if val >= crit {
		return "❌"
	}
	if val >= warn {
		return "⚠️ "
	}
	return "✅"
}
