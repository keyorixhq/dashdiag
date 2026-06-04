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

func printCPUReport(ctx context.Context, cpu *models.CPUInfo, freq *models.CPUFreqInfo, thermal *models.ThermalInfo, hw *models.HardwareInfo, _ output.OutputMode, elapsed time.Duration) { //nolint:funlen,cyclop // flat display renderer — each section is independent
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	numCPU := 1
	if cpu != nil && cpu.NumCPU > 0 {
		numCPU = cpu.NumCPU
	}

	// cpuLine prints a labelled metric row with consistent column alignment:
	//   <icon>  <label>         <value>
	// icon: "✅", "⚠️ ", "❌", or "   " (3-char placeholder when no icon)
	cpuLine := func(icon, label, value string) {
		fmt.Printf("  %s  %-20s %s\n", icon, label, value)
	}
	noIcon := "   "

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
		cpuLine(cpuIcon(cpu.UsagePct, 70, 90), "Usage:", fmt.Sprintf("%.1f%%", cpu.UsagePct))
		cpuLine(cpuIcon(load1Pct, 70, 90), "Load avg 1m:", fmt.Sprintf("%.2f  (%d%% of capacity)", cpu.LoadAvg1, int(load1Pct)))
		cpuLine(noIcon, "Load avg 5m:", fmt.Sprintf("%.2f", cpu.LoadAvg5))
		cpuLine(noIcon, "Load avg 15m:", fmt.Sprintf("%.2f", cpu.LoadAvg15))
		if cpu.IOwaitPct > 0.5 {
			cpuLine(cpuIcon(cpu.IOwaitPct, 10, 25), "IOWait:", fmt.Sprintf("%.1f%%", cpu.IOwaitPct))
		}
		if cpu.StealPct > 0.1 {
			cpuLine(cpuIcon(cpu.StealPct, 5, 15), "Steal:", fmt.Sprintf("%.1f%%  <- hypervisor over-provisioned?", cpu.StealPct))
		}
	}

	// Frequency
	if freq != nil {
		fmt.Println("\nFrequency")
		cpuLine(noIcon, "Governor:", freq.Governor)
		cpuLine(noIcon, "Current:", fmt.Sprintf("%d MHz", freq.CurrentMHz))
		if freq.MaxMHz > 0 {
			cpuLine(noIcon, "Max (boost):", fmt.Sprintf("%d MHz", freq.MaxMHz))
		}
		underLoad := cpu != nil && cpu.UsagePct > 30
		if freq.ThrottledPct > 5 && underLoad {
			cpuLine(cpuIcon(freq.ThrottledPct, 20, 50), "Throttled:", fmt.Sprintf("%.1f%%  <- CPU throttled under load", freq.ThrottledPct))
		} else {
			cpuLine("✅", "Throttled:", fmt.Sprintf("%.1f%%", freq.ThrottledPct))
		}
	}

	// Thermal
	if thermal != nil && thermal.Available {
		fmt.Println("\nThermal")
		cpuLine(cpuIcon(thermal.CPUTempC, 80, 95), "CPU temp:", fmt.Sprintf("%.1f°C", thermal.CPUTempC))
		if len(thermal.CoreTemps) > 1 {
			for name, temp := range thermal.CoreTemps {
				cpuLine(cpuIcon(temp, 80, 95), name+":", fmt.Sprintf("%.1f°C", temp))
			}
		}
	}

	// Top CPU processes — live 1s sample via drilldown
	fmt.Println("\nTop processes by CPU")
	if d, err := drilldown.TopProcessesByCPU(ctx, 10); err == nil && d != nil {
		if len(d.Rows) == 0 {
			fmt.Println("  (all processes idle)")
		} else {
			fmt.Printf("  %-8s %-6s %s\n", "PID", "CPU%", "COMMAND")
			for _, row := range d.Rows {
				if len(row) >= 3 {
					fmt.Printf("  %-8s %-6s %s\n", row[0], row[1], row[2])
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
