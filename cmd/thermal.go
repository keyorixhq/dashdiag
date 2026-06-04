package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
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
	rootCmd.AddCommand(thermalCmd)
	thermalCmd.Flags().Duration("watch-interval", 5*time.Second, "refresh interval for --watch mode")
}

var thermalCmd = &cobra.Command{
	Use:   "thermal",
	Short: "Thermal health — CPU temperature, core temps, sensor details",
	RunE:  runThermal,
}

func runThermal(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	watchFlag, _ := cmd.Flags().GetBool("watch")
	if watchFlag {
		interval, _ := cmd.Flags().GetDuration("watch-interval")
		return watchThermal(ctx, interval, mode)
	}

	p := output.NewCommandProgress("Thermal health", 3*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewThermalCollector()}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.ThermalInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		return outputJSON(os.Stdout, info)
	}

	printThermalReport(info, mode, elapsed)
	return nil
}

func watchThermal(ctx context.Context, interval time.Duration, mode output.OutputMode) error {
	run := func() {
		if mode == output.ModeHuman {
			fmt.Print("\033[H\033[2J") // clear screen
		}
		var result runner.Result
		for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewThermalCollector()}) {
			result = r
		}
		info, ok := result.Data.(*models.ThermalInfo)
		if !ok || info == nil {
			return
		}
		fmt.Printf("\n── %s ──\n", time.Now().Format("15:04:05"))
		printThermalReport(info, mode, 0)
	}

	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			run()
		}
	}
}

func printThermalReport(info *models.ThermalInfo, mode output.OutputMode, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if info.Source == "" {
		fmt.Println("\nNo thermal sensors detected.")
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleInfo.Render("ℹ️  Thermal data not available on this platform"))
		return
	}

	fmt.Printf("\nThermal Health  (source: %s)\n", info.Source)

	// Primary CPU temp
	cpuIcon := "✅"
	if info.CPUTempC >= 95 {
		cpuIcon = "❌"
	} else if info.CPUTempC >= 85 {
		cpuIcon = "⚠️ "
	}
	fmt.Printf("\n  %s  CPU temperature:  %.1f°C\n", cpuIcon, info.CPUTempC)

	// All sensor readings sorted by name
	if len(info.CoreTemps) > 0 {
		fmt.Println("\n  Sensors:")
		keys := make([]string, 0, len(info.CoreTemps))
		for k := range info.CoreTemps {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t := info.CoreTemps[k]
			icon := "✅"
			if t >= 95 {
				icon = "❌"
			} else if t >= 85 {
				icon = "⚠️ "
			}
			fmt.Printf("    %s  %-20s %.1f°C\n", icon, k, t)
		}
	}

	fmt.Println()
	fmt.Println(sep)

	issues := 0
	if info.CPUTempC >= 95 {
		issues++
	} else if info.CPUTempC >= 85 {
		issues++
	}

	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Thermal healthy. Checks passed%s", timing)))
	} else if info.CPUTempC >= 95 {
		fmt.Println(render.StyleCrit.Render(fmt.Sprintf("❌ CPU temperature critical%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  CPU temperature elevated%s", timing)))
	}
}
