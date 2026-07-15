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
	thermalCmd.Flags().Duration("watch-interval", 5*time.Second, "refresh interval for --watch mode (default 5s; health uses 60s)")
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
		if result.Err != nil {
			return result.Err
		}
		// The collector returns nil (not an empty struct) when no sensor exists, so
		// the section gates cleanly out of `dsd health`. But the standalone command
		// must still say something — otherwise `dsd thermal` on a VM/cloud guest with
		// no thermal zone prints nothing at all, which reads like a crash. Render the
		// same "not available" message printThermalReport uses for an empty source.
		info = &models.ThermalInfo{}
	}
	recordResultSeverity([]runner.Result{result})

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
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️ ", mode) + " Thermal data not available on this platform"))
		return
	}

	fmt.Printf("\nThermal Health  (source: %s)\n", info.Source)

	// Primary CPU temp
	cpuIcon := asciiOr("ok", iconOK, mode)
	if info.CPUTempC >= 95 {
		cpuIcon = asciiOr("fail", iconFail, mode)
	} else if info.CPUTempC >= 85 {
		cpuIcon = asciiOr("warn", iconWarnSp, mode)
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
			icon := asciiOr("ok", iconOK, mode)
			if t >= 95 {
				icon = asciiOr("fail", iconFail, mode)
			} else if t >= 85 {
				icon = asciiOr("warn", iconWarnSp, mode)
			}
			fmt.Printf("    %s  %-20s %.1f°C\n", icon, k, t)
		}
	}

	fmt.Println()
	fmt.Println(sep)

	// A thermal sensor was detected (Source set) but no temperature could be read
	// (CPUTempC stayed 0) — don't claim "healthy" off a reading we never got. The
	// health heuristic already gates CPUTempC==0; mirror that here.
	if info.CPUTempC <= 0 {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s Thermal sensor present (%s) but temperature unreadable%s",
			asciiOr("warn", iconWarnSp, mode), info.Source, timing)))
		return
	}

	issues := 0
	if info.CPUTempC >= 95 {
		issues++
	} else if info.CPUTempC >= 85 {
		issues++
	}

	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Thermal healthy. Checks passed%s", asciiOr("ok", iconOK, mode), timing)))
	} else if info.CPUTempC >= 95 {
		fmt.Println(render.StyleCrit.Render(fmt.Sprintf("%s CPU temperature critical%s", asciiOr("fail", iconFail, mode), timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s CPU temperature elevated%s", asciiOr("warn", iconWarnSp, mode), timing)))
	}
}
