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
	rootCmd.AddCommand(nvmeCmd)
}

var nvmeCmd = &cobra.Command{
	Use:   "nvme",
	Short: "NVMe drive health — SMART data, wear, temperature, mount status",
	RunE:  runNVMe,
}

func runNVMe(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")

	p := output.NewCommandProgress("NVMe health", 5*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewNVMeCollector()}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.NVMeInfo)
	if !ok || info == nil {
		return result.Err
	}

	printNVMeReport(info, mode, elapsed)
	return nil
}

func printNVMeReport(info *models.NVMeInfo, mode output.OutputMode, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if len(info.Devices) == 0 && len(info.SATADevices) == 0 {
		fmt.Println("\nNo drives detected.")
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleInfo.Render("ℹ️  No drive data available"))
		return
	}

	totalDrives := len(info.Devices) + len(info.SATADevices)
	fmt.Printf("\nDrive Health — %d drive(s)\n", totalDrives)

	issues := 0
	for _, dev := range info.Devices {
		fmt.Printf("\n%s  %s\n", dev.Name, dev.Model)

		// Mount status
		if len(dev.MountPoints) == 0 {
			osHint := ""
			if !dev.HasLinux {
				osHint = " (likely Windows/other OS)"
			}
			fmt.Printf("  ℹ️   Mounted:         not mounted%s\n", osHint)
		} else {
			fmt.Printf("  ✅  Mounted:         %s\n", strings.Join(dev.MountPoints, ", "))
		}

		// State
		stateIcon := "✅"
		if dev.State != "live" && dev.State != "" {
			stateIcon = "⚠️ "
		}
		fmt.Printf("  %s  State:           %s\n", stateIcon, dev.State)

		// Temperature
		if dev.TempC > 0 {
			tempIcon := "✅"
			if dev.TempC >= 70 {
				tempIcon = "⚠️ "
				issues++
			}
			fmt.Printf("  %s  Temperature:     %.0f°C\n", tempIcon, dev.TempC)
		}

		// Spare capacity
		spareIcon := "✅"
		if dev.AvailableSparePct > 0 && dev.AvailableSparePct <= dev.SpareThresholdPct {
			spareIcon = "❌"
			issues++
		} else if dev.AvailableSparePct > 0 && dev.AvailableSparePct < 20 {
			spareIcon = "⚠️ "
			issues++
		}
		fmt.Printf("  %s  Available spare: %d%% (threshold: %d%%)\n",
			spareIcon, dev.AvailableSparePct, dev.SpareThresholdPct)

		// Wear
		wearIcon := "✅"
		if dev.PercentageUsed >= 90 {
			wearIcon = "⚠️ "
			issues++
		}
		fmt.Printf("  %s  Wear:            %d%%\n", wearIcon, dev.PercentageUsed)

		// Media errors
		mediaIcon := "✅"
		if dev.MediaErrors > 0 {
			mediaIcon = "❌"
			issues++
		}
		fmt.Printf("  %s  Media errors:    %d\n", mediaIcon, dev.MediaErrors)

		// Critical warning
		if dev.CriticalWarning > 0 {
			fmt.Printf("  ❌  Critical warning: 0x%02x\n", dev.CriticalWarning)
			issues++
		}

		// Stats
		if dev.PowerOnHours > 0 {
			days := dev.PowerOnHours / 24
			fmt.Printf("  ✅  Power on:        %dh (%d days)\n", dev.PowerOnHours, days)
		}
		fmt.Printf("  ℹ️   Unsafe shutdowns: %d\n", dev.UnsafeShutdowns)
		if dev.PowerCycles > 0 {
			fmt.Printf("  ℹ️   Power cycles:    %d\n", dev.PowerCycles)
		}
	}

	// SATA/SAS drives
	for _, dev := range info.SATADevices {
		fmt.Printf("\n%s  %s  [%s]\n", dev.Name, dev.Model, strings.ToUpper(dev.Type))
		if dev.Error != "" {
			fmt.Printf("  ⚠️   Error:           %s\n", dev.Error)
			continue
		}
		smartIcon := "✅"
		if !dev.SmartOK {
			smartIcon = "❌"
			issues++
		}
		fmt.Printf("  %s  SMART:           %s\n", smartIcon, map[bool]string{true: "PASSED", false: "FAILED"}[dev.SmartOK])
		if dev.TempC > 0 {
			tempIcon := "✅"
			if dev.TempC >= 55 {
				tempIcon = "⚠️ "
				issues++
			}
			fmt.Printf("  %s  Temperature:     %d°C\n", tempIcon, dev.TempC)
		}
		if dev.ReallocatedSectors > 0 {
			fmt.Printf("  ⚠️   Reallocated:     %d sector(s)\n", dev.ReallocatedSectors)
			issues++
		}
		if dev.PendingSectors > 0 {
			fmt.Printf("  ⚠️   Pending:         %d sector(s)\n", dev.PendingSectors)
			issues++
		}
		if dev.UncorrectableErrors > 0 {
			fmt.Printf("  ❌  Uncorrectable:  %d error(s)\n", dev.UncorrectableErrors)
			issues++
		}
		if dev.PowerOnHours > 0 {
			fmt.Printf("  ✅  Power on:        %dh (%d days)\n", dev.PowerOnHours, dev.PowerOnHours/24)
		}
	}

	fmt.Println()
	fmt.Println(sep)

	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Drives healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleCrit.Render(fmt.Sprintf("❌ %d drive issue(s) found%s", issues, timing)))
	}
}
