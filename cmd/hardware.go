package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

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
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")

	p := output.NewCommandProgress("Hardware health", 15*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(cmd.Context(), []runner.Collector{collectors.NewHardwareCollector()}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.HardwareInfo)
	if !ok || info == nil {
		info = &models.HardwareInfo{}
	}

	jsonOut, _ := cmd.Flags().GetBool("json")
	if jsonOut {
		data, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	printHardwareReport(info, mode, elapsed)
	return nil
}

func printHardwareReport(info *models.HardwareInfo, mode output.OutputMode, elapsed time.Duration) { //nolint:cyclop,funlen // flat display renderer — each branch is a distinct section
	sep := render.StyleDim.Render("────────────────────────────────────────────────────────")

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
			tempLevel := "ok"
			if d.Type == "nvme" {
				if d.TempC >= 80 {
					tempLevel = "fail"
				} else if d.TempC >= 70 {
					tempLevel = "warn"
				}
			} else {
				if d.TempC >= 60 {
					tempLevel = "fail"
				} else if d.TempC >= 50 {
					tempLevel = "warn"
				}
			}
			fmt.Printf("  %-14s %s  %d°C\n", "Temperature:", output.StatusIcon(tempLevel, mode), d.TempC)
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

		// SATA bad sectors
		if d.Type != "nvme" {
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

	// ── Thermals ──────────────────────────────────────────────────────────────
	if len(info.Thermals) > 0 {
		fmt.Println(render.StyleBold.Render("Thermals"))
		for _, t := range info.Thermals {
			level := "ok"
			note := ""
			if t.TempC >= 95 {
				level = "fail"
				note = " — throttling"
			} else if t.TempC >= 85 {
				level = "warn"
				note = " — elevated"
			} else if t.TempC >= 70 {
				level = "warn"
				note = " — warm"
			}
			fmt.Printf("  %-14s %s  %d°C%s  (%s)\n",
				t.Label+":", output.StatusIcon(level, mode), t.TempC, note, t.Sensor)
		}
		fmt.Println()
	}

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
	fmt.Println(sep)
	fmt.Println(render.StyleDim.Render(fmt.Sprintf("done in %.1fs", elapsed.Seconds())))
	_ = os.Stdout.Sync()
}
