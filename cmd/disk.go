package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	rootCmd.AddCommand(diskCmd)
	diskCmd.Flags().Bool("deep", false, "deep mode: I/O rate sampling (adds ~2s)")
}

var diskCmd = &cobra.Command{
	Use:   "disk",
	Short: "Disk health — physical drives, SMART, filesystems, ZFS pools",
	RunE:  runDisk,
}

func runDisk(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	deep, _ := cmd.Flags().GetBool("deep")
	mode := output.DetectMode(plain, false, "")

	col := collectors.NewDiskCollector()
	if deep {
		col = collectors.NewDiskDeepCollector()
	}

	p := output.NewCommandProgress("Disk health", 12*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()
	info, ok := result.Data.(*models.DiskInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		return outputJSON(os.Stdout, info)
	}

	printDiskReport(info, mode, elapsed)
	return nil
}

func printDiskReport(info *models.DiskInfo, mode output.OutputMode, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	printDiskDrives(info)
	printDiskZFS(info)
	printDiskFilesystems(info)
	printDiskIO(info)

	fmt.Println()
	fmt.Println(sep)
	issues := countDiskIssues(info)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Disk healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  %d disk concern(s) found%s", issues, timing)))
	}
}

func printDiskDrives(info *models.DiskInfo) {
	if len(info.Drives) == 0 {
		return
	}
	fmt.Printf("\nPhysical Drives — %d found\n", len(info.Drives))
	for _, d := range info.Drives {
		mountStr := strings.Join(d.Mounts, "  ")
		sizeStr := diskFmtGB(d.SizeGB)
		modelStr := ""
		if d.Model != "" {
			modelStr = "  [" + d.Model + "]"
		}
		fmt.Printf("  %-12s %-6s %-5s %s%s\n",
			d.Name, sizeStr, string(d.Type), mountStr, modelStr)
		if d.SMART != nil {
			printSMARTLine(d.SMART)
		}
	}
}

func printDiskZFS(info *models.DiskInfo) {
	if len(info.ZFSPools) == 0 {
		return
	}
	fmt.Printf("\nZFS Pools (%d)\n", len(info.ZFSPools))
	for _, p := range info.ZFSPools {
		icon := "✅"
		switch p.State {
		case "DEGRADED", "FAULTED", "OFFLINE":
			icon = "❌"
		case "ONLINE":
			if p.UsedPct >= 95 {
				icon = "❌"
			} else if p.UsedPct >= 85 {
				icon = "⚠️ "
			}
		}
		errStr := ""
		if p.ReadErrors+p.WriteErrors+p.CksumErrors > 0 {
			errStr = fmt.Sprintf("  ⚠️  R:%d W:%d C:%d", p.ReadErrors, p.WriteErrors, p.CksumErrors)
		}
		scrubStr := ""
		if p.ScrubAgeDays > 30 {
			scrubStr = fmt.Sprintf("  ⚠️  last scrub %dd ago", p.ScrubAgeDays)
		} else if p.ScrubAgeDays < 0 {
			scrubStr = "  ⚠️  never scrubbed"
		}
		fmt.Printf("  %s  %-20s %s  %.0f%%  %.1fGB%s%s\n",
			icon, p.Name, p.State, p.UsedPct, p.SizeGB, errStr, scrubStr)
	}
}

func printDiskFilesystems(info *models.DiskInfo) {
	fmt.Printf("\nFilesystems (%d)\n", len(info.Filesystems))
	for _, fs := range info.Filesystems {
		if fs.TotalGB == 0 {
			continue
		}
		icon := "✅"
		if fs.UsedPct >= 95 {
			icon = "❌"
		} else if fs.UsedPct >= 85 {
			icon = "⚠️ "
		}
		roNote := ""
		if fs.ReadOnly {
			roNote = " [ro]"
		}
		fmt.Printf("  %s  %-22s %-6s %.1fG / %.1fG  (%.0f%%)%s\n",
			icon, fs.Mount, fs.FSType, fs.UsedGB, fs.TotalGB, fs.UsedPct, roNote)
		if fs.InodesUsedPct >= 85 {
			fmt.Printf("       ⚠️   inodes at %.0f%%\n", fs.InodesUsedPct)
		}
	}
}

func printDiskIO(info *models.DiskInfo) {
	if len(info.IOStats) == 0 {
		return
	}
	fmt.Printf("\nI/O rates (1s sample)\n")
	for _, io := range info.IOStats {
		fmt.Printf("  %-12s  read: %6.1f MB/s  write: %6.1f MB/s\n",
			io.Device, io.ReadMBs, io.WriteMBs)
	}
}

func countDiskIssues(info *models.DiskInfo) int {
	n := 0
	for _, fs := range info.Filesystems {
		if fs.UsedPct >= 85 || fs.InodesUsedPct >= 85 {
			n++
		}
	}
	for _, p := range info.ZFSPools {
		if p.State != "ONLINE" || p.UsedPct >= 85 || p.ReadErrors+p.WriteErrors+p.CksumErrors > 0 {
			n++
		}
	}
	for _, d := range info.Drives {
		if d.SMART != nil && !d.SMART.Healthy {
			n++
		}
	}
	return n
}

// printSMARTLine renders a compact SMART summary line indented under the drive.
func printSMARTLine(s *models.SMARTInfo) {
	if s.Error != "" {
		fmt.Printf("             SMART: %s\n", s.Error)
		return
	}
	icon := "✅"
	if !s.Healthy {
		icon = "❌"
	} else if s.PercentUsed >= 90 {
		icon = "⚠️ "
	} else if s.MediaErrors > 0 {
		icon = "⚠️ "
	}
	health := "PASSED"
	if !s.Healthy {
		health = "FAILED"
	}
	details := ""
	if s.PercentUsed > 0 || s.AvailableSpare > 0 {
		details = fmt.Sprintf("  wear:%d%%  spare:%d%%", s.PercentUsed, s.AvailableSpare)
	}
	tempStr := ""
	if s.Temperature > 0 {
		tempStr = fmt.Sprintf("  temp:%d°C", s.Temperature)
	}
	errStr := ""
	if s.MediaErrors > 0 {
		errStr = fmt.Sprintf("  errors:%d", s.MediaErrors)
	}
	fmt.Printf("             %s SMART: %s%s%s%s\n", icon, health, details, tempStr, errStr)
}

// diskFmtGB formats a float64 GB value into a compact string.
func diskFmtGB(gb float64) string {
	if gb >= 1000 {
		return fmt.Sprintf("%.0fTB", gb/1000)
	}
	return fmt.Sprintf("%.0fGB", gb)
}

// outputJSON writes v as indented JSON to w.
func outputJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
