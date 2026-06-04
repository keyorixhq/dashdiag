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
	"github.com/keyorixhq/dashdiag/internal/platform"
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
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	ctrCtx := platform.DetectContainerContext()
	col := collectors.NewDiskCollector(ctrCtx)
	if deep {
		col = collectors.NewDiskDeepCollector()
		col.ContainerCtx = ctrCtx
	}

	cols := []runner.Collector{col}
	if collectors.IsLVMPresent() {
		cols = append(cols, collectors.NewLVMCollector())
	}

	p := output.NewCommandProgress("Disk health", 12*time.Second, mode, len(cols))
	p.Start()
	defer p.Done()

	var results []runner.Result
	var diskResult runner.Result
	var lvmInfo *models.LVMInfo
	for r := range runner.RunAll(ctx, cols) {
		p.Step(r.Name)
		results = append(results, r)
		switch v := r.Data.(type) {
		case *models.DiskInfo:
			diskResult = r
		case *models.LVMInfo:
			lvmInfo = v
		}
	}

	elapsed := p.Elapsed()
	info, ok := diskResult.Data.(*models.DiskInfo)
	if !ok || info == nil {
		return diskResult.Err
	}

	// Propagate worst severity to the process exit code (BUG-022) — applies in
	// both human and JSON modes so CI gates on `dsd disk` / `dsd disk --json`.
	recordResultSeverity(results)

	if mode == output.ModeJSON {
		return outputJSON(os.Stdout, info)
	}

	printDiskReport(info, lvmInfo, mode, elapsed, deep)
	return nil
}

func printDiskReport(info *models.DiskInfo, lvmInfo *models.LVMInfo, mode output.OutputMode, elapsed time.Duration, deep bool) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	printDiskDrives(info)
	printDiskZFS(info)
	printDiskFilesystems(info)
	printDiskBtrfs(info)
	printDiskIO(info)
	printDiskLVM(lvmInfo)
	printDiskSteamOS(info)

	fmt.Println()
	fmt.Println(sep)
	issues := countDiskIssues(info, lvmInfo)
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

func printDiskBtrfs(info *models.DiskInfo) {
	if len(info.BtrfsVolumes) == 0 {
		return
	}
	fmt.Printf("\nBtrfs volumes (%d)\n", len(info.BtrfsVolumes))
	for _, v := range info.BtrfsVolumes {
		icon := "✅"
		statusStr := ""
		if v.Status == "degraded" || v.MissingDevs > 0 {
			icon = "❌"
			statusStr = fmt.Sprintf("  DEGRADED — %d missing device(s)", v.MissingDevs)
		} else if v.Status == "errors" {
			icon = "⚠️ "
			statusStr = "  device errors detected"
		}
		devStr := fmt.Sprintf("%d device(s)", v.TotalDevices)
		if v.MissingDevs > 0 {
			devStr = fmt.Sprintf("%d/%d device(s)", v.TotalDevices-v.MissingDevs, v.TotalDevices)
		}
		fmt.Printf("  %s  %-30s  %s%s\n", icon, v.MountPoint, devStr, statusStr)
		for _, d := range v.Devices {
			devIcon := "  "
			label := d.Path
			if d.Missing {
				devIcon = "  ❌"
				label = "<missing disk>"
			}
			errStr := ""
			if d.ReadErrs+d.WriteErrs+d.CorruptErrs > 0 {
				errStr = fmt.Sprintf("  read:%d write:%d corrupt:%d", d.ReadErrs, d.WriteErrs, d.CorruptErrs)
			}
			fmt.Printf("    %s  devid %d  %s%s\n", devIcon, d.DevID, label, errStr)
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

func countDiskIssues(info *models.DiskInfo, lvmInfo *models.LVMInfo) int {
	n := 0
	for _, fs := range info.Filesystems {
		if fs.UsedPct >= 85 || fs.InodesUsedPct >= 85 {
			n++
		}
	}
	for _, v := range info.BtrfsVolumes {
		if v.Status != "healthy" {
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
	// LVM: full VGs (≤5% free = CRIT) or degraded RAID
	if lvmInfo != nil {
		for _, vg := range lvmInfo.VGs {
			if vg.FreePct <= 5 {
				n++
			}
		}
		for _, r := range lvmInfo.RaidLVs {
			if r.Degraded {
				n++
			}
		}
	}
	n += countSteamOSDiskIssues(info.SteamOS)
	return n
}

// countSteamOSDiskIssues counts SteamOS partition-layout concerns (Spec 19) for
// the disk summary line.
func countSteamOSDiskIssues(d *models.SteamOSDisk) int {
	if d == nil {
		return 0
	}
	n := 0
	if d.ShaderCacheGB > 10 {
		n++
	}
	for _, bm := range d.BindMounts {
		if !bm.OK {
			n++
		}
	}
	return n
}

// printDiskSteamOS renders the SteamOS-only partition layout section (Spec 19).
func printDiskSteamOS(info *models.DiskInfo) {
	d := info.SteamOS
	if d == nil {
		return
	}
	// btrfs root errors appear in the Btrfs section above; /var + /home in the
	// Filesystems section. This section covers only the SteamOS-specific extras.
	fmt.Printf("\n[SteamOS storage]\n")

	if d.ShaderCacheGB > 0 {
		icon := "✅"
		if d.ShaderCacheGB > 30 {
			icon = "❌"
		} else if d.ShaderCacheGB > 10 {
			icon = "⚠️ "
		}
		fmt.Printf("  %s Shader cache: %.1f GB at ~/.steam/steam/shadercache/\n", icon, d.ShaderCacheGB)
	}

	for _, bm := range d.BindMounts {
		if bm.OK {
			fmt.Printf("  ✅ Bind mount %s → %s — intact\n", bm.Path, bm.Target)
		} else {
			fmt.Printf("  ⚠️  Bind mount %s → %s — broken\n", bm.Path, bm.Target)
		}
	}
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
	if s.PowerOnHours > 0 {
		days := s.PowerOnHours / 24
		fmt.Printf("               power-on: %dh (%d days)  shutdowns: %d  cycles: %d\n",
			s.PowerOnHours, days, s.UnsafeShutdowns, s.PowerCycles)
	}
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

func printDiskLVM(lvm *models.LVMInfo) {
	if lvm == nil || (len(lvm.VGs) == 0 && len(lvm.ThinPools) == 0 && len(lvm.Snapshots) == 0 && len(lvm.RaidLVs) == 0) {
		return
	}

	fmt.Printf("\nLVM (%d VG(s))\n", len(lvm.VGs))

	// Volume groups
	for _, vg := range lvm.VGs {
		icon := "✅"
		note := ""
		if vg.FreePct < 5 {
			icon = "❌"
			note = "  ← CRIT: VG almost full"
		} else if vg.FreePct < 15 {
			icon = "⚠️ "
			note = "  ← low on space"
		}
		fmt.Printf("  %s  %-20s %.1fGB total  %.1fGB free  (%.0f%%)%s\n",
			icon, vg.Name, vg.SizeGB, vg.FreeGB, vg.FreePct, note)
		if vg.MissingPVs > 0 {
			fmt.Printf("       ❌ %d missing PV(s) — data at risk\n", vg.MissingPVs)
		}
	}

	// Thin pools
	if len(lvm.ThinPools) > 0 {
		fmt.Printf("\n  Thin pools (%d):\n", len(lvm.ThinPools))
		for _, p := range lvm.ThinPools {
			dIcon := "✅"
			if p.DataPct >= 90 {
				dIcon = "❌"
			} else if p.DataPct >= 70 {
				dIcon = "⚠️ "
			}
			fmt.Printf("  %s  %-20s Data: %.0f%%  Meta: %.0f%%\n",
				dIcon, fmt.Sprintf("%s/%s", p.VG, p.Name), p.DataPct, p.MetaPct)
		}
	}

	// Snapshots
	if len(lvm.Snapshots) > 0 {
		fmt.Printf("\n  Snapshots (%d):\n", len(lvm.Snapshots))
		for _, s := range lvm.Snapshots {
			sIcon := "✅"
			if s.DataPct >= 90 {
				sIcon = "❌"
			} else if s.DataPct >= 70 {
				sIcon = "⚠️ "
			}
			fmt.Printf("  %s  %-20s → %-20s  Snap%%: %.0f%%\n",
				sIcon, fmt.Sprintf("%s/%s", s.VG, s.Name), s.Origin, s.DataPct)
		}
	}

	// RAID/mirror LVs
	if len(lvm.RaidLVs) > 0 {
		fmt.Printf("\n  RAID/mirror LVs (%d):\n", len(lvm.RaidLVs))
		for _, r := range lvm.RaidLVs {
			rIcon := "✅"
			status := fmt.Sprintf("sync: %.0f%%", r.SyncPct)
			if r.Degraded {
				rIcon = "❌"
				status = "DEGRADED"
			} else if r.Resyncing {
				rIcon = "⚠️ "
				status = fmt.Sprintf("resyncing %.0f%%", r.SyncPct)
			} else if r.SyncPct >= 100 {
				status = "in sync"
			}
			fmt.Printf("  %s  %-20s  %s  %s\n",
				rIcon, fmt.Sprintf("%s/%s", r.VG, r.Name), r.Type, status)
		}
	}
}
