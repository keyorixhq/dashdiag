package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
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
	deep, _ := cmd.Flags().GetBool("deep")

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

	return runDiagnostic(cmd, diagnostic{
		label:   "Disk health",
		timeout: 12 * time.Second,
		cols:    cols,
		jsonValue: func(r []runner.Result) (any, error) {
			info := resultData[*models.DiskInfo](r)
			if info == nil {
				return nil, firstErr(r)
			}
			return info, nil
		},
		render: func(r []runner.Result, mode output.OutputMode, elapsed time.Duration) error {
			info := resultData[*models.DiskInfo](r)
			if info == nil {
				return firstErr(r)
			}
			printDiskReport(info, resultData[*models.LVMInfo](r), mode, elapsed, deep)
			return nil
		},
	})
}

func printDiskReport(info *models.DiskInfo, lvmInfo *models.LVMInfo, mode output.OutputMode, elapsed time.Duration, _ bool) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	printDiskDrives(info, mode)
	printDiskZFS(info, mode)
	printDiskFilesystems(info, mode)
	printDiskBtrfs(info, mode)
	printDiskIO(info)
	printDiskLVM(lvmInfo, mode)
	printDiskSteamOS(info, mode)

	fmt.Println()
	fmt.Println(sep)
	issues := countDiskIssues(info, lvmInfo)
	switch {
	case issues > 0:
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s%d disk concern(s) found%s", asciiOr("warn", "⚠️  ", mode), issues, timing)))
	case diskHasUnverifiedReads(info, lvmInfo):
		// Reads failed (ZFS/LVM, commonly non-root) — checks that DID run passed, but
		// some couldn't run. Don't claim "healthy. Checks passed" (the false-OK dsd
		// health avoids with an INFO); say so explicitly instead.
		fmt.Println(render.StyleInfo.Render(fmt.Sprintf("%sDisk: checks passed, but some state could not be verified — run as root%s", asciiOr("info", "ℹ️  ", mode), timing)))
	default:
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%sDisk healthy. Checks passed%s", asciiOr("ok", "✅ ", mode), timing)))
	}
}

// diskHasUnverifiedReads reports whether any ZFS/LVM read failed (so the summary
// must not claim a clean "healthy" — the reads that failed were never checked). Keyed
// on the same *ReadFailed flags dsd health folds to INFO, so the two agree non-root.
func diskHasUnverifiedReads(info *models.DiskInfo, lvmInfo *models.LVMInfo) bool {
	if info != nil {
		if info.ZFSListReadFailed {
			return true
		}
		for _, p := range info.ZFSPools {
			if p.StatusReadFailed {
				return true
			}
		}
	}
	if lvmInfo != nil && (lvmInfo.VGReadFailed || lvmInfo.PVReadFailed || lvmInfo.LVReadFailed || lvmInfo.RaidReadFailed) {
		return true
	}
	return false
}

func printDiskDrives(info *models.DiskInfo, mode output.OutputMode) {
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
			printSMARTLine(d.SMART, mode)
		}
	}
}

func printDiskBtrfs(info *models.DiskInfo, mode output.OutputMode) {
	if len(info.BtrfsVolumes) == 0 {
		return
	}
	fmt.Printf("\nBtrfs volumes (%d)\n", len(info.BtrfsVolumes))
	for _, v := range info.BtrfsVolumes {
		icon := asciiOr("ok", "✅", mode)
		statusStr := ""
		if v.Status == "degraded" || v.MissingDevs > 0 {
			icon = asciiOr("fail", "❌", mode)
			statusStr = fmt.Sprintf("  DEGRADED — %d missing device(s)", v.MissingDevs)
		} else if v.Status == "errors" {
			icon = asciiOr("warn", "⚠️ ", mode)
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
				devIcon = "  " + asciiOr("fail", "❌", mode)
				label = "<missing disk>"
			}
			errStr := ""
			if d.ReadErrs+d.WriteErrs+d.CorruptErrs+d.GenErrs+d.FlushErrs > 0 {
				errStr = fmt.Sprintf("  read:%d write:%d corrupt:%d gen:%d flush:%d",
					d.ReadErrs, d.WriteErrs, d.CorruptErrs, d.GenErrs, d.FlushErrs)
			}
			fmt.Printf("    %s  devid %d  %s%s\n", devIcon, d.DevID, label, errStr)
		}
	}
}

func printDiskZFS(info *models.DiskInfo, mode output.OutputMode) {
	if len(info.ZFSPools) == 0 {
		// A live ZFS mount exists but `zpool list` errored (commonly non-root: /dev/zfs
		// needs privilege) → no pools parsed. Surface "could not verify" so the summary
		// can't read green, mirroring dsd health's INFO. Silent otherwise (no ZFS).
		if info.ZFSListReadFailed {
			fmt.Printf("\nZFS Pools\n  %s  pools could not be listed — run as root (zpool needs /dev/zfs)\n",
				asciiOr("info", "ℹ️", mode))
		}
		return
	}
	fmt.Printf("\nZFS Pools (%d)\n", len(info.ZFSPools))
	for _, p := range info.ZFSPools {
		icon := asciiOr("ok", "✅", mode)
		switch p.State {
		case "DEGRADED", "FAULTED", "OFFLINE":
			icon = asciiOr("fail", "❌", mode)
		case "ONLINE":
			if p.UsedPct >= analysis.DefaultDiskCritPct {
				icon = asciiOr("fail", "❌", mode)
			} else if p.UsedPct >= analysis.DefaultDiskWarnPct {
				icon = asciiOr("warn", "⚠️ ", mode)
			}
		}
		errStr := ""
		if p.ReadErrors+p.WriteErrors+p.CksumErrors > 0 {
			errStr = fmt.Sprintf("  %s R:%d W:%d C:%d", asciiOr("warn", "⚠️ ", mode), p.ReadErrors, p.WriteErrors, p.CksumErrors)
		}
		scrubStr := ""
		if p.ScrubAgeDays > 30 {
			// health treats an overdue scrub as INFO, not WARN — show it as a plain
			// note so the row severity matches the verdict.
			scrubStr = fmt.Sprintf("  last scrub %dd ago", p.ScrubAgeDays)
		} else if p.ScrubAgeDays < 0 {
			scrubStr = "  " + asciiOr("warn", "⚠️ ", mode) + " never scrubbed"
		}
		fmt.Printf("  %s  %-20s %s  %.0f%%  %.1fGB%s%s\n",
			icon, p.Name, p.State, p.UsedPct, p.SizeGB, errStr, scrubStr)
	}
}

func printDiskFilesystems(info *models.DiskInfo, mode output.OutputMode) {
	fmt.Printf("\nFilesystems (%d)\n", len(info.Filesystems))
	for _, fs := range info.Filesystems {
		if fs.TotalGB == 0 {
			continue
		}
		// Inherently read-only image fs (iso9660/squashfs/erofs/cramfs) are 100%-full by
		// design — show the row (transparent) but never a fault icon, matching the
		// verdict (#382). Otherwise the usage/inode thresholds apply.
		imageFS := analysis.IsInherentlyReadOnlyFS(fs.FSType)
		icon := asciiOr("ok", "✅", mode)
		if !imageFS && fs.UsedPct >= analysis.DefaultDiskCritPct {
			icon = asciiOr("fail", "❌", mode)
		} else if !imageFS && fs.UsedPct >= analysis.DefaultDiskWarnPct {
			icon = asciiOr("warn", "⚠️ ", mode)
		}
		roNote := ""
		if fs.ReadOnly {
			roNote = " [ro]"
		}
		fmt.Printf("  %s  %-22s %-6s %.1fG / %.1fG  (%.0f%%)%s\n",
			icon, fs.Mount, fs.FSType, fs.UsedGB, fs.TotalGB, fs.UsedPct, roNote)
		if !imageFS && fs.InodesUsedPct >= analysis.DefaultDiskWarnPct {
			fmt.Printf("       %s  inodes at %.0f%%\n", asciiOr("warn", "⚠️ ", mode), fs.InodesUsedPct)
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
		// Inherently read-only image filesystems (iso9660/squashfs/erofs/cramfs) are
		// packed to 100% at build time — normal, not a fault, and no admin action frees
		// space. Skip them, mirroring checkDisk (#382) so `dsd disk` and `dsd health`
		// agree (a full /cdrom or snap squashfs must not concern either).
		if analysis.IsInherentlyReadOnlyFS(fs.FSType) {
			continue
		}
		if fs.UsedPct >= analysis.DefaultDiskWarnPct || fs.InodesUsedPct >= analysis.DefaultDiskWarnPct {
			n++
		}
	}
	for _, v := range info.BtrfsVolumes {
		if v.Status != "healthy" {
			n++
		}
	}
	for _, p := range info.ZFSPools {
		if p.State != "ONLINE" || p.UsedPct >= analysis.DefaultDiskWarnPct || p.ReadErrors+p.WriteErrors+p.CksumErrors > 0 {
			n++
		}
	}
	for _, d := range info.Drives {
		// A drive whose SMART could not be read (smartctl/nvme-cli absent, permission,
		// EBS/virtual disk) carries Error set and Healthy defaulting to false — that is
		// "couldn't measure", NOT a fault. Counting it raises a false WARN where dsd
		// health correctly reports INFO. Skip it, mirroring printSMARTLine's early
		// return on Error. (Found live on EC2 RHEL/EBS with nvme-cli absent.)
		if d.SMART == nil || d.SMART.Error != "" {
			continue
		}
		// Count wear/media-error drives too, matching the SMART row icon and
		// checkNVMe — a still-"PASSED" drive with media errors or 90%+ wear must
		// not let the summary read "healthy".
		if !d.SMART.Healthy || d.SMART.MediaErrors > 0 || d.SMART.PercentUsed >= 90 {
			n++
		}
	}
	// LVM: degraded RAID. A fully-allocated VG is NOT a concern — it's the normal
	// default-install layout (root+swap take the whole VG); filesystem fill is the
	// real signal, scored elsewhere. Matches dsd health, which emits only INFO for
	// it (§O.1 widened — found live on CentOS Stream 8).
	if lvmInfo != nil {
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
func printDiskSteamOS(info *models.DiskInfo, mode output.OutputMode) {
	d := info.SteamOS
	if d == nil {
		return
	}
	// btrfs root errors appear in the Btrfs section above; /var + /home in the
	// Filesystems section. This section covers only the SteamOS-specific extras.
	fmt.Printf("\n[SteamOS storage]\n")

	if d.ShaderCacheGB > 0 {
		icon := asciiOr("ok", "✅", mode)
		if d.ShaderCacheGB > 30 {
			icon = asciiOr("fail", "❌", mode)
		} else if d.ShaderCacheGB > 10 {
			icon = asciiOr("warn", "⚠️ ", mode)
		}
		fmt.Printf("  %s Shader cache: %.1f GB at ~/.steam/steam/shadercache/\n", icon, d.ShaderCacheGB)
	}

	for _, bm := range d.BindMounts {
		if bm.OK {
			fmt.Printf("  %s Bind mount %s → %s — intact\n", asciiOr("ok", "✅", mode), bm.Path, bm.Target)
		} else {
			fmt.Printf("  %s Bind mount %s → %s — broken\n", asciiOr("warn", "⚠️ ", mode), bm.Path, bm.Target)
		}
	}
}

// printSMARTLine renders a compact SMART summary line indented under the drive.
func printSMARTLine(s *models.SMARTInfo, mode output.OutputMode) {
	if s.Error != "" {
		fmt.Printf("             SMART: %s\n", s.Error)
		return
	}
	// A virtual/cloud volume (e.g. AWS EBS) answers the SMART health query with
	// PASSED but passes through no real telemetry — don't render it as a confident
	// "PASSED". Mirrors `dsd health`, which already flags this (NVMeNoRealData).
	if s.NoRealTelemetry() {
		fmt.Printf("             %s SMART: no real telemetry — virtual/cloud volume (e.g. AWS EBS); on-device health not measurable\n",
			asciiOr("info", "ℹ️ ", mode))
		return
	}
	icon := asciiOr("ok", "✅", mode)
	if !s.Healthy {
		icon = asciiOr("fail", "❌", mode)
	} else if s.PercentUsed >= 90 {
		icon = asciiOr("warn", "⚠️ ", mode)
	} else if s.MediaErrors > 0 {
		icon = asciiOr("warn", "⚠️ ", mode)
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

func printDiskLVM(lvm *models.LVMInfo, mode output.OutputMode) {
	if lvm == nil {
		return
	}
	if len(lvm.VGs) == 0 && len(lvm.ThinPools) == 0 && len(lvm.Snapshots) == 0 && len(lvm.RaidLVs) == 0 {
		// vgs/pvs/lvs errored (commonly non-root: LVM metadata locks) → nothing parsed.
		// Surface "could not verify" so the summary can't read green (mirrors dsd
		// health's INFO). Silent when there's genuinely no LVM (no error).
		if lvm.VGReadFailed || lvm.PVReadFailed || lvm.LVReadFailed || lvm.RaidReadFailed {
			fmt.Printf("\nLVM\n  %s  LVM state could not be read — run as root (vgs/pvs/lvs need metadata access)\n",
				asciiOr("info", "ℹ️", mode))
		}
		return
	}

	fmt.Printf("\nLVM (%d VG(s))\n", len(lvm.VGs))

	// Volume groups
	for _, vg := range lvm.VGs {
		icon := asciiOr("ok", "✅", mode)
		note := ""
		// A fully-allocated VG is the normal default-install layout (root+swap take
		// the whole VG), NOT a near-full disk — so it stays OK here, matching dsd
		// health, which emits only an INFO note for it. Real pressure is the
		// filesystem fill, scored elsewhere. Thin-pool-backed VGs are allocation-by-
		// design too; their data%/meta% rows carry the verdict (§O.1 widened — found
		// live on CentOS Stream 8 where VG `cs` was 100% allocated, root FS at 38%).
		if analysis.VGBacksThinPool(lvm.ThinPools, vg.Name) {
			note = "  (thin-pool backed — allocation by design)"
		} else if analysis.LVMVGFullLevel(vg.FreePct) != "" {
			note = "  (fully allocated — normal; see filesystem usage)"
		}
		fmt.Printf("  %s  %-20s %.1fGB total  %.1fGB free  (%.0f%%)%s\n",
			icon, vg.Name, vg.SizeGB, vg.FreeGB, vg.FreePct, note)
		if vg.MissingPVs > 0 {
			fmt.Printf("       %s %d missing PV(s) — data at risk\n", asciiOr("fail", "❌", mode), vg.MissingPVs)
		}
	}

	// Thin pools
	if len(lvm.ThinPools) > 0 {
		fmt.Printf("\n  Thin pools (%d):\n", len(lvm.ThinPools))
		for _, p := range lvm.ThinPools {
			dIcon := asciiOr("ok", "✅", mode)
			switch analysis.LVMThinPoolLevel(p.DataPct) {
			case "CRIT":
				dIcon = asciiOr("fail", "❌", mode)
			case "WARN":
				dIcon = asciiOr("warn", "⚠️ ", mode)
			}
			fmt.Printf("  %s  %-20s Data: %.0f%%  Meta: %.0f%%\n",
				dIcon, fmt.Sprintf("%s/%s", p.VG, p.Name), p.DataPct, p.MetaPct)
		}
	}

	// Snapshots
	if len(lvm.Snapshots) > 0 {
		fmt.Printf("\n  Snapshots (%d):\n", len(lvm.Snapshots))
		for _, s := range lvm.Snapshots {
			sIcon := asciiOr("ok", "✅", mode)
			switch analysis.LVMSnapshotLevel(s.DataPct) {
			case "CRIT":
				sIcon = asciiOr("fail", "❌", mode)
			case "WARN":
				sIcon = asciiOr("warn", "⚠️ ", mode)
			}
			fmt.Printf("  %s  %-20s → %-20s  Snap%%: %.0f%%\n",
				sIcon, fmt.Sprintf("%s/%s", s.VG, s.Name), s.Origin, s.DataPct)
		}
	}

	// RAID/mirror LVs
	if len(lvm.RaidLVs) > 0 {
		fmt.Printf("\n  RAID/mirror LVs (%d):\n", len(lvm.RaidLVs))
		for _, r := range lvm.RaidLVs {
			rIcon := asciiOr("ok", "✅", mode)
			status := fmt.Sprintf("sync: %.0f%%", r.SyncPct)
			if r.Degraded {
				rIcon = asciiOr("fail", "❌", mode)
				status = "DEGRADED"
			} else if r.Resyncing {
				rIcon = asciiOr("warn", "⚠️ ", mode)
				status = fmt.Sprintf("resyncing %.0f%%", r.SyncPct)
			} else if r.SyncPct >= 100 {
				status = "in sync"
			}
			fmt.Printf("  %s  %-20s  %s  %s\n",
				rIcon, fmt.Sprintf("%s/%s", r.VG, r.Name), r.Type, status)
		}
	}
}
