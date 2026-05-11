package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
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
}

var diskCmd = &cobra.Command{
	Use:   "disk",
	Short: "Disk health — physical drives, mount status, filesystem usage",
	RunE:  runDisk,
}

func runDisk(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")

	p := output.NewCommandProgress("Disk health", 5*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewDiskCollector()}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.DiskInfo)
	if !ok || info == nil {
		return result.Err
	}

	printDiskReport(info, mode, elapsed)
	return nil
}

func printDiskReport(info *models.DiskInfo, mode output.OutputMode, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	// Physical drives
	drives := diskEnumeratePhysical()
	fmt.Printf("\nPhysical Drives — %d found\n", len(drives))
	for _, d := range drives {
		driveType := diskDriveType(d.name)
		mountStr := "not mounted"
		if len(d.mounts) > 0 {
			mountStr = strings.Join(d.mounts, "  ")
		} else if d.hasWindows {
			mountStr = "not mounted (Windows/other OS)"
		}
		fmt.Printf("  %-12s %-6s %-6s %s\n",
			filepath.Base(d.name), diskSizeStr(d.name), driveType, mountStr)
	}

	// Filesystem usage
	fmt.Printf("\nFilesystems (%d)\n", len(info.Filesystems))
	issues := 0
	for _, fs := range info.Filesystems {
		// Skip virtual/pseudo filesystems
		if fs.TotalGB == 0 {
			continue
		}
		icon := "✅"
		if fs.UsedPct >= 95 {
			icon = "❌"
			issues++
		} else if fs.UsedPct >= 85 {
			icon = "⚠️ "
			issues++
		}
		roNote := ""
		if fs.ReadOnly {
			roNote = " [ro]"
		}
		fmt.Printf("  %s  %-20s %-6s %.1fG / %.1fG  (%.0f%%)%s\n",
			icon, fs.Mount, fs.FSType, fs.UsedGB, fs.TotalGB, fs.UsedPct, roNote)
		if fs.InodesUsedPct >= 85 {
			fmt.Printf("       ⚠️   inodes at %.0f%%\n", fs.InodesUsedPct)
			issues++
		}
	}

	fmt.Println()
	fmt.Println(sep)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Disk healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  %d disk concern(s) found%s", issues, timing)))
	}
}

type physicalDrive struct {
	name       string
	mounts     []string
	hasWindows bool
}

// diskEnumeratePhysical lists physical drives from /proc/partitions
// and cross-references /proc/mounts for mount status.
func diskEnumeratePhysical() []physicalDrive {
	// Read all mounts once: dev → []mountpoints
	mountsByDev := make(map[string][]string)
	fstypeByDev := make(map[string]string)
	if data, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			dev := filepath.Base(fields[0])
			mount := fields[1]
			fstype := fields[2]
			if mount != "none" && !strings.HasPrefix(mount, "/run/netns") {
				mountsByDev[dev] = append(mountsByDev[dev], mount)
				fstypeByDev[dev] = fstype
			}
		}
	}

	windowsFS := map[string]bool{"ntfs": true}
	linuxFS := map[string]bool{
		"xfs": true, "ext4": true, "ext3": true, "ext2": true,
		"btrfs": true, "f2fs": true, "swap": true,
	}

	f, err := os.Open("/proc/partitions")
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	seen := make(map[string]bool)
	var drives []physicalDrive

	scanner := bufio.NewScanner(f)
	scanner.Scan() // header
	scanner.Scan() // blank
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		name := fields[3]

		// NVMe namespace: nvme0n1 (has 'n', no 'p')
		// SCSI disk: sda, sdb (3 chars, starts with sd)
		// Virtio disk: vda, vdb
		isNVMe := strings.HasPrefix(name, "nvme") && strings.Contains(name, "n") && !strings.Contains(name, "p")
		isSCSI := len(name) == 3 && strings.HasPrefix(name, "sd")
		isVirt := len(name) == 3 && strings.HasPrefix(name, "vd")
		if !isNVMe && !isSCSI && !isVirt {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true

		// Find mounted partitions of this drive
		var mounts []string
		hasWindows := false
		hasLinux := false

		for dev, devMounts := range mountsByDev {
			if !strings.HasPrefix(dev, name) {
				continue
			}
			for _, m := range devMounts {
				mounts = append(mounts, fmt.Sprintf("%s→%s", dev, m))
			}
			fs := fstypeByDev[dev]
			if windowsFS[fs] {
				hasWindows = true
			}
			if linuxFS[fs] {
				hasLinux = true
			}
		}

		// Heuristic: unmounted NVMe on dual-boot → likely Windows
		if len(mounts) == 0 && !hasLinux && isNVMe {
			hasWindows = true
		}

		drives = append(drives, physicalDrive{
			name:       "/dev/" + name,
			mounts:     mounts,
			hasWindows: hasWindows && !hasLinux,
		})
	}
	return drives
}

// diskDriveType returns "NVMe", "SSD", or "HDD".
func diskDriveType(devPath string) string {
	dev := filepath.Base(devPath)
	if strings.HasPrefix(dev, "nvme") {
		return "NVMe"
	}
	data, err := os.ReadFile(filepath.Join("/sys/block", dev, "queue/rotational")) // #nosec G304
	if err != nil {
		return "disk"
	}
	if strings.TrimSpace(string(data)) == "1" {
		return "HDD"
	}
	return "SSD"
}

// diskSizeStr returns a human-readable size for a block device from sysfs.
func diskSizeStr(devPath string) string {
	dev := filepath.Base(devPath)
	data, err := os.ReadFile(filepath.Join("/sys/block", dev, "size")) // #nosec G304
	if err != nil {
		return "?"
	}
	var sectors int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &sectors); err != nil || sectors == 0 {
		return "?"
	}
	gb := float64(sectors) * 512 / 1e9
	if gb >= 1000 {
		return fmt.Sprintf("%.0fTB", gb/1000)
	}
	return fmt.Sprintf("%.0fGB", gb)
}
