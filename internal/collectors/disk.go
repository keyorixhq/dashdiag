package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	gopsutildisk "github.com/shirou/gopsutil/v3/disk"

	"github.com/keyorixhq/dashdiag/internal/models"
)

var skipFSTypes = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "overlay": true, "squashfs": true,
	"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true,
	"devpts": true, "pstore": true, "securityfs": true, "debugfs": true,
	"hugetlbfs": true, "mqueue": true, "fusectl": true,
	"devfs": true, "efivarfs": true, "bpf": true, "tracefs": true,
}

type mountEntry struct {
	device, mountPoint, fsType string
	readOnly                   bool
}

type DiskCollector struct {
	mountsPath string
	Deep       bool
}

func NewDiskCollector() *DiskCollector {
	return &DiskCollector{mountsPath: "/proc/mounts"}
}

func NewDiskDeepCollector() *DiskCollector {
	return &DiskCollector{mountsPath: "/proc/mounts", Deep: true}
}

func (c *DiskCollector) Name() string { return "Disk" }
func (c *DiskCollector) Timeout() time.Duration {
	if c.Deep {
		return 12 * time.Second // extra time for smartctl + I/O sample
	}
	return 5 * time.Second
}

func readMounts(r io.Reader) ([]mountEntry, error) {
	var entries []mountEntry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		ro := len(fields) >= 4 && strings.Contains(","+fields[3]+",", ",ro,")
		entries = append(entries, mountEntry{
			device:     fields[0],
			mountPoint: fields[1],
			fsType:     fields[2],
			readOnly:   ro,
		})
	}
	return entries, scanner.Err()
}

func statfsToFS(e mountEntry) (models.FilesystemInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(e.mountPoint, &stat); err != nil {
		return models.FilesystemInfo{}, err
	}
	fs := models.FilesystemInfo{
		Device:   e.device,
		Mount:    e.mountPoint,
		FSType:   e.fsType,
		ReadOnly: e.readOnly,
		TotalGB:  float64(stat.Blocks) * float64(stat.Bsize) / 1e9,
		FreeGB:   float64(stat.Bfree) * float64(stat.Bsize) / 1e9,
	}
	fs.UsedGB = fs.TotalGB - fs.FreeGB
	if stat.Blocks > 0 {
		fs.UsedPct = (1 - float64(stat.Bavail)/float64(stat.Blocks)) * 100
	}
	if stat.Files > 0 {
		fs.InodesUsedPct = (1 - float64(stat.Ffree)/float64(stat.Files)) * 100
	}
	return fs, nil
}

func (c *DiskCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}
	f, err := os.Open(c.mountsPath)
	if err != nil {
		return nil, fmt.Errorf("opening mounts: %w", err)
	}
	defer func() { _ = f.Close() }()

	entries, err := readMounts(f)
	if err != nil {
		return nil, fmt.Errorf("parsing mounts: %w", err)
	}

	seen := make(map[string]bool)
	result := &models.DiskInfo{}
	for _, e := range entries {
		if skipFSTypes[e.fsType] || seen[e.mountPoint] {
			continue
		}
		if strings.HasPrefix(e.mountPoint, "/mnt/lima-") ||
			strings.HasPrefix(e.mountPoint, "/sys/") ||
			strings.HasPrefix(e.mountPoint, "/proc/") {
			continue
		}
		seen[e.mountPoint] = true
		fs, err := statfsToFS(e)
		if err != nil {
			continue
		}
		result.Filesystems = append(result.Filesystems, fs)
	}

	if runtime.GOOS == "linux" {
		c.collectLinuxExtras(result)
	}

	return result, nil
}

var skipMacFSTypes = map[string]bool{
	"devfs": true, "autofs": true, "synthfs": true, "bindfs": true,
}

func skipMacOSMount(fstype, mountpoint string) bool {
	if skipMacFSTypes[fstype] {
		return true
	}
	if mountpoint == "/dev" {
		return true
	}
	// Skip all /System/Volumes/* synthetic volumes except Data (the real user volume).
	if strings.HasPrefix(mountpoint, "/System/Volumes/") && mountpoint != "/System/Volumes/Data" {
		return true
	}
	return false
}

func (c *DiskCollector) collectDarwin(ctx context.Context) (*models.DiskInfo, error) {
	parts, err := gopsutildisk.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("disk partitions: %w", err)
	}
	result := &models.DiskInfo{}
	for _, p := range parts {
		if skipMacOSMount(p.Fstype, p.Mountpoint) {
			continue
		}
		usage, err := gopsutildisk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil {
			continue
		}
		ro := false
		for _, opt := range p.Opts {
			if opt == "ro" {
				ro = true
				break
			}
		}
		// Skip read-only volumes — disk images (DMG), installer mounts, etc.
		// A full read-only volume can never be cleaned up; alerting on it is noise.
		if ro {
			continue
		}
		result.Filesystems = append(result.Filesystems, models.FilesystemInfo{
			Device:        p.Device,
			Mount:         p.Mountpoint,
			FSType:        p.Fstype,
			ReadOnly:      ro,
			TotalGB:       float64(usage.Total) / 1e9,
			UsedGB:        float64(usage.Used) / 1e9,
			FreeGB:        float64(usage.Free) / 1e9,
			UsedPct:       usage.UsedPercent,
			InodesUsedPct: usage.InodesUsedPercent,
		})
	}
	return result, nil
}
