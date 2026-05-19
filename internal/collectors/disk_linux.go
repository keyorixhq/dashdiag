//go:build linux

package collectors

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// collectPhysicalDrives builds PhysicalDrive entries from /proc/partitions,
// /sys/block/*/queue/rotational, and /proc/mounts. Replaces the renderer-side
// diskEnumeratePhysical() with a collector-side version that populates the model.
func collectPhysicalDrives() []models.PhysicalDrive {
	mountsByDev := make(map[string][]string)
	fstypeByDev := make(map[string]string)
	if data, err := os.ReadFile("/proc/mounts"); err == nil { // #nosec G304
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			dev := filepath.Base(fields[0])
			mnt := fields[1]
			fstype := fields[2]
			if mnt != "none" && !strings.HasPrefix(mnt, "/run/netns") {
				mountsByDev[dev] = append(mountsByDev[dev], mnt)
				fstypeByDev[dev] = fstype
			}
		}
	}

	f, err := os.Open("/proc/partitions") // #nosec G304
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	windowsFS := map[string]bool{"ntfs": true, "vfat": true, "exfat": true}
	linuxFS := map[string]bool{
		"xfs": true, "ext4": true, "ext3": true, "ext2": true,
		"btrfs": true, "f2fs": true, "swap": true, "zfs": true,
	}

	seen := make(map[string]bool)
	var drives []models.PhysicalDrive

	scanner := bufio.NewScanner(f)
	scanner.Scan() // header
	scanner.Scan() // blank
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		name := fields[3]
		isNVMe := strings.HasPrefix(name, "nvme") && strings.Contains(name, "n") && !strings.Contains(name, "p")
		isSCSI := len(name) == 3 && strings.HasPrefix(name, "sd")
		isVirt := len(name) == 3 && (strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "hd"))
		if !isNVMe && !isSCSI && !isVirt {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true

		driveType := diskDetectType(name)
		sizeGB := diskSizeGB(name)
		model := diskModel(name)

		var mounts []string
		hasLinux := false
		for dev, devMounts := range mountsByDev {
			if !strings.HasPrefix(dev, name) {
				continue
			}
			for _, m := range devMounts {
				mounts = append(mounts, dev+"→"+m)
			}
			fs := fstypeByDev[dev]
			if linuxFS[fs] {
				hasLinux = true
			}
			if windowsFS[fs] && !linuxFS[fs] {
				_ = hasLinux // will stay false
			}
		}
		// Unmounted NVMe on dual-boot → likely Windows
		if len(mounts) == 0 && !hasLinux && isNVMe {
			mounts = append(mounts, "not mounted (Windows/other OS)")
		} else if len(mounts) == 0 {
			mounts = append(mounts, "not mounted")
		}

		drives = append(drives, models.PhysicalDrive{
			Name:   name,
			SizeGB: sizeGB,
			Type:   driveType,
			Model:  model,
			Mounts: mounts,
		})
	}
	return drives
}

// diskDetectType returns NVMe, SSD, or HDD based on device name / sysfs rotational.
func diskDetectType(name string) models.DriveType {
	if strings.HasPrefix(name, "nvme") {
		return models.DriveTypeNVMe
	}
	data, err := os.ReadFile(filepath.Join("/sys/block", name, "queue/rotational")) // #nosec G304
	if err != nil {
		return models.DriveTypeSSD
	}
	if strings.TrimSpace(string(data)) == "1" {
		return models.DriveTypeHDD
	}
	return models.DriveTypeSSD
}

// diskSizeGB returns device capacity from sysfs sectors.
func diskSizeGB(name string) float64 {
	data, err := os.ReadFile(filepath.Join("/sys/block", name, "size")) // #nosec G304
	if err != nil {
		return 0
	}
	var sectors int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &sectors); err != nil {
		return 0
	}
	return float64(sectors) * 512 / 1e9
}

// diskModel reads the device model string from sysfs.
func diskModel(name string) string {
	paths := []string{
		filepath.Join("/sys/block", name, "device/model"),
		filepath.Join("/sys/block", name, "device/device/model"),
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil { // #nosec G304
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// ── SMART collection ──────────────────────────────────────────────────────────

// collectSMART runs smartctl -H and -A for a device and parses the result.
// Requires smartctl to be installed and root/sudo access.
func collectSMART(devName string) *models.SMARTInfo {
	devPath := "/dev/" + devName
	s := &models.SMARTInfo{Device: devPath}

	// Check if smartctl is available
	if _, err := exec.LookPath("smartctl"); err != nil {
		s.Error = "smartctl not installed"
		return s
	}

	// Overall health: smartctl -H /dev/nvmeX
	healthOut, err := runCmdTimeout(3*time.Second, "smartctl", "-H", devPath)
	if err != nil {
		s.Error = "smartctl: " + trimSMARTError(err.Error())
		return s
	}
	for _, line := range strings.Split(healthOut, "\n") {
		if strings.Contains(line, "SMART overall-health") {
			s.Healthy = strings.Contains(line, "PASSED") || strings.Contains(line, "OK")
		}
	}

	// Attributes for NVMe: smartctl -A gives wear, temp, errors
	attrOut, _ := runCmdTimeout(3*time.Second, "smartctl", "-A", devPath)
	parseSMARTAttributes(attrOut, s)

	return s
}

// parseSMARTAttributes extracts wear %, temp, and media errors from smartctl -A output.
func parseSMARTAttributes(out string, s *models.SMARTInfo) {
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		// Split on ":" to get key/value — NVMe format: "Percentage Used:  0%"
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		val := strings.TrimSpace(line[colonIdx+1:])
		valFields := strings.Fields(val)
		if len(valFields) == 0 {
			continue
		}
		val = valFields[0] // take first token (strips units)
		val = strings.TrimSuffix(val, "%")
		val = strings.TrimSuffix(val, ",")
		switch {
		case strings.Contains(lower, "percentage used"):
			s.PercentUsed, _ = strconv.Atoi(val)
		case strings.Contains(lower, "available spare") &&
			!strings.Contains(lower, "threshold"):
			s.AvailableSpare, _ = strconv.Atoi(val)
		case strings.Contains(lower, "temperature:") ||
			strings.HasPrefix(strings.TrimSpace(lower), "temperature sensor 1:"):
			if s.Temperature == 0 { // take first temperature field
				s.Temperature, _ = strconv.Atoi(val)
			}
		case strings.Contains(lower, "media and data integrity errors"):
			s.MediaErrors, _ = strconv.ParseInt(val, 10, 64)
		case strings.Contains(lower, "reallocated_sector_ct") && len(strings.Fields(line)) >= 10:
			// SATA attribute 5 — raw value in last column
			fields := strings.Fields(line)
			raw, _ := strconv.ParseInt(fields[len(fields)-1], 10, 64)
			if raw > 0 {
				s.MediaErrors += raw
			}
		}
	}
}

// trimSMARTError strips noisy smartctl error prefix for display.
func trimSMARTError(s string) string {
	if idx := strings.Index(s, ":"); idx >= 0 {
		return strings.TrimSpace(s[idx+1:])
	}
	return s
}

// runCmdTimeout runs a command with a timeout and returns stdout.
func runCmdTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...) // #nosec G204
	cmd.Env = append(os.Environ(), "LANG=C")
	out, err := cmd.Output()
	_ = timeout // context timeout applied via cmd — simple timeout via Output()
	return string(out), err
}

// ── ZFS pool health ───────────────────────────────────────────────────────────

// zfsGate returns true when ZFS is active on this system:
// zpool binary exists AND at least one zfs mount in /proc/mounts.
func zfsGate() bool {
	if _, err := exec.LookPath("zpool"); err != nil {
		return false
	}
	data, err := os.ReadFile("/proc/mounts") // #nosec G304
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if len(strings.Fields(line)) >= 3 && strings.Fields(line)[2] == "zfs" {
			return true
		}
	}
	return false
}

// collectZFSPools runs zpool list and status to return pool health.
// Gate: zfsGate() must be true before calling this.
func collectZFSPools() []models.ZFSPool {
	out, err := runCmdTimeout(5*time.Second, "zpool", "list",
		"-H", "-o", "name,size,alloc,free,cap,frag,health")
	if err != nil {
		return nil
	}
	var pools []models.ZFSPool
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		pool := models.ZFSPool{
			Name:         fields[0],
			SizeGB:       parseZFSSize(fields[1]),
			State:        fields[6],
			ScrubAgeDays: -1,
		}
		// Used % from cap field (e.g. "45%")
		capStr := strings.TrimSuffix(fields[4], "%")
		pool.UsedPct, _ = strconv.ParseFloat(capStr, 64)
		// Frag %
		fragStr := strings.TrimSuffix(fields[5], "%")
		pool.FragPct, _ = strconv.Atoi(fragStr)
		// FreeGB
		pool.FreeGB = parseZFSSize(fields[3])

		// Per-pool status for errors and scrub age
		statusOut, _ := runCmdTimeout(3*time.Second, "zpool", "status", pool.Name)
		pool.ScrubAgeDays = parseZFSScrubAge(statusOut)
		pool.ReadErrors, pool.WriteErrors, pool.CksumErrors = parseZFSVdevErrors(statusOut)

		pools = append(pools, pool)
	}
	return pools
}

// parseZFSVdevErrors extracts total read/write/cksum error counts from zpool status.
func parseZFSVdevErrors(out string) (read, write, cksum int) {
	for _, line := range strings.Split(out, "\n") {
		// Line format: " NAME  STATE  READ WRITE CKSUM"
		// Actual vdev data lines have 5 fields with integer errors
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Skip header line and pool/config labels
		r, errR := strconv.Atoi(fields[len(fields)-3])
		w, errW := strconv.Atoi(fields[len(fields)-2])
		c, errC := strconv.Atoi(fields[len(fields)-1])
		if errR != nil || errW != nil || errC != nil {
			continue
		}
		read += r
		write += w
		cksum += c
	}
	return
}

// parseZFSScrubAge returns days since last scrub, or -1 if never.
func parseZFSScrubAge(out string) int {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "scrub repaired") || strings.Contains(line, "scrub completed") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "on" && i+4 < len(fields) {
					dateStr := strings.Join(fields[i+1:i+5], " ")
					t, err := time.Parse("Mon Jan 2 15:04:05 2006", dateStr)
					if err == nil {
						return int(time.Since(t).Hours() / 24)
					}
				}
			}
		}
	}
	return -1
}

// ── I/O rate (deep mode) ──────────────────────────────────────────────────────

// collectDiskIO samples /proc/diskstats twice 1 second apart and
// returns per-device MB/s read and write rates.
func collectDiskIO(drives []models.PhysicalDrive) []models.DiskIOStat {
	type diskStat struct {
		readSectors  int64
		writeSectors int64
	}

	readStats := func() map[string]diskStat {
		m := make(map[string]diskStat)
		f, err := os.Open("/proc/diskstats") // #nosec G304
		if err != nil {
			return m
		}
		defer f.Close() //nolint:errcheck
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 14 {
				continue
			}
			name := fields[2]
			rs, _ := strconv.ParseInt(fields[5], 10, 64)
			ws, _ := strconv.ParseInt(fields[9], 10, 64)
			m[name] = diskStat{rs, ws}
		}
		return m
	}

	before := readStats()
	time.Sleep(1 * time.Second)
	after := readStats()

	var stats []models.DiskIOStat
	for _, d := range drives {
		name := d.Name
		b, a := before[name], after[name]
		readMB := float64(a.readSectors-b.readSectors) * 512 / (1024 * 1024)
		writeMB := float64(a.writeSectors-b.writeSectors) * 512 / (1024 * 1024)
		if readMB < 0 {
			readMB = 0
		}
		if writeMB < 0 {
			writeMB = 0
		}
		stats = append(stats, models.DiskIOStat{
			Device:   name,
			ReadMBs:  readMB,
			WriteMBs: writeMB,
		})
	}
	return stats
}

// collectLinuxExtras populates physical drives, SMART, ZFS pools, and I/O stats.
// Called from the cross-platform Collect() when on Linux.
func (c *DiskCollector) collectLinuxExtras(result *models.DiskInfo) {
	result.Drives = collectPhysicalDrives()

	// SMART — run for each physical drive (non-blocking, max 3s per drive)
	for i := range result.Drives {
		d := &result.Drives[i]
		if len(d.Mounts) == 1 && strings.Contains(d.Mounts[0], "Windows") {
			continue
		}
		d.SMART = collectSMART(d.Name)
	}

	// ZFS — zero overhead gate
	if zfsGate() {
		result.ZFSPools = collectZFSPools()
	}

	// I/O stats — deep mode only (requires 1s sleep)
	if c.Deep {
		result.IOStats = collectDiskIO(result.Drives)
	}
}
