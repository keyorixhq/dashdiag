//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	diskSysBlock      = "/sys/block"
	diskSysClassBlock = "/sys/class/block/"
)

// collectPhysicalDrives builds PhysicalDrive entries from /proc/partitions,
// /sys/block/*/queue/rotational, and /proc/mounts. Replaces the renderer-side
// diskEnumeratePhysical() with a collector-side version that populates the model.
func collectPhysicalDrives() []models.PhysicalDrive {
	mountsByDev := make(map[string][]string)
	fstypeByDev := make(map[string]string)
	if data, err := readFile("/proc/mounts"); err == nil { // #nosec G304
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

	f, err := openFile("/proc/partitions") // #nosec G304
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
				mounts = append(mounts, dev+"->"+m)
			}
			fs := fstypeByDev[dev]
			if linuxFS[fs] {
				hasLinux = true
			}
			if windowsFS[fs] && !linuxFS[fs] {
				_ = hasLinux // will stay false
			}
		}
		// mounts is built by ranging a map, so sort for deterministic output
		// (stable JSON across runs/replays — TRIAGE Section I).
		sort.Strings(mounts)
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
	if err := scanner.Err(); err != nil {
		return nil
	}
	// Deterministic order so the drives list (and the I/O check derived from it) is
	// byte-stable across runs/replays — TRIAGE §I (the /proc/partitions scan order
	// has proven non-deterministic on some hosts).
	sort.Slice(drives, func(i, j int) bool { return drives[i].Name < drives[j].Name })
	return drives
}

// diskDetectType returns NVMe, SSD, or HDD based on device name / sysfs rotational.
func diskDetectType(name string) models.DriveType {
	if strings.HasPrefix(name, "nvme") {
		return models.DriveTypeNVMe
	}
	data, err := readFile(filepath.Join(diskSysBlock, name, "queue/rotational")) // #nosec G304
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
	data, err := readFile(filepath.Join(diskSysBlock, name, "size")) // #nosec G304
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
		filepath.Join(diskSysBlock, name, "device/model"),
		filepath.Join(diskSysBlock, name, "device/device/model"),
	}
	for _, p := range paths {
		if data, err := readFile(p); err == nil { // #nosec G304
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// ── SMART collection ──────────────────────────────────────────────────────────

// isVirtualDisk reports whether a drive is a hypervisor-backed virtual disk
// (virtio/QEMU/VMware/Hyper-V/VirtualBox/Xen). These do not expose real SMART
// data — smartctl against them errors or returns meaningless output — so SMART
// collection is skipped for them to avoid a false health warning.
//
// Detection uses two signals confirmed on real systems: the kernel device name
// (virtio-blk is vdX, Xen is xvdX) and the emulated-controller model string
// (e.g. "QEMU HARDDISK", "VMware Virtual S", "Msft Virtual Disk", "VBOX
// HARDDISK"). Bare-metal models (e.g. "Samsung SSD 980", "WDC WD2003FYYS",
// "LITEONIT LCS-128") match none of these and keep SMART collection.
func isVirtualDisk(d models.PhysicalDrive) bool {
	if strings.HasPrefix(d.Name, "vd") || strings.HasPrefix(d.Name, "xvd") {
		return true
	}
	model := strings.ToLower(d.Model)
	for _, tok := range []string{"qemu", "virtio", "vmware", "vbox", "virtual"} {
		if strings.Contains(model, tok) {
			return true
		}
	}
	return false
}

// collectSMART runs smartctl -H and -A for a device and parses the result.
// Requires smartctl to be installed and root/sudo access. ctx is the caller's
// collector context, propagated into runCmdTimeout rather than re-created.
func collectSMART(ctx context.Context, devName string) *models.SMARTInfo {
	devPath := "/dev/" + devName
	s := &models.SMARTInfo{Device: devPath}

	// Check if smartctl is available
	if _, err := lookPath("smartctl"); err != nil {
		s.Error = "smartctl not installed"
		return s
	}

	// Overall health: smartctl -H /dev/nvmeX. smartctl reports SMART findings via a
	// bitmask exit code — bit 3 ("DISK FAILING") is a NON-ZERO exit that still
	// prints a valid verdict on stdout. Treating any non-zero exit as a read error
	// and returning early silently skipped the one drive we most need to flag (a
	// failing drive was dropped, never producing the CRIT). So parse stdout
	// regardless of exit code; only error out when no verdict is present (e.g. the
	// device genuinely couldn't be opened).
	healthOut, err := runCmdTimeout(ctx, 3*time.Second, "smartctl", "-H", devPath)
	if healthy, ok := parseSMARTHealth(healthOut); ok {
		s.Healthy = healthy
	} else {
		if err != nil {
			s.Error = "smartctl: " + trimSMARTError(err.Error())
		} else {
			s.Error = "smartctl: no health status reported"
		}
		return s
	}

	// Attributes for NVMe: smartctl -A gives wear, temp, errors
	attrOut, _ := runCmdTimeout(ctx, 3*time.Second, "smartctl", "-A", devPath)
	parseSMARTAttributes(attrOut, s)

	return s
}

// parseSMARTHealth extracts the overall health verdict from `smartctl -H` output.
// Handles the SATA/NVMe form ("SMART overall-health self-assessment test result:
// PASSED") and the SAS form ("SMART Health Status: OK"). ok is false when no
// verdict line is present, so the caller can distinguish "no verdict" from
// "verdict says unhealthy" — critical because a FAILING drive exits non-zero but
// still prints its verdict here.
func parseSMARTHealth(out string) (healthy, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SMART overall-health") || strings.Contains(line, "SMART Health Status") {
			return strings.Contains(line, "PASSED") || strings.Contains(line, "OK"), true
		}
	}
	return false, false
}

// parseSMARTAttributes extracts wear %, temp, and media errors from smartctl -A output.
func parseSMARTAttributes(out string, s *models.SMARTInfo) {
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)

		// SATA/SAS attributes are tabular with no colon, e.g.
		//   "  5 Reallocated_Sector_Ct  0x0033  100 100 010  Pre-fail  Always  -  42"
		// the raw value being the last column. These MUST be handled before the
		// colon-based NVMe parsing below: the "no colon -> continue" guard used to
		// skip every SATA line, so reallocated/pending/uncorrectable sectors — the
		// classic pre-failure indicators that rise BEFORE overall SMART fails —
		// were silently never counted on SATA drives.
		if isSATAFailureAttr(lower) {
			if fields := strings.Fields(line); len(fields) >= 10 {
				if raw, err := strconv.ParseInt(fields[len(fields)-1], 10, 64); err == nil && raw > 0 {
					s.MediaErrors += raw
				}
			}
			continue
		}

		// NVMe key:value attributes — "Percentage Used:  0%".
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
		val = strings.ReplaceAll(val, ",", "") // strip thousand-separators e.g. "7,183"
		// Counts/percentages are assigned only for a clean, non-negative parse.
		// A garbled or hostile SMART log printing a negative media-error count
		// would otherwise land below the "> 0" failure thresholds in
		// analysis/heuristics.go — a false-OK (a dying drive read as healthy).
		// Mirrors the SATA path's `raw > 0` guard above.
		switch {
		case strings.Contains(lower, "percentage used"):
			if v, ok := nonNegSMARTInt(val); ok {
				s.PercentUsed = int(v)
			}
		case strings.Contains(lower, "available spare") &&
			!strings.Contains(lower, "threshold"):
			if v, ok := nonNegSMARTInt(val); ok {
				s.AvailableSpare = int(v)
			}
		case strings.Contains(lower, "temperature:") ||
			strings.HasPrefix(strings.TrimSpace(lower), "temperature sensor 1:"):
			// Temperature may legitimately be below 0 °C, so it is not clamped.
			if s.Temperature == 0 { // take first temperature field
				s.Temperature, _ = strconv.Atoi(val)
			}
		case strings.Contains(lower, "media and data integrity errors"):
			if v, ok := nonNegSMARTInt(val); ok {
				s.MediaErrors = v
			}
		case strings.Contains(lower, "power on hours"):
			if v, ok := nonNegSMARTInt(val); ok {
				s.PowerOnHours = v
			}
		case strings.Contains(lower, "unsafe shutdowns"):
			if v, ok := nonNegSMARTInt(val); ok {
				s.UnsafeShutdowns = v
			}
		case strings.Contains(lower, "power cycles"):
			if v, ok := nonNegSMARTInt(val); ok {
				s.PowerCycles = v
			}
		}
	}
}

// nonNegSMARTInt parses a SMART numeric attribute value, returning ok only for a
// clean, non-negative integer. Negative or garbled input (a corrupt or hostile
// SMART log) must not reach a counter where it could slip under the "> 0"
// failure thresholds as a false-OK.
func nonNegSMARTInt(val string) (int64, bool) {
	v, err := strconv.ParseInt(val, 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// isSATAFailureAttr matches the SATA/SAS SMART attribute names that signal
// (impending) media failure: reallocated, current-pending, and offline-
// uncorrectable sectors. These rise before the drive's overall SMART health
// flips to FAILED, so they are the early-warning a fleet wants for proactive
// replacement. All feed SMARTInfo.MediaErrors.
func isSATAFailureAttr(lowerLine string) bool {
	return strings.Contains(lowerLine, "reallocated_sector_ct") ||
		strings.Contains(lowerLine, "current_pending_sector") ||
		strings.Contains(lowerLine, "offline_uncorrectable")
}

// trimSMARTError strips noisy smartctl error prefix for display.
func trimSMARTError(s string) string {
	if idx := strings.Index(s, ":"); idx >= 0 {
		return strings.TrimSpace(s[idx+1:])
	}
	return s
}

// runCmdTimeout runs a command with a hard timeout and returns stdout. The
// timeout is enforced via context + WaitDelay so a wedged tool (smartctl on a
// dying disk, zpool on a hung pool, virsh against a stuck libvirtd) can't block
// the caller indefinitely. parent is the caller's own context (the collector's
// Collect ctx) — deriving from it, rather than context.Background(), means a
// runner-level cancellation of the whole collector immediately cuts short the
// command too, instead of the two deadlines being structurally unreachable
// from each other (CLAUDE.md: "Context must be propagated, never re-created").
// Routed through the active source so capture/replay see it. Stdout is
// returned even on a non-zero exit (smartctl -H prints the failing verdict and
// exits non-zero), with the exit surfaced as the error.
func runCmdTimeout(parent context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	res, err := curSource().Run(ctx, name, args...)
	if err != nil {
		return string(res.Stdout), err
	}
	if res.ExitCode != 0 {
		return string(res.Stdout), &cmdError{name: name, code: res.ExitCode}
	}
	return string(res.Stdout), nil
}

// ── ZFS pool health ───────────────────────────────────────────────────────────

// zfsGate returns true when ZFS is active on this system:
// zpool binary exists AND at least one zfs mount in /proc/mounts.
func zfsGate() bool {
	if _, err := lookPath("zpool"); err != nil {
		return false
	}
	data, err := readFile("/proc/mounts") // #nosec G304
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
// Gate: zfsGate() must be true before calling this. ctx is the caller's
// collector context, propagated into runCmdTimeout rather than re-created.
func collectZFSPools(ctx context.Context) (pools []models.ZFSPool, listReadFailed bool) {
	out, err := runCmdTimeout(ctx, 5*time.Second, "zpool", "list",
		"-H", "-o", "name,size,alloc,free,cap,frag,health")
	if err != nil {
		// The zfsGate() caller already confirmed a live ZFS mount, so a failed list
		// (permission/timeout) is a real "couldn't verify", not "no pools".
		return nil, true
	}
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
		pool.UsedPct = parseFloat(capStr)
		// Frag %
		fragStr := strings.TrimSuffix(fields[5], "%")
		pool.FragPct, _ = strconv.Atoi(fragStr)
		// FreeGB
		pool.FreeGB = parseZFSSize(fields[3])

		// Per-pool status for errors and scrub age. `zpool status` can hang on a
		// sick pool and hit the timeout; on error we must NOT leave the counts at 0
		// and ScrubAgeDays at -1 (which read as "no errors"/"never scrubbed") — flag
		// it so the verdict says "unverified" instead.
		statusOut, statusErr := runCmdTimeout(ctx, 3*time.Second, "zpool", "status", pool.Name)
		if statusErr != nil {
			pool.StatusReadFailed = true
		} else {
			pool.ScrubAgeDays = parseZFSScrubAge(statusOut)
			pool.ReadErrors, pool.WriteErrors, pool.CksumErrors = parseZFSVdevErrors(statusOut)
		}

		pools = append(pools, pool)
	}
	return pools, false
}

// parseZFSVdevErrors sums read/write/cksum error counts across the vdev lines of
// zpool status. A vdev line is "<name> <STATE> <READ> <WRITE> <CKSUM> [note]" —
// the three counters follow the STATE token (the name may itself be indented, so
// STATE is not at a fixed index), may be ZFS-abbreviated ("1.2K"), and may be
// trailed by a free-form note ("too many errors", "(resilvering)"). Anchoring on
// STATE avoids a last-3-fields read, which would silently drop any line carrying
// a note or an abbreviated count — exactly the errored vdevs that matter.
// Only used by this DiskCollector display path; the ZFSCollector verdict path
// (zfs.go) calls parseZFSVdevErrorLine per-line directly.
func parseZFSVdevErrors(out string) (read, write, cksum int) {
	for _, line := range strings.Split(out, "\n") {
		if r, w, c, ok := parseZFSVdevErrorLine(strings.TrimSpace(line)); ok {
			read += r
			write += w
			cksum += c
		}
	}
	return
}

// parseZFSScrubAge returns days since last scrub, or -1 if never.
func parseZFSScrubAge(out string) int {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "scrub repaired") || strings.Contains(line, "scrub completed") {
			fields := strings.Fields(line)
			for i, f := range fields {
				// "...on Sun Jun  1 03:28:31 2025" — the date after "on" is five
				// tokens (day, month, date, time, year); the old i+1:i+5 slice
				// dropped the year, so the parse always failed and scrub age
				// silently read as "never scrubbed".
				if f == "on" && i+5 < len(fields) {
					dateStr := strings.Join(fields[i+1:i+6], " ")
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

// DiskIOSampleGap is the real gap between the two /proc/diskstats samples
// collectDiskIO takes. 1s in production; tests may shrink it to keep the
// two-sample requirement (see CLAUDE.md's "IO collectors require TWO
// samples") without paying a real 1s sleep per test.
var DiskIOSampleGap = time.Second

// collectDiskIO samples /proc/diskstats twice DiskIOSampleGap apart and
// returns per-device MB/s read and write rates.
//
// measurement-honesty-03: if /proc/diskstats can't be opened on EITHER
// sample, every device previously still got a models.DiskIOStat entry —
// before[name]/after[name] on a missing key are zero-value structs, so the
// delta is always 0. cmd/disk.go's printDiskIO only skips its whole section
// when len(info.IOStats)==0, which doesn't trigger here (the slice is fully
// populated with fabricated zeros), so it printed "read: 0.0 MB/s write: 0.0
// MB/s" under the header "I/O rates (1s sample)" for every device — falsely
// claiming a real 1-second sample was taken when the underlying read never
// succeeded even once. Returns nil (not one zero-entry per drive) when
// either sample failed, so the existing len==0 skip in printDiskIO takes
// over instead of a fabricated all-zero table.
func collectDiskIO(drives []models.PhysicalDrive) []models.DiskIOStat {
	type diskStat struct {
		readSectors  int64
		writeSectors int64
	}

	readStats := func() (map[string]diskStat, bool) {
		m := make(map[string]diskStat)
		f, err := openFile("/proc/diskstats") // #nosec G304
		if err != nil {
			return m, false
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
		if err := scanner.Err(); err != nil {
			return m, true // partial map is still useful; caller tolerates missing devices
		}
		return m, true
	}

	before, beforeOK := readStats()
	time.Sleep(DiskIOSampleGap)
	after, afterOK := readStats()
	if !beforeOK || !afterOK {
		// A real read failure on either sample, not a genuinely idle host —
		// don't fabricate a "measured, 0.0 MB/s" entry for every drive.
		return nil
	}

	stats := make([]models.DiskIOStat, 0, len(drives))
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
// enrichDeviceSizes fills FilesystemInfo.DeviceSizeGB for each filesystem from
// the backing block device's /sys/class/block/<kname>/size, so the analysis layer
// can spot a device grown larger than the filesystem on it (resize forgotten).
func enrichDeviceSizes(filesystems []models.FilesystemInfo) {
	for i := range filesystems {
		if b, ok := deviceSizeBytes(filesystems[i].Device); ok {
			filesystems[i].DeviceSizeGB = float64(b) / 1e9
		}
	}
}

// deviceSizeBytes returns the size in bytes of the block device at devPath (a
// /dev/... path), read from sysfs (512-byte sectors). false when the path isn't a
// resolvable block device. Source-routed for replay fidelity.
func deviceSizeBytes(devPath string) (int64, bool) {
	kname := deviceKernelName(devPath)
	if kname == "" {
		return 0, false
	}
	data, err := readFile(diskSysClassBlock + kname + "/size") // #nosec G304 -- sysfs, kname is a basename
	if err != nil {
		return 0, false
	}
	sectors, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || sectors <= 0 {
		return 0, false
	}
	return sectors * 512, true // sysfs size is always 512-byte sectors
}

// deviceKernelName maps a /dev path to its sysfs kernel name (sda2, nvme0n1p2,
// dm-0). Direct nodes resolve by basename; symlinks (e.g. /dev/mapper/vg-lv → dm-0,
// /dev/disk/by-uuid/... ) are resolved one hop via readlink. "" when it can't be
// mapped to a /sys/class/block entry (don't guess).
func deviceKernelName(devPath string) string {
	if !strings.HasPrefix(devPath, "/dev/") {
		return ""
	}
	base := devPath[strings.LastIndex(devPath, "/")+1:]
	if base != "" && fileExists(diskSysClassBlock+base) {
		return base
	}
	if target, err := readLink(devPath); err == nil && target != "" {
		rb := target[strings.LastIndex(target, "/")+1:]
		if rb != "" && fileExists(diskSysClassBlock+rb) {
			return rb
		}
	}
	return ""
}

func (c *DiskCollector) collectLinuxExtras(ctx context.Context, result *models.DiskInfo) {
	result.Drives = collectPhysicalDrives()
	enrichDeviceSizes(result.Filesystems)

	// SMART — run for each physical drive (non-blocking, max 3s per drive)
	for i := range result.Drives {
		d := &result.Drives[i]
		if len(d.Mounts) == 1 && strings.Contains(d.Mounts[0], "Windows") {
			continue
		}
		// Virtual disks (virtio/QEMU/VMware/etc.) expose no real SMART data —
		// smartctl errors or returns meaningless output, producing a false
		// warning. Inside a container (LXC/Docker) SMART is equally irrelevant:
		// smartctl is typically absent and the host owns the physical disks.
		// Leave d.SMART nil so no SMART line, issue count, or insight is
		// surfaced for them.
		if isVirtualDisk(*d) || c.ContainerCtx.InContainer {
			continue
		}
		d.SMART = collectSMART(ctx, d.Name)
	}

	// ZFS — zero overhead gate
	if zfsGate() {
		result.ZFSPools, result.ZFSListReadFailed = collectZFSPools(ctx)
	}

	// btrfs — check mounted btrfs filesystems for missing devices and errors
	result.BtrfsVolumes = collectBtrfsVolumes(result.Filesystems)

	// Busy-filesystem check — only for mounts at WARN/CRIT usage or unexpectedly
	// read-only (needsBusyCheck gate); zero cost for healthy mounts.
	collectBusyFilesystems(ctx, result.Filesystems)

	// I/O stats — deep mode only (requires 1s sleep)
	if c.Deep {
		result.IOStats = collectDiskIO(result.Drives)
	}

	// SteamOS partition layout (Spec 19) — zero cost off-SteamOS.
	if SteamOSAvailable() {
		result.SteamOS = collectSteamOSDisk()
	}
}
