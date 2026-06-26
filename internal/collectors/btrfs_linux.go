//go:build linux

package collectors

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// collectBtrfsVolumes checks all mounted btrfs filesystems for missing devices
// and I/O errors using `btrfs filesystem show` and `btrfs device stats`.
func collectBtrfsVolumes(filesystems []models.FilesystemInfo) []models.BtrfsVolume {
	// Deduplicate: btrfs subvolumes all share the same UUID, only check once per mount
	seen := map[string]bool{}
	var mounts []string
	for _, fs := range filesystems {
		if fs.FSType != "btrfs" {
			continue
		}
		if !seen[fs.Mount] {
			seen[fs.Mount] = true
			mounts = append(mounts, fs.Mount)
		}
	}
	if len(mounts) == 0 {
		return nil
	}

	// Deduplicate further by UUID (multiple subvolumes share a filesystem)
	byUUID := map[string]*models.BtrfsVolume{}
	var order []string

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, mount := range mounts {
		vol := parseBtrfsShow(ctx, mount)
		if vol == nil {
			continue
		}
		if _, exists := byUUID[vol.UUID]; !exists {
			byUUID[vol.UUID] = vol
			order = append(order, vol.UUID)
			// Collect device error stats
			parseBtrfsDevStats(ctx, mount, vol)
		}
	}

	var result []models.BtrfsVolume
	for _, uuid := range order {
		result = append(result, *byUUID[uuid])
	}
	return result
}

// btrfsShowDevRe matches device lines in `btrfs filesystem show` output.
// Examples:
//
//	devid    1 size 2.00GiB used 2.00GiB path /dev/loop0
//	devid    2 size 0 used 0 path <missing disk> MISSING
var btrfsShowDevRe = regexp.MustCompile(`devid\s+(\d+)\s+size\s+\S+\s+used\s+\S+\s+path\s+(\S+)(\s+MISSING)?`)

// btrfsShowUUIDRe matches the UUID line in `btrfs filesystem show` output.
var btrfsShowUUIDRe = regexp.MustCompile(`uuid:\s+([a-f0-9-]+)`)

// parseBtrfsShow runs `btrfs filesystem show <mount>` and returns a BtrfsVolume.
func parseBtrfsShow(ctx context.Context, mount string) *models.BtrfsVolume {
	out, err := runCmd(ctx, "btrfs", "filesystem", "show", mount)
	if err != nil || out == "" {
		return nil
	}
	return applyBtrfsShow(out, mount, os.Geteuid() != 0)
}

// applyBtrfsShow parses `btrfs filesystem show` output into a BtrfsVolume. Split
// from parseBtrfsShow so the MISSING-device logic is unit-testable. nonRoot says
// whether the producing run lacked privilege — which matters because btrfs, run
// unprivileged, cannot open the block devices and prints EVERY present device as
// `size 0 ... MISSING` with its REAL path. That is "couldn't read the device",
// not "device is gone", and must NOT raise a DEGRADED CRIT. A genuinely absent
// device is shown with the `<missing disk>` placeholder path, which we still flag.
func applyBtrfsShow(out, mount string, nonRoot bool) *models.BtrfsVolume {
	vol := &models.BtrfsVolume{MountPoint: mount, Status: "healthy"}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if m := btrfsShowUUIDRe.FindStringSubmatch(line); m != nil {
			vol.UUID = m[1]
		}
		if m := btrfsShowDevRe.FindStringSubmatch(line); m != nil {
			devID, _ := strconv.Atoi(m[1])
			path := m[2]
			// A genuinely-absent device is the literal `<missing disk>` placeholder
			// (captured as "<missing"); a real /dev path with the MISSING suffix means
			// btrfs couldn't OPEN the device.
			placeholderMissing := strings.Contains(path, "missing")
			unreadable := m[3] != "" && !placeholderMissing

			// Real-path MISSING on a non-root run = the unprivileged "can't open device"
			// artifact, not a missing device. Don't count it; flag the volume so the
			// verdict degrades to an honest "unverified — run as root", not a false CRIT.
			if unreadable && nonRoot {
				vol.DevReadUnverified = true
				vol.Devices = append(vol.Devices, models.BtrfsDev{DevID: devID, Path: path})
				vol.TotalDevices++
				continue
			}

			missing := placeholderMissing || unreadable
			vol.TotalDevices++
			if missing {
				vol.MissingDevs++
			}
			vol.Devices = append(vol.Devices, models.BtrfsDev{
				DevID:   devID,
				Path:    path,
				Missing: missing,
			})
		}
	}

	if vol.UUID == "" {
		return nil
	}
	if vol.MissingDevs > 0 {
		vol.Status = "degraded"
		vol.StatusReason = "missing device(s) — filesystem running in degraded mode"
	} else if vol.DevReadUnverified {
		vol.Status = "unverified"
		vol.StatusReason = "device state could not be read without root"
	}
	return vol
}

// btrfsDevStatRe matches error counter lines in `btrfs device stats` output.
// Example: [/dev/loop0].read_io_errs    5
// All five counters btrfs reports are captured — generation_errs and flush_io_errs
// (transient-write / barrier failures) are real signals, not just read/write/corruption.
var btrfsDevStatRe = regexp.MustCompile(`\[([^\]]+)\]\.(read_io_errs|write_io_errs|corruption_errs|generation_errs|flush_io_errs)\s+(\d+)`)

// parseBtrfsDevStats runs `btrfs device stats <mount>` and populates error counters.
func parseBtrfsDevStats(ctx context.Context, mount string, vol *models.BtrfsVolume) {
	out, err := runCmd(ctx, "btrfs", "device", "stats", mount)
	if err != nil || out == "" {
		return
	}
	applyBtrfsDevStats(out, vol)
}

// applyBtrfsDevStats parses `btrfs device stats` output and populates per-device
// error counters on vol. Split from parseBtrfsDevStats so the parsing is unit
// testable against real command output without spawning btrfs.
func applyBtrfsDevStats(out string, vol *models.BtrfsVolume) {
	// `btrfs device stats` ran and produced output — the per-device error counters
	// below are now real readings, not zero-defaults. (parseBtrfsDevStats leaves this
	// false when the command errored, so the verdict can flag "counters not read".)
	vol.StatsRead = true
	// Build path → device index map
	pathIdx := map[string]int{}
	for i, dev := range vol.Devices {
		pathIdx[dev.Path] = i
	}

	for _, line := range strings.Split(out, "\n") {
		m := btrfsDevStatRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		path := m[1]
		counter := m[2]
		val, _ := strconv.ParseInt(m[3], 10, 64)
		if val == 0 {
			continue
		}
		// A non-zero counter means the volume HAS errors — flag it before trying to
		// attribute the error to a specific device. The device-stats path can fail to
		// match a path from `btrfs filesystem show` (multi-device, /dev/mapper or LUKS
		// names, or a show-parse that left vol.Devices empty); previously that
		// mismatch dropped the error entirely and the volume stayed "healthy" — a
		// false-OK on a storage-corruption signal. Per-device attribution below is
		// best-effort; the volume verdict no longer depends on it.
		if vol.Status == "healthy" {
			vol.Status = "errors"
			vol.StatusReason = "device I/O or corruption errors detected"
		}
		idx, ok := pathIdx[path]
		if !ok {
			continue
		}
		switch counter {
		case "read_io_errs":
			vol.Devices[idx].ReadErrs = val
		case "write_io_errs":
			vol.Devices[idx].WriteErrs = val
		case "corruption_errs":
			vol.Devices[idx].CorruptErrs = val
		case "generation_errs":
			vol.Devices[idx].GenErrs = val
		case "flush_io_errs":
			vol.Devices[idx].FlushErrs = val
		}
	}
}
