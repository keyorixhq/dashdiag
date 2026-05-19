//go:build linux

package collectors

import (
	"context"
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

	vol := &models.BtrfsVolume{MountPoint: mount, Status: "healthy"}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if m := btrfsShowUUIDRe.FindStringSubmatch(line); m != nil {
			vol.UUID = m[1]
		}
		if m := btrfsShowDevRe.FindStringSubmatch(line); m != nil {
			devID, _ := strconv.Atoi(m[1])
			path := m[2]
			missing := m[3] != "" || strings.Contains(path, "missing")
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
	}
	return vol
}

// btrfsDevStatRe matches error counter lines in `btrfs device stats` output.
// Example: [/dev/loop0].read_io_errs    5
var btrfsDevStatRe = regexp.MustCompile(`\[([^\]]+)\]\.(read_io_errs|write_io_errs|corruption_errs)\s+(\d+)`)

// parseBtrfsDevStats runs `btrfs device stats <mount>` and populates error counters.
func parseBtrfsDevStats(ctx context.Context, mount string, vol *models.BtrfsVolume) {
	out, err := runCmd(ctx, "btrfs", "device", "stats", mount)
	if err != nil || out == "" {
		return
	}

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
		}
		// Upgrade status if errors found
		if vol.Status == "healthy" {
			vol.Status = "errors"
			vol.StatusReason = "device I/O or corruption errors detected"
		}
	}
}
