//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// readEDACCounts reads the kernel EDAC (ECC memory error) counters from sysfs.
// Returns whether EDAC is present, and the summed corrected (CE) and
// uncorrected (UE) error counts across all memory controllers. Cheap — a few
// sysfs reads, no exec — so it is safe to call from the fast health path as well
// as the heavier hardware collector. Shared by both so the two paths can't drift.
func readEDACCounts() (available bool, corrected, uncorrected int64) {
	return readEDACCountsFrom("/sys/devices/system/edac/mc")
}

func readEDACCountsFrom(edacRoot string) (available bool, corrected, uncorrected int64) {
	entries, err := os.ReadDir(edacRoot)
	if err != nil {
		return false, 0, 0 // EDAC not available — common on VMs / consumer HW
	}
	available = true
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "mc") {
			continue
		}
		mcDir := filepath.Join(edacRoot, e.Name())
		corrected += readEDACCounter(filepath.Join(mcDir, "ce_count"))
		uncorrected += readEDACCounter(filepath.Join(mcDir, "ue_count"))
	}
	return available, corrected, uncorrected
}

func readEDACCounter(path string) int64 {
	b, err := os.ReadFile(path) // #nosec G304 -- hardcoded /sys EDAC path
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
