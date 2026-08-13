//go:build linux

package collectors

import (
	"path/filepath"
	"strconv"
	"strings"
)

// readEDACCounts reads the kernel EDAC (ECC memory error) counters from sysfs.
// Returns whether EDAC is present, the summed corrected (CE) and uncorrected
// (UE) error counts across all memory controllers, and whether any counter
// read/parse failed (internal-collectors-11-03: a TOCTOU window between the
// existence check and the read, or an unexpected sysfs value, must not
// silently collapse to a clean "0 errors" — that reads as verified-healthy on
// exactly the failing-memory-subsystem hosts where the sysfs interface is
// least reliable). Cheap — a few sysfs reads, no exec — so it is safe to call
// from the fast health path as well as the heavier hardware collector. Shared
// by both so the two paths can't drift.
func readEDACCounts() (available bool, corrected, uncorrected int64, countersUnreadable bool) {
	return readEDACCountsFrom("/sys/devices/system/edac/mc")
}

func readEDACCountsFrom(edacRoot string) (available bool, corrected, uncorrected int64, countersUnreadable bool) {
	entries, err := readDirNames(edacRoot)
	if err != nil {
		return false, 0, 0, false // EDAC sysfs absent — common on VMs / consumer HW
	}
	// available is true ONLY when a real memory controller (mc0, mc1, …) is
	// registered. The edac/mc *class* dir exists even on non-ECC hardware (just
	// power/subsystem/uevent, no mc* controller), so the dir's existence alone is NOT
	// proof of ECC. Setting available=true on the bare dir made dsd report
	// "ECC (UE): OK 0 uncorrected" on a non-ECC box — a false-OK implying ECC
	// protection that isn't there (found live on a bare-metal i7-6700, non-ECC).
	for _, e := range entries {
		if !strings.HasPrefix(e, "mc") {
			continue
		}
		mcDir := filepath.Join(edacRoot, e)
		// A real controller exposes ce_count; require it so a stray "mc"-prefixed
		// node doesn't count as an ECC controller.
		if !fileExists(filepath.Join(mcDir, "ce_count")) {
			continue
		}
		available = true
		ce, ceOK := readEDACCounter(filepath.Join(mcDir, "ce_count"))
		ue, ueOK := readEDACCounter(filepath.Join(mcDir, "ue_count"))
		if !ceOK || !ueOK {
			countersUnreadable = true
			continue // don't fold a failed read's 0 into the sum as if it were real
		}
		corrected += ce
		uncorrected += ue
	}
	return available, corrected, uncorrected, countersUnreadable
}

func readEDACCounter(path string) (int64, bool) {
	b, err := readFile(path) // #nosec G304 -- hardcoded /sys EDAC path
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
