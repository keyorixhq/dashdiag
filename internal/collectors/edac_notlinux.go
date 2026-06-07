//go:build !linux

package collectors

// readEDACCounts is a no-op off Linux — EDAC/ECC counters live in Linux sysfs.
func readEDACCounts() (available bool, corrected, uncorrected int64) {
	return false, 0, 0
}
