//go:build !linux

package collectors

// adjtimexSync is not available on non-Linux platforms.
func adjtimexSync() (synced bool, offsetMs float64, source string) {
	return false, -1, "unavailable"
}
