//go:build !linux

package collectors

// readMemHotplug is a no-op off Linux — the memory-hotplug interface lives in
// Linux sysfs (/sys/devices/system/memory).
func readMemHotplug() (checked bool, offlineBlocks int, offlineMB int64, autoOnline bool) {
	return false, 0, 0, false
}
