//go:build !linux

package collectors

// readCPUAvailability is Linux-only (relies on /sys/devices/system/cpu). On other
// platforms it reports nothing, so the offline-vCPU heuristic stays silent.
func readCPUAvailability() (present, online int, smt string, isolated bool) {
	return 0, 0, "", false
}
