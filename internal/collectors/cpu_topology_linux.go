//go:build linux

package collectors

import (
	"os"
	"strconv"
	"strings"
)

// parseCPURangeCount counts CPUs in a sysfs range list like "0-13" or "0-1,4-5".
// Returns 0 for an empty/invalid string.
func parseCPURangeCount(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	total := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && b >= a {
				total += b - a + 1
			}
		} else if _, err := strconv.Atoi(part); err == nil {
			total++
		}
	}
	return total
}

// cmdlineHasCPUIsolation reports whether the kernel cmdline intentionally isolates
// CPUs (isolcpus= / nohz_full=), which makes offline/isolated CPUs expected.
func cmdlineHasCPUIsolation(cmdline string) bool {
	return strings.Contains(cmdline, "isolcpus=") || strings.Contains(cmdline, "nohz_full=")
}

// readCPUAvailability reads how many CPUs are allocated (present) vs actually in
// use (online), plus the two reasons offline CPUs can be intentional: SMT being
// force-disabled (hyperthread siblings parked for a security mitigation) and
// isolcpus/nohz_full (cores deliberately isolated). The heuristic uses these to
// flag a hot-added vCPU the guest never onlined — present > online with no reason —
// without false-warning on the intentional cases. All world-readable, no root.
func readCPUAvailability() (present, online int, smt string, isolated bool) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	present = parseCPURangeCount(read("/sys/devices/system/cpu/present"))
	online = parseCPURangeCount(read("/sys/devices/system/cpu/online"))
	smt = read("/sys/devices/system/cpu/smt/control") // "" when absent (no SMT support)
	isolated = cmdlineHasCPUIsolation(read("/proc/cmdline"))
	return present, online, smt, isolated
}
