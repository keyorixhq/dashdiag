package collectors

import "strings"

// isNVMeController reports whether a /sys/class/nvme entry name is a primary
// controller (nvme0, nvme1, … nvme10, …) rather than a namespace (nvme0n1) or a
// multipath instance (nvme0c0n1). A controller is "nvme" followed by digits
// only; anything with a non-digit suffix character is a namespace/instance.
//
// The previous inline check (`strings.Contains(base, "n") && len(base) > 5`)
// wrongly skipped controllers numbered ≥10 ("nvme10" is 6 chars and contains
// the 'n' of "nvme"), dropping their SMART data on hosts with 10+ controllers.
func isNVMeController(base string) bool {
	suffix := strings.TrimPrefix(base, "nvme")
	if suffix == base || suffix == "" {
		return false // not an "nvme*" entry at all
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false // namespace (nvme0n1) or instance (nvme0c0) — not a controller
		}
	}
	return true
}
