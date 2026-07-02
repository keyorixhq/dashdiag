//go:build !linux

package collectors

import "github.com/keyorixhq/dashdiag/internal/platform"

// cgroupMemoryUsageBytes: cgroups are a Linux concept — always unmeasured elsewhere.
func cgroupMemoryUsageBytes(_ platform.ContainerContext) (int64, bool) { return 0, false }
