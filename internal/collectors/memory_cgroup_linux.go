//go:build linux

package collectors

import (
	"path/filepath"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

// cgroupMemoryUsageBytes reads the container's OWN current memory usage —
// memory.current on cgroup v2, memory.usage_in_bytes on cgroup v1 — via the paths
// ContainerContext already resolved from /proc/self/cgroup, NOT the bare
// /sys/fs/cgroup base: under --cgroupns=host the base is the host root cgroup, so
// reading it there would report the HOST's memory usage as the container's. ok is
// false when the counter file wasn't readable — 0-and-unmeasured must never be
// treated as "0 used" (that would read as a healthy container that's actually
// pinned at its limit).
func cgroupMemoryUsageBytes(cc platform.ContainerContext) (int64, bool) {
	var raw string
	switch {
	case cc.CgroupVersion == 2:
		dir := cc.CgroupV2Dir
		if dir == "" {
			dir = cgroupV2Base
		}
		raw = readFileTrimmedLocal(filepath.Join(dir, "memory.current"))
	case cc.CgroupVersion == 1 && cc.CgroupV1MemDir != "":
		raw = readFileTrimmedLocal(filepath.Join(cc.CgroupV1MemDir, "memory.usage_in_bytes"))
	default:
		return 0, false
	}
	if raw == "" {
		return 0, false
	}
	return parseInt64(raw), true
}
