//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// ContainerGuestCollector reports guest-side health for a workload inside a
// container (the tenant view). The container analog of the VM-guest collectors.
type ContainerGuestCollector struct{}

func NewContainerGuestCollector() *ContainerGuestCollector { return &ContainerGuestCollector{} }

func (c *ContainerGuestCollector) Name() string           { return "ContainerGuest" }
func (c *ContainerGuestCollector) Timeout() time.Duration { return 3 * time.Second }

// ContainerGuestAvailable reports whether dsd is running inside a container.
// Via the source so a container capture registers the collector under replay
// (and a non-container capture does not), reflecting the captured host.
func ContainerGuestAvailable() bool {
	return ContainerContextViaSource().InContainer
}

const cgroupV2Base = "/sys/fs/cgroup"

func (c *ContainerGuestCollector) Collect(_ context.Context) (interface{}, error) {
	cc := ContainerContextViaSource()
	info := &models.ContainerGuestInfo{
		InContainer:   cc.InContainer,
		Runtime:       containerRuntime(cc),
		CgroupV2:      cc.CgroupVersion == 2,
		MemLimitBytes: int64(cc.MemLimitMB * 1024 * 1024),
		CPUQuotaCores: cc.CPULimitCores,
		RunAsRoot:     os.Geteuid() == 0,
	}

	// Dynamic cgroup-v2 signals not carried by ContainerContext. Read from the
	// container's OWN cgroup dir (resolved via /proc/self/cgroup), not the bare
	// /sys/fs/cgroup base: under --cgroupns=host the base is the host root cgroup,
	// so reading memory.events/cpu.stat there reports the host's values (0 oom_kills,
	// 0 throttled) and a throttled/OOM-killed container would falsely read healthy.
	if info.CgroupV2 {
		cgDir := cc.CgroupV2Dir
		if cgDir == "" {
			cgDir = cgroupV2Base
		}
		memCurrent := readFileTrimmedLocal(filepath.Join(cgDir, "memory.current"))
		memEvents := readFileTrimmedLocal(filepath.Join(cgDir, "memory.events"))
		cpuStat := readFileTrimmedLocal(filepath.Join(cgDir, "cpu.stat"))
		info.MemCurrentBytes = parseInt64(memCurrent)
		info.OOMKills = cgroupKeyedValue(memEvents, "oom_kill")
		info.ThrottledPct = cgroupThrottledPct(cpuStat)
		// Measured only if a counter file was actually readable — mirrors the v1
		// guard below. A TOCTOU race, hardened LSM profile, minimal cgroupfs mount,
		// or a --cgroupns=host self-path resolution failure must not silently read
		// as "0 = healthy" (internal-collectors-05-02).
		info.CgroupV2Measured = memCurrent != "" || memEvents != "" || cpuStat != ""
	} else if cc.InContainer {
		// cgroup v1: the same signals live under per-controller dirs. cpu.stat carries
		// the SAME nr_periods/nr_throttled keys as v2; OOM-kills are the `oom_kill`
		// counter in the memory controller's memory.oom_control (kernel ≥4.13).
		cpuStat := readFileTrimmedLocal(filepath.Join(cc.CgroupV1CPUDir, "cpu.stat"))
		oomCtl := readFileTrimmedLocal(filepath.Join(cc.CgroupV1MemDir, "memory.oom_control"))
		info.MemCurrentBytes = parseInt64(readFileTrimmedLocal(filepath.Join(cc.CgroupV1MemDir, "memory.usage_in_bytes")))
		info.OOMKills = cgroupKeyedValue(oomCtl, "oom_kill")
		info.ThrottledPct = cgroupThrottledPct(cpuStat)
		// Measured only if a counter file was actually readable — if both are absent
		// (old kernel / controller not mounted) we stay honest ("not measured"), not a
		// silent 0 = healthy.
		info.CgroupV1Measured = cpuStat != "" || oomCtl != ""
	}

	info.WritableRootfs = rootfsWritable(readFileTrimmedLocal("/proc/mounts"))
	info.UnderlyingVM = underlyingVM()

	return info, nil
}

func containerRuntime(cc platform.ContainerContext) string {
	switch {
	case cc.IsKubernetes:
		return "kubernetes"
	case cc.IsDocker:
		return "docker"
	case cc.IsPodman:
		return "podman"
	default:
		return "container"
	}
}

// underlyingVM reports the hypervisor of the host beneath the container, best-effort
// from DMI (often readable from inside a container, masked in hardened ones). "" when
// masked or bare metal — we never guess.
func underlyingVM() string {
	vendor := strings.ToUpper(readFileTrimmedLocal(filepath.Join(dmiIDDir, "sys_vendor")))
	switch {
	case strings.Contains(vendor, "QEMU"):
		return "QEMU/KVM"
	case strings.Contains(vendor, "VMWARE"):
		return "VMware"
	default:
		return ""
	}
}

// cgroupKeyedValue returns the value for "key N" in a cgroup keyed file
// (memory.events, cpu.stat). -1-safe: 0 when the key is absent or unparseable.
func cgroupKeyedValue(content, key string) int64 {
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == key {
			return parseInt64(f[1])
		}
	}
	return 0
}

// cgroupThrottledPct returns the share of CPU scheduler periods the cgroup was
// throttled at its quota, from cpu.stat (nr_throttled / nr_periods). 0 when there
// were no periods (no CPU limit, or freshly started).
func cgroupThrottledPct(cpuStat string) float64 {
	periods := cgroupKeyedValue(cpuStat, "nr_periods")
	throttled := cgroupKeyedValue(cpuStat, "nr_throttled")
	if periods <= 0 {
		return 0
	}
	return float64(throttled) / float64(periods) * 100
}

// rootfsWritable reports whether / is mounted read-write (vs an immutable read-only
// root). Reads the / line of /proc/mounts; the mount options field carries rw/ro.
func rootfsWritable(procMounts string) bool {
	for _, line := range strings.Split(procMounts, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[1] == "/" {
			for _, opt := range strings.Split(f[3], ",") {
				if opt == "ro" {
					return false
				}
			}
			return true
		}
	}
	return false
}
