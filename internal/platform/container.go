package platform

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ContainerContext struct {
	InContainer   bool
	IsDocker      bool
	IsPodman      bool
	IsKubernetes  bool
	CPULimitCores float64
	MemLimitMB    float64
	CgroupVersion int
}

func DetectContainerContext() ContainerContext {
	return detectContainerContextFromPaths(
		"/.dockerenv",
		"/run/.containerenv",
		"/sys/fs/cgroup/cgroup.controllers",
		"/proc/self/cgroup",
	)
}

func detectContainerContextFromPaths(dockerenv, containerenv, cgroupControllers, procSelfCgroup string) ContainerContext {
	cc := ContainerContext{}
	cgroupBase := filepath.Dir(cgroupControllers)

	if fileExists(dockerenv) {
		cc.IsDocker = true
		cc.InContainer = true
	}

	if fileExists(containerenv) {
		cc.IsPodman = true
		cc.InContainer = true
	}

	cc.IsKubernetes = os.Getenv("KUBERNETES_SERVICE_HOST") != ""
	if cc.IsKubernetes {
		cc.InContainer = true
	}

	// LXC container detection:
	// /run/systemd/container contains "lxc" on systemd-based LXC containers.
	// /proc/1/environ contains container=lxc on older LXC setups.
	if !cc.InContainer {
		if b, err := os.ReadFile("/run/systemd/container"); err == nil {
			if strings.TrimSpace(string(b)) == "lxc" {
				cc.InContainer = true
			}
		}
	}
	if !cc.InContainer {
		if b, err := os.ReadFile("/proc/1/environ"); err == nil {
			if strings.Contains(string(b), "container=lxc") {
				cc.InContainer = true
			}
		}
	}

	if !cc.InContainer && cgroupMentionsContainer() {
		cc.InContainer = true
	}

	if fileExists(cgroupControllers) {
		cc.CgroupVersion = 2
		// In a container the limit lives at the container's OWN cgroup. With a
		// private cgroup namespace that is the base itself (/proc/self/cgroup is
		// "0::/"), but with --cgroupns=host it's a sub-path — reading the base
		// then gives the host root ("max") and falsely reports "unlimited".
		// Resolve the self path only inside a container so bare hosts (where the
		// process sits in some systemd slice) keep reporting the root.
		cgDir := cgroupBase
		if cc.InContainer {
			cgDir = cgroupV2SelfDir(cgroupBase, procSelfCgroup)
		}
		cc.MemLimitMB = parseCgroupV2Memory(filepath.Join(cgDir, "memory.max"))
		cc.CPULimitCores = parseCgroupV2CPU(filepath.Join(cgDir, "cpu.max"))
	} else {
		cc.CgroupVersion = 1
		memDir := filepath.Join(cgroupBase, "memory")
		if cc.InContainer {
			memDir = cgroupV1ControllerDir(cgroupBase, procSelfCgroup, "memory")
		}
		cc.MemLimitMB = parseCgroupV1Memory(filepath.Join(memDir, "memory.limit_in_bytes"))
	}

	return cc
}

// cgroupV2SelfDir returns the directory holding the process's own cgroup v2
// interface files, by joining the base mount with the path from the single
// "0::<path>" line of /proc/self/cgroup. A private namespace reports "0::/" so
// this resolves to base; --cgroupns=host reports the real sub-path. Falls back
// to base when /proc/self/cgroup can't be read.
func cgroupV2SelfDir(base, procSelfCgroup string) string {
	data, err := os.ReadFile(filepath.Clean(procSelfCgroup))
	if err != nil {
		return base
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(base, strings.TrimSpace(rel))
		}
	}
	return base
}

// cgroupV1ControllerDir returns the directory for a cgroup v1 controller's
// interface files. v1 /proc/self/cgroup lines are "id:controllers:path"; the
// file lives at <base>/<controller><path>. Falls back to <base>/<controller>.
func cgroupV1ControllerDir(base, procSelfCgroup, controller string) string {
	fallback := filepath.Join(base, controller)
	data, err := os.ReadFile(filepath.Clean(procSelfCgroup))
	if err != nil {
		return fallback
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, c := range strings.Split(parts[1], ",") {
			if c == controller {
				return filepath.Join(base, controller, parts[2])
			}
		}
	}
	return fallback
}

func parseCgroupV2Memory(path string) float64 {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return float64(v) / (1024 * 1024)
}

func parseCgroupV2CPU(path string) float64 {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return 0
	}
	parts := strings.Fields(strings.TrimSpace(string(data)))
	if len(parts) != 2 || parts[0] == "max" {
		return 0
	}
	quota, err1 := strconv.ParseFloat(parts[0], 64)
	period, err2 := strconv.ParseFloat(parts[1], 64)
	if err1 != nil || err2 != nil || period == 0 {
		return 0
	}
	return quota / period
}

func parseCgroupV1Memory(path string) float64 {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	// Values near MaxUint64 indicate "unlimited"
	if v > (1 << 60) {
		return 0
	}
	return float64(v) / (1024 * 1024)
}

func cgroupMentionsContainer() bool {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	s := string(data)
	return strings.Contains(s, "docker") || strings.Contains(s, "kubepods")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
