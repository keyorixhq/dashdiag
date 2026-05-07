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
	)
}

func detectContainerContextFromPaths(dockerenv, containerenv, cgroupControllers string) ContainerContext {
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

	if !cc.InContainer && cgroupMentionsContainer() {
		cc.InContainer = true
	}

	if fileExists(cgroupControllers) {
		cc.CgroupVersion = 2
		cc.MemLimitMB = parseCgroupV2Memory(filepath.Join(cgroupBase, "memory.max"))
		cc.CPULimitCores = parseCgroupV2CPU(filepath.Join(cgroupBase, "cpu.max"))
	} else {
		cc.CgroupVersion = 1
		cc.MemLimitMB = parseCgroupV1Memory(filepath.Join(cgroupBase, "memory", "memory.limit_in_bytes"))
	}

	return cc
}

func parseCgroupV2Memory(path string) float64 {
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
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
