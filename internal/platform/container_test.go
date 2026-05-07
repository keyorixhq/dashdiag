package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectContainer_Docker(t *testing.T) {
	dir := t.TempDir()
	dockerenv := filepath.Join(dir, "dockerenv")
	os.WriteFile(dockerenv, nil, 0644)

	cc := detectContainerContextFromPaths(dockerenv, filepath.Join(dir, "containerenv"), filepath.Join(dir, "cgroup", "cgroup.controllers"))

	if !cc.IsDocker {
		t.Error("expected IsDocker=true")
	}
	if !cc.InContainer {
		t.Error("expected InContainer=true")
	}
	if cc.IsPodman {
		t.Error("expected IsPodman=false")
	}
}

func TestDetectContainer_Podman(t *testing.T) {
	dir := t.TempDir()
	containerenv := filepath.Join(dir, "containerenv")
	os.WriteFile(containerenv, nil, 0644)

	cc := detectContainerContextFromPaths(filepath.Join(dir, "dockerenv"), containerenv, filepath.Join(dir, "cgroup", "cgroup.controllers"))

	if !cc.IsPodman {
		t.Error("expected IsPodman=true")
	}
	if !cc.InContainer {
		t.Error("expected InContainer=true")
	}
	if cc.IsDocker {
		t.Error("expected IsDocker=false")
	}
}

func TestDetectContainer_NotInContainer(t *testing.T) {
	dir := t.TempDir()
	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(dir, "cgroup", "cgroup.controllers"),
	)
	// IsKubernetes might be true if KUBERNETES_SERVICE_HOST is set in CI
	if cc.IsDocker || cc.IsPodman {
		t.Error("expected IsDocker=false and IsPodman=false for empty temp dir")
	}
}

func TestDetectContainer_CgroupV2_Memory(t *testing.T) {
	dir := t.TempDir()
	cgroupDir := filepath.Join(dir, "cgroup")
	os.MkdirAll(cgroupDir, 0755)
	os.WriteFile(filepath.Join(cgroupDir, "cgroup.controllers"), []byte("cpu memory io"), 0644)
	os.WriteFile(filepath.Join(cgroupDir, "memory.max"), []byte("536870912\n"), 0644)  // 512 MB
	os.WriteFile(filepath.Join(cgroupDir, "cpu.max"), []byte("100000 100000\n"), 0644) // 1 core

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(cgroupDir, "cgroup.controllers"),
	)

	if cc.CgroupVersion != 2 {
		t.Errorf("expected CgroupVersion=2, got %d", cc.CgroupVersion)
	}
	if cc.MemLimitMB != 512 {
		t.Errorf("expected MemLimitMB=512, got %f", cc.MemLimitMB)
	}
	if cc.CPULimitCores != 1.0 {
		t.Errorf("expected CPULimitCores=1.0, got %f", cc.CPULimitCores)
	}
}

func TestDetectContainer_CgroupV2_MemoryMax_Unlimited(t *testing.T) {
	dir := t.TempDir()
	cgroupDir := filepath.Join(dir, "cgroup")
	os.MkdirAll(cgroupDir, 0755)
	os.WriteFile(filepath.Join(cgroupDir, "cgroup.controllers"), []byte("cpu memory"), 0644)
	os.WriteFile(filepath.Join(cgroupDir, "memory.max"), []byte("max\n"), 0644)
	os.WriteFile(filepath.Join(cgroupDir, "cpu.max"), []byte("max 100000\n"), 0644)

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(cgroupDir, "cgroup.controllers"),
	)

	if cc.MemLimitMB != 0 {
		t.Errorf("expected MemLimitMB=0 (unlimited), got %f", cc.MemLimitMB)
	}
	if cc.CPULimitCores != 0 {
		t.Errorf("expected CPULimitCores=0 (unlimited), got %f", cc.CPULimitCores)
	}
}

func TestDetectContainer_CgroupV1_Memory(t *testing.T) {
	dir := t.TempDir()
	cgroupDir := filepath.Join(dir, "cgroup")
	memDir := filepath.Join(cgroupDir, "memory")
	os.MkdirAll(memDir, 0755)
	os.WriteFile(filepath.Join(memDir, "memory.limit_in_bytes"), []byte("268435456\n"), 0644) // 256 MB

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(cgroupDir, "cgroup.controllers"), // does not exist → v1
	)

	if cc.CgroupVersion != 1 {
		t.Errorf("expected CgroupVersion=1, got %d", cc.CgroupVersion)
	}
	if cc.MemLimitMB != 256 {
		t.Errorf("expected MemLimitMB=256, got %f", cc.MemLimitMB)
	}
}

func TestDetectContainer_BothDockerAndPodman(t *testing.T) {
	dir := t.TempDir()
	dockerenv := filepath.Join(dir, "dockerenv")
	containerenv := filepath.Join(dir, "containerenv")
	os.WriteFile(dockerenv, nil, 0644)
	os.WriteFile(containerenv, nil, 0644)

	cc := detectContainerContextFromPaths(dockerenv, containerenv, filepath.Join(dir, "cgroup.controllers"))

	if !cc.IsDocker || !cc.IsPodman || !cc.InContainer {
		t.Errorf("expected both Docker and Podman detected: %+v", cc)
	}
}
