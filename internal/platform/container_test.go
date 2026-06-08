package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// noSelfCgroup is a path that doesn't exist, so cgroup self-dir resolution falls
// back to the base mount (the behaviour these tests assert).
const noSelfCgroup = "/nonexistent/proc/self/cgroup"

func TestDetectContainer_Docker(t *testing.T) {
	dir := t.TempDir()
	dockerenv := filepath.Join(dir, "dockerenv")
	_ = os.WriteFile(dockerenv, nil, 0644)

	cc := detectContainerContextFromPaths(dockerenv, filepath.Join(dir, "containerenv"), filepath.Join(dir, "cgroup", "cgroup.controllers"), noSelfCgroup)

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
	_ = os.WriteFile(containerenv, nil, 0644)

	cc := detectContainerContextFromPaths(filepath.Join(dir, "dockerenv"), containerenv, filepath.Join(dir, "cgroup", "cgroup.controllers"), noSelfCgroup)

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
		noSelfCgroup,
	)
	// IsKubernetes might be true if KUBERNETES_SERVICE_HOST is set in CI
	if cc.IsDocker || cc.IsPodman {
		t.Error("expected IsDocker=false and IsPodman=false for empty temp dir")
	}
}

func TestDetectContainer_CgroupV2_Memory(t *testing.T) {
	dir := t.TempDir()
	cgroupDir := filepath.Join(dir, "cgroup")
	_ = os.MkdirAll(cgroupDir, 0755)
	_ = os.WriteFile(filepath.Join(cgroupDir, "cgroup.controllers"), []byte("cpu memory io"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupDir, "memory.max"), []byte("536870912\n"), 0644)  // 512 MB
	_ = os.WriteFile(filepath.Join(cgroupDir, "cpu.max"), []byte("100000 100000\n"), 0644) // 1 core

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(cgroupDir, "cgroup.controllers"),
		noSelfCgroup,
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
	_ = os.MkdirAll(cgroupDir, 0755)
	_ = os.WriteFile(filepath.Join(cgroupDir, "cgroup.controllers"), []byte("cpu memory"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupDir, "memory.max"), []byte("max\n"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupDir, "cpu.max"), []byte("max 100000\n"), 0644)

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(cgroupDir, "cgroup.controllers"),
		noSelfCgroup,
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
	_ = os.MkdirAll(memDir, 0755)
	_ = os.WriteFile(filepath.Join(memDir, "memory.limit_in_bytes"), []byte("268435456\n"), 0644) // 256 MB

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(cgroupDir, "cgroup.controllers"), // does not exist → v1
		noSelfCgroup,
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
	_ = os.WriteFile(dockerenv, nil, 0644)
	_ = os.WriteFile(containerenv, nil, 0644)

	cc := detectContainerContextFromPaths(dockerenv, containerenv, filepath.Join(dir, "cgroup.controllers"), noSelfCgroup)

	if !cc.IsDocker || !cc.IsPodman || !cc.InContainer {
		t.Errorf("expected both Docker and Podman detected: %+v", cc)
	}
}

// With --cgroupns=host the container's cgroup is at a sub-path; the limit must
// be read there, not at the base (which is the host root → "max" → false
// "unlimited"). The process is in a container (dockerenv set).
func TestDetectContainer_CgroupV2_HostNamespace(t *testing.T) {
	dir := t.TempDir()
	cgroupDir := filepath.Join(dir, "cgroup")
	subPath := "/system.slice/docker-abc123.scope"
	leaf := filepath.Join(cgroupDir, subPath)
	_ = os.MkdirAll(leaf, 0755)
	_ = os.WriteFile(filepath.Join(cgroupDir, "cgroup.controllers"), []byte("cpu memory"), 0644)
	// host root says unlimited; the container's own cgroup has the real limit
	_ = os.WriteFile(filepath.Join(cgroupDir, "memory.max"), []byte("max\n"), 0644)
	_ = os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("536870912\n"), 0644)  // 512 MB
	_ = os.WriteFile(filepath.Join(leaf, "cpu.max"), []byte("200000 100000\n"), 0644) // 2 cores

	dockerenv := filepath.Join(dir, "dockerenv")
	_ = os.WriteFile(dockerenv, nil, 0644)
	selfCgroup := filepath.Join(dir, "self-cgroup")
	_ = os.WriteFile(selfCgroup, []byte("0::"+subPath+"\n"), 0644)

	cc := detectContainerContextFromPaths(dockerenv, filepath.Join(dir, "containerenv"),
		filepath.Join(cgroupDir, "cgroup.controllers"), selfCgroup)

	if cc.MemLimitMB != 512 {
		t.Errorf("host-ns container MemLimitMB = %f, want 512 (read from sub-path, not host root)", cc.MemLimitMB)
	}
	if cc.CPULimitCores != 2.0 {
		t.Errorf("host-ns container CPULimitCores = %f, want 2.0", cc.CPULimitCores)
	}
}

// A private cgroup namespace reports "0::/" — resolution must collapse to base,
// preserving the common-case behaviour.
func TestDetectContainer_CgroupV2_PrivateNamespace(t *testing.T) {
	dir := t.TempDir()
	cgroupDir := filepath.Join(dir, "cgroup")
	_ = os.MkdirAll(cgroupDir, 0755)
	_ = os.WriteFile(filepath.Join(cgroupDir, "cgroup.controllers"), []byte("cpu memory"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupDir, "memory.max"), []byte("268435456\n"), 0644) // 256 MB at base

	dockerenv := filepath.Join(dir, "dockerenv")
	_ = os.WriteFile(dockerenv, nil, 0644)
	selfCgroup := filepath.Join(dir, "self-cgroup")
	_ = os.WriteFile(selfCgroup, []byte("0::/\n"), 0644)

	cc := detectContainerContextFromPaths(dockerenv, filepath.Join(dir, "containerenv"),
		filepath.Join(cgroupDir, "cgroup.controllers"), selfCgroup)

	if cc.MemLimitMB != 256 {
		t.Errorf("private-ns container MemLimitMB = %f, want 256 (base)", cc.MemLimitMB)
	}
}

// cgroup v1 under host namespace: the memory controller's limit lives at
// <base>/memory<path>/memory.limit_in_bytes.
func TestDetectContainer_CgroupV1_HostNamespace(t *testing.T) {
	dir := t.TempDir()
	cgroupDir := filepath.Join(dir, "cgroup")
	subPath := "/docker/abc123"
	leaf := filepath.Join(cgroupDir, "memory", subPath)
	_ = os.MkdirAll(leaf, 0755)
	// base memory limit looks unlimited; the container's own is 128 MB
	_ = os.MkdirAll(filepath.Join(cgroupDir, "memory"), 0755)
	_ = os.WriteFile(filepath.Join(cgroupDir, "memory", "memory.limit_in_bytes"), []byte("9223372036854771712\n"), 0644)
	_ = os.WriteFile(filepath.Join(leaf, "memory.limit_in_bytes"), []byte("134217728\n"), 0644) // 128 MB

	dockerenv := filepath.Join(dir, "dockerenv")
	_ = os.WriteFile(dockerenv, nil, 0644)
	selfCgroup := filepath.Join(dir, "self-cgroup")
	_ = os.WriteFile(selfCgroup, []byte("11:memory:"+subPath+"\n10:cpu,cpuacct:"+subPath+"\n"), 0644)

	cc := detectContainerContextFromPaths(dockerenv, filepath.Join(dir, "containerenv"),
		filepath.Join(cgroupDir, "cgroup.controllers"), selfCgroup) // no controllers file → v1

	if cc.CgroupVersion != 1 {
		t.Fatalf("expected v1, got %d", cc.CgroupVersion)
	}
	if cc.MemLimitMB != 128 {
		t.Errorf("host-ns v1 MemLimitMB = %f, want 128 (sub-path)", cc.MemLimitMB)
	}
}
