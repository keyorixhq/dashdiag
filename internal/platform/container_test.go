package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// noSelfCgroup is a path that doesn't exist, so cgroup self-dir resolution falls
// back to the base mount (the behaviour these tests assert).
const noSelfCgroup = "/nonexistent/proc/self/cgroup"

// noSystemdContainer and noProc1Environ are paths that don't exist, so the LXC
// marker-file reads fall through cleanly (the behaviour most tests assert;
// tests that specifically cover the LXC branches inject real content instead).
const (
	noSystemdContainer = "/nonexistent/run/systemd/container"
	noProc1Environ     = "/nonexistent/proc/1/environ"
)

// TestDetectContainerContext_RealPaths is a smoke test for the production
// wrapper: it hits the real /.dockerenv, /run/.containerenv, cgroup, and
// /proc/self/cgroup paths on whatever host runs the suite. It can't assert a
// specific ContainerContext (this test binary itself may or may not be running
// containerized), only that the call completes without panicking and returns
// internally consistent fields — the actual decision logic is exhaustively
// covered via detectContainerContextFromPaths elsewhere in this file.
func TestDetectContainerContext_RealPaths(t *testing.T) {
	t.Parallel()
	cc := DetectContainerContext()
	if cc.CgroupVersion != 1 && cc.CgroupVersion != 2 {
		t.Errorf("CgroupVersion = %d, want 1 or 2", cc.CgroupVersion)
	}
	if cc.IsDocker && !cc.InContainer {
		t.Error("IsDocker=true implies InContainer=true")
	}
	if cc.IsPodman && !cc.InContainer {
		t.Error("IsPodman=true implies InContainer=true")
	}
	if cc.IsKubernetes && !cc.InContainer {
		t.Error("IsKubernetes=true implies InContainer=true")
	}
}

// TestDetectContainer_Kubernetes covers the KUBERNETES_SERVICE_HOST env-var
// branch. It mutates process-global environment state, so — matching the
// convention in identity_test.go/sysinfo_test.go for shared mutable state —
// it does NOT call t.Parallel().
func TestDetectContainer_Kubernetes(t *testing.T) {
	prev, hadPrev := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	if err := os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	defer func() {
		if hadPrev {
			_ = os.Setenv("KUBERNETES_SERVICE_HOST", prev)
		} else {
			_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")
		}
	}()

	dir := t.TempDir()
	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(dir, "cgroup", "cgroup.controllers"),
		noSelfCgroup,
		noSystemdContainer,
		noProc1Environ,
	)
	if !cc.IsKubernetes {
		t.Error("expected IsKubernetes=true when KUBERNETES_SERVICE_HOST is set")
	}
	if !cc.InContainer {
		t.Error("expected InContainer=true when IsKubernetes=true")
	}
}

// TestCgroupV2SelfDir_ReadError covers the /proc/self/cgroup-unreadable fallback:
// resolution must collapse to the base mount rather than erroring.
func TestCgroupV2SelfDir_ReadError(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	if got := cgroupV2SelfDir(base, filepath.Join(base, "does-not-exist")); got != base {
		t.Errorf("cgroupV2SelfDir with unreadable self path = %q, want base %q", got, base)
	}
}

// TestCgroupV2SelfDir_NoMatchingLine covers the loop-completes-without-a-"0::"-
// line fallback (a self-cgroup file present but without the expected line).
func TestCgroupV2SelfDir_NoMatchingLine(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	selfCgroup := filepath.Join(base, "self-cgroup")
	if err := os.WriteFile(selfCgroup, []byte("1:cpu:/foo\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got := cgroupV2SelfDir(base, selfCgroup); got != base {
		t.Errorf("cgroupV2SelfDir with no 0:: line = %q, want base %q", got, base)
	}
}

// TestCgroupV1ControllerDir_ReadError covers the /proc/self/cgroup-unreadable
// fallback: resolution must collapse to <base>/<controller>.
func TestCgroupV1ControllerDir_ReadError(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	want := filepath.Join(base, "memory")
	if got := cgroupV1ControllerDir(base, filepath.Join(base, "does-not-exist"), "memory"); got != want {
		t.Errorf("cgroupV1ControllerDir with unreadable self path = %q, want %q", got, want)
	}
}

// TestCgroupV1ControllerDir_NoMatchingController covers two non-matching cases:
// a malformed line (not 3 colon-separated fields) and a line whose controller
// list doesn't include the one being resolved. Both must fall through to the
// <base>/<controller> fallback.
func TestCgroupV1ControllerDir_NoMatchingController(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	selfCgroup := filepath.Join(base, "self-cgroup")
	content := "malformed-line-no-colons\n4:pids:/foo\n"
	if err := os.WriteFile(selfCgroup, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	want := filepath.Join(base, "memory")
	if got := cgroupV1ControllerDir(base, selfCgroup, "memory"); got != want {
		t.Errorf("cgroupV1ControllerDir with no matching controller = %q, want %q", got, want)
	}
}

// TestParseCgroupV2Memory_Errors covers the ReadFile-error and
// ParseUint-error branches directly (bypassing detectContainerContextFromPaths).
func TestParseCgroupV2Memory_Errors(t *testing.T) {
	t.Parallel()
	t.Run("file absent", func(t *testing.T) {
		t.Parallel()
		if got := parseCgroupV2Memory(filepath.Join(t.TempDir(), "does-not-exist")); got != 0 {
			t.Errorf("parseCgroupV2Memory(absent) = %f, want 0", got)
		}
	})
	t.Run("unparseable content", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "memory.max")
		if err := os.WriteFile(path, []byte("not-a-number\n"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if got := parseCgroupV2Memory(path); got != 0 {
			t.Errorf("parseCgroupV2Memory(garbage) = %f, want 0", got)
		}
	})
}

// TestParseCgroupV2CPU_Errors covers the ReadFile-error, malformed-fields, and
// ParseFloat-error branches directly.
func TestParseCgroupV2CPU_Errors(t *testing.T) {
	t.Parallel()
	t.Run("file absent", func(t *testing.T) {
		t.Parallel()
		if got := parseCgroupV2CPU(filepath.Join(t.TempDir(), "does-not-exist")); got != 0 {
			t.Errorf("parseCgroupV2CPU(absent) = %f, want 0", got)
		}
	})
	t.Run("wrong field count", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "cpu.max")
		if err := os.WriteFile(path, []byte("100000\n"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if got := parseCgroupV2CPU(path); got != 0 {
			t.Errorf("parseCgroupV2CPU(one field) = %f, want 0", got)
		}
	})
	t.Run("unparseable quota", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "cpu.max")
		if err := os.WriteFile(path, []byte("garbage 100000\n"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if got := parseCgroupV2CPU(path); got != 0 {
			t.Errorf("parseCgroupV2CPU(unparseable quota) = %f, want 0", got)
		}
	})
	t.Run("unparseable period", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "cpu.max")
		if err := os.WriteFile(path, []byte("100000 garbage\n"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if got := parseCgroupV2CPU(path); got != 0 {
			t.Errorf("parseCgroupV2CPU(unparseable period) = %f, want 0", got)
		}
	})
}

// TestParseCgroupV1Memory_Errors covers the ReadFile-error, ParseUint-error,
// and near-MaxUint64-"unlimited" branches directly.
func TestParseCgroupV1Memory_Errors(t *testing.T) {
	t.Parallel()
	t.Run("file absent", func(t *testing.T) {
		t.Parallel()
		if got := parseCgroupV1Memory(filepath.Join(t.TempDir(), "does-not-exist")); got != 0 {
			t.Errorf("parseCgroupV1Memory(absent) = %f, want 0", got)
		}
	})
	t.Run("unparseable content", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "memory.limit_in_bytes")
		if err := os.WriteFile(path, []byte("not-a-number\n"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if got := parseCgroupV1Memory(path); got != 0 {
			t.Errorf("parseCgroupV1Memory(garbage) = %f, want 0", got)
		}
	})
	t.Run("near max uint64 is unlimited", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "memory.limit_in_bytes")
		// 2^62, well above the 1<<60 "unlimited" threshold.
		if err := os.WriteFile(path, []byte("4611686018427387904\n"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if got := parseCgroupV1Memory(path); got != 0 {
			t.Errorf("parseCgroupV1Memory(near-max) = %f, want 0 (unlimited)", got)
		}
	})
}

// TestCgroupMentionsContainer_RealPath is a smoke test for the production
// entry point: it reads the real /proc/self/cgroup on whatever host runs the
// suite. Result is host-dependent, so only call-completes-without-panicking is
// asserted here; the decision logic itself is exhaustively covered via
// cgroupMentionsContainerAt below, which injects synthetic content.
func TestCgroupMentionsContainer_RealPath(t *testing.T) {
	t.Parallel()
	_ = cgroupMentionsContainerAt("/proc/self/cgroup")
}

// TestCgroupMentionsContainerAt covers the injected core directly: the
// docker/kubepods match branches (previously unreachable without faking
// /proc/self/cgroup content), the no-match branch, and the unreadable-file
// branch.
func TestCgroupMentionsContainerAt(t *testing.T) {
	t.Parallel()
	t.Run("docker match", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "cgroup")
		if err := os.WriteFile(path, []byte("0::/system.slice/docker-abc123.scope\n"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if !cgroupMentionsContainerAt(path) {
			t.Error("expected true for cgroup path containing \"docker\"")
		}
	})
	t.Run("kubepods match", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "cgroup")
		if err := os.WriteFile(path, []byte("0::/kubepods/besteffort/pod123/abc\n"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if !cgroupMentionsContainerAt(path) {
			t.Error("expected true for cgroup path containing \"kubepods\"")
		}
	})
	t.Run("no match", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "cgroup")
		if err := os.WriteFile(path, []byte("0::/\n"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if cgroupMentionsContainerAt(path) {
			t.Error("expected false for cgroup path with no container marker")
		}
	})
	t.Run("file absent", func(t *testing.T) {
		t.Parallel()
		if cgroupMentionsContainerAt(filepath.Join(t.TempDir(), "does-not-exist")) {
			t.Error("expected false when /proc/self/cgroup is unreadable")
		}
	})
}

func TestDetectContainer_Docker(t *testing.T) {
	dir := t.TempDir()
	dockerenv := filepath.Join(dir, "dockerenv")
	_ = os.WriteFile(dockerenv, nil, 0644)

	cc := detectContainerContextFromPaths(dockerenv, filepath.Join(dir, "containerenv"), filepath.Join(dir, "cgroup", "cgroup.controllers"), noSelfCgroup, noSystemdContainer, noProc1Environ)

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

	cc := detectContainerContextFromPaths(filepath.Join(dir, "dockerenv"), containerenv, filepath.Join(dir, "cgroup", "cgroup.controllers"), noSelfCgroup, noSystemdContainer, noProc1Environ)

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
		noSystemdContainer,
		noProc1Environ,
	)
	// IsKubernetes might be true if KUBERNETES_SERVICE_HOST is set in CI
	if cc.IsDocker || cc.IsPodman {
		t.Error("expected IsDocker=false and IsPodman=false for empty temp dir")
	}
}

// TestDetectContainer_LXC_SystemdMarker covers the /run/systemd/container
// branch: on systemd-based LXC containers this file's content is exactly "lxc".
func TestDetectContainer_LXC_SystemdMarker(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	systemdContainer := filepath.Join(dir, "systemd-container")
	if err := os.WriteFile(systemdContainer, []byte("lxc\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(dir, "cgroup", "cgroup.controllers"),
		noSelfCgroup,
		systemdContainer,
		noProc1Environ,
	)
	if !cc.InContainer {
		t.Error("expected InContainer=true when /run/systemd/container == \"lxc\"")
	}
	if cc.IsDocker || cc.IsPodman {
		t.Error("LXC-via-systemd-marker must not also flag Docker/Podman")
	}
}

// TestDetectContainer_SystemdMarker_OtherEngine is the regression test for
// internal-platform-01-02: /run/systemd/container holds the ENGINE NAME
// (lxc, systemd-nspawn, oci, rkt, pouch, proot, ...), not just "lxc" — the
// file's mere non-empty presence is systemd's own authoritative "I detected
// I'm in a container" signal. Previously only the literal value "lxc"
// matched, so every other systemd-recognized engine (including
// systemd-nspawn) was silently misclassified as a bare host, letting
// cgroup-limit detection read the HOST's values instead of the container's.
func TestDetectContainer_SystemdMarker_OtherEngine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	systemdContainer := filepath.Join(dir, "systemd-container")
	if err := os.WriteFile(systemdContainer, []byte("nspawn\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(dir, "cgroup", "cgroup.controllers"),
		noSelfCgroup,
		systemdContainer,
		noProc1Environ,
	)
	if !cc.InContainer {
		t.Error("expected InContainer=true for a non-\"lxc\" but non-empty systemd-container value (e.g. systemd-nspawn)")
	}
	if cc.IsDocker || cc.IsPodman {
		t.Error("a generic systemd-container marker must not also flag Docker/Podman")
	}
}

// TestDetectContainer_LXC_ProcEnviron covers the /proc/1/environ fallback used
// by older LXC setups that predate the /run/systemd/container marker.
func TestDetectContainer_LXC_ProcEnviron(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	proc1Environ := filepath.Join(dir, "proc1-environ")
	// /proc/1/environ is NUL-separated KEY=VALUE entries.
	content := "PATH=/usr/bin\x00container=lxc\x00HOME=/root\x00"
	if err := os.WriteFile(proc1Environ, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(dir, "cgroup", "cgroup.controllers"),
		noSelfCgroup,
		noSystemdContainer,
		proc1Environ,
	)
	if !cc.InContainer {
		t.Error("expected InContainer=true when /proc/1/environ contains container=lxc")
	}
}

// TestDetectContainer_ProcEnviron_OtherEngine is the companion regression
// test to TestDetectContainer_SystemdMarker_OtherEngine for the
// /proc/1/environ fallback: container=<anything non-empty> is systemd's own
// signal, not just container=lxc.
func TestDetectContainer_ProcEnviron_OtherEngine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	proc1Environ := filepath.Join(dir, "proc1-environ")
	content := "PATH=/usr/bin\x00container=systemd-nspawn\x00HOME=/root\x00"
	if err := os.WriteFile(proc1Environ, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"),
		filepath.Join(dir, "containerenv"),
		filepath.Join(dir, "cgroup", "cgroup.controllers"),
		noSelfCgroup,
		noSystemdContainer,
		proc1Environ,
	)
	if !cc.InContainer {
		t.Error("expected InContainer=true for a non-\"lxc\" but non-empty container= value")
	}
}

// TestDetectContainer_CgroupMarkerOnly covers the final fallback signal: none
// of dockerenv/containerenv/k8s-env/systemd-container/proc1-environ fire, but
// /proc/self/cgroup itself mentions "docker" or "kubepods" (e.g. a Docker
// container reached via a bind-mounted /proc/self/cgroup without .dockerenv
// present). This must still flag InContainer=true.
func TestDetectContainer_CgroupMarkerOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	selfCgroup := filepath.Join(dir, "self-cgroup")
	if err := os.WriteFile(selfCgroup, []byte("0::/system.slice/docker-abc123.scope\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cc := detectContainerContextFromPaths(
		filepath.Join(dir, "dockerenv"), // absent
		filepath.Join(dir, "containerenv"),
		filepath.Join(dir, "cgroup", "cgroup.controllers"), // absent → v1
		selfCgroup,
		noSystemdContainer,
		noProc1Environ,
	)
	if !cc.InContainer {
		t.Error("expected InContainer=true when /proc/self/cgroup alone mentions \"docker\"")
	}
	if cc.IsDocker || cc.IsPodman || cc.IsKubernetes {
		t.Error("cgroup-marker-only detection must not also flag Docker/Podman/Kubernetes")
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
		noSystemdContainer,
		noProc1Environ,
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
		noSystemdContainer,
		noProc1Environ,
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
		noSystemdContainer,
		noProc1Environ,
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

	cc := detectContainerContextFromPaths(dockerenv, containerenv, filepath.Join(dir, "cgroup.controllers"), noSelfCgroup, noSystemdContainer, noProc1Environ)

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
		filepath.Join(cgroupDir, "cgroup.controllers"), selfCgroup, noSystemdContainer, noProc1Environ)

	if cc.MemLimitMB != 512 {
		t.Errorf("host-ns container MemLimitMB = %f, want 512 (read from sub-path, not host root)", cc.MemLimitMB)
	}
	if cc.CPULimitCores != 2.0 {
		t.Errorf("host-ns container CPULimitCores = %f, want 2.0", cc.CPULimitCores)
	}
	// CgroupV2Dir must point at the container's own sub-path, so dynamic reads
	// (memory.events/cpu.stat) hit the container's cgroup, not the host root.
	if cc.CgroupV2Dir != leaf {
		t.Errorf("host-ns CgroupV2Dir = %q, want sub-path %q (else oom_kills/throttle read the host root → false-OK)", cc.CgroupV2Dir, leaf)
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
		filepath.Join(cgroupDir, "cgroup.controllers"), selfCgroup, noSystemdContainer, noProc1Environ)

	if cc.MemLimitMB != 256 {
		t.Errorf("private-ns container MemLimitMB = %f, want 256 (base)", cc.MemLimitMB)
	}
	if cc.CgroupV2Dir != cgroupDir {
		t.Errorf("private-ns CgroupV2Dir = %q, want base %q", cc.CgroupV2Dir, cgroupDir)
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
		filepath.Join(cgroupDir, "cgroup.controllers"), selfCgroup, noSystemdContainer, noProc1Environ) // no controllers file → v1

	if cc.CgroupVersion != 1 {
		t.Fatalf("expected v1, got %d", cc.CgroupVersion)
	}
	if cc.MemLimitMB != 128 {
		t.Errorf("host-ns v1 MemLimitMB = %f, want 128 (sub-path)", cc.MemLimitMB)
	}
	// The per-controller dirs must resolve to the container's own sub-path so the
	// collector reads its memory.oom_control / cpu.stat, not the host root's.
	if cc.CgroupV1MemDir != leaf {
		t.Errorf("CgroupV1MemDir = %q, want %q", cc.CgroupV1MemDir, leaf)
	}
	if want := filepath.Join(cgroupDir, "cpu", subPath); cc.CgroupV1CPUDir != want {
		t.Errorf("CgroupV1CPUDir = %q, want %q (resolved from the cpu,cpuacct line)", cc.CgroupV1CPUDir, want)
	}
}
