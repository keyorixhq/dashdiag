//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestContainerGuestCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewContainerGuestCollector()
	if c.Name() != "ContainerGuest" {
		t.Errorf("Name() = %q, want ContainerGuest", c.Name())
	}
	if c.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

func TestContainerGuestAvailable(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{InContainer: true}),
	}, nil, nil)
	if !ContainerGuestAvailable() {
		t.Error("ContainerGuestAvailable() = false, want true")
	}

	withCombinedFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{InContainer: false}),
	}, nil, nil)
	if ContainerGuestAvailable() {
		t.Error("ContainerGuestAvailable() = true, want false")
	}
}

func TestContainerRuntime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cc   platform.ContainerContext
		want string
	}{
		{"kubernetes", platform.ContainerContext{IsKubernetes: true}, "kubernetes"},
		{"docker", platform.ContainerContext{IsDocker: true}, "docker"},
		{"podman", platform.ContainerContext{IsPodman: true}, "podman"},
		{"generic container", platform.ContainerContext{}, "container"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := containerRuntime(tt.cc); got != tt.want {
				t.Errorf("containerRuntime(%+v) = %q, want %q", tt.cc, got, tt.want)
			}
		})
	}
}

func TestUnderlyingVM(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("QEMU\n"))
	})
	if got := underlyingVM(); got != "QEMU/KVM" {
		t.Errorf("underlyingVM() = %q, want QEMU/KVM", got)
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("VMware, Inc.\n"))
	})
	if got := underlyingVM(); got != "VMware" {
		t.Errorf("underlyingVM() = %q, want VMware", got)
	}

	withFixtureSource(t, func(_ *source.Bundle) {}) // sys_vendor never seeded
	if got := underlyingVM(); got != "" {
		t.Errorf("underlyingVM() = %q, want empty when vendor is absent/unknown", got)
	}
}

func TestContainerGuestCollector_Collect_NotInContainer(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{InContainer: false}),
	}, nil, func(b *source.Bundle) {
		b.PutFile("/proc/mounts", []byte("overlay / overlay rw,relatime 0 0\n"))
	})

	c := NewContainerGuestCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerGuestInfo)
	if info.InContainer {
		t.Error("InContainer = true, want false")
	}
	if info.CgroupV1Measured {
		t.Error("CgroupV1Measured = true, want false outside a container")
	}
}

func TestContainerGuestCollector_Collect_CgroupV2(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{
			InContainer:   true,
			IsDocker:      true,
			CgroupVersion: 2,
			CgroupV2Dir:   "/sys/fs/cgroup",
			MemLimitMB:    512,
			CPULimitCores: 2,
		}),
	}, nil, func(b *source.Bundle) {
		b.PutFile("/sys/fs/cgroup/memory.current", []byte("104857600\n"))
		b.PutFile("/sys/fs/cgroup/memory.events", []byte("low 0\nhigh 0\nmax 0\noom 0\noom_kill 1\n"))
		b.PutFile("/sys/fs/cgroup/cpu.stat", []byte("nr_periods 100\nnr_throttled 25\nthrottled_usec 500\n"))
		b.PutFile("/proc/mounts", []byte("overlay / overlay rw,relatime 0 0\n"))
	})

	c := NewContainerGuestCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerGuestInfo)
	if !info.CgroupV2 {
		t.Error("CgroupV2 = false, want true")
	}
	if info.MemCurrentBytes != 104857600 {
		t.Errorf("MemCurrentBytes = %d, want 104857600", info.MemCurrentBytes)
	}
	if info.OOMKills != 1 {
		t.Errorf("OOMKills = %d, want 1", info.OOMKills)
	}
	if info.ThrottledPct != 25 {
		t.Errorf("ThrottledPct = %v, want 25", info.ThrottledPct)
	}
	if info.Runtime != "docker" {
		t.Errorf("Runtime = %q, want docker", info.Runtime)
	}
	if !info.WritableRootfs {
		t.Error("WritableRootfs = false, want true")
	}
	if !info.CgroupV2Measured {
		t.Error("CgroupV2Measured = false, want true — every v2 counter file was readable")
	}
}

// TestContainerGuestCollector_Collect_CgroupV2Unmeasured is the regression
// guard for internal-collectors-05-02: when NONE of memory.current/
// memory.events/cpu.stat are readable under the container's own v2 cgroup
// dir (TOCTOU race, hardened LSM profile, minimal cgroupfs mount, or a
// --cgroupns=host self-path resolution failure), the zero-valued
// MemCurrentBytes/OOMKills/ThrottledPct must not read as a silent "healthy" —
// CgroupV2Measured must be false.
func TestContainerGuestCollector_Collect_CgroupV2Unmeasured(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{
			InContainer:   true,
			IsDocker:      true,
			CgroupVersion: 2,
			CgroupV2Dir:   "/sys/fs/cgroup",
			MemLimitMB:    512,
			CPULimitCores: 2,
		}),
	}, nil, func(b *source.Bundle) {
		// Deliberately no memory.current/memory.events/cpu.stat files seeded.
		b.PutFile("/proc/mounts", []byte("overlay / overlay rw,relatime 0 0\n"))
	})

	c := NewContainerGuestCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerGuestInfo)
	if info.CgroupV2Measured {
		t.Error("CgroupV2Measured = true, want false — no v2 counter file was readable")
	}
	if info.MemCurrentBytes != 0 || info.OOMKills != 0 || info.ThrottledPct != 0 {
		t.Errorf("expected zero-valued counters, got %+v", info)
	}
}

// TestContainerGuestCollector_Collect_CgroupV2EmptyDirFallsBackToBase guards
// the cgDir=="" fallback to cgroupV2Base ("/sys/fs/cgroup"): an older/gap
// ContainerContext with no resolved CgroupV2Dir must still read from the base
// path rather than leaving the cgroup-v2 signals unmeasured.
func TestContainerGuestCollector_Collect_CgroupV2EmptyDirFallsBackToBase(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{
			InContainer:   true,
			IsDocker:      true,
			CgroupVersion: 2,
			CgroupV2Dir:   "",
			MemLimitMB:    512,
			CPULimitCores: 2,
		}),
	}, nil, func(b *source.Bundle) {
		b.PutFile("/sys/fs/cgroup/memory.current", []byte("52428800\n"))
		b.PutFile("/sys/fs/cgroup/memory.events", []byte("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"))
		b.PutFile("/sys/fs/cgroup/cpu.stat", []byte("nr_periods 100\nnr_throttled 0\nthrottled_usec 0\n"))
		b.PutFile("/proc/mounts", []byte("overlay / overlay rw,relatime 0 0\n"))
	})

	c := NewContainerGuestCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerGuestInfo)
	if info.MemCurrentBytes != 52428800 {
		t.Errorf("MemCurrentBytes = %d, want 52428800 (read from base cgroupV2Base fallback)", info.MemCurrentBytes)
	}
}

func TestContainerGuestCollector_Collect_CgroupV1Measured(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{
			InContainer:    true,
			CgroupVersion:  1,
			CgroupV1MemDir: "/sys/fs/cgroup/memory",
			CgroupV1CPUDir: "/sys/fs/cgroup/cpu",
		}),
	}, nil, func(b *source.Bundle) {
		b.PutFile("/sys/fs/cgroup/cpu/cpu.stat", []byte("nr_periods 10\nnr_throttled 0\n"))
		b.PutFile("/sys/fs/cgroup/memory/memory.oom_control", []byte("oom_kill_disable 0\nunder_oom 0\noom_kill 0\n"))
		b.PutFile("/sys/fs/cgroup/memory/memory.usage_in_bytes", []byte("52428800\n"))
		b.PutFile("/proc/mounts", []byte("overlay / overlay ro,relatime 0 0\n"))
	})

	c := NewContainerGuestCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerGuestInfo)
	if info.CgroupV2 {
		t.Error("CgroupV2 = true, want false (v1 host)")
	}
	if !info.CgroupV1Measured {
		t.Error("CgroupV1Measured = false, want true (both counter files were readable)")
	}
	if info.MemCurrentBytes != 52428800 {
		t.Errorf("MemCurrentBytes = %d, want 52428800", info.MemCurrentBytes)
	}
	if info.WritableRootfs {
		t.Error("WritableRootfs = true, want false (ro root)")
	}
}

func TestContainerGuestCollector_Collect_CgroupV1Unmeasured(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{
			InContainer:    true,
			CgroupVersion:  1,
			CgroupV1MemDir: "/sys/fs/cgroup/memory",
			CgroupV1CPUDir: "/sys/fs/cgroup/cpu",
		}),
	}, nil, func(b *source.Bundle) {
		b.PutFile("/proc/mounts", []byte("overlay / overlay rw,relatime 0 0\n"))
		// Neither cpu.stat nor memory.oom_control seeded — both reads come back
		// empty ("" on error), so CgroupV1Measured must stay false (not measured,
		// not a silent 0=healthy).
	})

	c := NewContainerGuestCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerGuestInfo)
	if info.CgroupV1Measured {
		t.Error("CgroupV1Measured = true, want false when both counter files are absent")
	}
}

func TestCgroupThrottledPct(t *testing.T) {
	// Verbatim cpu.stat from a real container (no throttling — idle):
	const idle = "usage_usec 81436\nuser_usec 63912\nsystem_usec 17524\nnice_usec 0\n" +
		"nr_periods 1\nnr_throttled 0\nthrottled_usec 0\nnr_bursts 0\nburst_usec 0\n"
	if got := cgroupThrottledPct(idle); got != 0 {
		t.Errorf("cgroupThrottledPct(idle) = %v, want 0", got)
	}
	// 80 of 100 periods throttled → 80%.
	if got := cgroupThrottledPct("nr_periods 100\nnr_throttled 80\nthrottled_usec 5000\n"); got != 80 {
		t.Errorf("cgroupThrottledPct(throttled) = %v, want 80", got)
	}
	// No periods yet (no CPU limit) → 0, not a divide-by-zero.
	if got := cgroupThrottledPct("nr_periods 0\nnr_throttled 0\n"); got != 0 {
		t.Errorf("cgroupThrottledPct(no periods) = %v, want 0", got)
	}
	if got := cgroupThrottledPct(""); got != 0 {
		t.Errorf("cgroupThrottledPct(empty) = %v, want 0", got)
	}
}

func TestCgroupKeyedValue(t *testing.T) {
	// Verbatim memory.events from a real container.
	const events = "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\nsock_throttled 0\n"
	if got := cgroupKeyedValue(events, "oom_kill"); got != 0 {
		t.Errorf("oom_kill = %d, want 0", got)
	}
	if got := cgroupKeyedValue("oom 2\noom_kill 5\n", "oom_kill"); got != 5 {
		t.Errorf("oom_kill = %d, want 5", got)
	}
	// "oom" must not match "oom_kill" (exact key only).
	if got := cgroupKeyedValue("oom_kill 5\n", "oom"); got != 0 {
		t.Errorf("oom = %d, want 0 (must not prefix-match oom_kill)", got)
	}
	if got := cgroupKeyedValue("", "oom_kill"); got != 0 {
		t.Errorf("empty = %d, want 0", got)
	}
}

func TestRootfsWritable(t *testing.T) {
	// Verbatim / line from a real container (overlay, rw).
	const rw = "overlay / overlay rw,relatime,lowerdir=/a:/b,upperdir=/c,workdir=/d 0 0\n" +
		"proc /proc proc rw,nosuid 0 0\n"
	if !rootfsWritable(rw) {
		t.Error("rw overlay root should be writable")
	}
	// Read-only root.
	const ro = "overlay / overlay ro,relatime,lowerdir=/a 0 0\n"
	if rootfsWritable(ro) {
		t.Error("ro root must be reported read-only")
	}
	// No / line → false (don't claim writable when we can't tell).
	if rootfsWritable("proc /proc proc rw 0 0\n") {
		t.Error("no root mount → must not report writable")
	}
}
