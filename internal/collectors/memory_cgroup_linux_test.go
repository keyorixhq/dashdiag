//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestCgroupMemoryUsageBytes(t *testing.T) {
	dirV2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirV2, "memory.current"), []byte("1073741824\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := cgroupMemoryUsageBytes(platform.ContainerContext{CgroupVersion: 2, CgroupV2Dir: dirV2}); !ok || got != 1073741824 {
		t.Errorf("v2: got %d ok=%v, want 1073741824/true", got, ok)
	}

	dirV1 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirV1, "memory.usage_in_bytes"), []byte("536870912\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := cgroupMemoryUsageBytes(platform.ContainerContext{CgroupVersion: 1, CgroupV1MemDir: dirV1}); !ok || got != 536870912 {
		t.Errorf("v1: got %d ok=%v, want 536870912/true", got, ok)
	}

	missing := platform.ContainerContext{CgroupVersion: 2, CgroupV2Dir: filepath.Join(dirV2, "does-not-exist")}
	if _, ok := cgroupMemoryUsageBytes(missing); ok {
		t.Error("unreadable memory.current must return ok=false, not a silent 0")
	}

	if _, ok := cgroupMemoryUsageBytes(platform.ContainerContext{}); ok {
		t.Error("no cgroup info (not a container) must return ok=false")
	}
}

// TestCgroupMemoryUsageBytes_V2EmptyDirFallback covers the cgroupV2Base fallback
// in cgroupMemoryUsageBytes: when CgroupVersion==2 but CgroupV2Dir is empty, the
// function reads from cgroupV2Base ("/sys/fs/cgroup") instead.
func TestCgroupMemoryUsageBytes_V2EmptyDirFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/fs/cgroup/memory.current", []byte("262144000\n"))
	})
	got, ok := cgroupMemoryUsageBytes(platform.ContainerContext{CgroupVersion: 2, CgroupV2Dir: ""})
	if !ok {
		t.Fatal("ok = false, want true (reading from cgroupV2Base fallback)")
	}
	if got != 262144000 {
		t.Errorf("got %d, want 262144000", got)
	}
}

// TestMemoryCollector_Collect_ContainerLimitUsesCgroupUsage is a regression guard:
// before the fix, UsedPct/FreeGB inside a memory-limited container stayed derived
// from host-wide /proc/meminfo while only TotalGB reflected the cgroup limit. Here
// the host reports ~90% used but the container itself is using a small fraction of
// its own (much smaller) limit — the verdict must reflect the CONTAINER's usage.
func TestMemoryCollector_Collect_ContainerLimitUsesCgroupUsage(t *testing.T) {
	meminfo := `MemTotal:       16384000 kB
MemFree:          819200 kB
MemAvailable:    1638400 kB
`
	f, err := os.CreateTemp(t.TempDir(), "meminfo-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(meminfo); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cgDir := t.TempDir()
	// Container is using only 256 MB of its 2048 MB limit.
	if err := os.WriteFile(filepath.Join(cgDir, "memory.current"), []byte("268435456\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &MemoryCollector{
		meminfoPath: f.Name(),
		ContainerCtx: platform.ContainerContext{
			InContainer: true, MemLimitMB: 2048, CgroupVersion: 2, CgroupV2Dir: cgDir,
		},
	}
	out, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	result, ok := out.(*models.MemoryInfo)
	if !ok {
		t.Fatalf("expected *models.MemoryInfo, got %T", out)
	}

	if !result.CgroupMemMeasured {
		t.Fatal("expected CgroupMemMeasured=true when memory.current is readable")
	}
	if result.TotalGB != 2 {
		t.Errorf("TotalGB = %v, want 2 (container limit)", result.TotalGB)
	}
	wantUsedPct := 256.0 / 2048.0 * 100 // 12.5%
	if abs(result.UsedPct-wantUsedPct) > 0.01 {
		t.Errorf("UsedPct = %v, want ~%.1f (from the container's own cgroup usage, NOT the host's ~90%%)", result.UsedPct, wantUsedPct)
	}
}

// TestMemoryCollector_Collect_ContainerLimitUnmeasuredCgroup confirms the honest
// fallback: when the cgroup usage counter isn't readable, TotalGB is still
// overridden to the container limit but CgroupMemMeasured stays false so the
// heuristic knows UsedPct/FreeGB are still host-wide and must not be scored.
func TestMemoryCollector_Collect_ContainerLimitUnmeasuredCgroup(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "meminfo-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("MemTotal: 16384000 kB\nMemAvailable: 1638400 kB\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c := &MemoryCollector{
		meminfoPath: f.Name(),
		ContainerCtx: platform.ContainerContext{
			InContainer: true, MemLimitMB: 2048, CgroupVersion: 2, CgroupV2Dir: filepath.Join(t.TempDir(), "missing"),
		},
	}
	out, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	result := out.(*models.MemoryInfo) //nolint:errcheck // just-checked type above
	if result.CgroupMemMeasured {
		t.Error("expected CgroupMemMeasured=false when memory.current is unreadable")
	}
	if result.TotalGB != 2 {
		t.Errorf("TotalGB = %v, want 2 (container limit still applied)", result.TotalGB)
	}
}
