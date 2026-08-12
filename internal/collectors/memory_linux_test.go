//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestMemoryCollector_Collect_PreKernel314NoMemAvailable is a regression guard
// for the pre-3.14-kernel fallback: when /proc/meminfo lacks MemAvailable,
// Collect must approximate it from MemFree+Buffers+Cached+SReclaimable
// (matching gopsutil) rather than leaving FreeGB/UsedPct at a wrong value.
func TestMemoryCollector_Collect_PreKernel314NoMemAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/meminfo", []byte(
			"MemTotal:       16384000 kB\n"+
				"MemFree:         1000000 kB\n"+
				"Buffers:          500000 kB\n"+
				"Cached:          2000000 kB\n"+
				"SReclaimable:     500000 kB\n"))
		b.PutGlob("/sys/devices/system/edac/mc", nil)
	})
	c := NewMemoryCollector(platform.ContainerContext{})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info, ok := raw.(*models.MemoryInfo)
	if !ok {
		t.Fatalf("unexpected type %T", raw)
	}
	// avail = 1000000+500000+2000000+500000 = 4000000 kB
	wantFreeGB := 4000000.0 / (1024 * 1024)
	if info.FreeGB < wantFreeGB-0.01 || info.FreeGB > wantFreeGB+0.01 {
		t.Errorf("FreeGB = %v, want ~%v (approximated MemAvailable)", info.FreeGB, wantFreeGB)
	}
	wantUsedPct := (16384000.0 - 4000000.0) / 16384000.0 * 100
	if info.UsedPct < wantUsedPct-0.01 || info.UsedPct > wantUsedPct+0.01 {
		t.Errorf("UsedPct = %v, want ~%v", info.UsedPct, wantUsedPct)
	}
}

// TestMemoryCollector_Collect_ContainerFreeGBClampsAtZero is a regression
// guard: when the container's cgroup usage counter reports MORE bytes used
// than the container's own memory limit (a momentary accounting skew right at
// the limit), FreeGB must clamp to 0 rather than go negative.
func TestMemoryCollector_Collect_ContainerFreeGBClampsAtZero(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/meminfo", []byte(
			"MemTotal:       16384000 kB\n"+
				"MemFree:         8000000 kB\n"+
				"MemAvailable:    8000000 kB\n"))
		b.PutGlob("/sys/devices/system/edac/mc", nil)
		// Container limited to 1GB, but cgroup reports 2GB used (over the limit).
		b.PutFile("/sys/fs/cgroup/memory.current", []byte("2147483648\n"))
	})
	c := NewMemoryCollector(platform.ContainerContext{
		InContainer:   true,
		MemLimitMB:    1024,
		CgroupVersion: 2,
		CgroupV2Dir:   "/sys/fs/cgroup",
	})
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info, ok := raw.(*models.MemoryInfo)
	if !ok {
		t.Fatalf("unexpected type %T", raw)
	}
	if !info.CgroupMemMeasured {
		t.Fatal("expected CgroupMemMeasured=true when the cgroup counter was readable")
	}
	if info.FreeGB != 0 {
		t.Errorf("FreeGB = %v, want 0 (clamped, usage exceeded the container limit)", info.FreeGB)
	}
	if info.TotalGB != 1 {
		t.Errorf("TotalGB = %v, want 1 (container limit overrides host total)", info.TotalGB)
	}
}

// TestMemoryCollector_Collect_MeminfoUnreadableNoLiveFallback covers
// internal-collectors-20-04. It supersedes the old
// TestMemoryCollector_Collect_GopsutilFallback, which asserted the OPPOSITE
// (buggy) behavior: on Linux, an unreadable /proc/meminfo used to fall
// through to a gopsutil live read via cachedJSON. Under `dsd replay` that read
// is routed through the Source too, so a replay bundle that simply never
// recorded /proc/meminfo (trimmed, corrupted, or hand-edited) landed on the
// SAME gopsutil branch and, if the bundle also lacked a recorded
// "gopsutil/mem/virtual" entry, either errored opaquely or — worse, on a bundle
// that happened to have stale gopsutil data recorded from a different run —
// silently reported those numbers as if they were live-verified. Collect must
// instead report MeminfoUnreadable and leave Total/Free/UsedPct at zero;
// gopsutil is Linux-reachable only through the (now removed) fallback branch,
// so this also drops the gopsutil-specific imports/helpers used only by that
// path.
func TestMemoryCollector_Collect_MeminfoUnreadableNoLiveFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/devices/system/edac/mc", nil)
		// Deliberately no /proc/meminfo file seeded: ReadFile fails, simulating
		// an incomplete replay bundle.
	})

	c := &MemoryCollector{meminfoPath: "/proc/meminfo", ContainerCtx: platform.ContainerContext{}}
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info, ok := raw.(*models.MemoryInfo)
	if !ok {
		t.Fatalf("unexpected type %T", raw)
	}
	if !info.MeminfoUnreadable {
		t.Error("expected MeminfoUnreadable=true when meminfo was never recorded in the replay bundle")
	}
	if info.TotalGB != 0 || info.FreeGB != 0 || info.UsedPct != 0 {
		t.Errorf("expected zero-valued Total/Free/UsedPct on unreadable meminfo, got %+v", info)
	}
}
