//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"testing"

	gopsutilmem "github.com/shirou/gopsutil/v3/mem"

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

// TestMemoryCollector_Collect_GopsutilFallback guards the non-Linux/no-
// /proc/meminfo branch: when meminfo can't be read (MemTotal stays 0), Collect
// must fall back to gopsutil's VirtualMemory, routed through cachedJSON so the
// value comes from the seeded "gopsutil/mem/virtual" fixture rather than a
// live re-read of this test host's real RAM.
func TestMemoryCollector_Collect_GopsutilFallback(t *testing.T) {
	vm := gopsutilmem.VirtualMemoryStat{
		Total:       8 * 1024 * 1024 * 1024,
		Available:   2 * 1024 * 1024 * 1024,
		UsedPercent: 75,
	}
	vmJSON, err := json.Marshal(vm)
	if err != nil {
		t.Fatalf("marshaling VirtualMemoryStat fixture: %v", err)
	}
	withCombinedFixture(t, map[string][]byte{
		"gopsutil/mem/virtual": vmJSON,
	}, nil, func(b *source.Bundle) {
		b.PutGlob("/sys/devices/system/edac/mc", nil)
		// Deliberately no /proc/meminfo file seeded: ReadFile must fail so
		// Collect falls through to the gopsutil branch.
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
	if want := 8.0; info.TotalGB != want {
		t.Errorf("TotalGB = %v, want %v (from the seeded gopsutil fixture, not real /proc/meminfo)", info.TotalGB, want)
	}
	if want := 2.0; info.FreeGB != want {
		t.Errorf("FreeGB = %v, want %v", info.FreeGB, want)
	}
	if info.UsedPct != 75 {
		t.Errorf("UsedPct = %v, want 75", info.UsedPct)
	}
}
