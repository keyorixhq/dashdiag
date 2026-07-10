//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestCPUFreqCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewCPUFreqCollector()
	if c.Name() != "CPUFreq" {
		t.Errorf("Name() = %q, want CPUFreq", c.Name())
	}
	if c.Timeout() <= 0 {
		t.Errorf("Timeout() = %v, want > 0", c.Timeout())
	}
}

// TestCPUFreqCollector_Collect_Absent guards the "no cpufreq" gate: an empty
// scaling_governor read means cpufreq is unavailable (VM/container/old
// kernel) — Collect must return the zero-value info without erroring.
func TestCPUFreqCollector_Collect_Absent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// scaling_governor deliberately not seeded -> readSysfsStr returns "".
	})
	c := NewCPUFreqCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.CPUFreqInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.CPUFreqInfo", raw)
	}
	if info.Governor != "" {
		t.Errorf("Governor = %q, want empty", info.Governor)
	}
}

// TestCPUFreqCollector_Collect_FullFixture exercises every populated field:
// governor, driver, current/max/min frequency (kHz -> MHz), CPU count from
// the glob, battery detection (BAT* form), and the derived throttle percent.
func TestCPUFreqCollector_Collect_FullFixture(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		base := "/sys/devices/system/cpu/cpu0/cpufreq"
		b.PutFile(base+"/scaling_governor", []byte("powersave\n"))
		b.PutFile(base+"/scaling_driver", []byte("intel_pstate\n"))
		b.PutFile(base+"/scaling_cur_freq", []byte("2400000\n"))
		b.PutFile(base+"/cpuinfo_max_freq", []byte("4800000\n"))
		b.PutFile(base+"/cpuinfo_min_freq", []byte("400000\n"))
		b.PutGlob("/sys/devices/system/cpu/cpu[0-9]*", []string{
			"/sys/devices/system/cpu/cpu0",
			"/sys/devices/system/cpu/cpu1",
			"/sys/devices/system/cpu/cpu2",
			"/sys/devices/system/cpu/cpu3",
		})
		b.PutGlob("/sys/class/power_supply/BAT*", []string{"/sys/class/power_supply/BAT0"})
	})
	c := NewCPUFreqCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CPUFreqInfo)
	if info.Governor != "powersave" {
		t.Errorf("Governor = %q, want powersave", info.Governor)
	}
	if info.ScalingDriver != "intel_pstate" {
		t.Errorf("ScalingDriver = %q, want intel_pstate", info.ScalingDriver)
	}
	if info.CurrentMHz != 2400 {
		t.Errorf("CurrentMHz = %d, want 2400", info.CurrentMHz)
	}
	if info.MaxMHz != 4800 {
		t.Errorf("MaxMHz = %d, want 4800", info.MaxMHz)
	}
	if info.MinMHz != 400 {
		t.Errorf("MinMHz = %d, want 400", info.MinMHz)
	}
	if info.CPUCount != 4 {
		t.Errorf("CPUCount = %d, want 4", info.CPUCount)
	}
	if !info.HasBattery {
		t.Error("HasBattery = false, want true (BAT0 present)")
	}
	// (4800-2400)/4800*100 = 50%
	if info.ThrottledPct < 49.9 || info.ThrottledPct > 50.1 {
		t.Errorf("ThrottledPct = %v, want ~50", info.ThrottledPct)
	}
}

// TestCPUFreqCollector_Collect_BatteryAltPath guards the second battery glob
// fallback ("battery" singular, e.g. some ACPI-non-standard layouts) when the
// BAT* glob yields nothing.
func TestCPUFreqCollector_Collect_BatteryAltPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		base := "/sys/devices/system/cpu/cpu0/cpufreq"
		b.PutFile(base+"/scaling_governor", []byte("performance\n"))
		b.PutGlob("/sys/class/power_supply/BAT*", nil)
		b.PutGlob("/sys/class/power_supply/battery", []string{"/sys/class/power_supply/battery"})
	})
	c := NewCPUFreqCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CPUFreqInfo)
	if !info.HasBattery {
		t.Error("HasBattery = false, want true (battery singular glob present)")
	}
}

// TestCPUFreqCollector_Collect_NoBattery guards the server/desktop case: no
// battery glob matches at all -> HasBattery stays false, and with no max/cur
// freq seeded, ThrottledPct stays at its zero value (guard against
// division-by-zero panics with MaxMHz==0).
func TestCPUFreqCollector_Collect_NoBattery(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		base := "/sys/devices/system/cpu/cpu0/cpufreq"
		b.PutFile(base+"/scaling_governor", []byte("schedutil\n"))
		b.PutGlob("/sys/class/power_supply/BAT*", nil)
		b.PutGlob("/sys/class/power_supply/battery", nil)
	})
	c := NewCPUFreqCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CPUFreqInfo)
	if info.HasBattery {
		t.Error("HasBattery = true, want false")
	}
	if info.ThrottledPct != 0 {
		t.Errorf("ThrottledPct = %v, want 0 (no max/current freq seeded)", info.ThrottledPct)
	}
}

func TestIsCPUFreqAvailable(t *testing.T) {
	t.Run("available", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/sys/devices/system/cpu/cpu0/cpufreq", source.FileMeta{IsDir: true, Mode: 0o755})
		})
		if !IsCPUFreqAvailable() {
			t.Error("IsCPUFreqAvailable() = false, want true")
		}
	})
	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			// Not seeded at all -> Replay.Stat returns ErrNotRecorded, which is
			// neither nil nor fs.ErrPermission, so fileExists() reports false.
		})
		if IsCPUFreqAvailable() {
			t.Error("IsCPUFreqAvailable() = true, want false")
		}
	})
}

func TestReadSysfsKHz(t *testing.T) {
	t.Run("valid value", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", []byte("3200000\n"))
		})
		if got := readSysfsKHz("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"); got != 3200000 {
			t.Errorf("readSysfsKHz() = %d, want 3200000", got)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if got := readSysfsKHz("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"); got != 0 {
			t.Errorf("readSysfsKHz() = %d, want 0", got)
		}
	})
}
