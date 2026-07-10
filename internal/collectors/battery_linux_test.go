//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestBatteryCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewBatteryCollector()
	if c.Name() != "Battery" {
		t.Errorf("Name() = %q, want Battery", c.Name())
	}
	if c.Timeout() <= 0 {
		t.Errorf("Timeout() = %v, want > 0", c.Timeout())
	}
}

// TestBatteryCollector_Collect_NoSupplies guards the gate-off case: no BAT*
// and no "battery" power_supply entries -> Collect returns (nil, nil), never
// a phantom "Battery OK" row on servers/desktops.
func TestBatteryCollector_Collect_NoSupplies(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/power_supply/BAT*", nil)
		b.PutGlob("/sys/class/power_supply/battery", nil)
	})
	c := NewBatteryCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil", raw)
	}
}

// TestBatteryCollector_Collect_BatteryBayEmpty guards the "present bay,
// present=0" branch: the BAT0 directory exists (i.e. globbed) but the
// battery itself is not physically inserted -> gate off to nil, not a
// zero-value BatteryInfo (which would misreport 0% capacity as real).
func TestBatteryCollector_Collect_BatteryBayEmpty(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/power_supply/BAT*", []string{"/sys/class/power_supply/BAT0"})
		b.PutFile("/sys/class/power_supply/BAT0/present", []byte("0\n"))
	})
	c := NewBatteryCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil (bay present but battery absent)", raw)
	}
}

// TestBatteryCollector_Collect_FullFixture exercises every populated field
// including the derived HealthPct.
func TestBatteryCollector_Collect_FullFixture(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/power_supply/BAT*", []string{"/sys/class/power_supply/BAT0"})
		bat := "/sys/class/power_supply/BAT0"
		b.PutFile(bat+"/present", []byte("1\n"))
		b.PutFile(bat+"/status", []byte("Discharging\n"))
		b.PutFile(bat+"/capacity", []byte("87\n"))
		b.PutFile(bat+"/energy_now", []byte("45000000\n"))
		b.PutFile(bat+"/energy_full", []byte("50000000\n"))
		b.PutFile(bat+"/energy_full_design", []byte("60000000\n"))
		b.PutFile(bat+"/cycle_count", []byte("312\n"))
		b.PutFile(bat+"/voltage_now", []byte("11800000\n"))
		b.PutFile(bat+"/power_now", []byte("8500000\n"))
		b.PutFile(bat+"/manufacturer", []byte("SMP\n"))
		b.PutFile(bat+"/model_name", []byte("DELL ABCD1234\n"))
	})
	c := NewBatteryCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.BatteryInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.BatteryInfo", raw)
	}
	if !info.Present {
		t.Error("Present = false, want true")
	}
	if info.Status != "Discharging" {
		t.Errorf("Status = %q, want Discharging", info.Status)
	}
	if info.CapacityPct != 87 {
		t.Errorf("CapacityPct = %d, want 87", info.CapacityPct)
	}
	if info.EnergyNowUWh != 45000000 || info.EnergyFullUWh != 50000000 || info.EnergyDesignUWh != 60000000 {
		t.Errorf("energy fields = %d/%d/%d, want 45000000/50000000/60000000",
			info.EnergyNowUWh, info.EnergyFullUWh, info.EnergyDesignUWh)
	}
	if info.CycleCounts != 312 {
		t.Errorf("CycleCounts = %d, want 312", info.CycleCounts)
	}
	if info.VoltageUV != 11800000 || info.PowerNowUW != 8500000 {
		t.Errorf("VoltageUV/PowerNowUW = %d/%d, want 11800000/8500000", info.VoltageUV, info.PowerNowUW)
	}
	if info.Manufacturer != "SMP" || info.ModelName != "DELL ABCD1234" {
		t.Errorf("Manufacturer/ModelName = %q/%q, want SMP/DELL ABCD1234", info.Manufacturer, info.ModelName)
	}
	// 50000000/60000000*100 = 83.33...
	if info.HealthPct < 83.2 || info.HealthPct > 83.4 {
		t.Errorf("HealthPct = %v, want ~83.33", info.HealthPct)
	}
}

// TestBatteryCollector_Collect_AltBatteryGlobPath guards the secondary glob
// fallback ("battery" singular) when the BAT* glob yields nothing.
func TestBatteryCollector_Collect_AltBatteryGlobPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/power_supply/BAT*", nil)
		b.PutGlob("/sys/class/power_supply/battery", []string{"/sys/class/power_supply/battery"})
		bat := "/sys/class/power_supply/battery"
		b.PutFile(bat+"/present", []byte("1\n"))
		b.PutFile(bat+"/capacity", []byte("50\n"))
	})
	c := NewBatteryCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.BatteryInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.BatteryInfo", raw)
	}
	if !info.Present || info.CapacityPct != 50 {
		t.Errorf("Present/CapacityPct = %v/%d, want true/50", info.Present, info.CapacityPct)
	}
}

// TestBatteryCollector_Collect_NoEnergyDesign guards the HealthPct
// division-by-zero guard: when energy_full_design is absent/zero,
// HealthPct must stay at its zero value rather than computing NaN/Inf.
func TestBatteryCollector_Collect_NoEnergyDesign(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/power_supply/BAT*", []string{"/sys/class/power_supply/BAT0"})
		bat := "/sys/class/power_supply/BAT0"
		b.PutFile(bat+"/present", []byte("1\n"))
		b.PutFile(bat+"/energy_full", []byte("50000000\n"))
		// energy_full_design intentionally not seeded -> readBatInt returns 0.
	})
	c := NewBatteryCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.BatteryInfo)
	if info.HealthPct != 0 {
		t.Errorf("HealthPct = %v, want 0", info.HealthPct)
	}
}

func TestReadBatString(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/class/power_supply/BAT0/manufacturer", []byte("  SMP  \n"))
		})
		if got := readBatString("/sys/class/power_supply/BAT0", "manufacturer"); got != "SMP" {
			t.Errorf("readBatString() = %q, want SMP (trimmed)", got)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if got := readBatString("/sys/class/power_supply/BAT0", "manufacturer"); got != "" {
			t.Errorf("readBatString() = %q, want empty", got)
		}
	})
}

func TestReadBatInt(t *testing.T) {
	t.Run("valid value", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/class/power_supply/BAT0/cycle_count", []byte("312\n"))
		})
		if got := readBatInt("/sys/class/power_supply/BAT0", "cycle_count"); got != 312 {
			t.Errorf("readBatInt() = %d, want 312", got)
		}
	})
	t.Run("missing file returns 0", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if got := readBatInt("/sys/class/power_supply/BAT0", "cycle_count"); got != 0 {
			t.Errorf("readBatInt() = %d, want 0", got)
		}
	})
	t.Run("garbled value returns 0", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/class/power_supply/BAT0/cycle_count", []byte("not-a-number\n"))
		})
		if got := readBatInt("/sys/class/power_supply/BAT0", "cycle_count"); got != 0 {
			t.Errorf("readBatInt() = %d, want 0", got)
		}
	})
}
