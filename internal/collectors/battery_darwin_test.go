//go:build darwin

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestBatteryCollector_Collect_IoregFails is the regression test for the
// false-OK fix: a genuine ioreg exec failure must set StatusReason so
// checkBattery can distinguish it from the legitimate "no AppleSmartBattery
// service" (desktop Mac) case — both previously returned an identical
// &models.BatteryInfo{} with Present=false and no explanation.
func TestBatteryCollector_Collect_IoregFails(t *testing.T) {
	prev := SetSource(source.NewReplay(source.NewBundle())) // no PutCmd seeded → command errors as not-recorded
	t.Cleanup(func() { SetSource(prev) })

	c := &BatteryCollector{}
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.BatteryInfo)
	if info.Present {
		t.Error("Present = true, want false")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when ioreg fails to run")
	}
}

// TestBatteryCollector_Collect_NoBatteryService is the control: a clean exit
// with empty output (genuinely no AppleSmartBattery service, e.g. Mac
// Studio/mini) must NOT set StatusReason — that's the legitimate absence
// case, distinct from a read failure.
func TestBatteryCollector_Collect_NoBatteryService(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("ioreg", []string{"-rn", "AppleSmartBattery"}, "", 0)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	c := &BatteryCollector{}
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.BatteryInfo)
	if info.Present {
		t.Error("Present = true, want false")
	}
	if info.StatusReason != "" {
		t.Errorf("StatusReason = %q, want empty for the genuine no-battery-service case", info.StatusReason)
	}
}

// TestBatteryCollector_Collect_MissingCurrentCapacity covers the malformed-
// output failure mode: ioreg exits 0 with non-empty output, but the expected
// CurrentCapacity field is absent.
func TestBatteryCollector_Collect_MissingCurrentCapacity(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("ioreg", []string{"-rn", "AppleSmartBattery"}, "  | |   \"SomeOtherKey\" = 1\n", 0)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	c := &BatteryCollector{}
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.BatteryInfo)
	if info.Present {
		t.Error("Present = true, want false")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when CurrentCapacity is missing from non-empty output")
	}
}
