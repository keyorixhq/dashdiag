//go:build linux

package collectors

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestThermalCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewThermalCollector()
	if c.Name() != "CPU Thermal" {
		t.Errorf("Name() = %q, want CPU Thermal", c.Name())
	}
	if c.Timeout() != 1*time.Second {
		t.Errorf("Timeout() = %v, want 1s", c.Timeout())
	}
	if c.InContainer {
		t.Error("NewThermalCollector() InContainer = true, want false")
	}
	c2 := NewThermalCollectorWithContext(true)
	if !c2.InContainer {
		t.Error("NewThermalCollectorWithContext(true) InContainer = false, want true")
	}
}

func TestThermalCollector_Collect_InContainer(t *testing.T) {
	t.Parallel()
	c := &ThermalCollector{InContainer: true}
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil (host sensors misleading in container)", raw)
	}
}

func TestThermalCollector_Collect_K10TempHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/hwmon/hwmon*", []string{"/sys/class/hwmon/hwmon0"})
		b.PutFile("/sys/class/hwmon/hwmon0/name", []byte("k10temp\n"))
		b.PutGlob("/sys/class/hwmon/hwmon0/temp*_input", []string{
			"/sys/class/hwmon/hwmon0/temp1_input",
			"/sys/class/hwmon/hwmon0/temp2_input",
		})
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_input", []byte("45123\n"))
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_label", []byte("Tctl\n"))
		b.PutFile("/sys/class/hwmon/hwmon0/temp2_input", []byte("40000\n"))
		// temp2_label intentionally unseeded -> synthetic "tempN" label fallback.
	})

	c := NewThermalCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.ThermalInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.ThermalInfo", raw)
	}
	if info.Source != "k10temp" {
		t.Errorf("Source = %q, want k10temp", info.Source)
	}
	if info.CPUTempC != 45.123 {
		t.Errorf("CPUTempC = %v, want 45.123", info.CPUTempC)
	}
	if info.CoreTemps["Tctl"] != 45.123 {
		t.Errorf("CoreTemps[Tctl] = %v, want 45.123", info.CoreTemps["Tctl"])
	}
	if info.CoreTemps["temp2"] != 40.0 {
		t.Errorf("CoreTemps[temp2] = %v, want 40.0 (synthetic label fallback)", info.CoreTemps["temp2"])
	}
}

// TestThermalCollector_Collect_ContextCancelled guards internal-collectors-32-06:
// Collect previously discarded its context entirely (`Collect(_ context.Context)`),
// so an adversarial/pathologically large hwmon tree (or a slow/hanging
// FUSE-based sysfs) could stall the walk past the collector's declared 1s
// Timeout() with no way for the runner to interrupt it. With an ALREADY-
// cancelled context, Collect must return promptly with an error rather than
// walking every hwmon entry to completion.
func TestThermalCollector_Collect_ContextCancelled(t *testing.T) {
	hwmons := make([]string, 200)
	for i := range hwmons {
		hwmons[i] = "/sys/class/hwmon/hwmon" + strconv.Itoa(i)
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/hwmon/hwmon*", hwmons)
		for _, h := range hwmons {
			b.PutFile(h+"/name", []byte("k10temp\n"))
		}
	})

	c := NewThermalCollector()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Collect starts walking hwmon entries

	start := time.Now()
	_, err := c.Collect(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from Collect with an already-cancelled context, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Collect took %v with an already-cancelled context — did not respect cancellation promptly", elapsed)
	}
}

func TestThermalCollector_Collect_ThermalZoneFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/hwmon/hwmon*", []string{}) // no hwmon match
		b.PutGlob("/sys/class/thermal/thermal_zone*/temp", []string{
			"/sys/class/thermal/thermal_zone0/temp",
			"/sys/class/thermal/thermal_zone1/temp",
		})
		b.PutFile("/sys/class/thermal/thermal_zone0/temp", []byte("38000\n"))
		b.PutFile("/sys/class/thermal/thermal_zone1/temp", []byte("52500\n"))
	})

	c := NewThermalCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.ThermalInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.ThermalInfo", raw)
	}
	if info.Source != "thermal_zone" {
		t.Errorf("Source = %q, want thermal_zone", info.Source)
	}
	if info.CPUTempC != 52.5 {
		t.Errorf("CPUTempC = %v, want 52.5 (highest zone wins)", info.CPUTempC)
	}
}

func TestThermalCollector_Collect_NoSensorsFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/hwmon/hwmon*", []string{})
		b.PutGlob("/sys/class/thermal/thermal_zone*/temp", []string{})
	})

	c := NewThermalCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil when no CPU thermal sensor is present", raw)
	}
}

func TestThermalCollector_Collect_UnrecognizedDriverSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/hwmon/hwmon*", []string{"/sys/class/hwmon/hwmon0"})
		b.PutFile("/sys/class/hwmon/hwmon0/name", []byte("nvme\n"))
		b.PutGlob("/sys/class/thermal/thermal_zone*/temp", []string{})
	})

	c := NewThermalCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil (nvme is not a recognized CPU sensor driver)", raw)
	}
}

func TestReadHwmonTemps_BadValueSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/hwmon/hwmon0/temp*_input", []string{
			"/sys/class/hwmon/hwmon0/temp1_input",
			"/sys/class/hwmon/hwmon0/temp2_input",
		})
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_input", []byte("not-a-number\n"))
		b.PutFile("/sys/class/hwmon/hwmon0/temp2_input", []byte("30000\n"))
		b.PutFile("/sys/class/hwmon/hwmon0/temp2_label", []byte("Package id 0\n"))
	})
	info := &models.ThermalInfo{CoreTemps: make(map[string]float64)}
	readHwmonTemps(context.Background(), "/sys/class/hwmon/hwmon0", info)
	if _, ok := info.CoreTemps["temp1"]; ok {
		t.Error("a non-numeric temp*_input value must be skipped, not recorded")
	}
	if info.CoreTemps["Package id 0"] != 30.0 {
		t.Errorf("CoreTemps[Package id 0] = %v, want 30.0", info.CoreTemps["Package id 0"])
	}
	if info.CPUTempC != 30.0 {
		t.Errorf("CPUTempC = %v, want 30.0 ('Package id 0' label sets CPUTempC)", info.CPUTempC)
	}
}

func TestReadSensorLabel(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_label", []byte("  Tdie  \n"))
	})
	if got := readSensorLabel("/sys/class/hwmon/hwmon0/temp1_label"); got != "Tdie" {
		t.Errorf("readSensorLabel() = %q, want Tdie", got)
	}
	if got := readSensorLabel("/sys/class/hwmon/hwmon0/missing_label"); got != "" {
		t.Errorf("readSensorLabel(missing) = %q, want empty", got)
	}
}

// TestReadSensorLabel_SanitizesControlChars is the regression test for
// internal-collectors-32-07: the raw sysfs label is used both as an
// info.CoreTemps map key and eventual display data, so it must have
// control/ANSI bytes stripped before being returned.
func TestReadSensorLabel_SanitizesControlChars(t *testing.T) {
	esc := string(rune(27))
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_label", []byte("Tdie"+esc+"[31m\n"))
	})
	if got := readSensorLabel("/sys/class/hwmon/hwmon0/temp1_label"); got != "Tdie[31m" {
		t.Errorf("readSensorLabel() = %q, want ESC stripped to Tdie[31m", got)
	}
}

func TestReadThermalZone_BadValueSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/thermal/thermal_zone*/temp", []string{
			"/sys/class/thermal/thermal_zone0/temp",
			"/sys/class/thermal/thermal_zone1/temp",
		})
		b.PutFile("/sys/class/thermal/thermal_zone0/temp", []byte("garbage\n"))
		b.PutFile("/sys/class/thermal/thermal_zone1/temp", []byte("41000\n"))
	})
	info := &models.ThermalInfo{CoreTemps: make(map[string]float64)}
	readThermalZone(context.Background(), info)
	if info.CPUTempC != 41.0 {
		t.Errorf("CPUTempC = %v, want 41.0 (garbage zone skipped)", info.CPUTempC)
	}
	if info.Source != "thermal_zone" {
		t.Errorf("Source = %q, want thermal_zone", info.Source)
	}
}

// TestReadThermalZone_ReadErrorSkipped covers line 117-118: readFile on a zone
// temp file fails (unseeded path) → continue to the next zone.
func TestReadThermalZone_ReadErrorSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/thermal/thermal_zone*/temp", []string{
			"/sys/class/thermal/thermal_zone0/temp",
			"/sys/class/thermal/thermal_zone1/temp",
		})
		// zone0 temp NOT seeded → readFile returns ErrNotRecorded → continue
		b.PutFile("/sys/class/thermal/thermal_zone1/temp", []byte("55000\n"))
	})
	info := &models.ThermalInfo{CoreTemps: make(map[string]float64)}
	readThermalZone(context.Background(), info)
	if info.CPUTempC != 55.0 {
		t.Errorf("CPUTempC = %v, want 55.0 (failed zone skipped, second zone read)", info.CPUTempC)
	}
}

// TestReadHwmonTemps_ReadErrorSkipped covers line 80-81: readFile on a temp*_input
// file fails (unseeded path) → continue to the next sensor.
func TestReadHwmonTemps_ReadErrorSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/hwmon/hwmon0/temp*_input", []string{
			"/sys/class/hwmon/hwmon0/temp1_input",
			"/sys/class/hwmon/hwmon0/temp2_input",
		})
		// temp1_input NOT seeded → readFile fails → continue
		b.PutFile("/sys/class/hwmon/hwmon0/temp2_input", []byte("62000\n"))
		b.PutFile("/sys/class/hwmon/hwmon0/temp2_label", []byte("Tdie\n"))
	})
	info := &models.ThermalInfo{CoreTemps: make(map[string]float64)}
	readHwmonTemps(context.Background(), "/sys/class/hwmon/hwmon0", info)
	if info.CPUTempC != 62.0 {
		t.Errorf("CPUTempC = %v, want 62.0 (failed sensor skipped, second sensor read)", info.CPUTempC)
	}
	if _, bad := info.CoreTemps["temp1"]; bad {
		t.Error("failed-to-read sensor must not appear in CoreTemps")
	}
}

// TestThermalCollector_Collect_HwmonNameReadError covers line 46-47: readFile on
// the hwmon "name" file fails → continue to the next hwmon device.
func TestThermalCollector_Collect_HwmonNameReadError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/hwmon/hwmon*", []string{"/sys/class/hwmon/hwmon0"})
		// hwmon0/name NOT seeded → readFile returns error → continue
		// No thermal_zone either → no CPU sensor → nil result
		b.PutGlob("/sys/class/thermal/thermal_zone*/temp", []string{})
	})
	c := NewThermalCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil (hwmon name unreadable, no fallback)", raw)
	}
}
