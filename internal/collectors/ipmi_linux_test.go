//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Real ipmitool sdr format: "Name | value unit | status" (3 columns)
const ipmisdrOK = `Inlet Temp       | 22.000 degrees C  | ok
Exhaust Temp     | 31.000 degrees C  | ok
Temp             | 44.000 degrees C  | ok
Fan1A RPM        | 4080.000 RPM      | ok
Fan2A RPM        | 4080.000 RPM      | ok
PS1 Status       | 0x01              | ok
PS2 Status       | 0x01              | ok
PS1 Input Power  | 84.000 Watts      | ok
Voltage          | 1.792 Volts       | ok
`

const ipmisdrPSUFailed = `Inlet Temp       | 22.000 degrees C  | ok
Fan1A RPM        | 4080.000 RPM      | ok
PS1 Status       | 0x00              | cr
PS2 Status       | 0x01              | ok
`

const ipmisdrFanFailed = `Inlet Temp       | 22.000 degrees C  | ok
Fan1A RPM        | 0.000 RPM         | cr
Fan2A RPM        | 4080.000 RPM      | ok
PS1 Status       | 0x01              | ok
`

func countSensorsByNameAndStatus(sensors []iSensor, nameFragment, status string) int {
	n := 0
	for _, s := range sensors {
		if strings.Contains(strings.ToLower(s.name), nameFragment) && s.status == status {
			n++
		}
	}
	return n
}

type iSensor struct{ name, status string }

func toISensors(out string) []iSensor {
	raw := parseIPMISDR(out)
	result := make([]iSensor, len(raw))
	for i, s := range raw {
		result[i] = iSensor{s.Name, s.Status}
	}
	return result
}

func TestParseIPMISDR(t *testing.T) {
	t.Run("all ok sensors parsed correctly", func(t *testing.T) {
		sensors := parseIPMISDR(ipmisdrOK)
		if len(sensors) == 0 {
			t.Fatal("expected sensors, got none")
		}
		for _, s := range sensors {
			if s.Status != "ok" {
				t.Errorf("sensor %q status = %q, want ok", s.Name, s.Status)
			}
		}
		// Verify temp value parsed
		found := false
		for _, s := range sensors {
			if s.Name == "Inlet Temp" {
				found = true
				if s.Value != 22.0 {
					t.Errorf("Inlet Temp value = %f, want 22.0", s.Value)
				}
			}
		}
		if !found {
			t.Error("Inlet Temp sensor not found")
		}
	})

	t.Run("PSU critical detected", func(t *testing.T) {
		s := toISensors(ipmisdrPSUFailed)
		psuFailed := countSensorsByNameAndStatus(s, "ps", "cr")
		if psuFailed != 1 {
			t.Errorf("PSU cr count = %d, want 1", psuFailed)
		}
	})

	t.Run("fan critical detected", func(t *testing.T) {
		s := toISensors(ipmisdrFanFailed)
		fanFailed := countSensorsByNameAndStatus(s, "fan", "cr")
		if fanFailed != 1 {
			t.Errorf("fan cr count = %d, want 1", fanFailed)
		}
	})

	t.Run("no reading lines skipped", func(t *testing.T) {
		out := "Ghost | no reading | ok\nInlet | 22.000 degrees C | ok\n"
		sensors := parseIPMISDR(out)
		for _, s := range sensors {
			if s.Name == "Ghost" {
				t.Error("'no reading' sensor should be skipped")
			}
		}
	})
}

// TestIsPSUSensor pins the PSU-name matching, incl. the real Dell/Supermicro
// "PS1 Status"/"PS2 Status" form the old substring check missed (so PSU failures
// went unreported). "ups1" must NOT match (it's a UPS, not a PSU).
func TestIsPSUSensor(t *testing.T) {
	for _, n := range []string{"psu1", "power supply 1", "ps1 status", "ps2 status", "pwr ps3"} {
		if !isPSUSensor(n) {
			t.Errorf("isPSUSensor(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"fan1", "inlet temp", "ups1 status", "cpu1 temp"} {
		if isPSUSensor(n) {
			t.Errorf("isPSUSensor(%q) = true, want false", n)
		}
	}
}

// TestNormaliseIPMIStatus guards every branch of the status-code mapping,
// including the substring forms ("non-critical", "non-recoverable") that must
// be checked in the right order relative to "critical" (a naive
// strings.Contains(s, "critical") would also match "non-critical").
func TestNormaliseIPMIStatus(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"ok", "ok"},
		{"OK", "ok"},
		{"nc", "nc"},
		{"non-critical", "nc"},
		{"cr", "cr"},
		{"critical", "cr"},
		{"nr", "nr"},
		{"non-recoverable", "nr"},
		{"ns", "na"},
		{"na", "na"},
		{"n/a", "na"},
		{"weird-status", "weird-status"},
	}
	for _, tc := range cases {
		if got := normaliseIPMIStatus(tc.in); got != tc.want {
			t.Errorf("normaliseIPMIStatus(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIPMICollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewIPMICollector()
	if c.Name() != "IPMI" {
		t.Errorf("Name() = %q, want IPMI", c.Name())
	}
	if c.Timeout() != 8*time.Second {
		t.Errorf("Timeout() = %v, want 8s", c.Timeout())
	}
}

// TestIsIPMIPresent guards the two device-path forms and the not-present case.
func TestIsIPMIPresent(t *testing.T) {
	t.Run("/dev/ipmi0 present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/dev/ipmi0", source.FileMeta{})
		})
		if !IsIPMIPresent() {
			t.Error("expected true when /dev/ipmi0 exists")
		}
	})

	t.Run("/dev/ipmi/0 present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/dev/ipmi/0", source.FileMeta{})
		})
		if !IsIPMIPresent() {
			t.Error("expected true when /dev/ipmi/0 exists")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if IsIPMIPresent() {
			t.Error("expected false when neither IPMI device path exists")
		}
	})
}

// TestIPMICollector_Collect_NotDetected guards the gate-off path: no /dev/ipmi0
// and no ipmitool on PATH must return an empty IPMIInfo{} without running sdr.
func TestIPMICollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("which", []string{"ipmitool"})
	})
	c := NewIPMICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.IPMIInfo)
	if info.Available {
		t.Errorf("expected Available=false when IPMI is not detected, got %+v", info)
	}
}

// TestIPMICollector_Collect_SDRListFullHappyPath exercises the primary
// `ipmitool sdr list full` path with PSU/fan/temp findings all counted.
func TestIPMICollector_Collect_SDRListFullHappyPath(t *testing.T) {
	out := "Inlet Temp     | 55.000 degrees C  | cr\n" +
		"Fan1A RPM      | 0.000 RPM         | cr\n" +
		"PS1 Status     | 0x00              | nr\n" +
		"Voltage        | 1.792 Volts       | ok\n"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/dev/ipmi0", source.FileMeta{})
		b.PutCmd("ipmitool", []string{"sdr", "list", "full"}, out, 0)
	})
	c := NewIPMICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.IPMIInfo)
	if !info.Available {
		t.Fatal("Available = false, want true")
	}
	if info.PSUFailed != 1 {
		t.Errorf("PSUFailed = %d, want 1", info.PSUFailed)
	}
	if info.FanFailed != 1 {
		t.Errorf("FanFailed = %d, want 1", info.FanFailed)
	}
	if info.TempCritical != 1 {
		t.Errorf("TempCritical = %d, want 1", info.TempCritical)
	}
}

// TestIPMICollector_Collect_FallbackToPlainSDR guards the "sdr list full"
// fails, older-ipmitool "sdr" fallback succeeds path.
func TestIPMICollector_Collect_FallbackToPlainSDR(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/dev/ipmi0", source.FileMeta{})
		b.PutCmd("ipmitool", []string{"sdr", "list", "full"}, "", 1)
		b.PutCmd("ipmitool", []string{"sdr"}, "Inlet Temp | 22.000 degrees C | ok\n", 0)
	})
	c := NewIPMICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.IPMIInfo)
	if !info.Available {
		t.Fatal("Available = false, want true (plain sdr fallback should still succeed)")
	}
	if len(info.Sensors) != 1 {
		t.Errorf("expected 1 sensor from the fallback sdr output, got %+v", info.Sensors)
	}
}

// TestIPMICollector_Collect_BothSDRFail guards the both-commands-failed branch:
// which sub-branch fires (NeedsRoot vs a real error Status) depends on the real
// os.Geteuid() with no injectable seam in this file — matching the established
// pattern (see hwraid_linux_test.go / nvme_linux_test.go), the assertion only
// pins the shared invariant that a failed read is flagged one way or the other,
// never a silent healthy verdict.
func TestIPMICollector_Collect_BothSDRFail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/dev/ipmi0", source.FileMeta{})
		b.PutCmd("ipmitool", []string{"sdr", "list", "full"}, "", 1)
		b.PutCmd("ipmitool", []string{"sdr"}, "", 1)
	})
	c := NewIPMICollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.IPMIInfo)
	if info.Available {
		t.Error("Available = true, want false when both sdr reads failed")
	}
	if !info.NeedsRoot && info.Status == "" {
		t.Errorf("expected NeedsRoot or a Status set on a failed read, got %+v (silent healthy verdict)", info)
	}
}
