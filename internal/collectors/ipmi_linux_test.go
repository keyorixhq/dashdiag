//go:build linux

package collectors

import (
	"strings"
	"testing"
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
