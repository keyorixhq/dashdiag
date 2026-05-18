//go:build darwin

package collectors

import "testing"

const x86ThermalOutput = `
    | |   "CPU Die Temperature" = 52
    | |   "GPU Die Temperature" = 43
`

const batteryThermalOutput = `
      "Temperature" = 3025
      "Voltage" = 12205
`

func TestParseDarwinThermalOutput(t *testing.T) {
	t.Run("Intel: reads CPU Die Temperature", func(t *testing.T) {
		temp := parseDarwinThermalOutput(x86ThermalOutput, "")
		if temp != 52 {
			t.Errorf("got %.1f, want 52", temp)
		}
	})

	t.Run("Apple Silicon: falls back to battery proxy", func(t *testing.T) {
		// No X86PlatformPlugin output — falls back to battery
		temp := parseDarwinThermalOutput("", batteryThermalOutput)
		// 3025 * 0.01 = 30.25
		if temp < 30.0 || temp > 31.0 {
			t.Errorf("got %.2f, want ~30.25", temp)
		}
	})

	t.Run("Intel takes priority over battery", func(t *testing.T) {
		temp := parseDarwinThermalOutput(x86ThermalOutput, batteryThermalOutput)
		if temp != 52 {
			t.Errorf("got %.1f, want 52 (X86 should win)", temp)
		}
	})

	t.Run("no data returns 0", func(t *testing.T) {
		temp := parseDarwinThermalOutput("", "")
		if temp != 0 {
			t.Errorf("got %.1f, want 0", temp)
		}
	})
}
