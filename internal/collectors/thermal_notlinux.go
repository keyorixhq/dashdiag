//go:build darwin

package collectors

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ThermalCollector reads CPU temperature on macOS.
// Sources tried in order:
//  1. X86PlatformPlugin  — Intel Macs: "CPU Die Temperature" directly in °C
//  2. AppleSmartBattery  — all Macs: battery temp proxy (0.01°C units)
//
// Apple Silicon CPU die temp requires root (powermetrics) — not attempted here.
type ThermalCollector struct {
	InContainer bool
}

func NewThermalCollector() *ThermalCollector { return &ThermalCollector{} }
func NewThermalCollectorWithContext(inContainer bool) *ThermalCollector {
	return &ThermalCollector{InContainer: inContainer}
}
func (c *ThermalCollector) Name() string           { return "CPU Thermal" }
func (c *ThermalCollector) Timeout() time.Duration { return 4 * time.Second }

func (c *ThermalCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ThermalInfo{Available: true}

	// Source 1: Intel — X86PlatformPlugin has "CPU Die Temperature" in °C
	if temp := intelCPUTemp(ctx); temp > 0 {
		info.CPUTempC = temp
		info.Source = "X86PlatformPlugin"
		return info, nil
	}

	// Source 2: Battery temperature proxy (Apple Silicon + Intel, no root)
	// AppleSmartBattery "Temperature" is in 0.01°C units.
	// Not the CPU die, but correlates with load and is better than nothing.
	if temp := batteryTempProxy(ctx); temp > 0 {
		info.CPUTempC = temp
		info.Source = "battery-proxy"
		return info, nil
	}

	// No temperature accessible without root on this platform
	info.Available = false
	return info, nil
}

// intelCPUTemp reads CPU Die Temperature from X86PlatformPlugin (Intel Macs).
func intelCPUTemp(ctx context.Context) float64 {
	out, err := runCmd(ctx, "ioreg", "-rn", "X86PlatformPlugin")
	if err != nil || out == "" {
		return 0
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "CPU Die Temperature") {
			if eq := strings.Index(line, " = "); eq >= 0 {
				if v, err := strconv.ParseFloat(strings.TrimSpace(line[eq+3:]), 64); err == nil && v > 0 {
					return v
				}
			}
		}
	}
	return 0
}

// batteryTempProxy reads battery temperature from AppleSmartBattery.
// Value is in 0.01°C. Not CPU die temperature but available without root on all Macs.
func batteryTempProxy(ctx context.Context) float64 {
	out, err := runCmd(ctx, "ioreg", "-rn", "AppleSmartBattery")
	if err != nil || out == "" {
		return 0
	}
	raw := ioregInt(parseIORegKV(out)["Temperature"])
	if raw <= 0 {
		return 0
	}
	return float64(raw) / 100.0
}

// parseDarwinThermalOutput is used by unit tests.
func parseDarwinThermalOutput(x86Out, battOut string) float64 {
	for _, line := range strings.Split(x86Out, "\n") {
		if strings.Contains(line, "CPU Die Temperature") {
			if eq := strings.Index(line, " = "); eq >= 0 {
				if v, err := strconv.ParseFloat(strings.TrimSpace(line[eq+3:]), 64); err == nil && v > 0 {
					return v
				}
			}
		}
	}
	kv := parseIORegKV(battOut)
	if raw := ioregInt(kv["Temperature"]); raw > 0 {
		return float64(raw) / 100.0
	}
	return 0
}
