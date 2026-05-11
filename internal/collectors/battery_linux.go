//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// BatteryCollector reads battery health directly from /sys/class/power_supply/.
// All data is in kernel sysfs — no external tools needed.
type BatteryCollector struct{}

func NewBatteryCollector() *BatteryCollector { return &BatteryCollector{} }

func (c *BatteryCollector) Name() string           { return "Battery" }
func (c *BatteryCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *BatteryCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.BatteryInfo{}

	// Find first battery
	supplies, _ := filepath.Glob("/sys/class/power_supply/BAT*")
	if len(supplies) == 0 {
		supplies, _ = filepath.Glob("/sys/class/power_supply/battery")
	}
	if len(supplies) == 0 {
		return info, nil // no battery — desktop system
	}

	bat := supplies[0]
	info.Present = readBatString(bat, "present") == "1"
	if !info.Present {
		return info, nil
	}

	info.Status = readBatString(bat, "status")
	info.CapacityPct = int(readBatInt(bat, "capacity"))
	info.EnergyNowUWh = readBatInt(bat, "energy_now")
	info.EnergyFullUWh = readBatInt(bat, "energy_full")
	info.EnergyDesignUWh = readBatInt(bat, "energy_full_design")
	info.CycleCounts = int(readBatInt(bat, "cycle_count"))
	info.VoltageUV = readBatInt(bat, "voltage_now")
	info.PowerNowUW = readBatInt(bat, "power_now")
	info.Manufacturer = readBatString(bat, "manufacturer")
	info.ModelName = readBatString(bat, "model_name")

	// Calculate health percentage
	if info.EnergyDesignUWh > 0 {
		info.HealthPct = float64(info.EnergyFullUWh) / float64(info.EnergyDesignUWh) * 100
	}

	return info, nil
}

func readBatString(base, file string) string {
	data, err := os.ReadFile(filepath.Join(base, file)) // #nosec G304 -- sysfs path
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readBatInt(base, file string) int64 {
	s := readBatString(base, file)
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}
