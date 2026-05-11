//go:build darwin

package collectors

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// BatteryCollector reads battery health from IOKit via ioreg on macOS.
// ioreg -rn AppleSmartBattery runs in ~22ms.
type BatteryCollector struct{}

func NewBatteryCollector() *BatteryCollector { return &BatteryCollector{} }

func (c *BatteryCollector) Name() string           { return "Battery" }
func (c *BatteryCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *BatteryCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.BatteryInfo{}

	out, err := runCmd(ctx, "ioreg", "-rn", "AppleSmartBattery")
	if err != nil || out == "" {
		return info, nil
	}

	kv := parseIORegKV(out)
	if kv["CurrentCapacity"] == "" {
		return info, nil
	}

	info.Present = true
	info.CapacityPct = ioregInt(kv["CurrentCapacity"])
	info.CycleCounts = ioregInt(kv["CycleCount"])
	info.EnergyFullUWh = int64(ioregInt(kv["AppleRawMaxCapacity"]))
	info.EnergyDesignUWh = int64(ioregInt(kv["DesignCapacity"]))
	info.EnergyNowUWh = int64(ioregInt(kv["AppleRawCurrentCapacity"]))
	info.VoltageUV = int64(ioregInt(kv["Voltage"]))

	switch {
	case kv["IsCharging"] == "Yes":
		info.Status = "Charging"
	case kv["FullyCharged"] == "Yes":
		info.Status = "Full"
	default:
		info.Status = "Discharging"
	}

	if info.EnergyDesignUWh > 0 {
		info.HealthPct = float64(info.EnergyFullUWh) / float64(info.EnergyDesignUWh) * 100
	}

	return info, nil
}

// parseIORegKV parses ioreg output into a key-value map.
// ioreg lines look like: `    | |   |       "CycleCount" = 161`
func parseIORegKV(out string) map[string]string {
	kv := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		// Strip ioreg tree formatting (pipes, spaces) before first quote
		idx := strings.Index(line, "\"")
		if idx < 0 {
			continue
		}
		line = line[idx:]
		eqIdx := strings.Index(line, " = ")
		if eqIdx < 0 {
			continue
		}
		key := strings.Trim(line[:eqIdx], "\"")
		val := strings.TrimSpace(line[eqIdx+3:])
		if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
			val = val[1 : len(val)-1]
		}
		if _, exists := kv[key]; !exists {
			kv[key] = val
		}
	}
	return kv
}

func ioregInt(s string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}
