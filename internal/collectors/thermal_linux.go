//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ThermalCollector reads CPU temperature directly from sysfs hwmon.
// Supports k10temp (AMD), coretemp (Intel), and generic thermal_zone.
// No external tools needed — all data is in /sys/class/hwmon/.
type ThermalCollector struct{}

func NewThermalCollector() *ThermalCollector { return &ThermalCollector{} }

func (c *ThermalCollector) Name() string           { return "Thermal" }
func (c *ThermalCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *ThermalCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.ThermalInfo{CoreTemps: make(map[string]float64)}

	// Walk /sys/class/hwmon looking for CPU temp sensors
	hwmons, err := filepath.Glob("/sys/class/hwmon/hwmon*")
	if err != nil || len(hwmons) == 0 {
		return info, nil
	}

	for _, hwmon := range hwmons {
		name, err := os.ReadFile(filepath.Join(hwmon, "name"))
		if err != nil {
			continue
		}
		driverName := strings.TrimSpace(string(name))

		// k10temp = AMD, coretemp = Intel
		if driverName != "k10temp" && driverName != "coretemp" {
			continue
		}

		info.Source = driverName
		readHwmonTemps(hwmon, info)
		break // use first CPU thermal sensor found
	}

	// Fallback to /sys/class/thermal/thermal_zone* if no hwmon found
	if info.Source == "" {
		readThermalZone(info)
	}

	return info, nil
}

// readHwmonTemps reads temp*_input files from a hwmon directory.
// Values are in millidegrees Celsius.
func readHwmonTemps(hwmon string, info *models.ThermalInfo) {
	inputs, _ := filepath.Glob(filepath.Join(hwmon, "temp*_input"))
	for _, input := range inputs {
		raw, err := os.ReadFile(input) // #nosec G304 -- path from filepath.Glob under /sys/class/hwmon
		if err != nil {
			continue
		}
		milliC, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if err != nil {
			continue
		}
		tempC := milliC / 1000.0

		// Read label for this sensor
		base := strings.TrimSuffix(input, "_input")
		label := readSensorLabel(base + "_label")
		if label == "" {
			label = fmt.Sprintf("temp%s", filepath.Base(base)[4:])
		}

		// Tctl/Tdie is the primary AMD CPU temp
		if label == "Tctl" || label == "Tdie" || label == "Package id 0" {
			info.CPUTempC = tempC
		}
		info.CoreTemps[label] = tempC
	}
}

func readSensorLabel(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 -- path from filepath.Glob
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readThermalZone reads from /sys/class/thermal/thermal_zone* as fallback.
func readThermalZone(info *models.ThermalInfo) {
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	for _, zone := range zones {
		raw, err := os.ReadFile(zone) // #nosec G304 -- path from filepath.Glob
		if err != nil {
			continue
		}
		milliC, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if err != nil {
			continue
		}
		tempC := milliC / 1000.0
		if tempC > info.CPUTempC {
			info.CPUTempC = tempC
			info.Source = "thermal_zone"
		}
	}
}
