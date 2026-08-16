//go:build linux

package collectors

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ThermalCollector reads CPU temperature directly from sysfs hwmon.
// Supports k10temp (AMD), coretemp (Intel), and generic thermal_zone.
// No external tools needed — all data is in /sys/class/hwmon/.
type ThermalCollector struct {
	InContainer bool // suppress host sensor readings inside LXC/Docker
}

func NewThermalCollector() *ThermalCollector { return &ThermalCollector{} }

func NewThermalCollectorWithContext(inContainer bool) *ThermalCollector {
	return &ThermalCollector{InContainer: inContainer}
}

func (c *ThermalCollector) Name() string           { return "CPU Thermal" }
func (c *ThermalCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *ThermalCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ThermalInfo{Available: true, CoreTemps: make(map[string]float64)}

	// Inside LXC containers, hwmon sensors read the HOST CPU temperature.
	// This is misleading — the container has no CPU of its own.
	// Skip thermal collection entirely in container environments.
	if c.InContainer {
		return nil, nil // host sensors are misleading in a container — absent, gate off
	}

	// Walk /sys/class/hwmon looking for CPU temp sensors. ctx.Err() is checked
	// between entries so an adversarial/pathologically large hwmon tree (many
	// hwmon* devices, or a slow/hanging FUSE-based sysfs) can't run the walk
	// past the collector's own 1s Timeout() with no way for the runner to
	// interrupt it.
	hwmons, _ := glob("/sys/class/hwmon/hwmon*")
	for _, hwmon := range hwmons {
		if err := ctx.Err(); err != nil {
			return info, err
		}
		name, err := readFile(filepath.Join(hwmon, "name"))
		if err != nil {
			continue
		}
		driverName := strings.TrimSpace(string(name))

		// k10temp = AMD, coretemp = Intel
		if driverName != "k10temp" && driverName != "coretemp" {
			continue
		}

		info.Source = driverName
		readHwmonTemps(ctx, hwmon, info)
		break // use first CPU thermal sensor found
	}

	// Fallback to /sys/class/thermal/thermal_zone* if no hwmon found
	if info.Source == "" {
		readThermalZone(ctx, info)
	}

	if info.Source == "" {
		// No CPU thermal sensor anywhere (typical of cloud/KVM guests) — gate off
		// rather than emit a phantom "Thermal ✅ OK" row with no temperature data.
		return nil, nil
	}
	return info, nil
}

// readHwmonTemps reads temp*_input files from a hwmon directory.
// Values are in millidegrees Celsius.
func readHwmonTemps(ctx context.Context, hwmon string, info *models.ThermalInfo) {
	inputs, _ := glob(filepath.Join(hwmon, "temp*_input"))
	for _, input := range inputs {
		if ctx.Err() != nil {
			return
		}
		raw, err := readFile(input)
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

// readSensorLabel reads a hwmon temp*_label file. internal-collectors-32-07:
// the raw label is used both as an info.CoreTemps map key and eventual display
// data, so it's sanitized here rather than at either call site.
func readSensorLabel(path string) string {
	data, err := readFile(path)
	if err != nil {
		return ""
	}
	return source.SanitizeControl(strings.TrimSpace(string(data)))
}

// readThermalZone reads from /sys/class/thermal/thermal_zone* as fallback.
func readThermalZone(ctx context.Context, info *models.ThermalInfo) {
	zones, _ := glob("/sys/class/thermal/thermal_zone*/temp")
	for _, zone := range zones {
		if ctx.Err() != nil {
			return
		}
		raw, err := readFile(zone)
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
