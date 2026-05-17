//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// IPMICollector reads BMC sensor data via ipmitool or the ipmi_si kernel driver.
// Falls back gracefully when IPMI is unavailable.
type IPMICollector struct{}

func NewIPMICollector() *IPMICollector          { return &IPMICollector{} }
func (c *IPMICollector) Name() string           { return "IPMI" }
func (c *IPMICollector) Timeout() time.Duration { return 8 * time.Second }

func (c *IPMICollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.IPMIInfo{}

	// Detect IPMI availability: kernel driver device or ipmitool in PATH
	if _, err := os.Stat("/dev/ipmi0"); os.IsNotExist(err) {
		if _, err2 := runCmd(ctx, "which", "ipmitool"); err2 != nil {
			return info, nil // no IPMI — skip silently
		}
	}

	// Try ipmitool sdr — most portable across vendor implementations
	out, err := runCmd(ctx, "ipmitool", "sdr", "list", "full")
	if err != nil {
		// Try without "list full" (older ipmitool versions)
		out, err = runCmd(ctx, "ipmitool", "sdr")
		if err != nil {
			info.Status = "error"
			info.StatusReason = "ipmitool available but sdr read failed — check IPMI access"
			return info, nil
		}
	}

	info.Available = true
	info.Sensors = parseIPMISDR(out)

	for _, s := range info.Sensors {
		name := strings.ToLower(s.Name)
		switch {
		case (strings.Contains(name, "psu") || strings.Contains(name, "power supply")) &&
			(s.Status == "cr" || s.Status == "nr" || s.Status == "nc"):
			info.PSUFailed++
		case strings.Contains(name, "fan") &&
			(s.Status == "cr" || s.Status == "nr" || s.Status == "nc"):
			info.FanFailed++
		case strings.Contains(name, "temp") &&
			(s.Status == "cr" || s.Status == "nr"):
			info.TempCritical++
		}
	}
	return info, nil
}

// IsIPMIPresent returns true when IPMI hardware is accessible.
func IsIPMIPresent() bool {
	if _, err := os.Stat("/dev/ipmi0"); err == nil {
		return true
	}
	// Also check /dev/ipmi/0 (some distros)
	if _, err := os.Stat("/dev/ipmi/0"); err == nil {
		return true
	}
	return false
}

// parseIPMISDR parses `ipmitool sdr` output.
// Format: "Sensor Name     | Value     | Status"
func parseIPMISDR(out string) []models.IPMISensor {
	var sensors []models.IPMISensor
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		rawVal := strings.TrimSpace(parts[1])
		status := strings.TrimSpace(parts[2])
		if name == "" || rawVal == "no reading" || rawVal == "disabled" {
			continue
		}

		sensor := models.IPMISensor{
			Name:   name,
			Status: normaliseIPMIStatus(status),
		}

		// Parse "X.XX Volts", "XX degrees C", etc.
		fields := strings.Fields(rawVal)
		if len(fields) >= 1 {
			if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
				sensor.Value = v
			}
			if len(fields) >= 2 {
				sensor.Unit = fields[1]
			}
		}
		sensors = append(sensors, sensor)
	}
	return sensors
}

// normaliseIPMIStatus maps ipmitool status strings to short codes.
func normaliseIPMIStatus(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case s == "ok":
		return "ok"
	case strings.Contains(s, "non-critical") || s == "nc":
		return "nc"
	case strings.Contains(s, "critical") || s == "cr":
		return "cr"
	case strings.Contains(s, "non-recoverable") || s == "nr":
		return "nr"
	case s == "ns", s == "na", s == "n/a":
		return "na"
	default:
		return s
	}
}
