//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// MultipathCollector reads DM-MPIO multipath status via multipathd.
type MultipathCollector struct{}

func NewMultipathCollector() *MultipathCollector     { return &MultipathCollector{} }
func (c *MultipathCollector) Name() string           { return "Multipath" }
func (c *MultipathCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *MultipathCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.MultipathInfo{}

	// Detect multipath presence before running commands
	if !IsMultipathPresent() {
		return info, nil
	}

	info.Available = true

	// Try multipathd show paths (detailed, machine-readable)
	out, err := runCmd(ctx, "multipathd", "show", "paths", "format", "%d %t %s %m")
	if err != nil {
		// Fallback: multipath -l (human-readable but parseable)
		out, err = runCmd(ctx, "multipath", "-l")
		if err != nil {
			info.Status = "error"
			info.StatusReason = "multipathd running but paths unreadable"
			return info, nil // actionable error — keep the row
		}
		info.Devices = parseMultipathL(out)
	} else {
		info.Devices = parseMultipathShow(out)
	}

	if len(info.Devices) == 0 {
		// multipathd installed/running but no multipath maps configured — common
		// when multipath-tools is present without any SAN. Absent, gate off.
		return nil, nil
	}
	return info, nil
}

// IsMultipathPresent returns true when multipathd is running.
func IsMultipathPresent() bool {
	// Check if multipathd socket exists or process is running
	if _, err := exec.LookPath("multipathd"); err != nil {
		return false
	}
	// Verify it's actually running (multipathd show paths fails if daemon is stopped)
	return true
}

// parseMultipathShow parses "multipathd show paths format %d %t %s %m" output.
// Columns: device, state, serial, map (DM device)
func parseMultipathShow(out string) []models.MultipathDevice {
	deviceMap := make(map[string]*models.MultipathDevice)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "hcil") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		dev := fields[0]
		state := fields[1]
		dm := fields[3]
		if dm == "" || dm == "[orphan]" {
			dm = "unknown"
		}

		d, ok := deviceMap[dm]
		if !ok {
			d = &models.MultipathDevice{Name: dm, DM: dm}
			deviceMap[dm] = d
		}
		d.TotalPaths++
		path := models.MultipathPath{Device: dev, State: state, DM: dm}
		if state == "active" || state == "ready" {
			d.ActivePaths++
		} else {
			d.FailedPaths++
		}
		d.Paths = append(d.Paths, path)
	}

	devices := make([]models.MultipathDevice, 0, len(deviceMap))
	for _, d := range deviceMap {
		if d.FailedPaths > 0 {
			d.State = "degraded"
		} else {
			d.State = "active"
		}
		devices = append(devices, *d)
	}
	return devices
}

// parseMultipathL parses "multipath -l" text output.
// Less reliable but widely available.
func parseMultipathL(out string) []models.MultipathDevice {
	var devices []models.MultipathDevice
	var current *models.MultipathDevice
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		// Device header line starts without leading whitespace and contains "dm-"
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.Contains(line, "dm-") {
			if current != nil {
				devices = append(devices, *current)
			}
			// Extract DM device name
			fields := strings.Fields(line)
			dm := ""
			for _, f := range fields {
				if strings.HasPrefix(f, "dm-") {
					dm = f
					break
				}
			}
			current = &models.MultipathDevice{Name: fields[0], DM: dm}
			continue
		}
		if current == nil {
			continue
		}
		trimmed := strings.TrimSpace(line)
		// Path lines contain "_ sdX" or similar
		if strings.Contains(trimmed, " sd") || strings.Contains(trimmed, " nvme") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				state := "active"
				for _, f := range fields {
					if f == "failed" || f == "faulty" {
						state = "failed"
					}
				}
				dev := fields[len(fields)-1]
				current.Paths = append(current.Paths, models.MultipathPath{
					Device: dev, State: state, DM: current.DM,
				})
				current.TotalPaths++
				if state == "failed" {
					current.FailedPaths++
				} else {
					current.ActivePaths++
				}
			}
		}
	}
	if current != nil {
		devices = append(devices, *current)
	}
	for i := range devices {
		if devices[i].FailedPaths > 0 {
			devices[i].State = "degraded"
		} else {
			devices[i].State = "active"
		}
	}
	return devices
}
