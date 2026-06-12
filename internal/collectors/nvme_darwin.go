//go:build darwin

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// NVMeCollector reads drive identity and SMART status on macOS via diskutil.
// Uses diskutil list to find physical disks, then diskutil info for each.
type NVMeCollector struct{}

func NewNVMeCollector() *NVMeCollector { return &NVMeCollector{} }

func (c *NVMeCollector) Name() string           { return "Drives" }
func (c *NVMeCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *NVMeCollector) Collect(ctx context.Context) (interface{}, error) {
	return collectDrivesDarwinText(ctx)
}

func collectDrivesDarwinText(ctx context.Context) (*models.NVMeInfo, error) {
	info := &models.NVMeInfo{}

	// diskutil list shows all disks; filter for physical internal disks
	out, err := runCmd(ctx, "diskutil", "list")
	if err != nil || out == "" {
		return info, nil
	}

	// Extract disk identifiers like disk0, disk1 (not diskNsM which are partitions)
	var physDisks []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "/dev/disk") {
			// e.g. "/dev/disk0 (internal, physical):"
			if strings.Contains(line, "internal") || strings.Contains(line, "physical") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					name := strings.TrimPrefix(parts[0], "/dev/")
					physDisks = append(physDisks, name)
				}
			}
		}
	}

	for _, disk := range physDisks {
		dev := driveInfoDarwin(ctx, disk)
		if dev.Name != "" {
			info.SATADevices = append(info.SATADevices, dev)
		}
	}

	return info, nil
}

// driveInfoDarwin reads model name and SMART status for one disk via diskutil info.
func driveInfoDarwin(ctx context.Context, disk string) models.SATADevice {
	dev := models.SATADevice{Name: disk}

	out, err := runCmd(ctx, "diskutil", "info", disk)
	if err != nil || out == "" {
		return dev
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Device / Media Name:") {
			dev.Model = strings.TrimSpace(strings.TrimPrefix(line, "Device / Media Name:"))
		}
		if strings.HasPrefix(line, "SMART Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "SMART Status:"))
			// SmartRead gates the analysis verdict: only a real verdict (Verified/
			// Passed/Failing) counts as "read". "Not Supported" → unread INFO, not a
			// CRIT and not a silent skip. (Without SmartRead, a healthy Mac drive was
			// mis-reported "SMART not read" after the SATADevice SmartRead guard landed.)
			if read, ok := darwinSMARTStatus(status); read {
				dev.SmartRead = true
				dev.SmartOK = ok
			}
		}
	}

	return dev
}
