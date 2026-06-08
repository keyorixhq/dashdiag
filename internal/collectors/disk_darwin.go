//go:build darwin

package collectors

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// collectDarwin overrides the base implementation to add physical drive + SMART data.
func (c *DiskCollector) collectDarwin(ctx context.Context) (*models.DiskInfo, error) {
	result, err := c.collectDarwinBase(ctx)
	if err != nil {
		return result, err
	}
	// Physical drives + SMART via diskutil (no external tools needed)
	result.Drives = collectDarwinDrives(ctx)
	return result, nil
}

// collectDarwinDrives enumerates physical disks on macOS via diskutil list
// and enriches each with SMART status from diskutil info.
// No external tools required — diskutil ships with every macOS.
func collectDarwinDrives(ctx context.Context) []models.PhysicalDrive {
	// diskutil list -plist would be ideal but needs plist parsing.
	// Plain text format is stable enough for our purposes.
	out, err := runDarwinCmd(ctx, "diskutil", "list")
	if err != nil {
		return nil
	}

	var drives []models.PhysicalDrive
	seen := make(map[string]bool)

	for _, line := range strings.Split(out, "\n") {
		// Lines starting with /dev/diskN (internal, physical): are top-level disks
		if !strings.HasPrefix(line, "/dev/disk") {
			continue
		}
		// Exclude synthesized (APFS containers) and external virtual disks
		if strings.Contains(line, "synthesized") || strings.Contains(line, "virtual") {
			continue
		}
		// Extract device path: first field
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		dev := fields[0] // e.g. /dev/disk0
		if seen[dev] {
			continue
		}
		seen[dev] = true

		d := collectDarwinDriveInfo(ctx, dev)
		if d != nil {
			drives = append(drives, *d)
		}
	}
	return drives
}

// collectDarwinDriveInfo runs diskutil info /dev/diskN and parses the result.
func collectDarwinDriveInfo(ctx context.Context, dev string) *models.PhysicalDrive {
	out, err := runDarwinCmd(ctx, "diskutil", "info", dev)
	if err != nil {
		return nil
	}

	drive := &models.PhysicalDrive{
		Name:  strings.TrimPrefix(dev, "/dev/"),
		SMART: &models.SMARTInfo{Device: dev},
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])
		if val == "" {
			continue
		}

		switch key {
		case "Device / Media Name":
			drive.Model = val
		case "Protocol":
			if val == "Apple Fabric" || strings.Contains(val, "NVM") {
				drive.Type = models.DriveTypeNVMe
			} else if strings.Contains(val, "SATA") || strings.Contains(val, "SAS") {
				drive.Type = models.DriveTypeSSD
			}
		case "Solid State":
			if val == "Yes" && drive.Type == "" {
				drive.Type = models.DriveTypeSSD
			} else if val == "No" {
				drive.Type = models.DriveTypeHDD
			}
		case "Disk Size":
			// "500.3 GB (500277792768 Bytes) ..."
			drive.SizeGB = parseDarwinSize(val)
		case "SMART Status":
			drive.SMART.Healthy = val == "Verified" || val == "Passed"
			if !drive.SMART.Healthy {
				drive.SMART.Error = "SMART: " + val
			}
		case "Mount Point":
			if val != "" {
				drive.Mounts = append(drive.Mounts, drive.Name+"→"+val)
			}
		}
	}

	// Default type for Apple internal SSD
	if drive.Type == "" && strings.HasPrefix(drive.Model, "APPLE SSD") {
		drive.Type = models.DriveTypeNVMe
	}
	if drive.Type == "" {
		drive.Type = models.DriveTypeSSD
	}
	if len(drive.Mounts) == 0 {
		// Apple internal disks are APFS containers — volumes are on synthesized disks
		if strings.HasPrefix(drive.Model, "APPLE") {
			drive.Mounts = []string{"APFS container (volumes on disk3+)"}
		} else {
			drive.Mounts = []string{"not mounted"}
		}
	}

	return drive
}

// parseDarwinSize extracts GB from diskutil size strings like:
// "500.3 GB (500277792768 Bytes) (exactly 977105064 512-Byte-Units)"
func parseDarwinSize(s string) float64 {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0
	}
	var val float64
	if _, err := fmt.Sscanf(fields[0], "%f", &val); err != nil {
		return 0
	}
	unit := strings.ToUpper(fields[1])
	switch unit {
	case "TB":
		return val * 1000
	case "GB":
		return val
	case "MB":
		return val / 1000
	}
	return val
}

// runDarwinCmd runs a command with a context timeout and returns stdout.
func runDarwinCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, name, args...) // #nosec G204
	cmd.Env = localeSafeEnv()
	out, err := cmd.Output()
	return string(out), err
}
