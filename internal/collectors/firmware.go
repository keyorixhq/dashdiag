//go:build linux || darwin

package collectors

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// FirmwareCollector checks for pending firmware upgrades via fwupd.
// fwupd is installed by default on RHEL/Rocky/Fedora/Ubuntu/Debian.
type FirmwareCollector struct{}

func NewFirmwareCollector() *FirmwareCollector { return &FirmwareCollector{} }

func (c *FirmwareCollector) Name() string           { return "Firmware" }
func (c *FirmwareCollector) Timeout() time.Duration { return 30 * time.Second }

func (c *FirmwareCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.FirmwareInfo{}

	// Check fwupdmgr is available
	if _, err := runCmd(ctx, "fwupdmgr", "--version"); err != nil {
		info.Status = "unavailable"
		info.StatusReason = "fwupd not installed"
		return info, nil
	}
	info.Available = true

	// Get upgrades as JSON — cleanest output
	out, err := runCmd(ctx, "fwupdmgr", "get-upgrades", "--json")
	if err != nil {
		// fwupdmgr exits non-zero when no upgrades available
		if strings.Contains(out, "Nothing to do") ||
			strings.Contains(out, "no upgrades") ||
			strings.Contains(out, "No upgrades") {
			info.Status = "OK"
			return info, nil
		}
		// May need daemon refresh
		info.StatusReason = "fwupdmgr get-upgrades failed"
		return info, nil
	}

	// Parse JSON output
	var result struct {
		Devices []struct {
			Name     string   `json:"Name"`
			Summary  string   `json:"Summary"`
			Flags    []string `json:"Flags"`
			Releases []struct {
				Version    string   `json:"Version"`
				Summary    string   `json:"Summary"`
				Urgency    string   `json:"Urgency"`
				Categories []string `json:"Categories"`
			} `json:"Releases"`
			Version string `json:"Version"`
		} `json:"Devices"`
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		info.StatusReason = "failed to parse fwupdmgr output"
		return info, nil
	}

	for _, dev := range result.Devices {
		needsReboot := false
		for _, flag := range dev.Flags {
			if flag == "needs-reboot" {
				needsReboot = true
				break
			}
		}

		newVer := ""
		isSecurity := false
		if len(dev.Releases) > 0 {
			newVer = dev.Releases[0].Version
			// Security-relevant: dbx updates, BIOS security, urgency=critical/high
			urgency := strings.ToLower(dev.Releases[0].Urgency)
			if urgency == "critical" || urgency == "high" {
				isSecurity = true
			}
			for _, cat := range dev.Releases[0].Categories {
				if strings.Contains(strings.ToLower(cat), "security") {
					isSecurity = true
				}
			}
		}
		// dbx is always security-relevant
		if strings.Contains(strings.ToLower(dev.Name), "dbx") ||
			strings.Contains(strings.ToLower(dev.Summary), "revocation") ||
			strings.Contains(strings.ToLower(dev.Summary), "secure boot") {
			isSecurity = true
		}

		upgrade := models.FirmwareUpgrade{
			Name:        dev.Name,
			Summary:     dev.Summary,
			CurrentVer:  dev.Version,
			NewVer:      newVer,
			NeedsReboot: needsReboot,
			SecurityFix: isSecurity,
		}
		info.Upgrades = append(info.Upgrades, upgrade)
		info.UpgradeCount++
		if isSecurity {
			info.SecurityCount++
		}
	}

	return info, nil
}
