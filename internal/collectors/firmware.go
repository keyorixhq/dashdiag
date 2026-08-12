//go:build linux || darwin

package collectors

import (
	"context"
	"encoding/json"
	"slices"
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

func (c *FirmwareCollector) Collect(ctx context.Context) (any, error) {
	info := &models.FirmwareInfo{}

	// fwupdmgr not on PATH at all — genuinely not installed.
	if _, err := lookPath("fwupdmgr"); err != nil {
		info.Status = "unavailable"
		info.StatusReason = "fwupd not installed"
		return info, nil
	}
	// fwupdmgr IS installed, but the version probe itself failed (fwupd daemon
	// down, D-Bus unreachable). That's a real gap, not "not installed" — collapsing
	// the two here silently dropped the whole Firmware section on a host that
	// genuinely has fwupd but whose daemon isn't responding. Available stays true
	// so checkFirmware's StatusReason disclosure branch fires instead of the
	// caller reading this identically to a host with no fwupd at all.
	if _, err := runCmd(ctx, "fwupdmgr", "--version"); err != nil {
		info.Available = true
		info.StatusReason = "fwupdmgr --version failed: " + err.Error()
		return info, nil
	}
	info.Available = true

	// Get upgrades as JSON — cleanest output. runCmdOutput (not runCmd) because
	// fwupdmgr exits non-zero to *report* "no upgrades", while still printing
	// that message to stdout — runCmd would discard it and mask the OK case.
	out, err := runCmdOutput(ctx, "fwupdmgr", "get-upgrades", "--json")
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
		needsReboot := slices.Contains(dev.Flags, "needs-reboot")

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
