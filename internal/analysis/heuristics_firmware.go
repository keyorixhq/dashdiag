package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	fwCatFirmware      = "Firmware"
	fwCatSnapshots     = "Snapshots"
	fwCatSubscription  = "Subscription"
	fwInspectFwupd     = "to inspect: fwupdmgr get-upgrades"
	fwFixSUSERenewShrt = "to fix: renew at https://scc.suse.com"
)

func checkFirmware(f models.FirmwareInfo) []models.Insight {
	var out []models.Insight

	if !f.Available {
		return out
	}

	// The upgrade query failed or its output was unparseable (daemon needs a refresh,
	// permission/D-Bus error, garbled JSON). UpgradeCount stays 0, which would read as
	// "no pending firmware" — and silently miss pending dbx / Secure Boot security
	// updates. Surface it rather than pass as clean. Status=="OK" is the recognized
	// "nothing to do" path, which is a genuine clean.
	if f.StatusReason != "" && f.Status != "OK" {
		return []models.Insight{unverifiedInsight("INFO", fwCatFirmware,
			"firmware update status could not be verified: "+f.StatusReason,
			[]string{
				fwInspectFwupd,
				"to refresh: fwupdmgr refresh   (run as root)",
			},
		)}
	}

	if f.UpgradeCount == 0 {
		return out
	}

	// Security-critical firmware (dbx, BIOS security patches)
	if f.SecurityCount > 0 {
		var names []string
		for _, u := range f.Upgrades {
			if u.SecurityFix {
				names = append(names, u.Name)
			}
		}
		out = append(out, insight("WARN", fwCatFirmware,
			fmt.Sprintf("%d security-relevant firmware upgrade(s) pending: %s",
				f.SecurityCount, strings.Join(names, ", ")),
			[]string{
				fwInspectFwupd,
				"to apply:   fwupdmgr update",
				"note: most firmware updates require a reboot",
			},
		))
	}

	// Non-security firmware upgrades
	nonSec := f.UpgradeCount - f.SecurityCount
	if nonSec > 0 {
		out = append(out, insight("INFO", fwCatFirmware,
			fmt.Sprintf("%d non-security firmware upgrade(s) available", nonSec),
			[]string{fwInspectFwupd},
		))
	}

	return out
}

// checkSnapper evaluates Btrfs/Snapper snapshot health.
// Thresholds:
//
//	WARN  — no snapshot in >24h (rollback safety window exceeded)
//	WARN  — total snapshot space >20GB (may indicate cleanup needed)
//	CRIT  — no snapshot in >72h (3 days without a rollback point)
//	INFO  — snapper available but no snapshots exist yet
func checkSnapper(s models.SnapperInfo) []models.Insight {
	if !s.Available {
		return nil // snapper not installed — not an error, just skip
	}

	var out []models.Insight

	if s.Error != "" {
		// "run as root" is an expected non-root limitation — INFO not WARN, and
		// unverified (snapper's real state, not confirmed clean/broken).
		if strings.Contains(s.Error, "run as root") {
			out = append(out, unverifiedInsight("INFO", fwCatSnapshots,
				fmt.Sprintf("snapper: %s", s.Error),
				nil,
			))
			return out
		}
		out = append(out, insight("WARN", fwCatSnapshots,
			fmt.Sprintf("snapper: %s", s.Error),
			nil,
		))
		return out
	}

	// No snapshots at all
	if s.SnapshotCount == 0 {
		out = append(out, insight("WARN", fwCatSnapshots,
			"snapper is installed but no snapshots exist — system has no rollback points",
			[]string{
				"to fix: snapper create --description 'initial'",
				"to enable automatic snapshots: snapper set-config TIMELINE_CREATE=yes",
			},
		))
		return out
	}

	// Staleness — how long since last snapshot
	switch {
	case s.LastSnapshotH < 0:
		// Could not determine last snapshot time — treat as stale
		out = append(out, unverifiedInsight("WARN", fwCatSnapshots,
			fmt.Sprintf("%d snapshot(s) found but last snapshot time could not be determined", s.SnapshotCount),
			[]string{"to check: sudo snapper list"},
		))
	case s.LastSnapshotH >= 72:
		out = append(out, insight("CRIT", fwCatSnapshots,
			fmt.Sprintf("no Btrfs snapshot in %dh — system has no recent rollback point", s.LastSnapshotH),
			[]string{
				"to fix: snapper create --description 'manual'",
				"to enable timeline: snapper set-config TIMELINE_CREATE=yes",
			},
		))
	case s.LastSnapshotH >= 24:
		out = append(out, insight("WARN", fwCatSnapshots,
			fmt.Sprintf("last Btrfs snapshot was %dh ago — rollback window may be stale", s.LastSnapshotH),
			[]string{
				"to fix: snapper create --description 'manual'",
				"to check schedule: snapper get-config | grep TIMELINE",
			},
		))
	}

	// Space usage
	switch {
	case s.TotalSpaceGB >= 50:
		out = append(out, insight("CRIT", fwCatSnapshots,
			fmt.Sprintf("Btrfs snapshots consuming %.1f GB — filesystem space at risk", s.TotalSpaceGB),
			[]string{
				"to clean up: snapper delete --sync <number>",
				"to list by size: sudo snapper list",
				"to limit retention: snapper set-config NUMBER_LIMIT=10",
			},
		))
	case s.TotalSpaceGB >= 20:
		out = append(out, insight("WARN", fwCatSnapshots,
			fmt.Sprintf("Btrfs snapshots consuming %.1f GB — consider pruning old snapshots", s.TotalSpaceGB),
			[]string{
				"to clean up: snapper delete --sync <number>",
				"to limit retention: snapper set-config NUMBER_LIMIT=10",
			},
		))
	}

	// Healthy state — emit INFO so the check is visible in output
	if len(out) == 0 {
		msg := fmt.Sprintf("%d Btrfs snapshot(s)", s.SnapshotCount)
		if s.LastSnapshotH >= 0 {
			msg += fmt.Sprintf(" — last < %dh ago", s.LastSnapshotH+1)
		}
		if s.TotalSpaceGB > 0 {
			msg += fmt.Sprintf(", %.1f GB used", s.TotalSpaceGB)
		}
		out = append(out, insight("OK", fwCatSnapshots, msg, nil))
	}

	return out
}

// checkSUSEConnect surfaces SUSEConnect subscription status in dsd health.
// CRIT if expired or expires <=14d, WARN if <=30d, OK otherwise.
// Silent (no insight) when SUSEConnect is not registered — non-SLES systems.
func checkSUSEConnect(s models.SUSEConnectInfo) []models.Insight {
	switch s.Platform {
	case "rhel":
		return checkRHELSubscription(s)
	case "ubuntu-pro":
		return checkUbuntuPro(s)
	default: // "suse" or legacy (empty platform field)
		return checkSUSESubscription(s)
	}
}

func checkSUSESubscription(s models.SUSEConnectInfo) []models.Insight {
	if !s.Registered {
		// SUSEConnect present but the status query failed — we couldn't read whether
		// the host is registered, so don't assert it's unregistered (FALSE_OK_SWEEP #14).
		if s.Status == "query-failed" {
			return []models.Insight{unverifiedInsight("INFO", fwCatSubscription,
				"SUSE registration not verified — SUSEConnect --status failed (network/SCC error?)",
				[]string{"to inspect: SUSEConnect --status", "to inspect: SUSEConnect --status-text"},
			)}
		}
		return []models.Insight{insight("WARN", fwCatSubscription,
			"SUSE system is not registered — security patches unavailable without SUSEConnect",
			[]string{
				"to fix: SUSEConnect -r <REGCODE>",
				"to register: https://scc.suse.com",
			},
		)}
	}
	switch {
	case s.ExpiresDays == 0:
		return []models.Insight{insight("CRIT", fwCatSubscription,
			"SUSE subscription EXPIRED — security patches unavailable",
			[]string{fwFixSUSERenewShrt},
		)}
	case s.ExpiresDays > 0 && s.ExpiresDays <= 14:
		return []models.Insight{insight("CRIT", fwCatSubscription,
			fmt.Sprintf("SUSE subscription expires in %d day(s) — renew immediately", s.ExpiresDays),
			[]string{fwFixSUSERenewShrt},
		)}
	case s.ExpiresDays > 14 && s.ExpiresDays <= 30:
		return []models.Insight{insight("WARN", fwCatSubscription,
			fmt.Sprintf("SUSE subscription expires in %d day(s)", s.ExpiresDays),
			[]string{fwFixSUSERenewShrt},
		)}
	default:
		return nil // OK — no insight needed
	}
}

func checkRHELSubscription(s models.SUSEConnectInfo) []models.Insight {
	// subscription-manager printed something that matched none of the known
	// patterns (current/expired/not registered) — the raw text landed in Status
	// unparsed. Don't let that silently read as "current" via the default case
	// below; disclose that the status could not be determined.
	if s.StatusUnverified {
		return []models.Insight{unverifiedInsight("INFO", fwCatSubscription,
			"RHEL/Oracle subscription status could not be determined — subscription-manager output did not match a known pattern",
			[]string{"to inspect: subscription-manager status"},
		)}
	}
	switch s.Status {
	case "unregistered-rhui":
		// RHUI/PAYG cloud image (AWS/Azure/GCP): "not registered" is the normal
		// state and updates come from the cloud RHUI repos, so registration is not
		// required. Silent — warning here would false-alarm on nearly every cloud
		// RHEL host. (Actual update availability is reported by the Packages check.)
		return nil
	case "unregistered":
		return []models.Insight{insight("WARN", fwCatSubscription,
			"RHEL/Oracle system is not registered — security updates may be unavailable",
			[]string{
				"to fix: subscription-manager register --auto-attach",
				"to inspect: subscription-manager status",
				"note: Rocky/AlmaLinux do not require registration; cloud PAYG (RHUI) images do not either",
			},
		)}
	case "expired":
		return []models.Insight{insight("CRIT", fwCatSubscription,
			"Red Hat subscription EXPIRED — security patches unavailable",
			[]string{
				"to fix: renew at https://access.redhat.com",
				"to inspect: subscription-manager list --consumed",
			},
		)}
	default:
		return nil // current — no insight needed
	}
}

func checkUbuntuPro(s models.SUSEConnectInfo) []models.Insight {
	if s.Status == "detached" {
		// Ubuntu Pro is optional — INFO not WARN (Ubuntu still works without it)
		return []models.Insight{insight("INFO", fwCatSubscription,
			"Ubuntu Pro not attached — ESM security patches and Livepatch unavailable",
			[]string{
				"to attach: pro attach <token>  (free for up to 5 personal machines)",
				"to get token: ubuntu.com/pro",
				"to inspect: pro status",
			},
		)}
	}
	return nil // attached — no insight needed
}
