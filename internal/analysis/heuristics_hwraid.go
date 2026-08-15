package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	hwRaidCat        = "HardwareRAID"
	hwRaidInspectPfx = "to inspect: "
)

// checkHWRaid turns hardware-RAID controller state into insights. This is the false-OK
// hardware RAID is built to cause: the OS sees one healthy block device while the
// controller runs a degraded array with no redundancy, or a failed drive that hasn't
// been replaced. Degraded/offline virtual drives and failed disks are CRIT; rebuilds,
// predictive failures and a bad cache battery are WARN. When the controller CLI needs
// root or its output can't be parsed, we say so — never a healthy verdict over unread
// state.
func checkHWRaid(d models.HWRaidInfo) []models.Insight {
	if !d.Available {
		return nil
	}
	if d.NeedsRoot {
		return []models.Insight{unverifiedInsight("INFO", hwRaidCat,
			"hardware RAID controller detected but its status is root-only — re-run as root to verify the array is healthy",
			[]string{"to inspect: sudo " + hwRaidInspectHint(d.Tool)})}
	}
	if d.ReadFailed {
		return []models.Insight{unverifiedInsight("INFO", hwRaidCat,
			"hardware RAID controller detected but its status output could not be parsed — treat as UNVERIFIED, not healthy",
			[]string{hwRaidInspectPfx + hwRaidInspectHint(d.Tool)})}
	}

	var out []models.Insight
	for _, c := range d.Controllers {
		label := hwRaidCtrlLabel(c)
		for _, vd := range c.VirtualDrives {
			switch {
			case vd.Offline:
				out = append(out, insight("CRIT", hwRaidCat,
					fmt.Sprintf("%s: virtual drive %q is OFFLINE — the volume is inaccessible and data on it is unavailable", label, vd.Name),
					[]string{hwRaidInspectPfx + hwRaidInspectHint(d.Tool)}))
			case vd.Degraded:
				out = append(out, insight("CRIT", hwRaidCat,
					fmt.Sprintf("%s: virtual drive %q (%s) is DEGRADED — the array is running WITHOUT redundancy; one more drive failure means data loss", label, vd.Name, vd.RaidLevel),
					[]string{
						hwRaidInspectPfx + hwRaidInspectHint(d.Tool),
						"action:     replace the failed physical drive so the array can rebuild",
					}))
			case vd.Rebuilding:
				out = append(out, insight("WARN", hwRaidCat,
					fmt.Sprintf("%s: virtual drive %q is REBUILDING — redundancy is not restored until the rebuild completes", label, vd.Name),
					[]string{hwRaidInspectPfx + hwRaidInspectHint(d.Tool)}))
			}
		}
		for _, pd := range c.PhysicalDrives {
			switch {
			case pd.Failed:
				out = append(out, insight("CRIT", hwRaidCat,
					fmt.Sprintf("%s: physical drive %s has FAILED — replace it; the array behind it has lost a member", label, pd.Location),
					[]string{hwRaidInspectPfx + hwRaidInspectHint(d.Tool)}))
			case pd.Predictive:
				out = append(out, insight("WARN", hwRaidCat,
					fmt.Sprintf("%s: physical drive %s reports PREDICTIVE FAILURE — it is about to fail; replace it proactively", label, pd.Location),
					[]string{hwRaidInspectPfx + hwRaidInspectHint(d.Tool)}))
			case pd.Rebuilding:
				out = append(out, insight("WARN", hwRaidCat,
					fmt.Sprintf("%s: physical drive %s is REBUILDING into the array", label, pd.Location),
					[]string{hwRaidInspectPfx + hwRaidInspectHint(d.Tool)}))
			}
		}
		if c.BBUDegraded {
			out = append(out, insight("WARN", hwRaidCat,
				fmt.Sprintf("%s: controller cache battery/capacitor is not healthy (%s) — the controller may have disabled write-back cache (slower writes), and unflushed cache is at risk on power loss", label, c.BBUStatus),
				[]string{hwRaidInspectPfx + hwRaidInspectHint(d.Tool)}))
		} else if c.BBUStatusUnreadable {
			// internal-collectors-16-02: a BBU/CacheVault entry was present
			// but its state couldn't be read — distinct from no entry at all
			// (genuinely no battery-backed cache, which stays silent).
			out = append(out, unverifiedInsight("INFO", hwRaidCat,
				fmt.Sprintf("%s: cache battery/capacitor state could not be read — health unverified", label),
				[]string{hwRaidInspectPfx + hwRaidInspectHint(d.Tool)}))
		}
	}
	return out
}

func hwRaidCtrlLabel(c models.HWRaidController) string {
	if c.Model != "" {
		return fmt.Sprintf("controller %d (%s)", c.ID, c.Model)
	}
	return fmt.Sprintf("controller %d", c.ID)
}

func hwRaidInspectHint(tool string) string {
	switch tool {
	case "ssacli", "hpssacli":
		return "ssacli ctrl all show config detail"
	default:
		return "storcli /cALL show all   (perccli on Dell PERC)"
	}
}
