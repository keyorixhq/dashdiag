package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	pveCatPVE          = "PVE"
	inspectPVETasks    = "to inspect: pvesh get /nodes/localhost/tasks --typefilter vzdump"
	inspectPVECMStatus = "to inspect: pvecm status"
	inspectPVESMStatus = "to inspect: pvesm status"
)

// checkPVE surfaces Proxmox VE host health issues.
// Silent no-op on non-Proxmox hosts.
func checkPVE(p models.PVEInfo) []models.Insight {
	if !p.IsPVE {
		return nil
	}
	if p.NeedsRoot {
		return []models.Insight{unverifiedInsight("INFO", pveCatPVE,
			"Proxmox VE detected — run as root for full cluster/storage/backup checks",
			[]string{"to run: sudo dsd health"},
		)}
	}
	// pvedaemon exists and we are root, but the pvesh API probe failed — pmxcfs /
	// pve-cluster down or unreachable. Every collection below is empty, so without
	// this the node reads as a clean "healthy" with quorum implicitly OK (false-OK).
	// Stop here: we cannot verify quorum, storage, or backups, so don't pretend to.
	if !p.APIReachable {
		return []models.Insight{unverifiedInsight("WARN", pveCatPVE,
			"Proxmox VE API (pvesh) not responding — cluster quorum, storage, and backup health could NOT be verified",
			[]string{
				"to inspect: systemctl status pve-cluster corosync pvedaemon",
				"to inspect: pvesh get /cluster/status",
				"note: pmxcfs (/etc/pve) must be mounted and quorate for the API to respond",
			},
		)}
	}
	out := make([]models.Insight, 0, 8)
	out = append(out, checkPVESubscription(p)...)
	out = append(out, checkPVECluster(p)...)
	out = append(out, checkPVEStorage(p)...)
	out = append(out, checkPVEBackups(p)...)
	out = append(out, checkPVETaskErrors(p)...)
	return out
}

// checkPVETaskErrors surfaces recent failed Proxmox tasks (last 24h). The
// collector gathers these but nothing consumed them, so failed migrations,
// snapshots, restores, etc. were silently invisible. Backups (vzdump) are
// excluded here — they're covered by checkPVEBackups via RecentBackups, so
// including them would double-warn.
func checkPVETaskErrors(p models.PVEInfo) []models.Insight {
	var types []string
	seen := map[string]bool{}
	n := 0
	for _, t := range p.TaskErrors {
		if t.Type == "vzdump" {
			continue // backups handled by checkPVEBackups
		}
		n++
		if !seen[t.Type] {
			seen[t.Type] = true
			types = append(types, t.Type)
		}
	}
	if n == 0 {
		if !p.TasksVerified {
			// The task list couldn't be read — recent failed migrations/restores/
			// snapshots are invisible exactly when the task API is unhealthy
			// (FALSE_OK_SWEEP #7). Report "not verified" instead of a silent clean.
			return []models.Insight{unverifiedInsight("INFO", pveCatPVE,
				"Proxmox task log unreadable — recent task failures could NOT be verified",
				[]string{
					"to inspect: pvesh get /nodes/localhost/tasks --errors 1",
					"to inspect: cat /var/log/pve/tasks/index",
				},
			)}
		}
		return nil
	}
	return []models.Insight{insight("WARN", pveCatPVE,
		fmt.Sprintf("%d Proxmox task(s) failed in the last 24h (%s)", n, strings.Join(types, ", ")),
		[]string{
			"to inspect: pvesh get /nodes/localhost/tasks --errors 1",
			"to inspect: cat /var/log/pve/tasks/index",
		},
	)}
}

func checkPVESubscription(p models.PVEInfo) []models.Insight {
	switch p.Subscription.Status {
	case "notfound", "":
		return []models.Insight{insight("WARN", pveCatPVE,
			"no Proxmox VE subscription — security updates require an active subscription",
			[]string{
				"note: without a subscription, security patches lag behind the enterprise repo",
				"to subscribe: https://www.proxmox.com/en/proxmox-ve/pricing",
			},
		)}
	case "expired":
		return []models.Insight{insight("CRIT", pveCatPVE,
			"Proxmox VE subscription has EXPIRED — no access to security updates",
			[]string{
				"to renew: https://www.proxmox.com/en/proxmox-ve/pricing",
				"to inspect: pvesh get /nodes/localhost/subscription",
			},
		)}
	case "unverified":
		// pvesh failed and we fell back to the auth file — a key is configured but
		// its live status (active vs EXPIRED) could not be read. Don't claim healthy.
		return []models.Insight{unverifiedInsight("INFO", pveCatPVE,
			"Proxmox VE subscription configured but live status could NOT be verified (pvesh failed)",
			[]string{
				"to inspect: pvesh get /nodes/localhost/subscription",
				"note: an expired subscription leaves the auth file in place, so presence alone is not proof of an active subscription",
			},
		)}
	}
	return nil
}

func checkPVECluster(p models.PVEInfo) []models.Insight {
	out := make([]models.Insight, 0, 4)

	if !p.QuorumOK {
		out = append(out, insight("CRIT", pveCatPVE,
			"cluster quorum LOST — VMs cannot start or migrate until quorum is restored",
			[]string{
				inspectPVECMStatus,
				"to inspect: systemctl status corosync pve-cluster",
				"note: do not force quorum unless certain of network partition vs node failure",
			},
		))
	}

	if !p.HAFencingOK {
		out = append(out, insight("CRIT", pveCatPVE,
			"HA fencing device unreachable — "+p.HAFencingMsg,
			[]string{
				inspectPVECMStatus,
				"to inspect: ha-manager status",
				"note: without fencing, HA cannot safely restart VMs from a failed node",
			},
		))
	} else if !p.HAVerified {
		// The HA endpoint answered but the response was unparseable — we cannot say
		// fencing is healthy. (A node without HA configured stays verified, so this
		// does not fire on the common standalone case.)
		out = append(out, unverifiedInsight("INFO", pveCatPVE,
			"HA fencing state could NOT be verified — the HA status response was unreadable",
			[]string{
				"to inspect: pvesh get /cluster/ha/status/current",
				"to inspect: ha-manager status",
			},
		))
	}

	if len(p.Nodes) > 1 {
		versions := map[string]bool{}
		for _, n := range p.Nodes {
			if n.Version != "" {
				versions[n.Version] = true
			}
		}
		if len(versions) > 1 {
			out = append(out, insight("WARN", pveCatPVE,
				fmt.Sprintf("cluster has mixed PVE versions across %d nodes — live migration may fail", len(p.Nodes)),
				[]string{
					inspectPVECMStatus,
					"to fix: apt update && apt full-upgrade  (on each node, one at a time)",
				},
			))
		}
		for _, n := range p.Nodes {
			if !n.Online {
				out = append(out, insight("CRIT", pveCatPVE,
					fmt.Sprintf("cluster node %s is OFFLINE", n.Name),
					[]string{
						inspectPVECMStatus,
						fmt.Sprintf("to inspect: ssh root@%s 'systemctl status pve-cluster corosync'", n.Name),
					},
				))
			}
		}
	}
	return out
}

func checkPVEStorage(p models.PVEInfo) []models.Insight {
	var out []models.Insight
	if !p.StoragesVerified {
		// The storage list query failed — inactive/full storage (the exact failure
		// dsd pve exists to catch) would otherwise read clean (FALSE_OK_SWEEP #6).
		out = append(out, unverifiedInsight("INFO", pveCatPVE,
			"Proxmox storage health NOT verified — the storage list query failed",
			[]string{
				inspectPVESMStatus,
				"to inspect: pvesh get /nodes/localhost/storage",
			},
		))
	}
	for _, s := range p.Storages {
		if !s.Active {
			if !s.Enabled {
				// Intentionally disabled in storage.cfg (admin-disabled or an
				// optional/removable mount) — not a fault. §O.4.
				out = append(out, insight("INFO", pveCatPVE,
					fmt.Sprintf("storage %s (%s) is disabled — skipping", s.Name, s.Type),
					nil,
				))
				continue
			}
			out = append(out, insight("CRIT", pveCatPVE,
				fmt.Sprintf("storage %s (%s) is INACTIVE", s.Name, s.Type),
				[]string{
					inspectPVESMStatus,
					fmt.Sprintf("to inspect: pvesh get /nodes/localhost/storage/%s/status", s.Name),
				},
			))
			continue
		}
		if l := PVEStorageLevel(s.UsedPct); l != "" {
			out = append(out, insight(l, pveCatPVE,
				fmt.Sprintf("storage %s (%s) is %.0f%% full (%.1f GB free of %.1f GB)",
					s.Name, s.Type, s.UsedPct, s.TotalGB-s.UsedGB, s.TotalGB),
				[]string{
					inspectPVESMStatus,
					"note: full storage prevents VM disk writes and snapshot creation",
					"to free: remove old backups, snapshots, or ISO images",
				},
			))
		}
	}
	return out
}

func checkPVEBackups(p models.PVEInfo) []models.Insight {
	var out []models.Insight
	if !p.BackupVerified && p.BackupAgeDays < 0 && len(p.BackupStatuses) == 0 {
		// The vzdump task query failed and the on-disk fallback found nothing, so
		// the "no successful backup" CRIT below (gated on len(BackupStatuses)>0) can
		// never fire — backup health unverified would read as a silent OK
		// (FALSE_OK_SWEEP #8). Surface it honestly instead.
		return []models.Insight{unverifiedInsight("INFO", pveCatPVE,
			"Proxmox backup health NOT verified — the vzdump task query failed and no backup archives were found",
			[]string{
				inspectPVETasks,
				"to inspect: ls /var/log/vzdump/",
			},
		)}
	}
	if !p.GuestsVerified {
		// internal-models-11-02: BackupStatuses is built per-guest from
		// p.Guests (collectPVEBackups(ctx, info.Guests)) — if guest
		// enumeration itself failed, BackupStatuses is empty regardless of
		// whether BackupVerified (the vzdump task query) succeeded, so the
		// "no successful backup" CRIT below (gated on BackupStatuses>0) can
		// never fire for a real host with VMs/CTs that simply couldn't be
		// listed. Disclose it in addition to whatever the vzdump-task-based
		// checks below still find — never a replacement for them.
		out = append(out, unverifiedInsight("INFO", pveCatPVE,
			"per-guest backup audit NOT verified — VM/LXC guest enumeration failed",
			[]string{
				"to inspect: pvesh get /nodes/localhost/qemu",
				"to inspect: pvesh get /nodes/localhost/lxc",
			},
		))
	}
	switch {
	case p.BackupAgeDays < 0 && len(p.BackupStatuses) > 0:
		// No backup at all is CRIT, not WARN — VMs have no recovery point.
		// This must bubble into the PVE summary row to match `dsd pve` (BUG-019).
		// Gate on BackupStatuses (one entry per NON-template guest): a fresh node
		// or a template-only node has nothing to back up, so "no recovery point"
		// there is a false positive — don't CRIT when there's nothing to protect.
		out = append(out, insight("CRIT", pveCatPVE,
			"no successful backup found — VMs have no recovery point",
			[]string{
				inspectPVETasks,
				"to schedule: Datacenter → Backup → Add",
			},
		))
	case p.BackupAgeDays > 7:
		out = append(out, insight("WARN", pveCatPVE,
			fmt.Sprintf("last successful backup was %d days ago", p.BackupAgeDays),
			[]string{
				inspectPVETasks,
				"to run now: vzdump --all --compress zstd --storage local",
			},
		))
	}
	failed := 0
	for _, t := range p.RecentBackups {
		if t.Status != "OK" {
			failed++
		}
	}
	if failed > 0 {
		out = append(out, insight("WARN", pveCatPVE,
			fmt.Sprintf("%d backup task(s) failed in the last 7 days", failed),
			[]string{
				inspectPVETasks,
				"to inspect: ls /var/log/vzdump/",
			},
		))
	}

	// Per-VM backup gaps hidden by a healthy global age. The node-wide
	// BackupAgeDays only reflects the MOST RECENT successful backup across all
	// guests, so a single never-backed-up or stale guest is invisible when others
	// back up nightly. Only meaningful once the node has at least one successful
	// backup (BackupAgeDays >= 0) — i.e. backups ARE working, so a guest with none
	// is a forgotten/excluded guest, not an unconfigured node (already CRIT above).
	if p.BackupAgeDays >= 0 {
		var never, stale []string
		for _, s := range p.BackupStatuses {
			label := s.Name
			if label == "" {
				label = fmt.Sprintf("VMID %d", s.VMID)
			}
			switch {
			case s.LastBackupDays < 0:
				never = append(never, label)
			case s.LastBackupDays > 7:
				stale = append(stale, fmt.Sprintf("%s (%dd)", label, s.LastBackupDays))
			}
		}
		if len(never) > 0 {
			out = append(out, insight("WARN", pveCatPVE,
				fmt.Sprintf("%d VM/CT have no backup while others on this node do: %s — no recovery point",
					len(never), strings.Join(firstN(never, 5), ", ")),
				[]string{
					"to inspect: Datacenter → Backup — confirm every guest is in a backup job",
					"note: newly-created guests may simply not have hit their first backup window yet",
				},
			))
		}
		if len(stale) > 0 {
			out = append(out, insight("WARN", pveCatPVE,
				fmt.Sprintf("%d VM/CT backup(s) older than 7 days: %s",
					len(stale), strings.Join(firstN(stale, 5), ", ")),
				[]string{inspectPVETasks},
			))
		}
	}
	return out
}
