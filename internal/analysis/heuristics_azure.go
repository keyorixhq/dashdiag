package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkAzure reports guest-side health for a Linux VM on Azure. The headline check is
// the Accelerated-Networking datapath — the false-green where AN reads "enabled" in
// the portal but the SR-IOV VF never attached, so traffic silently rides the slow
// synthetic path — plus the Azure Linux agent and the Hyper-V PTP time source. Silent
// on every non-Azure host (the collector only runs behind the DMI gate). When
// everything it could verify is clean it emits one INFO recognition line.
func checkAzure(a models.AzureInfo) []models.Insight {
	if !a.IsAzure {
		return nil
	}
	var out []models.Insight
	out = append(out, azureANInsights(a)...)
	out = append(out, azureWAAgentInsights(a)...)
	out = append(out, azureTimeSyncInsights(a)...)
	out = append(out, azureTempDiskInsights(a)...)
	out = append(out, azureCachingInsights(a)...)
	if len(out) == 0 {
		out = append(out, insight("INFO", "Azure", azureRecognitionLine(a), nil))
	}
	return out
}

// azureTempDiskInsights warns only when persistent data is layered onto the ephemeral
// temp/resource disk — the "lost my data on host migration" footgun. A temp disk that
// simply exists and is used as scratch is normal and stays quiet (folded into the
// recognition line), so the common VM is not nagged.
func azureTempDiskInsights(a models.AzureInfo) []models.Insight {
	if a.TempDiskPresent && a.PersistentDataAtRisk {
		return []models.Insight{insight("WARN", "Azure",
			fmt.Sprintf("/etc/fstab mounts persistent data under the Azure temp/resource disk (%s) — this storage is EPHEMERAL and its contents are lost on deallocation or host migration",
				a.TempDiskMount),
			[]string{
				"to inspect: grep " + a.TempDiskMount + " /etc/fstab",
				"note: the temp disk is for scratch/swap only; move persistent data to a managed data disk",
			})}
	}
	return nil
}

// azureCachingInsights flags the one documented host-cache hazard: a DATA disk with
// ReadWrite host caching. Azure recommends None/ReadOnly for data disks (ReadWrite
// write-back caching risks consistency for write-heavy/database volumes). The OS disk's
// ReadWrite default is correct and is never flagged. An unread storage profile
// (DisksChecked == false) produces no insight and is omitted from the recognition line
// — never a silent "caching OK".
func azureCachingInsights(a models.AzureInfo) []models.Insight {
	if !a.DisksChecked {
		return nil
	}
	var out []models.Insight
	for _, d := range a.Disks {
		if !d.IsOS && strings.EqualFold(d.Caching, "ReadWrite") {
			out = append(out, insight("WARN", "Azure",
				fmt.Sprintf("data disk LUN %d (%s) has ReadWrite host caching — Azure recommends None or ReadOnly for data disks; ReadWrite write-back caching risks data consistency for write-heavy/database workloads",
					d.Lun, diskLabel(d)),
				[]string{"to fix: set the disk's host caching to None (or ReadOnly) in the Azure portal/CLI for write-heavy volumes"}))
		}
	}
	return out
}

// diskLabel is the disk's name, or a placeholder when IMDS reported none.
func diskLabel(d models.AzureDisk) string {
	if d.Name != "" {
		return d.Name
	}
	return "unnamed"
}

// azureANInsights flags a broken Accelerated-Networking datapath: a VF that is present
// but not bonded under a synthetic NIC, or bonded but down. A healthy active VF and a
// synthetic-only NIC (AN simply not enabled) are NOT flagged — they're summarised in
// the recognition line — so the common no-AN VM stays quiet instead of being nagged
// about a feature it never asked for.
func azureANInsights(a models.AzureInfo) []models.Insight {
	var out []models.Insight
	for _, vf := range a.AN {
		switch {
		case !vf.Bonded:
			out = append(out, insight("WARN", "Azure",
				fmt.Sprintf("Accelerated Networking VF %s (%s) is present but NOT bonded to a synthetic NIC — traffic is not using the accelerated datapath",
					vf.VF, vf.Driver),
				[]string{
					"to inspect: ip link show " + vf.VF,
					"note: the VF should be enslaved under an hv_netvsc interface (Azure transparent bonding); a standalone VF means AN is not wired up",
				}))
		case !vf.Up:
			out = append(out, insight("WARN", "Azure",
				fmt.Sprintf("Accelerated Networking VF %s (%s) is bonded to %s but its operstate is down — the accelerated datapath is degraded",
					vf.VF, vf.Driver, vf.Synthetic),
				[]string{"to inspect: ip link show " + vf.VF}))
		}
	}
	return out
}

func azureWAAgentInsights(a models.AzureInfo) []models.Insight {
	if a.WAAgentInstalled && !a.WAAgentRunning {
		return []models.Insight{insight("WARN", "Azure",
			"Azure Linux agent (waagent) is installed but not running — VM extensions, provisioning, and portal-driven password / SSH-key reset will fail",
			[]string{"to fix: systemctl enable --now walinuxagent   (RHEL/SUSE: waagent)"})}
	}
	return nil
}

func azureTimeSyncInsights(a models.AzureInfo) []models.Insight {
	if a.TimeSyncChecked && !a.UsesHyperVPTP {
		return []models.Insight{insight("INFO", "Azure",
			"NTP is not using the Hyper-V PTP clock (/dev/ptp_hyperv) — Azure's recommended low-drift time source; a chrony PHC refclock avoids NTP drift and egress latency",
			[]string{"to fix (chrony): add 'refclock PHC /dev/ptp_hyperv poll 3 dpoll -2 offset 0' to /etc/chrony.conf, then restart chrony"})}
	}
	return nil
}

// azureRecognitionLine summarises what dsd verified clean, asserting only what it
// actually observed: the Accelerated-Networking datapath state, the agent, and the
// time source.
func azureRecognitionLine(a models.AzureInfo) string {
	var parts []string
	switch {
	case a.HasVF:
		parts = append(parts, "Accelerated Networking active ("+anDrivers(a)+")")
	case len(a.SyntheticNICs) > 0:
		parts = append(parts, "networking on the synthetic hv_netvsc path (no AN VF)")
	}
	switch {
	case a.WAAgentRunning:
		parts = append(parts, "waagent running")
	case !a.WAAgentInstalled:
		parts = append(parts, "waagent not installed")
	}
	if a.TimeSyncChecked && a.UsesHyperVPTP {
		parts = append(parts, "Hyper-V PTP time sync")
	}
	if a.DynamicMemory {
		dm := "Dynamic Memory enabled"
		if a.DynMemMaxMB > 0 {
			dm = fmt.Sprintf("Dynamic Memory enabled (max %d MB)", a.DynMemMaxMB)
		}
		parts = append(parts, dm)
	}
	if a.TempDiskPresent && !a.PersistentDataAtRisk {
		td := "temp disk ephemeral"
		if a.TempDiskMount != "" {
			td = "temp disk at " + a.TempDiskMount + " (ephemeral)"
		}
		parts = append(parts, td)
	}
	if a.DisksChecked && len(a.Disks) > 0 {
		parts = append(parts, fmt.Sprintf("host caching OK (%d disk(s))", len(a.Disks)))
	}
	summary := "guest recognised"
	if len(parts) > 0 {
		summary = strings.Join(parts, "; ")
	}
	return "Azure VM — " + summary
}

// anDrivers returns the distinct VF drivers in use (e.g. "mlx5_core"), for the
// recognition line. Only reached when all VFs are healthy (bonded + up).
func anDrivers(a models.AzureInfo) string {
	seen := map[string]bool{}
	var drivers []string
	for _, vf := range a.AN {
		if vf.Driver != "" && !seen[vf.Driver] {
			seen[vf.Driver] = true
			drivers = append(drivers, vf.Driver)
		}
	}
	sort.Strings(drivers)
	if len(drivers) == 0 {
		return "VF"
	}
	return strings.Join(drivers, ", ")
}
