package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	haCatHACluster   = "HACluster"
	haInspectCrmStat = "to inspect: crm status"
)

// checkHA flags Pacemaker/Corosync HA-cluster faults: lost quorum, offline nodes,
// failed/stopped resources, and disabled/unconfigured fencing (STONITH) — the classic
// "it failed over and corrupted the data" footgun. Silent on a healthy, fully-fenced
// cluster; honest about "couldn't read" under non-root rather than implying healthy.
func checkHA(d models.HAInfo) []models.Insight {
	if !d.Available {
		return nil
	}
	if !d.Running {
		return []models.Insight{insight("WARN", haCatHACluster,
			"Pacemaker/Corosync is installed but not running — this node is not an active cluster member",
			[]string{"to inspect: systemctl status corosync pacemaker", "to start: systemctl start corosync pacemaker"})}
	}
	if !d.StatusReadable {
		return []models.Insight{unverifiedInsight("INFO", haCatHACluster,
			"the cluster is running but its status could not be read — run as root to verify nodes, resources, and fencing",
			[]string{"to inspect: sudo crm status"})}
	}
	var out []models.Insight
	if d.QuorumKnown && !d.Quorate {
		out = append(out, insight("CRIT", haCatHACluster,
			"the cluster has LOST QUORUM — this partition stops/refuses resources to avoid split-brain; managed services may be down",
			[]string{"to inspect: corosync-quorumtool -s", haInspectCrmStat}))
	}
	if len(d.OfflineNodes) > 0 {
		out = append(out, insight("CRIT", haCatHACluster,
			fmt.Sprintf("%d of %d cluster node(s) OFFLINE: %s — redundancy is reduced or lost", len(d.OfflineNodes), d.NodesTotal, strings.Join(firstN(d.OfflineNodes, 3), ", ")),
			[]string{haInspectCrmStat, "to inspect: corosync-quorumtool -l"}))
	}
	if len(d.FailedResources) > 0 {
		out = append(out, insight("CRIT", haCatHACluster,
			fmt.Sprintf("%d cluster resource(s) FAILED: %s — the service they manage may be down", len(d.FailedResources), strings.Join(firstN(d.FailedResources, 3), ", ")),
			[]string{"to inspect: crm status --failcounts", "to recover: crm resource cleanup <rsc>"}))
	}
	if len(d.StoppedResources) > 0 {
		out = append(out, insight("WARN", haCatHACluster,
			fmt.Sprintf("%d cluster resource(s) stopped: %s", len(d.StoppedResources), strings.Join(firstN(d.StoppedResources, 3), ", ")),
			[]string{haInspectCrmStat, "to start: crm resource start <rsc>"}))
	}
	if len(d.AmbiguousResources) > 0 {
		// internal-collectors-14-04: these resources are counted in
		// ResourcesTotal but matched none of Failed/Started/Stopped above —
		// a multi-state resource's transitional role or a blocked/unmanaged
		// resource. Disclose rather than let them silently vanish.
		out = append(out, unverifiedInsight("INFO", haCatHACluster,
			fmt.Sprintf("%d cluster resource(s) in an unrecognized role/state, not counted as started/stopped/failed: %s", len(d.AmbiguousResources), strings.Join(firstN(d.AmbiguousResources, 3), ", ")),
			[]string{haInspectCrmStat, "note: common for multi-state (promotable) resources mid-transition (Promoting/Unpromoted/Stopping) or a blocked/unmanaged resource"}))
	}
	if !d.StonithEnabled {
		out = append(out, insight("WARN", haCatHACluster,
			"STONITH (fencing) is DISABLED — on a node failure the cluster cannot safely fence it, risking split-brain and data corruption on shared storage",
			[]string{"to inspect: crm configure show | grep stonith-enabled", "note: production HA needs fencing enabled with a real STONITH device"}))
	} else if d.StonithDevices == 0 {
		out = append(out, insight("WARN", haCatHACluster,
			"STONITH is enabled but NO fence device is configured — resources may refuse to start until a fencing device exists",
			[]string{"to inspect: crm configure show type:primitive"}))
	}
	return out
}
