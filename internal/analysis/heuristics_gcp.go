package analysis

import (
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkGCP reports guest-side health for a Linux VM on Google Compute Engine. The
// actionable checks are the Google guest agent (installed-but-down silently breaks
// SSH-key / OS-Login propagation) and a host-maintenance policy of TERMINATE on a
// non-preemptible VM (the operator likely expected live migration). Silent on every
// non-GCP host (the collector only runs behind the DMI gate). When everything it could
// verify is clean it emits one INFO recognition line.
// GCPInsights is the exported entry point for the standalone `dsd gcp` command. It
// returns exactly what `dsd health` evaluates for a GCE guest (it IS checkGCP), so
// the two verdicts cannot drift — the cmd↔health consistency invariant.
func GCPInsights(g models.GCPInfo) []models.Insight { return checkGCP(g) }

func checkGCP(g models.GCPInfo) []models.Insight {
	if !g.IsGCP {
		return nil
	}
	var out []models.Insight
	out = append(out, gcpGuestAgentInsights(g)...)
	out = append(out, gcpMaintenanceInsights(g)...)
	out = append(out, gcpTimeSyncInsights(g)...)
	if len(out) == 0 {
		out = append(out, insight("INFO", "GCP", gcpRecognitionLine(g), nil))
	}
	return out
}

func gcpGuestAgentInsights(g models.GCPInfo) []models.Insight {
	if g.GuestAgentInstalled && !g.GuestAgentRunning {
		return []models.Insight{insight("WARN", "GCP",
			"Google guest agent is installed but not running — SSH-key propagation, OS Login, and account management will silently fail",
			[]string{"to fix: systemctl enable --now google-guest-agent"})}
	}
	return nil
}

// gcpMaintenanceInsights flags an in-progress maintenance event, and the catchable
// misconfiguration: a non-preemptible VM set to TERMINATE on host maintenance (it will
// stop rather than live-migrate). A preemptible VM is EXPECTED to terminate, so that is
// not flagged.
func gcpMaintenanceInsights(g models.GCPInfo) []models.Insight {
	if !g.MaintenanceChecked {
		return nil
	}
	var out []models.Insight
	if g.ActiveMaintenance != "" {
		out = append(out, insight("WARN", "GCP",
			"a host-maintenance event is in progress ("+g.ActiveMaintenance+") — the VM is being live-migrated or will be stopped shortly",
			[]string{"to inspect: curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/maintenance-event"}))
	}
	if strings.EqualFold(g.OnHostMaintenance, "TERMINATE") && !g.Preemptible {
		out = append(out, insight("WARN", "GCP",
			"on-host-maintenance is set to TERMINATE on a non-preemptible VM — it will be STOPPED (not live-migrated) during Google host maintenance, causing unplanned downtime",
			[]string{"to fix: set --maintenance-policy=MIGRATE (gcloud compute instances set-scheduling) unless the stop is intentional"}))
	}
	return out
}

func gcpTimeSyncInsights(g models.GCPInfo) []models.Insight {
	if g.TimeSyncChecked && !g.UsesMetadataNTP {
		return []models.Insight{insight("INFO", "GCP",
			"NTP is not using the GCP metadata server (metadata.google.internal / 169.254.169.254) — Google's recommended low-drift time source",
			[]string{"to fix (chrony): set 'server metadata.google.internal iburst' in /etc/chrony.conf, then restart chrony"})}
	}
	return nil
}

// gcpRecognitionLine summarises what dsd verified clean, asserting only what it
// actually observed: the NIC datapath, the guest agent, host-maintenance policy, OS
// Login, and the time source. Anything not measured is omitted, never implied OK.
func gcpRecognitionLine(g models.GCPInfo) string {
	var parts []string
	switch {
	case g.UsesGVNIC:
		parts = append(parts, "gVNIC networking (gve)")
	case g.NICDriver != "":
		parts = append(parts, "networking on "+g.NICDriver)
	}
	switch {
	case g.GuestAgentRunning:
		parts = append(parts, "guest agent running")
	case !g.GuestAgentInstalled:
		parts = append(parts, "guest agent not installed")
	}
	if g.MaintenanceChecked && g.OnHostMaintenance != "" {
		parts = append(parts, "on-host-maintenance="+g.OnHostMaintenance)
	}
	if g.OSLoginChecked && g.OSLoginEnabled {
		parts = append(parts, "OS Login enabled")
	}
	if g.TimeSyncChecked && g.UsesMetadataNTP {
		parts = append(parts, "metadata NTP time sync")
	}
	summary := "guest recognised"
	if len(parts) > 0 {
		summary = strings.Join(parts, "; ")
	}
	return "GCP VM — " + summary
}
