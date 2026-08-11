package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkOCI reports guest-side health for a Linux instance on Oracle Cloud
// Infrastructure: IMDS v2 security posture, oracle-cloud-agent health, time
// sync against OCI's metadata NTP server, and VNIC ring-buffer drops. Silent
// on every non-OCI host (the collector only runs behind the DMI gate). When
// everything it could verify is clean it emits one INFO recognition line.
// OCIInsights is the exported entry point for the standalone `dsd oci`
// command. It returns exactly what `dsd health` evaluates for an OCI guest
// (it IS checkOCI), so the two verdicts cannot drift.
func OCIInsights(o models.OCIInfo) []models.Insight { return checkOCI(o) }

func checkOCI(o models.OCIInfo) []models.Insight {
	if !o.IsOCI {
		return nil
	}
	var out []models.Insight
	out = append(out, ociIMDSInsights(o)...)
	out = append(out, ociAgentInsights(o)...)
	out = append(out, ociTimeSyncInsights(o)...)
	out = append(out, ociVNICInsights(o)...)
	if len(out) == 0 {
		if !o.IMDSChecked && !o.AgentChecked && !o.TimeSyncChecked && !o.VNICChecked {
			// Nothing at all could be verified — the recognition line reflects
			// that, not a confirmed-clean posture.
			out = append(out, unverifiedInsight("INFO", "OCI", ociRecognitionLine(o), nil))
		} else {
			out = append(out, insight("INFO", "OCI", ociRecognitionLine(o), nil))
		}
	}
	return out
}

func ociIMDSInsights(o models.OCIInfo) []models.Insight {
	if o.IMDSChecked && o.IMDSv1Open {
		return []models.Insight{insight("WARN", "OCI",
			"legacy/unauthenticated IMDS access is reachable (a request without the required Authorization header still returned 200) — instance metadata is reachable via the SSRF path IMDS v2 exists to close",
			[]string{
				"to inspect: curl -s -o /dev/null -w '%{http_code}\\n' http://169.254.169.254/opc/v2/instance/",
				"note: a correctly configured instance returns 403 here",
			})}
	}
	return nil
}

func ociAgentInsights(o models.OCIInfo) []models.Insight {
	if !o.AgentChecked || !o.AgentInstalled {
		return nil
	}
	var out []models.Insight
	if !o.AgentRunning {
		out = append(out, insight("WARN", "OCI",
			"oracle-cloud-agent is installed but not running — Compute Instance Run Command, monitoring, and OS Management Hub plugins are unavailable on this instance",
			[]string{"to fix: systemctl enable --now oracle-cloud-agent"}))
	}
	if !o.AgentUpdaterRunning {
		out = append(out, insight("INFO", "OCI",
			"oracle-cloud-agent-updater is not running — the agent itself will not receive updates",
			[]string{"to fix: systemctl enable --now oracle-cloud-agent-updater"}))
	}
	return out
}

func ociTimeSyncInsights(o models.OCIInfo) []models.Insight {
	if !o.TimeSyncChecked {
		return nil
	}
	if !o.UsesOCITimeSync {
		return []models.Insight{insight("INFO", "OCI",
			"NTP is not pointed at OCI's metadata NTP server (169.254.169.254) — the link-local service avoids clock drift and egress latency",
			[]string{"to fix (chrony): add 'server 169.254.169.254 iburst' to /etc/chrony.conf, then restart chrony"})}
	}
	if !o.TimeSynced {
		return []models.Insight{insight("WARN", "OCI",
			"NTP is configured against OCI's metadata NTP server but chrony shows no synced source — time sync is not actually happening",
			[]string{
				"to inspect: chronyc sources",
				"note: a security-list/NSG change blocking 169.254.169.254 would cause exactly this",
			})}
	}
	return nil
}

func ociVNICInsights(o models.OCIInfo) []models.Insight {
	var out []models.Insight
	for _, v := range o.VNICs {
		if v.RxDrops == 0 && v.TxTimeouts == 0 {
			continue
		}
		var parts []string
		if v.RxDrops > 0 {
			parts = append(parts, fmt.Sprintf("%d rx drop(s)", v.RxDrops))
		}
		if v.TxTimeouts > 0 {
			parts = append(parts, fmt.Sprintf("%d tx timeout(s)", v.TxTimeouts))
		}
		out = append(out, insight("WARN", "OCI",
			fmt.Sprintf("%s: %s on the VNIC ring buffer since boot — real packet loss the generic NIC-error counters don't catch",
				v.Iface, strings.Join(parts, ", ")),
			[]string{"to inspect: ethtool -S " + v.Iface + " | grep -E 'drops|timeouts'"}))
	}
	return out
}

// ociRecognitionLine summarises what dsd verified clean, asserting only the
// things it actually checked. If none of the four sub-checks ran at all, it
// says so rather than defaulting to "no issues found" for a host where
// nothing was actually verified.
func ociRecognitionLine(o models.OCIInfo) string {
	shape := o.Shape
	if shape == "" {
		shape = "instance"
	}
	if !o.IMDSChecked && !o.AgentChecked && !o.TimeSyncChecked && !o.VNICChecked {
		return fmt.Sprintf("OCI %s — guest-side posture could not be verified: IMDS, cloud agent, time sync, and VNICs were all unreachable or unreadable", shape)
	}
	var parts []string
	if o.IMDSChecked && !o.IMDSv1Open {
		parts = append(parts, "IMDS v2 enforced")
	}
	if o.AgentChecked && o.AgentInstalled && o.AgentRunning {
		parts = append(parts, "cloud agent running")
	}
	if o.TimeSyncChecked && o.UsesOCITimeSync && o.TimeSynced {
		parts = append(parts, "time synced")
	}
	if o.VNICChecked && len(o.VNICs) > 0 {
		parts = append(parts, "VNIC rings clean")
	}
	summary := "no guest-side posture issues found"
	if len(parts) > 0 {
		summary = strings.Join(parts, "; ")
	}
	return fmt.Sprintf("OCI %s — %s", shape, summary)
}
