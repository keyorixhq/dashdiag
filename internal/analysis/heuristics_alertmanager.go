package analysis

import (
	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkAlertmanager surfaces health for a local Alertmanager. Gated on Detected.
// The headline signal is a FAILED config reload — Alertmanager keeps serving its
// last-good routing/receiver config, so recent edits are silently not applied (you
// think alerts route to PagerDuty; they're still going to the old receiver). Never
// a silent OK when status couldn't be read.
//
// Cluster gossip status is collected for context (JSON) but deliberately NOT
// alerted on: the /api/v2/status enum is ready/settling/disabled, and "settling" is
// a normal startup transient that resolves to "ready" within seconds (verified
// live) — warning on it would false-alarm on every freshly-restarted Alertmanager,
// and a one-shot probe can't distinguish transient-settling from a stuck mesh.
func checkAlertmanager(a models.AlertmanagerInfo) []models.Insight {
	if !a.Detected {
		return nil
	}

	var out []models.Insight
	if a.IdentityUnverified {
		// internal-collectors-01-02: the JSON-shape identity check can be
		// spoofed by any unprivileged local process binding :9093 first.
		// Disclose alongside (never replacing) whatever finding follows.
		out = append(out, unverifiedInsight("INFO", "Alertmanager",
			"Alertmanager was detected via an HTTP response shape match only — the listening process's identity could not be confirmed",
			[]string{"note: run as root, or verify with: ss -tlnp | grep :9093"}))
	}

	if !a.StatusRead {
		return append(out, unverifiedInsight("INFO", "Alertmanager",
			"Alertmanager is up, but its status API could not be read",
			[]string{
				"note: /api/v2/status must be reachable (a reverse proxy or auth may block it)",
				"to inspect: curl -s localhost:9093/api/v2/status",
			},
		))
	}

	// A failed config reload means recent routing/receiver edits aren't applied.
	if a.ConfigReloadRead && !a.ConfigReloadOK {
		out = append(out, insight("WARN", "Alertmanager",
			"configuration reload FAILED — Alertmanager is serving its last-good config, so recent routing/receiver edits are not applied",
			[]string{
				"to inspect: amtool check-config /etc/alertmanager/alertmanager.yml",
				"note: check the Alertmanager log for the parse error, then reload (SIGHUP or POST /-/reload)",
			}))
	} else if !a.ConfigReloadRead {
		// The status API answered, but the /metrics scrape that carries the
		// config-reload gauge did not — the one signal this check exists to
		// report was never actually established. Say so; don't go silent.
		out = append(out, unverifiedInsight("INFO", "Alertmanager",
			"Alertmanager is up, but its config-reload status could not be read",
			[]string{
				"note: /metrics must be reachable (a reverse proxy or auth may block it)",
				"to inspect: curl -s localhost:9093/metrics | grep alertmanager_config_last_reload_successful",
			},
		))
	}

	return out
}
