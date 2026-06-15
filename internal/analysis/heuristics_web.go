package analysis

import "github.com/keyorixhq/dashdiag/internal/models"

// checkNginx surfaces health issues for a local nginx server. Gated on Detected
// (a running nginx process), silent when healthy. The headline is config
// validity: nginx keeps serving its last-loaded config, so a broken on-disk
// config is a latent outage that only bites on the next reload — `dsd` surfaces
// it first. Never a silent OK when the config couldn't be tested.
func checkNginx(n models.NginxInfo) []models.Insight {
	if !n.Detected {
		return nil
	}

	// Invalid on-disk config — the next reload/restart will fail.
	if n.ConfigTested && !n.ConfigValid {
		msg := "nginx on-disk config is INVALID — a reload/restart will fail"
		if n.ConfigError != "" {
			msg += ": " + n.ConfigError
		}
		return []models.Insight{insight("CRIT", "Nginx", msg,
			[]string{
				"to inspect: nginx -t",
				"note: nginx is still serving its last-loaded config — a reload or restart now would fail and could take the site down",
			})}
	}

	// Couldn't validate (usually non-root) — say so rather than imply healthy.
	if !n.ConfigTested {
		return []models.Insight{insight("INFO", "Nginx",
			"nginx is running; its config was not validated (nginx -t needs root to read the config)",
			[]string{"to inspect: sudo nginx -t"},
		)}
	}

	return nil
}
