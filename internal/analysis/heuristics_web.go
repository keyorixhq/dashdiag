package analysis

import "github.com/keyorixhq/dashdiag/internal/models"

// webConfigVerdict turns a web-server's on-disk config-test result into insights.
// Shared by nginx/apache/haproxy: the value is that these servers keep serving
// their last-loaded config, so a broken on-disk config is a latent outage that
// only bites on the next reload — surfaced here as CRIT. An unreadable config
// (no root) is reported as INFO, never a silent OK.
func webConfigVerdict(server string, configTested, configValid bool, configError string) []models.Insight {
	if configTested && !configValid {
		msg := server + " on-disk config is INVALID — a reload/restart will fail"
		if configError != "" {
			msg += ": " + configError
		}
		return []models.Insight{insight("CRIT", server, msg,
			[]string{
				"to inspect: re-run the server's config test",
				"note: " + server + " is still serving its last-loaded config — a reload or restart now would fail and could take the service down",
			})}
	}
	if !configTested {
		return []models.Insight{unverifiedInsight("INFO", server,
			server+" is running; its config was not validated (the config test needs root to read the config)",
			[]string{"to inspect: re-run the config test as root"},
		)}
	}
	return nil
}

// checkNginx surfaces nginx config-validity issues. Gated on Detected.
func checkNginx(n models.NginxInfo) []models.Insight {
	if !n.Detected {
		return nil
	}
	return webConfigVerdict("Nginx", n.ConfigTested, n.ConfigValid, n.ConfigError)
}

// checkApache surfaces Apache httpd config-validity issues. Gated on Detected.
func checkApache(a models.ApacheInfo) []models.Insight {
	if !a.Detected {
		return nil
	}
	return webConfigVerdict("Apache", a.ConfigTested, a.ConfigValid, a.ConfigError)
}

// checkHAProxy surfaces HAProxy config-validity issues. Gated on Detected.
func checkHAProxy(h models.HAProxyInfo) []models.Insight {
	if !h.Detected {
		return nil
	}
	return webConfigVerdict("HAProxy", h.ConfigTested, h.ConfigValid, h.ConfigError)
}
