package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkVault surfaces HashiCorp Vault misconfigurations detectable without
// credentials. Auth method, audit devices, token TTLs, and dynamic secrets
// require an authenticated client and are surfaced by the platform-side
// reasoning layer.
func checkVault(v models.VaultInfo) []models.Insight {
	if !v.Available {
		return nil
	}

	if !v.Reachable {
		return []models.Insight{insight("WARN", "Vault",
			"Vault expected but not responding on port 8200 — secrets manager is down",
			[]string{
				"to inspect: systemctl status vault",
				"to inspect: journalctl -u vault -n 50",
			},
		)}
	}

	if !v.StatusRead {
		// Distinguish: server responded (HTTPStatus > 0) with a non-Vault body
		// (proxy interception, wrong port) vs. no parseable response at all.
		if v.HTTPStatus > 0 {
			return []models.Insight{insight("WARN", "Vault",
				fmt.Sprintf("Vault health endpoint returned HTTP %d but response was not valid Vault JSON — check for proxy interception or wrong port", v.HTTPStatus),
				[]string{
					"note: a load balancer or reverse proxy may be intercepting the request",
					"to inspect: curl -sk https://127.0.0.1:8200/v1/sys/health",
				},
			)}
		}
		return []models.Insight{unverifiedInsight("INFO", "Vault",
			"Vault is up but its API could not be read — health state unverified",
			[]string{
				"note: /v1/sys/health must be reachable (a firewall or proxy may block it)",
				"to inspect: curl -sk https://127.0.0.1:8200/v1/sys/health",
			},
		)}
	}

	var out []models.Insight
	if v.IdentityUnverified {
		// internal-collectors-33-05: vaultProbeBase only confirmed a
		// non-empty HTTP response, not that the responder is really Vault —
		// spoofable by any unprivileged local process binding :8200 first.
		// Disclose alongside (never replacing) whatever finding follows.
		out = append(out, unverifiedInsight("INFO", "Vault",
			"Vault was detected via an HTTP response only — the listening process's identity could not be confirmed",
			[]string{"note: run as root, or verify with: ss -tlnp | grep :8200"}))
	}

	// Dev mode: no persistence, root token printed to stdout, TLS disabled.
	// Report this before the TLS check — dev mode implies no TLS by design, so
	// a separate TLS finding would be redundant and misleading.
	if v.DevMode {
		out = append(out, insight("CRIT", "Vault",
			"Vault running in dev mode: no data persistence, root token printed to stdout — not suitable for production",
			[]string{
				"note: all secrets are lost on restart",
				"note: dev mode disables TLS and uses an in-memory storage backend",
				"to fix: deploy Vault with a persistent storage backend and a proper config file",
			},
		))
	}

	if v.Sealed {
		out = append(out, insight("CRIT", "Vault",
			"Vault is sealed: all secret reads are failing until an operator unseals it",
			[]string{
				"to unseal: vault operator unseal (requires unseal key shares)",
				"to inspect: vault status",
			},
		))
	}

	if !v.Initialized {
		out = append(out, insight("WARN", "Vault",
			"Vault is installed but has never been initialised — secrets management is non-functional",
			[]string{
				"to initialise: vault operator init",
				"note: initialisation generates the unseal keys and root token",
			},
		))
	}

	// TLS: only flag when not in dev mode (dev mode already reported above).
	if !v.DevMode && !v.TLSEnabled {
		out = append(out, insight("WARN", "Vault",
			"Vault API is accepting plaintext HTTP — secrets transit unencrypted",
			[]string{
				"to fix: set tls_cert_file and tls_key_file in the listener block",
				"to inspect: curl -s http://127.0.0.1:8200/v1/sys/health",
			},
		))
	}

	return out
}
