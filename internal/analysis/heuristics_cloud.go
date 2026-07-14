package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	cloudCatMeta         = "CloudMeta"
	cloudCatInit         = "CloudInit"
	cloudInspectInitLong = "to inspect: cloud-init status --long"
)

func checkCloudMeta(c models.CloudInfo) []models.Insight {
	if !c.Available {
		return nil
	}
	var out []models.Insight
	if c.SpotTermination {
		out = append(out, insight("CRIT", cloudCatMeta,
			fmt.Sprintf("%s spot/preemptible instance scheduled for termination — save state now", c.Provider),
			[]string{
				"note: instance will be terminated imminently",
				"to inspect: check instance metadata for exact termination time",
			}))
	} else if c.SpotCheckFailed {
		// The termination probe hit an IMDS error, so we can't confirm there's no
		// pending reclaim — surface it rather than imply "no termination scheduled".
		out = append(out, insight("INFO", cloudCatMeta,
			fmt.Sprintf("%s spot-termination check could not be confirmed — IMDS error on the termination probe", c.Provider),
			[]string{"to inspect: curl -s http://169.254.169.254/latest/meta-data/spot/termination-time"}))
	}
	if c.MaintenanceEvent {
		out = append(out, insight("WARN", cloudCatMeta,
			fmt.Sprintf("%s maintenance event pending: %s", c.Provider, c.MaintenanceDetails),
			[]string{"to inspect: check cloud provider console for details"}))
	}
	return out
}

// checkCloudInit flags instances that booted but never finished configuring.
// Generic to every cloud-init platform (not provider-specific). Silent when
// cloud-init completed cleanly, is disabled, or never ran.
func checkCloudInit(c models.CloudInitInfo) []models.Insight {
	if !c.Available {
		return nil
	}
	// cloud-init is present (status.json exists) but its status could not be read —
	// don't pass an instance with an unknown provisioning state as a silent OK.
	if c.StatusUnverified {
		return []models.Insight{insight("INFO", cloudCatInit,
			"cloud-init present but its status could NOT be read — provisioning state unverified",
			[]string{
				cloudInspectInitLong,
				"to inspect: cat /run/cloud-init/status.json",
			},
		)}
	}
	ds := c.Datasource
	if ds == "" {
		ds = "unknown"
	}
	var out []models.Insight

	switch {
	case c.Status == "error" || len(c.Errors) > 0:
		hints := []string{}
		for i, e := range c.Errors {
			if i >= 3 {
				break
			}
			hints = append(hints, "error: "+e)
		}
		hints = append(hints,
			cloudInspectInitLong,
			"logs: /var/log/cloud-init.log, /var/log/cloud-init-output.log")
		out = append(out, insight("CRIT", cloudCatInit,
			fmt.Sprintf("cloud-init failed — instance configuration incomplete (datasource: %s)", ds),
			hints))

	case strings.Contains(c.ExtendedStatus, "degraded") || len(c.RecoverableErrors) > 0:
		hints := []string{}
		for i, e := range c.RecoverableErrors {
			if i >= 3 {
				break
			}
			hints = append(hints, e)
		}
		hints = append(hints, cloudInspectInitLong)
		out = append(out, insight("WARN", cloudCatInit,
			"cloud-init completed with recoverable errors — some configuration may be missing",
			hints))

	case c.Status == "running":
		out = append(out, insight("INFO", cloudCatInit,
			"cloud-init still running — instance configuration in progress",
			[]string{"note: provisioning not yet complete; re-check after boot settles"}))
	}
	return out
}
