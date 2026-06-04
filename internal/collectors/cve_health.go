package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// CVEHealthCollector folds the CVE security-advisory scan into `dsd health` so
// actively-exploited and critical CVEs surface as live WARN/CRIT verdicts
// alongside the rest of the health check — rather than only via `dsd cve`.
//
// It is opt-in (gated behind `dsd health --cve`) because the underlying package
// manager scan can be slow on systems with stale or large metadata. The scan is
// the same severity-bucketed data as `dsd cve --all`, cross-referenced against
// the CISA KEV catalog when a sidecar file is available.
type CVEHealthCollector struct{}

func NewCVEHealthCollector() *CVEHealthCollector { return &CVEHealthCollector{} }

func (c *CVEHealthCollector) Name() string           { return "CVE" }
func (c *CVEHealthCollector) Timeout() time.Duration { return 60 * time.Second }

func (c *CVEHealthCollector) Collect(ctx context.Context) (interface{}, error) {
	res := ScanAllCVEs(ctx)
	if res == nil {
		return &models.CVEAllResult{}, nil
	}
	// Cross-reference pending advisories against the CISA KEV catalog. No-op when
	// no sidecar catalog is present — keeps air-gapped hosts working.
	EnrichCVEAllWithKEV(res)
	return res, nil
}
