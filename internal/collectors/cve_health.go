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

func (c *CVEHealthCollector) Name() string { return "CVE" }

// BUG-098: this must exceed ScanAllCVEs' own internal 120s budget (list + KEV
// enrichment) — the runner wraps Collect in context.WithTimeout(ctx, Timeout()),
// and a child context's deadline can never exceed its parent's, so a shorter
// value here silently overrides ScanAllCVEs' internal ceiling. Found live on a
// cold dnf cache (Oracle Linux, 6 default repos): the flat 60s here cut the scan
// off well before ScanAllCVEs' own 120s allowance ever got a chance to matter,
// misreporting a scan that was still legitimately in progress as "timed out."
func (c *CVEHealthCollector) Timeout() time.Duration { return 130 * time.Second }

func (c *CVEHealthCollector) Collect(ctx context.Context) (interface{}, error) {
	// Cache the FULL CVE verdict (package-manager/OVAL scan + KEV enrichment) so
	// it is frozen into a capture bundle and replays from there. CVE inputs —
	// `rpm -qa`, the OVAL feed, the KEV catalog — aren't individually routed
	// through Source, and CVE data is time-varying (feeds/advisories change
	// daily), so freezing the RESULT is both the hermetic AND the correct-snapshot
	// behavior: `dsd replay`/`dsd diff` reproduce "what this host was exposed to
	// at capture time", not today's feed. On a live run this is a transparent
	// pass-through (Live.Cached just runs the scan).
	var out *models.CVEAllResult
	err := cachedJSON("cve/health", func() (any, error) {
		res := ScanAllCVEs(ctx)
		if res == nil {
			res = &models.CVEAllResult{}
		}
		// Cross-reference pending advisories against the CISA KEV catalog. No-op
		// when no sidecar catalog is present — keeps air-gapped hosts working.
		EnrichCVEAllWithKEV(res)
		return res, nil
	}, &out)
	if err != nil || out == nil {
		// Replaying a bundle captured without --cve-scan: nothing recorded. Surface
		// it honestly rather than running a live scan against the replaying machine.
		return &models.CVEAllResult{
			StatusReason: "CVE scan not captured in this bundle (re-capture with: dsd capture --raw --cve-scan)",
		}, nil
	}
	return out, nil
}
