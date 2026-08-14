//go:build !linux && !darwin

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// SecurityCollector is a no-op on non-Linux platforms.
type SecurityCollector struct {
	profile platform.Profile
}

func NewSecurityCollector() *SecurityCollector { return &SecurityCollector{} }

// NewSecurityCollectorWithProfile mirrors the Linux constructor; the profile is
// unused on non-Linux platforms where the collector is a no-op.
func NewSecurityCollectorWithProfile(p platform.Profile) *SecurityCollector {
	return &SecurityCollector{profile: p}
}

func (c *SecurityCollector) Name() string           { return "Hardening" }
func (c *SecurityCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *SecurityCollector) Collect(_ context.Context) (interface{}, error) {
	// internal-collectors-30-01: a bare zero-value SecurityInfo leaves every
	// "couldn't check" sentinel unset, which checkSecurityAuditGaps relies on
	// exclusively to disclose an audit gap — its own doc comment states the
	// exact failure mode this produced: "a non-root run reads as audited,
	// clean" (here, a run on ANY platform this build targets reads as
	// audited-clean, since none of the hardening checks are implemented at
	// all on non-Linux/non-Darwin). Set the same sentinels a real
	// implementation sets when it can't read its sources, so the standard
	// "not audited" INFO disclosures fire instead of total silence.
	return &models.SecurityInfo{
		NeedsRoot:              true,
		SSHConfigUnreadable:    true,
		ShadowUnreadable:       true,
		FailedLoginsUnreadable: true,
		PAMFailuresUnreadable:  true,
	}, nil
}

// CollectSUSEConnect is a no-op on non-Linux platforms.
func CollectSUSEConnect(_ context.Context, _ *models.SecurityInfo) { /* no-op */ }

// SUIDBinScanPaths mirrors the Linux variable; unused on non-Linux (no SUID scan).
var SUIDBinScanPaths []string

// ScanSUIDBinaries is a no-op on non-Linux platforms.
func ScanSUIDBinaries(_ *models.SecurityInfo) { /* no-op */ }
