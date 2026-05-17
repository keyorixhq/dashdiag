package collectors

import (
	"context"
	"os"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// IsSUSEHost returns true when this is a SUSE/openSUSE system.
// SUSEConnect and subscription checks are only meaningful on SUSE-family distros.
func IsSUSEHost() bool {
	// SUSEConnect binary is the definitive indicator
	if _, err := os.Stat("/usr/bin/SUSEConnect"); err == nil {
		return true
	}
	// zypper package manager is SUSE-specific
	if _, err := os.Stat("/usr/bin/zypper"); err == nil {
		return true
	}
	return false
}

// SUSEConnectCollector surfaces SUSEConnect subscription status in dsd health.
// On non-SLES systems SUSEConnect is absent — CollectSUSEConnect returns
// an empty SecurityInfo with Registered=false, which checkSUSEConnect skips.
type SUSEConnectCollector struct{}

func NewSUSEConnectCollector() *SUSEConnectCollector { return &SUSEConnectCollector{} }

func (c *SUSEConnectCollector) Name() string           { return "Subscription" }
func (c *SUSEConnectCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *SUSEConnectCollector) Collect(ctx context.Context) (interface{}, error) {
	sec := &models.SecurityInfo{}
	CollectSUSEConnect(ctx, sec)
	return &models.SUSEConnectInfo{
		Registered:  sec.SUSEConnectRegistered,
		ExpiresDays: sec.SUSEConnectExpiresDays,
		Status:      sec.SUSEConnectStatus,
	}, nil
}
