package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

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
