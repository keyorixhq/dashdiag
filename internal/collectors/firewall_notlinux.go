//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type FirewallCollector struct{}

func NewFirewallCollector() *FirewallCollector      { return &FirewallCollector{} }
func (c *FirewallCollector) Name() string           { return "Firewall" }
func (c *FirewallCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *FirewallCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.FirewallInfo{}, nil
}
