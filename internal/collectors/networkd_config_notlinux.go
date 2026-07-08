//go:build !linux

package collectors

import (
	"context"
	"time"
)

type NetworkdConfigCollector struct{}

func NewNetworkdConfigCollector() *NetworkdConfigCollector { return &NetworkdConfigCollector{} }
func (c *NetworkdConfigCollector) Name() string            { return "Networkd" }
func (c *NetworkdConfigCollector) Timeout() time.Duration  { return 1 * time.Second }

func (c *NetworkdConfigCollector) Collect(_ context.Context) (any, error) {
	return nil, nil // systemd-networkd is Linux-only
}

// NetworkdAvailable is always false off Linux.
func NetworkdAvailable() bool { return false }
