//go:build !linux

package collectors

import (
	"context"
	"time"
)

type DNSResolverCollector struct{}

func NewDNSResolverCollector() *DNSResolverCollector   { return &DNSResolverCollector{} }
func (c *DNSResolverCollector) Name() string           { return "DNS resolver" }
func (c *DNSResolverCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *DNSResolverCollector) Collect(_ context.Context) (interface{}, error) {
	return nil, nil // systemd-resolved / resolvectl are Linux-only
}
