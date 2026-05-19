//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type DNSCollector struct{}

func NewDNSCollector() *DNSCollector { return &DNSCollector{} }

func (c *DNSCollector) Name() string           { return "DNS" }
func (c *DNSCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *DNSCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.DNSResolverInfo{}, nil
}
