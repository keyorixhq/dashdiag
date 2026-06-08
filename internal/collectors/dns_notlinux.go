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
	// The resolver audit (resolv.conf / NetworkManager / systemd-resolved) is
	// Linux-only. Report Manager "none" — the sentinel checkDNS uses to skip the
	// resolution-failure CRIT — so the audit degrades to a clean no-op off Linux
	// instead of a false "DNS resolution failing" from the zero value.
	return &models.DNSResolverInfo{Manager: "none"}, nil
}
