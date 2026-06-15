//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HAProxyAvailable is false off Linux — the /proc-based probe is Linux-only.
func HAProxyAvailable() bool { return false }

type HAProxyCollector struct{}

func NewHAProxyCollector() *HAProxyCollector { return &HAProxyCollector{} }

func (c *HAProxyCollector) Name() string           { return "HAProxy" }
func (c *HAProxyCollector) Timeout() time.Duration { return time.Second }
func (c *HAProxyCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.HAProxyInfo{Detected: false}, nil
}
