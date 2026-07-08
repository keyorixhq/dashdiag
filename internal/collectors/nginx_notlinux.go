//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// NginxAvailable is false off Linux — the /proc-based probe is Linux-only.
func NginxAvailable() bool { return false }

type NginxCollector struct{}

func NewNginxCollector() *NginxCollector { return &NginxCollector{} }

func (c *NginxCollector) Name() string           { return "Nginx" }
func (c *NginxCollector) Timeout() time.Duration { return time.Second }
func (c *NginxCollector) Collect(_ context.Context) (any, error) {
	return &models.NginxInfo{Detected: false}, nil
}
