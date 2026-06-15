//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// GrafanaAvailable is false off Linux — the probe is Linux-only.
func GrafanaAvailable() bool { return false }

type GrafanaCollector struct{}

func NewGrafanaCollector() *GrafanaCollector { return &GrafanaCollector{} }

func (c *GrafanaCollector) Name() string           { return "Grafana" }
func (c *GrafanaCollector) Timeout() time.Duration { return time.Second }
func (c *GrafanaCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.GrafanaInfo{Detected: false}, nil
}
