//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// PrometheusAvailable is false off Linux — the probe is Linux-only.
func PrometheusAvailable() bool { return false }

type PrometheusCollector struct{}

func NewPrometheusCollector() *PrometheusCollector { return &PrometheusCollector{} }

func (c *PrometheusCollector) Name() string           { return "Prometheus" }
func (c *PrometheusCollector) Timeout() time.Duration { return time.Second }
func (c *PrometheusCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.PrometheusInfo{Detected: false}, nil
}
