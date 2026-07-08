//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// AlertmanagerAvailable is false off Linux — the probe is Linux-only.
func AlertmanagerAvailable() bool { return false }

type AlertmanagerCollector struct{}

func NewAlertmanagerCollector() *AlertmanagerCollector { return &AlertmanagerCollector{} }

func (c *AlertmanagerCollector) Name() string           { return "Alertmanager" }
func (c *AlertmanagerCollector) Timeout() time.Duration { return time.Second }
func (c *AlertmanagerCollector) Collect(_ context.Context) (any, error) {
	return &models.AlertmanagerInfo{Detected: false}, nil
}
