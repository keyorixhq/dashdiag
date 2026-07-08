//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// EnvoyAvailable is false off Linux — the probe is Linux-only.
func EnvoyAvailable() bool { return false }

type EnvoyCollector struct{}

func NewEnvoyCollector() *EnvoyCollector { return &EnvoyCollector{} }

func (c *EnvoyCollector) Name() string           { return "Envoy" }
func (c *EnvoyCollector) Timeout() time.Duration { return time.Second }
func (c *EnvoyCollector) Collect(_ context.Context) (any, error) {
	return &models.EnvoyInfo{Detected: false}, nil
}
