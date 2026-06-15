//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TraefikAvailable is false off Linux — the probe is Linux-only.
func TraefikAvailable() bool { return false }

type TraefikCollector struct{}

func NewTraefikCollector() *TraefikCollector { return &TraefikCollector{} }

func (c *TraefikCollector) Name() string           { return "Traefik" }
func (c *TraefikCollector) Timeout() time.Duration { return time.Second }
func (c *TraefikCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.TraefikInfo{Detected: false}, nil
}
