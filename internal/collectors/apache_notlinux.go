//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ApacheAvailable is false off Linux — the /proc-based probe is Linux-only.
func ApacheAvailable() bool { return false }

type ApacheCollector struct{}

func NewApacheCollector() *ApacheCollector { return &ApacheCollector{} }

func (c *ApacheCollector) Name() string           { return "Apache" }
func (c *ApacheCollector) Timeout() time.Duration { return time.Second }
func (c *ApacheCollector) Collect(_ context.Context) (any, error) {
	return &models.ApacheInfo{Detected: false}, nil
}
