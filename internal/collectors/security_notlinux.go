//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// SecurityCollector is a no-op on non-Linux platforms.
type SecurityCollector struct{}

func NewSecurityCollector() *SecurityCollector { return &SecurityCollector{} }

func (c *SecurityCollector) Name() string           { return "Hardening" }
func (c *SecurityCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *SecurityCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.SecurityInfo{}, nil
}
