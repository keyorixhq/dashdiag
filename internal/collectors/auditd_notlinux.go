//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type AuditCollector struct{}

func NewAuditCollector() *AuditCollector         { return &AuditCollector{} }
func (c *AuditCollector) Name() string           { return "Auditd" }
func (c *AuditCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *AuditCollector) Collect(_ context.Context) (any, error) {
	return &models.AuditInfo{}, nil
}

func IsAuditdPresent() bool { return false }
