//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type ISCSICollector struct{}

func NewISCSICollector() *ISCSICollector         { return &ISCSICollector{} }
func (c *ISCSICollector) Name() string           { return "ISCSI" }
func (c *ISCSICollector) Timeout() time.Duration { return 2 * time.Second }

func (c *ISCSICollector) Collect(_ context.Context) (interface{}, error) {
	return &models.ISCSIInfo{}, nil
}

func IsISCSIPresent() bool { return false }
