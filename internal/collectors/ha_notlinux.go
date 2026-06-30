//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Non-Linux stub — Pacemaker/Corosync is a Linux-only stack.
type HACollector struct{}

func NewHACollector() *HACollector            { return &HACollector{} }
func (c *HACollector) Name() string           { return "HACluster" }
func (c *HACollector) Timeout() time.Duration { return time.Second }
func (c *HACollector) Collect(context.Context) (interface{}, error) {
	return &models.HAInfo{}, nil
}
func HAAvailable() bool { return false }
