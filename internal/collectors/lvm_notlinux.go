//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type LVMCollector struct{}

func NewLVMCollector() *LVMCollector { return &LVMCollector{} }

func (c *LVMCollector) Name() string           { return "LVM" }
func (c *LVMCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *LVMCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.LVMInfo{}, nil
}
