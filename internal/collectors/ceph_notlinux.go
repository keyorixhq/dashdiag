//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type CephCollector struct{}

func NewCephCollector() *CephCollector          { return &CephCollector{} }
func (c *CephCollector) Name() string           { return "Ceph" }
func (c *CephCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *CephCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.CephInfo{}, nil
}

func IsCephPresent() bool { return false }
