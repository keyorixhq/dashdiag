//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type VLANCollector struct{}

func NewVLANCollector() *VLANCollector          { return &VLANCollector{} }
func (c *VLANCollector) Name() string           { return "VLAN" }
func (c *VLANCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *VLANCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.VLANInfo{}, nil
}

func IsVLANPresent() bool { return false }
