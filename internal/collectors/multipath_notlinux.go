//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type MultipathCollector struct{}

func NewMultipathCollector() *MultipathCollector     { return &MultipathCollector{} }
func (c *MultipathCollector) Name() string           { return "Multipath" }
func (c *MultipathCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *MultipathCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.MultipathInfo{}, nil
}

func IsMultipathPresent() bool { return false }
