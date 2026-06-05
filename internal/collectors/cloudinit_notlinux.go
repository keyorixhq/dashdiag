//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type CloudInitCollector struct{}

func NewCloudInitCollector() *CloudInitCollector { return &CloudInitCollector{} }

func (c *CloudInitCollector) Name() string           { return "CloudInit" }
func (c *CloudInitCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *CloudInitCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.CloudInitInfo{}, nil
}

// CloudInitAvailable is always false off Linux (cloud-init is a Linux thing).
func CloudInitAvailable() bool { return false }
