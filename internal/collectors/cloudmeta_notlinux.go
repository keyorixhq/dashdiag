//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type CloudMetaCollector struct{}

func NewCloudMetaCollector() *CloudMetaCollector     { return &CloudMetaCollector{} }
func (c *CloudMetaCollector) Name() string           { return "CloudMeta" }
func (c *CloudMetaCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *CloudMetaCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.CloudInfo{}, nil
}

func IsCloudInstance() bool { return false }
