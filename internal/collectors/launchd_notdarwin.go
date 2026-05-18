//go:build !darwin

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type LaunchdCollector struct{}

func NewLaunchdCollector() *LaunchdCollector       { return &LaunchdCollector{} }
func (c *LaunchdCollector) Name() string           { return "Launchd" }
func (c *LaunchdCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *LaunchdCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.LaunchdInfo{}, nil
}
