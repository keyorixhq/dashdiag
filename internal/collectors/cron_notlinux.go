//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type CronCollector struct{}

func NewCronCollector() *CronCollector { return &CronCollector{} }

func (c *CronCollector) Name() string           { return "Cron" }
func (c *CronCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *CronCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.CronInfo{}, nil
}
