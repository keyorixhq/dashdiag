//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type OOMCollector struct{}

func NewOOMCollector() *OOMCollector           { return &OOMCollector{} }
func (c *OOMCollector) Name() string           { return "OOM" }
func (c *OOMCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *OOMCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.OOMInfo{}, nil
}
