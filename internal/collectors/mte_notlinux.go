//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type MTECollector struct{}

func NewMTECollector() *MTECollector           { return &MTECollector{} }
func (c *MTECollector) Name() string           { return "MTE" }
func (c *MTECollector) Timeout() time.Duration { return 5 * time.Second }

func (c *MTECollector) Collect(_ context.Context) (interface{}, error) {
	return &models.MTEInfo{}, nil
}

func IsMTEAvailable() bool { return false }
