//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type HugePagesCollector struct{}

func NewHugePagesCollector() *HugePagesCollector     { return &HugePagesCollector{} }
func (c *HugePagesCollector) Name() string           { return "HugePages" }
func (c *HugePagesCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *HugePagesCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.HugePagesInfo{}, nil
}

func IsHugePagesConfigured() bool { return false }
