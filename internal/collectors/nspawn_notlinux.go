//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type NspawnCollector struct{}

func NewNspawnCollector() *NspawnCollector        { return &NspawnCollector{} }
func (c *NspawnCollector) Name() string           { return "Nspawn" }
func (c *NspawnCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *NspawnCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.NspawnInfo{}, nil
}

func IsNspawnPresent() bool { return false }
